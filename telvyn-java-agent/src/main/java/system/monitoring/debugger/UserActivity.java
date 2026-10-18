package system.monitoring.debugger;

import java.lang.instrument.Instrumentation;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Locale;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import static net.bytebuddy.matcher.ElementMatchers.*;

/**
 * Eventos automáticos de usuário do Spring Security, como o Datadog no Java: login com sucesso, login com
 * falha (com usr_exists, pelo UserDetailsService) e cadastro (UserDetailsManager.createUser). Só login por
 * usuário e senha (UsernamePasswordAuthenticationToken), não a validação de token de cada requisição.
 * Login de usuário bloqueado recebe a resposta de bloqueio. Modo de coleta: identification (id e login como
 * estão), anonymization (hash "anon_" + SHA-256 truncado em 128 bits) ou disabled — pela tela ou por
 * telvyn.security.user-tracking / TELVYN_SECURITY_USER_TRACKING; "disabled" local sempre vale.
 */
public final class UserActivity {
    private static final ThreadLocal<int[]> depth = ThreadLocal.withInitial(() -> new int[1]);
    private static final ThreadLocal<Boolean> exists = new ThreadLocal<>();
    private static volatile LocalAttackReporter reporter;

    private UserActivity() {}

    public static void install(Instrumentation instrumentation) {
        new AgentBuilder.Default().disableClassFormatChanges()
            .type(hasSuperType(named("org.springframework.security.authentication.AuthenticationManager")).and(not(isInterface())))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Authenticate.class).on(named("authenticate").and(not(isAbstract())).and(takesArguments(1)))))
            .installOn(instrumentation);
        new AgentBuilder.Default().disableClassFormatChanges()
            .type(hasSuperType(named("org.springframework.security.core.userdetails.UserDetailsService")).and(not(isInterface())))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(LoadUser.class).on(named("loadUserByUsername").and(not(isAbstract())).and(takesArguments(String.class)))))
            .installOn(instrumentation);
        new AgentBuilder.Default().disableClassFormatChanges()
            .type(hasSuperType(named("org.springframework.security.provisioning.UserDetailsManager")).and(not(isInterface())))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(CreateUser.class).on(named("createUser").and(not(isAbstract())).and(takesArguments(1)))))
            .installOn(instrumentation);
        // API manual (telvyn-java-api, como o EventTrackerV2 do Datadog): os métodos da API não fazem nada sem o agente.
        new AgentBuilder.Default().disableClassFormatChanges()
            .type(named("system.monitoring.telvyn.TelvynSecurity"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(Manual.class).on(namedOneOf("trackUserLoginSuccess", "trackUserLoginFailure", "trackUserSignup", "setUser").and(isStatic())))
                .visit(Advice.to(ManualBlocked.class).on(named("isUserBlocked").and(isStatic()).and(takesArguments(String.class)))))
            .installOn(instrumentation);
    }

    static String mode() {
        String local = System.getProperty("telvyn.security.user-tracking");
        if (local == null) local = System.getenv("TELVYN_SECURITY_USER_TRACKING");
        local = local == null ? "identification" : local.trim().toLowerCase(Locale.ROOT);
        if ("disabled".equals(local)) return local;
        String remote = JavaProtection.userTracking();
        if (remote != null) return remote;
        return "anonymization".equals(local) ? local : "identification";
    }

    /** Mesmo formato do Datadog: "anon_" + os primeiros 128 bits do SHA-256, em hexadecimal. */
    static String anonymize(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return "anon_" + HexFormat.of().formatHex(digest, 0, 16);
        } catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    private static LocalAttackReporter reporter() {
        if (SpringMvcSecurity.wafReporter() == null) return null; // como no Datadog, exige a detecção de ataques ligada
        var current = reporter;
        if (current != null) return current;
        synchronized (UserActivity.class) {
            if (reporter == null) reporter = new LocalAttackReporter(Collector.url() + "/v1/security/users", SnapshotSink.service(), SnapshotSink.host(), ProbeMetricSink.environment(), ProbeMetricSink.version(), null);
            return reporter;
        }
    }

    private static boolean isType(Object value, String name) {
        for (Class<?> type = value == null ? null : value.getClass(); type != null; type = type.getSuperclass()) if (type.getName().equals(name)) return true;
        return false;
    }

    private static String text(Object target, String method) {
        try { Object value = JavaProtection.call(target, method, new Class<?>[]{}); return value instanceof String text && !text.isBlank() ? text : null; }
        catch (ReflectiveOperationException | RuntimeException unavailable) { return null; }
    }

    /** Evento com o contexto da requisição em curso; devolve true quando o login de usuário bloqueado foi respondido. */
    static boolean report(String event, String user, String login, Boolean userExists) {
        return report(event, user, login, userExists, "spring-security", mode());
    }

    static boolean report(String event, String user, String login, Boolean userExists, String framework, String mode) {
        Object[] request = SpringMvcSecurity.current();
        // Só dentro de uma requisição (como o Datadog, que anota o trace): usuários criados na subida não são cadastros.
        if (request == null || "disabled".equals(mode) || user == null && login == null) return false;
        var out = reporter();
        if (out == null) return false;
        WafInspector.State state = (WafInspector.State) request[2];
        String[] trace = SpringMvcSecurity.trace();
        if (trace[0] == null) trace = state.trace;
        boolean anonymous = "anonymization".equals(mode);
        out.reportUser(event, user == null ? null : anonymous ? anonymize(user) : user, login == null ? null : anonymous ? anonymize(login) : login, userExists,
                state.ip, state.userAgent, framework, mode, trace[0], trace[1]);
        // Login com sucesso de usuário na lista de bloqueio: a requisição de login é barrada (como o Datadog).
        return "login_success".equals(event) && !state.blocked
                && SpringMvcSecurity.userPhase(state, request[0], request[1], user, SpringMvcSecurity.wafReporter());
    }

    public static void enter() {
        if (depth.get()[0]++ == 0) exists.remove();
    }

    public static void exit(Object input, Object result, Throwable thrown) {
        if (--depth.get()[0] > 0) return;
        Boolean found = exists.get();
        exists.remove();
        if (!isType(input, "org.springframework.security.authentication.UsernamePasswordAuthenticationToken")) return;
        String login = text(input, "getName");
        boolean blocked;
        if (thrown != null) {
            if (!isType(thrown, "org.springframework.security.core.AuthenticationException")) return;
            blocked = report("login_failure", null, login, found);
        } else {
            if (result == null || !Boolean.TRUE.equals(call(result, "isAuthenticated"))) return;
            Object principal = call(result, "getPrincipal");
            String user = principal instanceof String name ? name : principal == null ? null : text(principal, "getUsername");
            if (user == null) user = text(result, "getName");
            blocked = report("login_success", user, login, Boolean.TRUE);
        }
        if (blocked) throw new SpringMvcSecurity.BlockedRequestException();
    }

    private static Object call(Object target, String method) {
        try { return JavaProtection.call(target, method, new Class<?>[]{}); } catch (ReflectiveOperationException | RuntimeException unavailable) { return null; }
    }

    public static class Authenticate {
        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter() { UserActivity.enter(); }
        // Sem suppress: o login de usuário bloqueado sai como BlockedRequestException (tratada na cadeia de filtros).
        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Argument(0) Object input, @Advice.Return Object result, @Advice.Thrown Throwable thrown) {
            UserActivity.exitSafely(input, result, thrown);
        }
    }

    public static void exitSafely(Object input, Object result, Throwable thrown) {
        try { exit(input, result, thrown); }
        catch (SpringMvcSecurity.BlockedRequestException blocked) { throw blocked; }
        catch (RuntimeException | LinkageError failure) { LocalAttackReporter.reportLoss("user activity failure"); }
    }

    /** Chamada da API manual: eventos sempre como informados (o modo de coleta só vale para o automático, como no Datadog). */
    public static void manual(String method, Object[] args) {
        try {
            String first = args.length > 0 && args[0] instanceof String value && !value.isBlank() ? value : null;
            String second = args.length > 1 && args[1] instanceof String value && !value.isBlank() ? value : null;
            boolean blocked = switch (method) {
                case "trackUserLoginSuccess" -> report("login_success", second == null ? first : second, first, Boolean.TRUE, "sdk", "identification");
                case "trackUserLoginFailure" -> report("login_failure", null, first, args.length > 1 && args[1] instanceof Boolean exists ? exists : null, "sdk", "identification");
                case "trackUserSignup" -> report("signup", second == null ? first : second, first, null, "sdk", "identification");
                case "setUser" -> {
                    Object[] request = SpringMvcSecurity.current();
                    var waf = SpringMvcSecurity.wafReporter();
                    yield first != null && request != null && waf != null && !((WafInspector.State) request[2]).blocked
                            && SpringMvcSecurity.userPhase((WafInspector.State) request[2], request[0], request[1], first, waf);
                }
                default -> false;
            };
            if (blocked) throw new SpringMvcSecurity.BlockedRequestException();
        } catch (SpringMvcSecurity.BlockedRequestException blocked) { throw blocked; }
        catch (RuntimeException | LinkageError failure) { LocalAttackReporter.reportLoss("user activity failure"); }
    }

    /** isUserBlocked da API manual: a lista de usuários da tela, com o bloqueio permitido. */
    public static boolean blocked(String user) {
        try { return JavaProtection.allowBlocking() && JavaProtection.userBlocked(user); } catch (RuntimeException | LinkageError failure) { return false; }
    }

    public static class Manual {
        // Sem suppress: usuário bloqueado sai como BlockedRequestException, tratada no fim da requisição; a resposta já foi enviada.
        @Advice.OnMethodEnter
        public static void enter(@Advice.Origin("#m") String method, @Advice.AllArguments Object[] args) { UserActivity.manual(method, args); }
    }

    public static class ManualBlocked {
        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(@Advice.Argument(0) String user, @Advice.Return(readOnly = false) boolean blocked) { blocked = UserActivity.blocked(user); }
    }

    public static class LoadUser {
        @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
        public static void exit(@Advice.Return Object user, @Advice.Thrown Throwable thrown) { UserActivity.loaded(user, thrown); }
    }

    public static void loaded(Object user, Throwable thrown) {
        if (depth.get()[0] == 0) return;
        if (thrown == null) exists.set(user != null);
        else if (isType(thrown, "org.springframework.security.core.userdetails.UsernameNotFoundException")) exists.set(false);
    }

    public static class CreateUser {
        @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
        public static void exit(@Advice.Argument(0) Object user, @Advice.Thrown Throwable thrown) { if (thrown == null) UserActivity.signup(user); }
    }

    public static void signup(Object user) {
        try { String name = user == null ? null : text(user, "getUsername"); report("signup", name, name, null); }
        catch (RuntimeException | LinkageError failure) { LocalAttackReporter.reportLoss("user activity failure"); }
    }
}
