package system.monitoring.debugger;

import java.lang.instrument.Instrumentation;
import java.lang.reflect.Array;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import static net.bytebuddy.matcher.ElementMatchers.*;

/**
 * Detecção e bloqueio de ataques no servidor HTTP do Grizzly (e no Jersey sobre ele), como a instrumentação de
 * Grizzly do Datadog. Início em {@code HttpHandler.doHandle} (IP, cabeçalhos, cookies, query, endereço), status e
 * liberação depois do atendimento (inclusive assíncrono). Durante o atendimento a requisição fica disponível para
 * o corpo e os parâmetros do Jersey e para a API manual.
 */
public final class GrizzlySecurity {
    private GrizzlySecurity() {}

    public static void install(Instrumentation instrumentation) {
        Agents.builder()
            .type(named("org.glassfish.grizzly.http.server.HttpHandler"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Handle.class).on(named("doHandle").and(takesArguments(2)))))
            .installOn(instrumentation);
    }

    private static Object call(Object target, String method, Class<?>[] types, Object... args) throws ReflectiveOperationException {
        return JavaProtection.call(target, method, types, args);
    }

    /** Início do atendimento: devolve true quando bloqueou e respondeu. */
    public static boolean start(Object request, Object response) {
        var reporter = SpringMvcSecurity.wafReporter();
        if (reporter == null || request == null) return false;
        try {
            if (call(request, "getAttribute", new Class<?>[]{String.class}, VertxSecurity.STATE) instanceof WafInspector.State existing) {
                SpringMvcSecurity.current(new Object[]{request, response, existing});
                return false;
            }
            String ip = JavaProtection.clientIp(request);
            String method = String.valueOf(call(request, "getMethod", new Class<?>[]{}));
            String path = (String) call(request, "getRequestURI", new Class<?>[]{});
            Object agent = call(request, "getHeader", new Class<?>[]{String.class}, "User-Agent");
            var state = WafInspector.open(ip, method, path, agent instanceof String value ? value : null, SpringMvcSecurity.trace());
            call(request, "setAttribute", new Class<?>[]{String.class, Object.class}, VertxSecurity.STATE, state);
            SpringMvcSecurity.current(new Object[]{request, response, state});
            closeAfterService(request, response, state);
            if (JavaProtection.allowBlocking() && JavaProtection.denied(ip)) return block(state, request, response, "ip", reporter);
            Map<String, Object> data = new LinkedHashMap<>();
            Map<String, Object> headers = new LinkedHashMap<>();
            for (Object name : (Iterable<?>) call(request, "getHeaderNames", new Class<?>[]{})) {
                String key = String.valueOf(name).toLowerCase(Locale.ROOT);
                if ("cookie".equals(key)) continue;
                List<String> values = new ArrayList<>();
                for (Object value : (Iterable<?>) call(request, "getHeaders", new Class<?>[]{String.class}, String.valueOf(name))) values.add(String.valueOf(value));
                headers.put(key, values.size() == 1 ? values.get(0) : values);
            }
            data.put("server.request.headers.no_cookies", headers);
            Object cookies = call(request, "getCookies", new Class<?>[]{});
            if (cookies != null && Array.getLength(cookies) > 0) {
                Map<String, Object> jar = new LinkedHashMap<>();
                for (int i = 0; i < Array.getLength(cookies); i++) {
                    Object cookie = Array.get(cookies, i);
                    jar.put(String.valueOf(call(cookie, "getName", new Class<?>[]{})), call(cookie, "getValue", new Class<?>[]{}));
                }
                data.put("server.request.cookies", jar);
            }
            String query = (String) call(request, "getQueryString", new Class<?>[]{});
            data.put("server.request.query", WafInspector.parseQuery(query));
            data.put("server.request.uri.raw", query == null ? path : path + "?" + query);
            data.put("server.request.method", method);
            if (ip != null) data.put("http.client_ip", ip);
            return SpringMvcSecurity.decide(state, WafInspector.run(state, data), reporter) && block(state, request, response, "rule", reporter);
        } catch (Exception | LinkageError failure) { LocalAttackReporter.reportLoss("Grizzly inspection failure"); return false; }
    }

    private static boolean block(WafInspector.State state, Object request, Object response, String by, LocalAttackReporter reporter) {
        if (JavaProtection.respond(request, response) == null) return false;
        state.blocked = true;
        if (!"rule".equals(by)) reporter.reportWaf("blocked", null, null, 0, WafInspector.engineVersion(), state.ip, state.method, state.path, state.userAgent, state.user, by, state.trace[0], state.trace[1]);
        return true;
    }

    /** Status e liberação do contexto do WAF quando o atendimento termina (AfterServiceListener). */
    private static void closeAfterService(Object request, Object response, WafInspector.State state) throws ReflectiveOperationException {
        ClassLoader loader = request.getClass().getClassLoader();
        Class<?> listener = Class.forName("org.glassfish.grizzly.http.server.AfterServiceListener", false, loader);
        Object after = Proxy.newProxyInstance(loader, new Class<?>[]{listener}, (proxy, method, args) -> {
            if (!"onAfterService".equals(method.getName())) return method.getName().equals("hashCode") ? System.identityHashCode(proxy) : method.getName().equals("equals") ? proxy == args[0] : "telvyn-after-service";
            try {
                var reporter = SpringMvcSecurity.wafReporter();
                if (reporter != null && !state.blocked) ApiSecurity.finish(state, call(response, "getStatus", new Class<?>[]{}), () -> ApiSecurity.servletHeaders(response), reporter);
            } catch (ReflectiveOperationException | RuntimeException ignored) { /* status indisponível */ }
            finally { WafInspector.close(state); }
            return null;
        });
        call(request, "addAfterServiceListener", new Class<?>[]{listener}, after);
    }

    public static void end() { SpringMvcSecurity.current(null); }

    public static class Handle {
        @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class, suppress = Throwable.class)
        public static boolean enter(@Advice.Argument(0) Object request, @Advice.Argument(1) Object response) { return GrizzlySecurity.start(request, response); }
        // Bloqueada: o atendimento terminou (true), a resposta de bloqueio já foi escrita.
        @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
        public static void exit(@Advice.Enter boolean blocked, @Advice.Return(readOnly = false) boolean done) {
            GrizzlySecurity.end();
            if (blocked) done = true;
        }
    }
}
