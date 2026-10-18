package system.monitoring.debugger;

import java.lang.instrument.Instrumentation;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import static net.bytebuddy.matcher.ElementMatchers.*;

/**
 * Detecção e bloqueio de ataques no Vert.x Web (e no que roda sobre ele, como o Quarkus), como a instrumentação de
 * Vert.x do Datadog, sem dependência do Vert.x. Início da requisição quando o roteador cria o contexto (IP,
 * cabeçalhos, cookies, query, endereço — inclusive rotas inexistentes); fase de rota antes de cada handler
 * (parâmetros de rota, corpo lido pelo BodyHandler, JSON ou formulário); status no fim. Bloqueio responde pelo
 * próprio Vert.x e interrompe o roteamento. Durante o handler, a requisição fica disponível para a API manual.
 */
public final class VertxSecurity {
    static final String STATE = "telvyn.security.waf";

    private VertxSecurity() {}

    public static void install(Instrumentation instrumentation) {
        Agents.builder()
            .type(named("io.vertx.ext.web.impl.RoutingContextImpl"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(Start.class).on(isConstructor().and(takesArguments(4))))
                .visit(Advice.to(Next.class).on(named("next").and(takesArguments(0)))))
            .installOn(instrumentation);
        Agents.builder()
            .type(namedOneOf("io.vertx.ext.web.impl.RouteState", "io.vertx.ext.web.impl.RouteImpl"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Route.class).on(named("handleContext").and(takesArguments(1)))))
            .installOn(instrumentation);
    }

    private static Object call(Object target, String method, Class<?>[] types, Object... args) throws ReflectiveOperationException {
        return JavaProtection.call(target, method, types, args);
    }

    private static Object call(Object target, String method) throws ReflectiveOperationException { return call(target, method, new Class<?>[]{}); }

    private static WafInspector.State state(Object context) {
        try { return call(context, "get", new Class<?>[]{String.class}, STATE) instanceof WafInspector.State state ? state : null; }
        catch (ReflectiveOperationException | RuntimeException unavailable) { return null; }
    }

    /** Contexto criado pelo roteador: início da requisição; bloqueio já responde. */
    public static void start(Object context, Object request) {
        var reporter = SpringMvcSecurity.wafReporter();
        if (reporter == null || context == null || request == null || state(context) != null) return;
        try {
            Function<String, String> header = name -> {
                try { return call(request, "getHeader", new Class<?>[]{String.class}, name) instanceof String value ? value : null; }
                catch (ReflectiveOperationException | RuntimeException unavailable) { return null; }
            };
            String ip = JavaProtection.clientIp(header, () -> {
                try { Object address = call(request, "remoteAddress"); return address == null ? null : (String) call(address, "host"); }
                catch (ReflectiveOperationException | RuntimeException unavailable) { return null; }
            });
            String method = String.valueOf(call(call(request, "method"), "name"));
            String path = (String) call(request, "path");
            var state = WafInspector.open(ip, method, path, header.apply("User-Agent"), SpringMvcSecurity.trace());
            call(context, "put", new Class<?>[]{String.class, Object.class}, STATE, state);
            // Também no contexto do Vert.x da requisição: o Quarkus REST continua o trabalho em outra thread.
            Object vertxContext = Class.forName("io.vertx.core.Vertx", false, context.getClass().getClassLoader()).getMethod("currentContext").invoke(null);
            if (vertxContext != null) call(vertxContext, "putLocal", new Class<?>[]{Object.class, Object.class}, STATE, new Object[]{request, call(request, "response"), state});
            closeAtEnd(context, request, state);
            if (JavaProtection.allowBlocking() && JavaProtection.denied(ip)) { block(state, request, "ip", reporter); return; }
            Map<String, Object> data = new LinkedHashMap<>();
            Map<String, Object> headers = new LinkedHashMap<>();
            Object all = call(request, "headers");
            for (Object name : (Iterable<?>) call(all, "names")) {
                String key = String.valueOf(name).toLowerCase(Locale.ROOT);
                if ("cookie".equals(key)) continue;
                List<?> values = (List<?>) call(all, "getAll", new Class<?>[]{String.class}, String.valueOf(name));
                headers.put(key, values.size() == 1 ? values.get(0) : new ArrayList<>(values));
            }
            data.put("server.request.headers.no_cookies", headers);
            String cookie = header.apply("Cookie");
            if (cookie != null && !cookie.isBlank()) {
                Map<String, Object> jar = new LinkedHashMap<>();
                for (String part : cookie.split(";")) {
                    int split = part.indexOf('=');
                    if (split > 0) jar.put(part.substring(0, split).trim(), part.substring(split + 1).trim());
                }
                data.put("server.request.cookies", jar);
            }
            String query = (String) call(request, "query");
            data.put("server.request.query", WafInspector.parseQuery(query));
            data.put("server.request.uri.raw", call(request, "uri"));
            data.put("server.request.method", method);
            if (ip != null) data.put("http.client_ip", ip);
            if (SpringMvcSecurity.decide(state, WafInspector.run(state, data), reporter)) block(state, request, "rule", reporter);
        } catch (Exception | LinkageError failure) { LocalAttackReporter.reportLoss("Vert.x inspection failure"); }
    }

    /** Requisição em curso guardada no contexto do Vert.x atual ({requisição, resposta, estado}), ou null. */
    static Object[] contextCurrent(ClassLoader loader) {
        try {
            Object vertxContext = Class.forName("io.vertx.core.Vertx", false, loader).getMethod("currentContext").invoke(null);
            return vertxContext != null && call(vertxContext, "getLocal", new Class<?>[]{Object.class}, STATE) instanceof Object[] current ? current : null;
        } catch (ReflectiveOperationException | RuntimeException | LinkageError unavailable) { return null; }
    }

    /** Requisição bloqueada: o roteamento para (nenhum handler roda). */
    public static boolean blocked(Object context) {
        var state = state(context);
        return state != null && state.blocked;
    }

    /** Antes de cada handler: parâmetros de rota e corpo, uma vez cada; disponibiliza a requisição para a API manual. */
    public static boolean route(Object context) {
        var state = state(context);
        if (state == null || state.blocked) return state != null;
        var reporter = SpringMvcSecurity.wafReporter();
        try {
            Object request = call(context, "request");
            SpringMvcSecurity.current(new Object[]{request, call(request, "response"), state});
            if (reporter == null) return false;
            Map<String, Object> data = new LinkedHashMap<>();
            if (!state.routeInspected && call(context, "pathParams") instanceof Map<?, ?> params && !params.isEmpty()) {
                // O curinga "*" é só o resto da URI (rota genérica, como a do Quarkus), não um parâmetro nomeado.
                Map<Object, Object> named = new LinkedHashMap<>(params);
                named.remove("*");
                if (!named.isEmpty()) {
                    state.routeInspected = true;
                    data.put("server.request.path_params", WafInspector.introspect(named));
                }
            }
            if (!state.bodyInspected) {
                Object body = body(context, request);
                if (body != null) { state.bodyInspected = true; data.put("server.request.body", body); }
            }
            // Arquivos enviados (BodyHandler com uploads): nomes, como o Datadog.
            if (!state.filesInspected && call(context, "fileUploads") instanceof Iterable<?> uploads) {
                List<String> names = new ArrayList<>();
                for (Object upload : uploads) if (call(upload, "fileName") instanceof String name && !name.isEmpty()) names.add(name);
                if (!names.isEmpty()) { state.filesInspected = true; data.put("server.request.body.filenames", names); }
            }
            if (!data.isEmpty() && SpringMvcSecurity.decide(state, WafInspector.run(state, data), reporter)) { block(state, request, "rule", reporter); return true; }
        } catch (Exception | LinkageError failure) { LocalAttackReporter.reportLoss("Vert.x route inspection failure"); }
        return false;
    }

    public static void routeEnd() { SpringMvcSecurity.current(null); }

    /** Corpo já lido pelo BodyHandler: JSON (objeto ou lista) ou formulário; nada se o corpo ainda não foi lido. */
    private static Object body(Object context, Object request) throws ReflectiveOperationException {
        Object contentType = call(request, "getHeader", new Class<?>[]{String.class}, "Content-Type");
        String type = contentType == null ? "" : contentType.toString().toLowerCase(Locale.ROOT);
        if (type.startsWith("application/x-www-form-urlencoded") || type.startsWith("multipart/form-data")) {
            Map<String, Object> form = new LinkedHashMap<>();
            Object attributes = call(request, "formAttributes");
            for (Object name : (Iterable<?>) call(attributes, "names"))
                form.put(String.valueOf(name), call(attributes, "getAll", new Class<?>[]{String.class}, String.valueOf(name)));
            return form.isEmpty() ? null : form;
        }
        Object body;
        try { body = call(context, "body"); } catch (NoSuchMethodException older) { body = null; }
        if (body != null) {
            if (Boolean.TRUE.equals(call(body, "isEmpty"))) return null;
            if (type.contains("json")) {
                Object json;
                try { json = call(body, "asJsonObject"); } catch (ReflectiveOperationException notObject) { json = null; }
                if (json == null) try { json = call(body, "asJsonArray"); } catch (ReflectiveOperationException notArray) { json = null; }
                if (json != null) return WafInspector.introspect(json);
            }
            Object text = call(body, "asString");
            return text instanceof String value && !value.isEmpty() ? value : null;
        }
        // Vert.x 3 / 4 antigo: getBodyAsString / getBodyAsJson.
        Object text = call(context, "getBodyAsString");
        if (!(text instanceof String value) || value.isEmpty()) return null;
        return type.contains("json") ? WafInspector.introspect(call(context, "getBodyAsJson")) : value;
    }

    private static void block(WafInspector.State state, Object request, String by, LocalAttackReporter reporter) {
        if (JavaProtection.respond(request, null) == null) return;
        state.blocked = true;
        if (!"rule".equals(by)) reporter.reportWaf("blocked", null, null, 0, WafInspector.engineVersion(), state.ip, state.method, state.path, state.userAgent, state.user, by, state.trace[0], state.trace[1]);
    }

    /** Status e liberação do contexto do WAF no fim da resposta (ou quando a conexão cai). */
    private static void closeAtEnd(Object context, Object request, WafInspector.State state) throws ReflectiveOperationException {
        ClassLoader loader = context.getClass().getClassLoader();
        Class<?> handler = Class.forName("io.vertx.core.Handler", false, loader);
        Object end = Proxy.newProxyInstance(loader, new Class<?>[]{handler}, (proxy, method, args) -> {
            if (!"handle".equals(method.getName())) return method.getName().equals("hashCode") ? System.identityHashCode(proxy) : method.getName().equals("equals") ? proxy == args[0] : "telvyn-end";
            try {
                var reporter = SpringMvcSecurity.wafReporter();
                if (reporter != null && !state.blocked) {
                    Object status = call(call(request, "response"), "getStatusCode");
                    SpringMvcSecurity.decide(state, WafInspector.run(state, Map.of("server.response.status", String.valueOf(status))), reporter);
                }
            } catch (ReflectiveOperationException | RuntimeException ignored) { /* status indisponível */ }
            finally { WafInspector.close(state); }
            return null;
        });
        try { call(context, "addEndHandler", new Class<?>[]{handler}, end); }
        catch (NoSuchMethodException older) { call(context, "addBodyEndHandler", new Class<?>[]{handler}, end); }
    }

    public static class Start {
        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(@Advice.This Object context, @Advice.Argument(2) Object request) { VertxSecurity.start(context, request); }
    }

    public static class Next {
        @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class, suppress = Throwable.class)
        public static boolean enter(@Advice.This Object context) { return VertxSecurity.blocked(context); }
    }

    public static class Route {
        @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class, suppress = Throwable.class)
        public static boolean enter(@Advice.Argument(0) Object context) { return VertxSecurity.route(context); }
        // Bloqueio pela API manual dentro do handler: a resposta já foi enviada, o roteador não trata como falha.
        @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
        public static void exit(@Advice.Thrown(readOnly = false) Throwable thrown) {
            VertxSecurity.routeEnd();
            if (thrown instanceof SpringMvcSecurity.BlockedRequestException) thrown = null;
        }
    }
}
