package system.monitoring.debugger;

import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Detecção e bloqueio de ataques no Spring WebFlux (sem dependência do Spring ou do Reactor). Mesmas regras
 * e decisões do Spring MVC; a diferença é a resposta, que no modelo reativo é um fluxo: quando a requisição é
 * bloqueada, o resultado do handler vira a escrita da resposta de bloqueio. O usuário logado (Spring Security
 * reativo) é lido de forma assíncrona antes de o handler rodar: o resultado do handler só executa quando assinado.
 */
public final class WebFluxWaf {
    private static final String STATE = "telvyn.security.waf";
    private static final String BLOCK = "telvyn.security.block";
    private static final String URI_VARIABLES = "org.springframework.web.reactive.HandlerMapping.uriTemplateVariables";

    private WebFluxWaf() {}

    @SuppressWarnings("unchecked")
    private static Map<String, Object> attributes(Object exchange) throws ReflectiveOperationException {
        return (Map<String, Object>) JavaProtection.call(exchange, "getAttributes", new Class<?>[]{});
    }

    /** Início (handler já escolhido): IP, cabeçalhos, cookies, query, endereço e parâmetros de rota. */
    public static void start(Object exchange) {
        var reporter = SpringMvcSecurity.wafReporter();
        if (reporter == null || exchange == null) return;
        try {
            var attributes = attributes(exchange);
            if (attributes.get(STATE) instanceof WafInspector.State existing) {
                // Endpoint funcional depois do anotado (ou o inverso): só acrescenta os parâmetros de rota.
                if (!existing.blocked && !existing.routeInspected) route(exchange, existing, attributes, reporter);
                return;
            }
            Object request = JavaProtection.call(exchange, "getRequest", new Class<?>[]{});
            Object headers = JavaProtection.call(request, "getHeaders", new Class<?>[]{});
            Function<String, String> header = name -> {
                try { return JavaProtection.call(headers, "getFirst", new Class<?>[]{String.class}, name) instanceof String value ? value : null; }
                catch (ReflectiveOperationException | RuntimeException unavailable) { return null; }
            };
            Supplier<String> remote = () -> {
                try {
                    Object address = JavaProtection.call(request, "getRemoteAddress", new Class<?>[]{});
                    return address instanceof InetSocketAddress socket && socket.getAddress() != null ? socket.getAddress().getHostAddress() : null;
                } catch (ReflectiveOperationException | RuntimeException unavailable) { return null; }
            };
            String ip = JavaProtection.clientIp(header, remote);
            URI uri = (URI) JavaProtection.call(request, "getURI", new Class<?>[]{});
            String method = String.valueOf(JavaProtection.call(request, "getMethod", new Class<?>[]{}));
            var state = WafInspector.open(ip, method, uri.getRawPath(), header.apply("User-Agent"), SpringMvcSecurity.trace());
            attributes.put(STATE, state);
            closeOnCommit(exchange, state, reporter);
            if (JavaProtection.allowBlocking() && JavaProtection.denied(ip)) { attributes.put(BLOCK, "ip"); state.blocked = true; return; }
            Map<String, Object> data = new LinkedHashMap<>();
            Map<String, Object> plain = new LinkedHashMap<>();
            for (var entry : ((Map<?, ?>) headers).entrySet()) {
                String name = String.valueOf(entry.getKey()).toLowerCase(java.util.Locale.ROOT);
                if (!"cookie".equals(name)) plain.put(name, entry.getValue() instanceof List<?> list && list.size() == 1 ? list.get(0) : entry.getValue());
            }
            data.put("server.request.headers.no_cookies", plain);
            Object cookies = JavaProtection.call(request, "getCookies", new Class<?>[]{});
            if (cookies instanceof Map<?, ?> jar && !jar.isEmpty()) {
                Map<String, Object> values = new LinkedHashMap<>();
                for (var entry : jar.entrySet()) {
                    if (entry.getValue() instanceof List<?> list && !list.isEmpty())
                        values.put(String.valueOf(entry.getKey()), JavaProtection.call(list.get(0), "getValue", new Class<?>[]{}));
                }
                data.put("server.request.cookies", values);
            }
            data.put("server.request.query", WafInspector.parseQuery(uri.getRawQuery()));
            data.put("server.request.uri.raw", uri.getRawQuery() == null ? uri.getRawPath() : uri.getRawPath() + "?" + uri.getRawQuery());
            data.put("server.request.method", method);
            if (ip != null) data.put("http.client_ip", ip);
            if (SpringMvcSecurity.decide(state, WafInspector.run(state, data), reporter)) { attributes.put(BLOCK, "rule"); state.blocked = true; return; }
            route(exchange, state, attributes, reporter);
        } catch (Exception | LinkageError failure) { LocalAttackReporter.reportLoss("reactive inspection failure"); }
    }

    private static void route(Object exchange, WafInspector.State state, Map<String, Object> attributes, LocalAttackReporter reporter) {
        if (!(attributes.get(URI_VARIABLES) instanceof Map<?, ?> params) || params.isEmpty()) return;
        state.routeInspected = true;
        if (SpringMvcSecurity.decide(state, WafInspector.run(state, Map.of("server.request.path_params", WafInspector.introspect(params))), reporter)) {
            attributes.put(BLOCK, "rule");
            state.blocked = true;
        }
    }

    /** Status da resposta e liberação do contexto quando a resposta é confirmada. */
    private static void closeOnCommit(Object exchange, WafInspector.State state, LocalAttackReporter reporter) throws ReflectiveOperationException {
        Object response = JavaProtection.call(exchange, "getResponse", new Class<?>[]{});
        ClassLoader loader = exchange.getClass().getClassLoader();
        Class<?> mono = Class.forName("reactor.core.publisher.Mono", false, loader);
        Method empty = mono.getMethod("empty");
        Supplier<Object> action = () -> {
            try {
                if (!state.blocked) {
                    Object status = JavaProtection.call(response, "getStatusCode", new Class<?>[]{});
                    String code = status == null ? "200" : String.valueOf(JavaProtection.call(status, "value", new Class<?>[]{}));
                    SpringMvcSecurity.decide(state, WafInspector.run(state, Map.of("server.response.status", code)), reporter);
                }
            } catch (ReflectiveOperationException | RuntimeException ignored) { /* status indisponível */ }
            finally { WafInspector.close(state); }
            try { return empty.invoke(null); } catch (ReflectiveOperationException impossible) { throw new IllegalStateException(impossible); }
        };
        JavaProtection.call(response, "beforeCommit", new Class<?>[]{Supplier.class}, action);
    }

    /** Resultado do handler: bloqueio decidido no início troca o resultado pela resposta; bloqueio no corpo idem. */
    public static Object wrap(Object exchange, Object result) {
        try {
            if (exchange == null || result == null) return result;
            var attributes = attributes(exchange);
            if (!(attributes.get(STATE) instanceof WafInspector.State state)) return result;
            ClassLoader loader = exchange.getClass().getClassLoader();
            if (attributes.get(BLOCK) instanceof String by) {
                var reporter = SpringMvcSecurity.wafReporter();
                if (reporter != null && !"rule".equals(by))
                    reporter.reportWaf("blocked", null, null, 0, WafInspector.engineVersion(), state.ip, state.method, state.path, state.userAgent, state.user, by, state.trace[0], state.trace[1]);
                return respond(exchange, loader);
            }
            Function<Object, Object> fallback = error -> {
                try { return respond(exchange, loader); } catch (ReflectiveOperationException failure) { throw new IllegalStateException(failure); }
            };
            Object guarded = JavaProtection.call(result, "onErrorResume", new Class<?>[]{Class.class, Function.class}, SpringMvcSecurity.BlockedRequestException.class, fallback);
            // Usuário logado: lido antes de o handler rodar; bloqueado na tela → resposta de bloqueio no lugar do handler.
            Function<Object, Object> byUser = principal -> {
                try {
                    String user = principalName(principal);
                    if (user != null) {
                        state.user = user;
                        if (JavaProtection.allowBlocking() && JavaProtection.userBlocked(user) && !JavaProtection.passed(state.ip)) {
                            state.blocked = true;
                            var reporter = SpringMvcSecurity.wafReporter();
                            if (reporter != null) reporter.reportWaf("blocked", null, null, 0, WafInspector.engineVersion(), state.ip, state.method, state.path, state.userAgent, user, "user", state.trace[0], state.trace[1]);
                            return respond(exchange, loader);
                        }
                    }
                    return guarded;
                } catch (ReflectiveOperationException failure) { throw new IllegalStateException(failure); }
            };
            Object principal = JavaProtection.call(exchange, "getPrincipal", new Class<?>[]{});
            Class<?> mono = Class.forName("reactor.core.publisher.Mono", false, loader);
            Object withUser = JavaProtection.call(principal, "flatMap", new Class<?>[]{Function.class}, byUser);
            return JavaProtection.call(withUser, "switchIfEmpty", new Class<?>[]{mono}, guarded);
        } catch (Exception | LinkageError failure) { LocalAttackReporter.reportLoss("reactive blocking failure"); return result; }
    }

    /** Corpo lido do @RequestBody: inspeciona o valor e, se bloquear, troca por erro tratado no wrap. */
    public static Object body(Object exchange, Object result) {
        try {
            var reporter = SpringMvcSecurity.wafReporter();
            if (reporter == null || result == null || !(attributes(exchange).get(STATE) instanceof WafInspector.State state)) return result;
            ClassLoader loader = exchange.getClass().getClassLoader();
            Class<?> mono = Class.forName("reactor.core.publisher.Mono", false, loader);
            Class<?> publisher = Class.forName("org.reactivestreams.Publisher", false, loader);
            Method just = mono.getMethod("just", Object.class), error = mono.getMethod("error", Throwable.class);
            Function<Object, Object> inspect = value -> {
                try {
                    if (value == null || publisher.isInstance(value) || state.blocked || state.bodyInspected) return just.invoke(null, value);
                    state.bodyInspected = true;
                    if (SpringMvcSecurity.decide(state, WafInspector.run(state, Map.of("server.request.body", WafInspector.introspect(value))), reporter)) {
                        state.blocked = true;
                        return error.invoke(null, new SpringMvcSecurity.BlockedRequestException());
                    }
                    return just.invoke(null, value);
                } catch (ReflectiveOperationException failure) { throw new IllegalStateException(failure); }
            };
            return JavaProtection.call(result, "flatMap", new Class<?>[]{Function.class}, inspect);
        } catch (Exception | LinkageError failure) { LocalAttackReporter.reportLoss("reactive body inspection failure"); return result; }
    }

    /** Nome do principal autenticado (exceto anônimo), como o Spring Security o expõe. */
    private static String principalName(Object principal) {
        if (principal == null || principal.getClass().getName().endsWith("AnonymousAuthenticationToken")) return null;
        try {
            if (Boolean.FALSE.equals(JavaProtection.call(principal, "isAuthenticated", new Class<?>[]{}))) return null;
        } catch (ReflectiveOperationException | RuntimeException notAuthentication) { /* Principal simples */ }
        return principal instanceof java.security.Principal value && value.getName() != null && !value.getName().isBlank() ? value.getName() : null;
    }

    /** Escreve a resposta de bloqueio no ServerHttpResponse e devolve o Mono da escrita. */
    private static Object respond(Object exchange, ClassLoader loader) throws ReflectiveOperationException {
        Object request = JavaProtection.call(exchange, "getRequest", new Class<?>[]{});
        Object requestHeaders = JavaProtection.call(request, "getHeaders", new Class<?>[]{});
        Object accept = JavaProtection.call(requestHeaders, "getFirst", new Class<?>[]{String.class}, "Accept");
        var block = JavaProtection.blockResponse(accept instanceof String value ? value : null);
        Object response = JavaProtection.call(exchange, "getResponse", new Class<?>[]{});
        Class<?> statusType;
        Object status;
        try {
            statusType = Class.forName("org.springframework.http.HttpStatusCode", false, loader);
            status = statusType.getMethod("valueOf", int.class).invoke(null, block.status());
        } catch (ClassNotFoundException older) {
            statusType = Class.forName("org.springframework.http.HttpStatus", false, loader);
            status = statusType.getMethod("valueOf", int.class).invoke(null, block.status());
        }
        JavaProtection.call(response, "setStatusCode", new Class<?>[]{statusType}, status);
        Object headers = JavaProtection.call(response, "getHeaders", new Class<?>[]{});
        Class<?> mono = Class.forName("reactor.core.publisher.Mono", false, loader);
        if (block.location() != null) {
            JavaProtection.call(headers, "set", new Class<?>[]{String.class, String.class}, "Location", block.location());
            return JavaProtection.call(response, "setComplete", new Class<?>[]{});
        }
        JavaProtection.call(headers, "set", new Class<?>[]{String.class, String.class}, "Content-Type", block.contentType());
        Object factory = JavaProtection.call(response, "bufferFactory", new Class<?>[]{});
        Object buffer = JavaProtection.call(factory, "wrap", new Class<?>[]{byte[].class}, (Object) block.body());
        Object body = mono.getMethod("just", Object.class).invoke(null, buffer);
        Class<?> publisher = Class.forName("org.reactivestreams.Publisher", false, loader);
        return JavaProtection.call(response, "writeWith", new Class<?>[]{publisher}, body);
    }
}
