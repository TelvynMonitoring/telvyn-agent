package system.monitoring.debugger;

import java.lang.instrument.Instrumentation;
import java.util.Map;
import java.lang.reflect.Proxy;
import net.bytebuddy.asm.Advice;
import static net.bytebuddy.matcher.ElementMatchers.*;

/**
 * Corpo e parâmetros de rota no Ratpack, como a instrumentação de Ratpack do Datadog (o início da requisição vem do
 * Netty). Corpo: o resultado de {@code DefaultContext.parse(TypedData, Parse)} (JSON, formulário). Parâmetros de rota:
 * os {@code PathTokens} do contexto quando o handler da rota (envolvido no {@code PathHandler}) roda. O bloqueio responde pela API do
 * Ratpack; no corpo, a leitura falha com a exceção de bloqueio, que o tratamento de erro do contexto ignora (a resposta
 * já foi enviada), como o Datadog faz.
 */
public final class RatpackSecurity {
    private RatpackSecurity() {}

    public static void install(Instrumentation instrumentation) {
        Agents.builder()
            .type(named("ratpack.handling.internal.DefaultContext"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(Parse.class).on(named("parse").and(takesArguments(2)).and(takesArgument(0, named("ratpack.http.TypedData")))))
                .visit(Advice.to(Error.class).on(named("error").and(takesArguments(1)).and(takesArgument(0, Throwable.class)))))
            .installOn(instrumentation);
        // Handler da rota com parâmetros: envolvido no PathHandler (como o Datadog) para ver os parâmetros já resolvidos.
        Agents.builder()
            .type(named("ratpack.path.internal.PathHandler"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(PathRoute.class).on(isConstructor().and(takesArguments(2)))))
            .installOn(instrumentation);
    }

    private static Object call(Object target, String method, Class<?>[] types, Object... args) throws ReflectiveOperationException {
        return JavaProtection.call(target, method, types, args);
    }

    /** Estado da requisição: o do canal Netty da requisição (início inspecionado pelo Netty). */
    private static WafInspector.State state(Object context) throws ReflectiveOperationException {
        Object channel = call(call(context, "getDirectChannelAccess", new Class<?>[]{}), "getChannel", new Class<?>[]{});
        return NettySecurity.state(channel);
    }

    /** Resposta de bloqueio pela API do Ratpack. */
    private static boolean respond(Object context, WafInspector.State state) throws ReflectiveOperationException {
        Object request = call(context, "getRequest", new Class<?>[]{});
        Object accept = call(call(request, "getHeaders", new Class<?>[]{}), "get", new Class<?>[]{CharSequence.class}, "Accept");
        var block = JavaProtection.blockResponse(accept instanceof String value ? value : null);
        Object response = call(context, "getResponse", new Class<?>[]{});
        call(response, "status", new Class<?>[]{int.class}, block.status());
        if (block.location() != null) {
            call(call(response, "getHeaders", new Class<?>[]{}), "set", new Class<?>[]{CharSequence.class, Object.class}, "Location", block.location());
            call(response, "send", new Class<?>[]{});
        } else {
            call(response, "contentType", new Class<?>[]{CharSequence.class}, block.contentType());
            call(response, "send", new Class<?>[]{String.class}, new String(block.body(), java.nio.charset.StandardCharsets.UTF_8));
        }
        state.blocked = true;
        return true;
    }

    /** Corpo interpretado; devolve true quando bloqueou (a leitura deve falhar). */
    public static boolean body(Object context, Object body) {
        var reporter = SpringMvcSecurity.wafReporter();
        if (reporter == null || body == null) return false;
        try {
            var state = state(context);
            if (state == null || state.blocked || state.bodyInspected) return false;
            state.bodyInspected = true;
            return SpringMvcSecurity.decide(state, WafInspector.run(state, Map.of("server.request.body", WafInspector.introspect(body))), reporter) && respond(context, state);
        } catch (ReflectiveOperationException | RuntimeException | LinkageError failure) { LocalAttackReporter.reportLoss("Ratpack body inspection failure"); return false; }
    }

    /** Handler da rota envolvido: parâmetros de rota antes de chamá-lo; bloqueado, o handler não roda. */
    public static Object wrap(Object handler) {
        if (handler == null) return null;
        try {
            ClassLoader loader = handler.getClass().getClassLoader();
            Class<?> type = Class.forName("ratpack.handling.Handler", false, loader);
            if (!type.isInstance(handler) || Proxy.isProxyClass(handler.getClass())) return handler;
            return Proxy.newProxyInstance(loader, new Class<?>[]{type}, (proxy, method, args) -> {
                if ("handle".equals(method.getName()) && args != null && args.length == 1 && route(args[0])) return null;
                try { return method.invoke(handler, args); } catch (java.lang.reflect.InvocationTargetException failure) { throw failure.getCause(); }
            });
        } catch (ReflectiveOperationException | RuntimeException | LinkageError unavailable) { return handler; }
    }

    /** Parâmetros de rota do contexto: devolve true quando bloqueou. */
    public static boolean route(Object context) {
        var reporter = SpringMvcSecurity.wafReporter();
        if (reporter == null || context == null) return false;
        try {
            if (!(call(context, "getPathTokens", new Class<?>[]{}) instanceof Map<?, ?> tokens) || tokens.isEmpty()) return false;
            var state = state(context);
            if (state == null || state.blocked || state.routeInspected) return false;
            state.routeInspected = true;
            return SpringMvcSecurity.decide(state, WafInspector.run(state, Map.of("server.request.path_params", WafInspector.introspect(tokens))), reporter) && respond(context, state);
        } catch (ReflectiveOperationException | RuntimeException | LinkageError failure) { LocalAttackReporter.reportLoss("Ratpack route inspection failure"); return false; }
    }

    public static class Parse {
        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.This Object context, @Advice.Return Object body, @Advice.Thrown Throwable thrown) {
            if (thrown == null && RatpackSecurity.body(context, body)) throw new SpringMvcSecurity.BlockedRequestException();
        }
    }

    public static class PathRoute {
        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Argument(value = 1, readOnly = false, typing = net.bytebuddy.implementation.bytecode.assign.Assigner.Typing.DYNAMIC) Object handler) {
            handler = RatpackSecurity.wrap(handler);
        }
    }

    /** Erro de requisição bloqueada: a resposta de bloqueio já foi enviada, não é falha da aplicação. */
    public static class Error {
        @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class, suppress = Throwable.class)
        public static boolean enter(@Advice.Argument(0) Throwable failure) { return failure instanceof SpringMvcSecurity.BlockedRequestException; }
    }
}
