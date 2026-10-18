package system.monitoring.debugger;

import java.lang.instrument.Instrumentation;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import static net.bytebuddy.matcher.ElementMatchers.*;

/**
 * Corpo e parâmetros de rota no JAX-RS (Jersey, RESTEasy e Quarkus REST), como as instrumentações de Jersey e
 * RESTEasy do Datadog. Corpo: o objeto lido pelo Jersey (fim do encadeamento de leitura) ou injetado pelo RESTEasy
 * (se a leitura for assíncrona, o RESTEasy devolve um CompletionStage e o corpo não é inspecionado). Quarkus REST: antes de
 * chamar o recurso, com parâmetros de rota, formulário e corpo já lidos. O bloqueio sai como
 * {@code WebApplicationException} com a resposta de bloqueio: o próprio framework responde, sem erro.
 * A requisição em curso vem do servlet (thread) ou do contexto do Vert.x (Quarkus).
 */
public final class JaxRsSecurity {
    private JaxRsSecurity() {}

    public static void install(Instrumentation instrumentation) {
        // Corpo no ponto em que o framework termina a leitura (classes nomeadas: sem examinar a hierarquia de toda classe).
        Agents.builder()
            .type(named("org.glassfish.jersey.message.internal.ReaderInterceptorExecutor$TerminalReaderInterceptor"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(BodyRead.class).on(named("aroundReadFrom").and(takesArguments(1)))))
            .installOn(instrumentation);
        Agents.builder()
            .type(named("org.jboss.resteasy.core.MessageBodyParameterInjector"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(BodyRead.class).on(named("inject").and(takesArguments(3)))))
            .installOn(instrumentation);
        // Parâmetros de rota na chamada do recurso: Jersey e RESTEasy clássico.
        Agents.builder()
            .type(named("org.glassfish.jersey.server.model.internal.AbstractJavaResourceMethodDispatcher"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Invoke.class).on(named("invoke").and(takesArguments(3)))))
            .installOn(instrumentation);
        Agents.builder()
            .type(named("org.jboss.resteasy.core.ResourceMethodInvoker"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Invoke.class).on(named("invokeOnTarget").and(takesArguments(3)))))
            .installOn(instrumentation);
        Agents.builder()
            .type(named("org.jboss.resteasy.reactive.server.handlers.InvocationHandler"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(QuarkusInvoke.class)
                .on(named("handle").and(takesArgument(0, named("org.jboss.resteasy.reactive.server.core.ResteasyReactiveRequestContext"))))))
            .installOn(instrumentation);
    }

    /** Requisição em curso: servlet ou Vert.x na thread; senão o contexto do Vert.x (trabalho do Quarkus em outra thread). */
    private static Object[] current(ClassLoader loader) {
        Object[] current = SpringMvcSecurity.current();
        return current != null ? current : VertxSecurity.contextCurrent(loader);
    }

    /**
     * Estado da requisição a partir do objeto do framework: propriedades do Jersey (ContainerRequest, contexto de
     * leitura) e atributos do RESTEasy, que repassam aos atributos do servidor (Grizzly, servlet), mesmo quando o
     * framework atende em outra thread; senão a requisição em curso.
     */
    private static WafInspector.State state(Object holder) {
        for (String accessor : new String[]{"getProperty", "getAttribute"}) {
            try { if (JavaProtection.call(holder, accessor, new Class<?>[]{String.class}, VertxSecurity.STATE) instanceof WafInspector.State state) return state; }
            catch (ReflectiveOperationException | RuntimeException unavailable) { /* próximo */ }
        }
        Object[] current = current(holder.getClass().getClassLoader());
        return current != null && current[2] instanceof WafInspector.State state ? state : null;
    }

    /** Accept da requisição (para a resposta de bloqueio em HTML ou JSON). */
    private static String accept(Object holder) {
        try { if (JavaProtection.call(holder, "getHeaderString", new Class<?>[]{String.class}, "Accept") instanceof String value) return value; } catch (ReflectiveOperationException | RuntimeException next) { /* próximo */ }
        try { if (JavaProtection.call(JavaProtection.call(holder, "getHttpHeaders", new Class<?>[]{}), "getHeaderString", new Class<?>[]{String.class}, "Accept") instanceof String value) return value; } catch (ReflectiveOperationException | RuntimeException next) { /* próximo */ }
        try { if (JavaProtection.call(JavaProtection.call(holder, "getHeaders", new Class<?>[]{}), "getFirst", new Class<?>[]{Object.class}, "Accept") instanceof String value) return value; } catch (ReflectiveOperationException | RuntimeException next) { /* próximo */ }
        Object[] current = current(holder.getClass().getClassLoader());
        try { return current != null && JavaProtection.call(current[0], "getHeader", new Class<?>[]{String.class}, "Accept") instanceof String value ? value : null; }
        catch (ReflectiveOperationException | RuntimeException unavailable) { return null; }
    }

    /** Corpo lido pelo framework (holder: contexto de leitura do Jersey ou HttpRequest do RESTEasy). */
    public static void body(Object holder, Object body) {
        if (body == null || body instanceof java.io.InputStream || body instanceof java.util.concurrent.CompletionStage<?>) return;
        var state = state(holder);
        var reporter = SpringMvcSecurity.wafReporter();
        if (state == null || reporter == null || state.blocked || state.bodyInspected) return;
        state.bodyInspected = true;
        Object value = body instanceof byte[] bytes ? new String(bytes, StandardCharsets.UTF_8) : WafInspector.introspect(body);
        if (SpringMvcSecurity.decide(state, WafInspector.run(state, Map.of("server.request.body", value)), reporter)) throw blocked(holder.getClass().getClassLoader(), accept(holder), state);
    }

    /** Quarkus REST, antes do recurso: parâmetros de rota, formulário e corpo. */
    public static void quarkus(Object context) {
        ClassLoader loader = context.getClass().getClassLoader();
        Object[] current = current(loader);
        var reporter = SpringMvcSecurity.wafReporter();
        if (current == null || reporter == null || !(current[2] instanceof WafInspector.State state) || state.blocked) return;
        Map<String, Object> data = new LinkedHashMap<>();
        try {
            Object uriInfo = JavaProtection.call(context, "getUriInfo", new Class<?>[]{});
            if (JavaProtection.call(uriInfo, "getPathParameters", new Class<?>[]{}) instanceof Map<?, ?> params && !params.isEmpty())
                data.put("server.request.path_params", WafInspector.introspect(params));
            if (!state.bodyInspected) {
                Object form = JavaProtection.call(context, "getFormData", new Class<?>[]{});
                if (form instanceof Iterable<?> names) {
                    Map<String, Object> fields = new LinkedHashMap<>();
                    for (Object name : names) {
                        List<String> values = new ArrayList<>();
                        for (Object item : (Iterable<?>) JavaProtection.call(form, "get", new Class<?>[]{String.class}, String.valueOf(name)))
                            if (!Boolean.TRUE.equals(JavaProtection.call(item, "isFileItem", new Class<?>[]{})) && JavaProtection.call(item, "getValue", new Class<?>[]{}) instanceof String value) values.add(value);
                        if (!values.isEmpty()) fields.put(String.valueOf(name), values);
                    }
                    if (!fields.isEmpty()) data.put("server.request.body", fields);
                }
                if (!data.containsKey("server.request.body")) {
                    Object entity = JavaProtection.call(context, "getRequestEntity", new Class<?>[]{});
                    if (entity != null && !(entity instanceof java.io.InputStream)) data.put("server.request.body", WafInspector.introspect(entity));
                }
                if (data.containsKey("server.request.body")) state.bodyInspected = true;
            }
        } catch (ReflectiveOperationException | RuntimeException | LinkageError failure) { LocalAttackReporter.reportLoss("JAX-RS inspection failure"); return; }
        if (!data.isEmpty() && SpringMvcSecurity.decide(state, WafInspector.run(state, data), reporter)) throw blocked(loader, accept(context), state);
    }

    /** Jersey (ContainerRequest.getUriInfo) e RESTEasy clássico (HttpRequest.getUri): parâmetros de rota antes do recurso. */
    public static void params(Object request) {
        ClassLoader loader = request.getClass().getClassLoader();
        var state = state(request);
        var reporter = SpringMvcSecurity.wafReporter();
        if (state == null || reporter == null || state.blocked || state.routeInspected) return;
        Object params;
        try {
            Object uriInfo;
            try { uriInfo = JavaProtection.call(request, "getUriInfo", new Class<?>[]{}); }
            catch (NoSuchMethodException resteasy) { uriInfo = JavaProtection.call(request, "getUri", new Class<?>[]{}); }
            params = JavaProtection.call(uriInfo, "getPathParameters", new Class<?>[]{});
        } catch (ReflectiveOperationException | RuntimeException | LinkageError failure) { LocalAttackReporter.reportLoss("JAX-RS inspection failure"); return; }
        Map<String, Object> data = new LinkedHashMap<>();
        if (params instanceof Map<?, ?> map && !map.isEmpty()) data.put("server.request.path_params", WafInspector.introspect(map));
        // RESTEasy: @FormParam vem dos parâmetros de formulário decodificados, não do leitor de corpo.
        if (!state.bodyInspected) {
            try {
                Object type = JavaProtection.call(JavaProtection.call(request, "getHttpHeaders", new Class<?>[]{}), "getMediaType", new Class<?>[]{});
                if (type != null && type.toString().toLowerCase(java.util.Locale.ROOT).startsWith("application/x-www-form-urlencoded")
                        && JavaProtection.call(request, "getDecodedFormParameters", new Class<?>[]{}) instanceof Map<?, ?> form && !form.isEmpty()) {
                    state.bodyInspected = true;
                    data.put("server.request.body", WafInspector.introspect(form));
                }
            } catch (ReflectiveOperationException | RuntimeException notResteasy) { /* Jersey lê o formulário pelo leitor de corpo */ }
        }
        if (data.isEmpty()) return;
        state.routeInspected = true;
        if (SpringMvcSecurity.decide(state, WafInspector.run(state, data), reporter)) throw blocked(loader, accept(request), state);
    }

    /** WebApplicationException com a resposta de bloqueio da tela (javax ou jakarta, o que a aplicação usa). */
    private static RuntimeException blocked(ClassLoader loader, String accept, WafInspector.State state) {
        state.blocked = true;
        try {
            var block = JavaProtection.blockResponse(accept);
            String api = namespace(loader);
            Class<?> response = Class.forName(api + ".core.Response", false, loader);
            Object builder = response.getMethod("status", int.class).invoke(null, block.status());
            if (block.location() != null) builder = JavaProtection.call(builder, "header", new Class<?>[]{String.class, Object.class}, "Location", block.location());
            else builder = JavaProtection.call(JavaProtection.call(builder, "type", new Class<?>[]{String.class}, block.contentType()), "entity", new Class<?>[]{Object.class}, new String(block.body(), StandardCharsets.UTF_8));
            Object built = JavaProtection.call(builder, "build", new Class<?>[]{});
            return (RuntimeException) Class.forName(api + ".WebApplicationException", false, loader).getConstructor(response).newInstance(built);
        } catch (ReflectiveOperationException | RuntimeException | LinkageError failure) {
            LocalAttackReporter.reportLoss("JAX-RS block response unavailable");
            return new SpringMvcSecurity.BlockedRequestException();
        }
    }

    private static String namespace(ClassLoader loader) {
        try { Class.forName("jakarta.ws.rs.core.Response", false, loader); return "jakarta.ws.rs"; }
        catch (ClassNotFoundException absent) { return "javax.ws.rs"; }
    }

    public static class BodyRead {
        // Sem suppress: o bloqueio sai como WebApplicationException (o framework responde).
        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Argument(0) Object holder, @Advice.Return Object body, @Advice.Thrown Throwable thrown) {
            if (thrown == null) JaxRsSecurity.bodySafely(holder, body);
        }
    }

    public static class Invoke {
        @Advice.OnMethodEnter
        public static void enter(@Advice.Argument(0) Object request) { JaxRsSecurity.paramsSafely(request); }
    }

    public static void paramsSafely(Object request) {
        try { params(request); }
        catch (SpringMvcSecurity.BlockedRequestException blocked) { throw blocked; }
        catch (RuntimeException failure) {
            if (failure.getClass().getName().endsWith(".WebApplicationException")) throw failure;
            LocalAttackReporter.reportLoss("JAX-RS inspection failure");
        } catch (LinkageError failure) { LocalAttackReporter.reportLoss("JAX-RS inspection failure"); }
    }

    public static class QuarkusInvoke {
        @Advice.OnMethodEnter
        public static void enter(@Advice.Argument(0) Object context) { JaxRsSecurity.quarkusSafely(context); }
    }

    public static void bodySafely(Object holder, Object body) {
        try { body(holder, body); }
        catch (SpringMvcSecurity.BlockedRequestException blocked) { throw blocked; }
        catch (RuntimeException failure) {
            if (failure.getClass().getName().endsWith(".WebApplicationException")) throw failure;
            LocalAttackReporter.reportLoss("JAX-RS body inspection failure");
        } catch (LinkageError failure) { LocalAttackReporter.reportLoss("JAX-RS body inspection failure"); }
    }

    public static void quarkusSafely(Object context) {
        try { quarkus(context); }
        catch (SpringMvcSecurity.BlockedRequestException blocked) { throw blocked; }
        catch (RuntimeException failure) {
            if (failure.getClass().getName().endsWith(".WebApplicationException")) throw failure;
            LocalAttackReporter.reportLoss("JAX-RS inspection failure");
        } catch (LinkageError failure) { LocalAttackReporter.reportLoss("JAX-RS inspection failure"); }
    }
}
