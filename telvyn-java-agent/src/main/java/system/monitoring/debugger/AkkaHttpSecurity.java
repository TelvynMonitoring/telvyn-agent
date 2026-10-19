package system.monitoring.debugger;

import com.google.gson.Gson;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.function.Function;
import net.bytebuddy.asm.Advice;
import static net.bytebuddy.matcher.ElementMatchers.*;

/**
 * Detecção e bloqueio de ataques no Akka HTTP e no Pekko HTTP (e no Play, que roda sobre o Akka HTTP), como a
 * instrumentação de Akka HTTP. A função de atendimento ({@code HttpExt.bindAndHandleAsync}, usada pelas
 * rotas do Java DSL, pelo bind de função e pelo Play) é envolvida: início da requisição (IP, cabeçalhos, cookies,
 * query, endereço) com bloqueio, e status no fim. Corpo (JSON, formulário, texto): o que já chegou inteiro
 * ({@code HttpEntity.Strict}) no início, com bloqueio antes do handler; o restante quando é materializado para a
 * desserialização ({@code HttpEntity.toStrict}), e um bloqueio faz a desserialização falhar (o handler da rota não
 * roda) e a resposta final vira a de bloqueio. O Pekko usa o mesmo código com o pacote
 * {@code org.apache.pekko}.
 */
public final class AkkaHttpSecurity {
    private static final Map<Object, WafInspector.State> ENTITIES = Collections.synchronizedMap(new WeakHashMap<>());

    private AkkaHttpSecurity() {}

    public static void install(Instrumentation instrumentation) {
        for (String prefix : new String[]{"akka", "org.apache.pekko"}) {
            Agents.builder()
                .type(named(prefix + ".http.scaladsl.HttpExt"))
                .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Bind.class)
                    .on(named("bindAndHandleAsync").and(takesArgument(0, named("scala.Function1"))))))
                .installOn(instrumentation);
            Agents.builder()
                .type(namedOneOf(prefix + ".http.scaladsl.model.HttpEntity", prefix + ".http.scaladsl.model.HttpEntity$Strict"))
                .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ToStrict.class)
                    .on(named("toStrict").and(takesArguments(2)).and(takesArgument(0, named("scala.concurrent.duration.FiniteDuration"))))))
                .installOn(instrumentation);
        }
    }

    private static Object call(Object target, String method, Class<?>[] types, Object... args) throws ReflectiveOperationException {
        return JavaProtection.call(target, method, types, args);
    }

    private static Object call(Object target, String method) throws ReflectiveOperationException { return call(target, method, new Class<?>[]{}); }

    /** Prefixo do pacote (akka ou org.apache.pekko) de uma classe do servidor. */
    private static String prefix(Object value) { return value.getClass().getName().startsWith("org.apache.pekko.") ? "org.apache.pekko" : "akka"; }

    /** Função scala.Function1 implementada por um proxy (métodos default do Scala chamados como estão). */
    private static Object function(ClassLoader loader, Function<Object, Object> apply) throws ClassNotFoundException {
        Class<?> type = Class.forName("scala.Function1", false, loader);
        InvocationHandler handler = (proxy, method, args) -> {
            if ("apply".equals(method.getName()) && args != null && args.length == 1) return apply.apply(args[0]);
            if (method.isDefault()) return InvocationHandler.invokeDefault(proxy, method, args);
            return switch (method.getName()) {
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                default -> "telvyn-function";
            };
        };
        return Proxy.newProxyInstance(loader, new Class<?>[]{type}, handler);
    }

    /** Envolve a função de atendimento do servidor. */
    public static Object wrap(Object handler) {
        if (handler == null || Proxy.isProxyClass(handler.getClass())) return handler;
        try {
            ClassLoader loader = handler.getClass().getClassLoader();
            Class.forName("scala.Function1", false, loader);
            return function(loader, request -> serve(handler, request));
        } catch (ClassNotFoundException | RuntimeException | LinkageError unavailable) { return handler; }
    }

    /** Atende a requisição; qualquer falha da proteção segue com o handler original (nunca quebra a aplicação). */
    private static Object serve(Object handler, Object request) {
        var reporter = SpringMvcSecurity.wafReporter();
        WafInspector.State state = null;
        try {
            if (reporter != null) state = start(request, reporter);
            if (state != null && state.blocked) return successful(blockResponse(request), request);
        } catch (Exception | LinkageError failure) {
            LocalAttackReporter.reportLoss("Akka HTTP inspection failure");
            if (state != null) { WafInspector.close(state); state = null; }
        }
        Object future = invoke(handler, request);
        if (state == null) return future;
        try { return finish(future, request, state); }
        catch (Exception | LinkageError failure) { WafInspector.close(state); return future; }
    }

    /** Chama o handler original pela interface scala.Function1 (a classe concreta costuma ser um lambda inacessível). */
    private static Object invoke(Object handler, Object request) {
        try {
            return Class.forName("scala.Function1", false, handler.getClass().getClassLoader()).getMethod("apply", Object.class).invoke(handler, request);
        } catch (java.lang.reflect.InvocationTargetException failure) {
            if (failure.getCause() instanceof RuntimeException runtime) throw runtime;
            if (failure.getCause() instanceof Error error) throw error;
            throw new IllegalStateException(failure.getCause());
        } catch (ReflectiveOperationException impossible) { throw new IllegalStateException(impossible); }
    }

    /** Início da requisição; devolve o estado (bloqueado quando já deve responder com a página de bloqueio). */
    private static WafInspector.State start(Object request, LocalAttackReporter reporter) throws Exception {
        Map<String, Object> headers = new LinkedHashMap<>();
        String cookie = null;
        for (Object header : (Iterable<?>) call(request, "getHeaders")) {
            String name = String.valueOf(call(header, "lowercaseName"));
            String value = String.valueOf(call(header, "value"));
            if ("cookie".equals(name)) { cookie = value; continue; }
            headers.merge(name, value, (a, b) -> a instanceof List<?> list ? append(list, b) : List.of(a, b));
        }
        Object uri = call(request, "getUri");
        String path = String.valueOf(call(uri, "path"));
        Object raw = call(uri, "rawQueryString");
        String query = raw instanceof java.util.Optional<?> optional && optional.isPresent() ? String.valueOf(optional.get()) : null;
        String method = String.valueOf(call(call(request, "method"), "value"));
        String ip = JavaProtection.clientIp(name -> headers.get(name) instanceof String value ? value : null, () -> remote(request));
        var state = WafInspector.open(ip, method, path, headers.get("user-agent") instanceof String agent ? agent : null, SpringMvcSecurity.trace());
        ENTITIES.put(call(request, "entity"), state);
        if (JavaProtection.allowBlocking() && JavaProtection.denied(ip)) { state.blocked = true; reporter.reportWaf("blocked", null, null, 0, WafInspector.engineVersion(), ip, method, path, state.userAgent, null, "ip", state.trace[0], state.trace[1]); return state; }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("server.request.headers.no_cookies", headers);
        if (cookie != null) {
            Map<String, Object> jar = new LinkedHashMap<>();
            for (String part : cookie.split(";")) { int split = part.indexOf('='); if (split > 0) jar.put(part.substring(0, split).trim(), part.substring(split + 1).trim()); }
            data.put("server.request.cookies", jar);
        }
        data.put("server.request.query", WafInspector.parseQuery(query));
        data.put("server.request.uri.raw", query == null ? path : path + "?" + query);
        data.put("server.request.method", method);
        if (ip != null) data.put("http.client_ip", ip);
        if (SpringMvcSecurity.decide(state, WafInspector.run(state, data), reporter)) { state.blocked = true; return state; }
        // Corpo que já chegou inteiro (HttpEntity.Strict): os desserializadores usam os dados direto, sem toStrict.
        Object entity = call(request, "entity");
        if (entity.getClass().getName().endsWith(".http.scaladsl.model.HttpEntity$Strict")) { ENTITIES.remove(entity); body(entity, state); }
        return state;
    }

    private static String remote(Object request) {
        try {
            String prefix = prefix(request);
            ClassLoader loader = request.getClass().getClassLoader();
            Object key = Class.forName(prefix + ".http.javadsl.model.AttributeKeys", false, loader).getMethod("remoteAddress").invoke(null);
            Object found = call(request, "getAttribute", new Class<?>[]{Class.forName(prefix + ".http.javadsl.model.AttributeKey", false, loader)}, key);
            Object remote = found instanceof java.util.Optional<?> optional && optional.isPresent() ? optional.get() : null;
            Object address = remote == null ? null : call(remote, "getAddress");
            return address instanceof java.util.Optional<?> inet && inet.isPresent() && inet.get() instanceof java.net.InetAddress value ? value.getHostAddress() : null;
        } catch (ReflectiveOperationException | RuntimeException unavailable) { return null; }
    }

    private static Object append(List<?> list, Object value) { var out = new ArrayList<Object>(list); out.add(value); return out; }

    /** Resposta de bloqueio do Akka/Pekko HTTP (API Java do modelo). */
    private static Object blockResponse(Object request) throws ReflectiveOperationException {
        String prefix = prefix(request);
        ClassLoader loader = request.getClass().getClassLoader();
        Object accept = null;
        for (Object header : (Iterable<?>) call(request, "getHeaders")) if ("accept".equals(call(header, "lowercaseName"))) accept = call(header, "value");
        var block = JavaProtection.blockResponse(accept instanceof String value ? value : null);
        Class<?> responseType = Class.forName(prefix + ".http.javadsl.model.HttpResponse", false, loader);
        Object response = call(responseType.getMethod("create").invoke(null), "withStatus", new Class<?>[]{int.class}, block.status());
        if (block.location() != null) {
            Object header = Class.forName(prefix + ".http.javadsl.model.headers.RawHeader", false, loader).getMethod("create", String.class, String.class).invoke(null, "Location", block.location());
            return call(response, "addHeader", new Class<?>[]{Class.forName(prefix + ".http.javadsl.model.HttpHeader", false, loader)}, header);
        }
        Class<?> types = Class.forName(prefix + ".http.javadsl.model.ContentTypes", false, loader);
        Object contentType = types.getField(block.contentType().startsWith("text/html") ? "TEXT_HTML_UTF8" : "APPLICATION_JSON").get(null);
        return call(response, "withEntity", new Class<?>[]{Class.forName(prefix + ".http.javadsl.model.ContentType$NonBinary", false, loader), String.class}, contentType, new String(block.body(), StandardCharsets.UTF_8));
    }

    private static Object successful(Object value, Object anchor) throws ReflectiveOperationException {
        Class<?> future = Class.forName("scala.concurrent.Future$", false, anchor.getClass().getClassLoader());
        return future.getMethod("successful", Object.class).invoke(future.getField("MODULE$").get(null), value);
    }

    private static Object executor(ClassLoader loader) throws ReflectiveOperationException {
        Class<?> type = Class.forName("scala.concurrent.ExecutionContext$", false, loader);
        Object module = type.getField("MODULE$").get(null);
        try { return type.getMethod("parasitic").invoke(module); } catch (NoSuchMethodException older) { return type.getMethod("global").invoke(module); }
    }

    /** Fim: status inspecionado; requisição bloqueada no corpo responde com a página de bloqueio. */
    private static Object finish(Object future, Object request, WafInspector.State state) throws ReflectiveOperationException {
        ClassLoader loader = request.getClass().getClassLoader();
        Object transform = function(loader, result -> {
            try {
                if (state.blocked) return Class.forName("scala.util.Success", false, loader).getConstructor(Object.class).newInstance(blockResponse(request));
                var reporter = SpringMvcSecurity.wafReporter();
                if (reporter != null && Boolean.TRUE.equals(call(result, "isSuccess"))) {
                    Object response = call(result, "get");
                    ApiSecurity.finish(state, call(call(response, "status"), "intValue"), () -> {
                        Map<String, Object> headers = new LinkedHashMap<>();
                        try { for (Object header : (Iterable<?>) call(response, "getHeaders")) headers.put(String.valueOf(call(header, "lowercaseName")), String.valueOf(call(header, "value"))); }
                        catch (ReflectiveOperationException unavailable) { /* sem cabeçalhos */ }
                        return headers;
                    }, reporter);
                }
                return result;
            } catch (ReflectiveOperationException | RuntimeException failure) { return result; }
            finally { WafInspector.close(state); }
        });
        return call(future, "transform", new Class<?>[]{Class.forName("scala.Function1", false, loader), Class.forName("scala.concurrent.ExecutionContext", false, loader)}, transform, executor(loader));
    }

    /** Corpo materializado para a desserialização: inspeciona; bloqueado, a materialização falha. */
    public static Object strict(Object entity, Object future) {
        WafInspector.State state = ENTITIES.remove(entity);
        if (state == null || state.blocked || state.bodyInspected || future == null) return future;
        try {
            ClassLoader loader = future.getClass().getClassLoader();
            Object transform = function(loader, result -> {
                try {
                    if (!Boolean.TRUE.equals(call(result, "isSuccess"))) return result;
                    if (body(call(result, "get"), state)) return Class.forName("scala.util.Failure", false, loader).getConstructor(Throwable.class).newInstance(new SpringMvcSecurity.BlockedRequestException());
                } catch (ReflectiveOperationException | RuntimeException failure) { LocalAttackReporter.reportLoss("Akka HTTP body inspection failure"); }
                return result;
            });
            return call(future, "transform", new Class<?>[]{Class.forName("scala.Function1", false, loader), Class.forName("scala.concurrent.ExecutionContext", false, loader)}, transform, executor(loader));
        } catch (ReflectiveOperationException | RuntimeException | LinkageError failure) { return future; }
    }

    /** Corpo do HttpEntity.Strict: JSON, formulário ou texto; devolve true quando bloqueou. */
    private static boolean body(Object strict, WafInspector.State state) throws ReflectiveOperationException {
        var reporter = SpringMvcSecurity.wafReporter();
        if (reporter == null) return false;
        String text = String.valueOf(call(call(strict, "getData"), "utf8String"));
        if (text.isEmpty()) return false;
        state.bodyInspected = true;
        String type = String.valueOf(call(strict, "getContentType")).toLowerCase(Locale.ROOT);
        Object body = text;
        if (type.contains("json")) {
            try { body = WafInspector.introspect(new Gson().fromJson(text, Object.class)); } catch (RuntimeException notJson) { /* texto */ }
        } else if (type.startsWith("application/x-www-form-urlencoded")) {
            Map<String, List<String>> form = new LinkedHashMap<>();
            for (String pair : text.split("&")) {
                if (pair.isEmpty()) continue;
                int split = pair.indexOf('=');
                try { form.computeIfAbsent(URLDecoder.decode(split < 0 ? pair : pair.substring(0, split), StandardCharsets.UTF_8), key -> new ArrayList<>()).add(split < 0 ? "" : URLDecoder.decode(pair.substring(split + 1), StandardCharsets.UTF_8)); }
                catch (IllegalArgumentException malformed) { /* par inválido */ }
            }
            body = form;
        }
        if (!SpringMvcSecurity.decide(state, WafInspector.run(state, Map.of("server.request.body", body)), reporter)) return false;
        state.blocked = true;
        return true;
    }

    public static class Bind {
        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Argument(value = 0, readOnly = false, typing = net.bytebuddy.implementation.bytecode.assign.Assigner.Typing.DYNAMIC) Object handler) {
            handler = AkkaHttpSecurity.wrap(handler);
        }
    }

    public static class ToStrict {
        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(@Advice.This Object entity, @Advice.Return(readOnly = false, typing = net.bytebuddy.implementation.bytecode.assign.Assigner.Typing.DYNAMIC) Object future) {
            future = AkkaHttpSecurity.strict(entity, future);
        }
    }
}
