package system.monitoring.debugger;

import java.lang.instrument.Instrumentation;
import java.net.InetSocketAddress;
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
 * Detecção e bloqueio de ataques no Netty 4 (e no que roda direto sobre ele: Ratpack, Micronaut, Play com backend
 * Netty), como a instrumentação de Netty do Datadog. Quando o decodificador HTTP do servidor produz uma requisição:
 * IP, cabeçalhos, cookies, query e endereço; status quando a resposta é codificada. O bloqueio responde pelo canal,
 * fecha a conexão e a requisição não chega à aplicação. Canais do Vert.x e do Reactor Netty (Spring WebFlux) ficam
 * com a inspeção dos próprios frameworks, para não inspecionar duas vezes.
 */
public final class NettySecurity {
    private static final Map<Object, WafInspector.State> CHANNELS = Collections.synchronizedMap(new WeakHashMap<>());
    /** Decodificadores descartando o restante de uma requisição bloqueada (até o último conteúdo). */
    private static final Map<Object, Boolean> DROPPING = Collections.synchronizedMap(new WeakHashMap<>());

    private NettySecurity() {}

    public static void install(Instrumentation instrumentation) {
        Agents.builder()
            .type(named("io.netty.handler.codec.http.HttpObjectDecoder"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Decode.class).on(named("decode").and(takesArguments(3)))))
            .installOn(instrumentation);
        Agents.builder()
            .type(named("io.netty.handler.codec.http.HttpObjectEncoder"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Encode.class).on(named("encode").and(takesArguments(3)))))
            .installOn(instrumentation);
    }

    private static Object call(Object target, String method, Class<?>[] types, Object... args) throws ReflectiveOperationException {
        return JavaProtection.call(target, method, types, args);
    }

    private static boolean is(Object value, String type, ClassLoader loader) {
        try { return Class.forName(type, false, loader).isInstance(value); } catch (ClassNotFoundException absent) { return false; }
    }

    /** Pipeline de framework que tem inspeção própria (Vert.x, Reactor Netty). */
    private static boolean framework(Object context) throws ReflectiveOperationException {
        Object pipeline = call(context, "pipeline", new Class<?>[]{});
        for (Object handler : ((Map<?, ?>) call(pipeline, "toMap", new Class<?>[]{})).values()) {
            String name = handler.getClass().getName();
            if (name.startsWith("io.vertx.") || name.startsWith("reactor.netty.")) return true;
        }
        return false;
    }

    /** Mensagens produzidas por esta chamada do decodificador (a partir de start). */
    public static void decoded(Object decoder, Object context, List<Object> out, int start) {
        if (out == null || out.size() <= start) return;
        ClassLoader loader = decoder.getClass().getClassLoader();
        try {
            for (int i = start; i < out.size(); i++) {
                Object message = out.get(i);
                if (Boolean.TRUE.equals(DROPPING.get(decoder))) {
                    if (is(message, "io.netty.handler.codec.http.HttpContent", loader)) {
                        if (is(message, "io.netty.handler.codec.http.LastHttpContent", loader)) DROPPING.remove(decoder);
                        out.remove(i--);
                        call(message, "release", new Class<?>[]{});
                        continue;
                    }
                    DROPPING.remove(decoder);
                }
                if (!is(message, "io.netty.handler.codec.http.HttpRequest", loader)) continue;
                if (start(context, message, loader)) {
                    out.remove(i--);
                    if (!is(message, "io.netty.handler.codec.http.LastHttpContent", loader)) DROPPING.put(decoder, Boolean.TRUE);
                    else call(message, "release", new Class<?>[]{});
                }
            }
        } catch (Exception | LinkageError failure) { LocalAttackReporter.reportLoss("Netty inspection failure"); }
    }

    /** Início da requisição: devolve true quando bloqueou (resposta enviada, conexão fechada). */
    private static boolean start(Object context, Object request, ClassLoader loader) throws Exception {
        var reporter = SpringMvcSecurity.wafReporter();
        if (reporter == null || framework(context)) return false;
        Object headers = call(request, "headers", new Class<?>[]{});
        Function<String, String> header = name -> {
            try { return call(headers, "get", new Class<?>[]{String.class}, name) instanceof String value ? value : null; }
            catch (ReflectiveOperationException | RuntimeException unavailable) { return null; }
        };
        Object channel = call(context, "channel", new Class<?>[]{});
        String ip = JavaProtection.clientIp(header, () -> {
            try { return call(channel, "remoteAddress", new Class<?>[]{}) instanceof InetSocketAddress address && address.getAddress() != null ? address.getAddress().getHostAddress() : null; }
            catch (ReflectiveOperationException | RuntimeException unavailable) { return null; }
        });
        String method = String.valueOf(call(call(request, "method", new Class<?>[]{}), "name", new Class<?>[]{}));
        String uri = (String) call(request, "uri", new Class<?>[]{});
        int split = uri.indexOf('?');
        String path = split < 0 ? uri : uri.substring(0, split);
        var state = WafInspector.open(ip, method, path, header.apply("User-Agent"), SpringMvcSecurity.trace());
        WafInspector.State previous = CHANNELS.put(channel, state);
        if (previous != null) WafInspector.close(previous);
        if (JavaProtection.allowBlocking() && JavaProtection.denied(ip)) return block(context, header.apply("Accept"), state, "ip", reporter, loader);
        Map<String, Object> data = new LinkedHashMap<>();
        Map<String, Object> plain = new LinkedHashMap<>();
        for (Object entry : (Iterable<?>) headers) {
            var pair = (Map.Entry<?, ?>) entry;
            String name = String.valueOf(pair.getKey()).toLowerCase(Locale.ROOT);
            if ("cookie".equals(name)) continue;
            plain.merge(name, String.valueOf(pair.getValue()), (a, b) -> a instanceof List<?> list ? append(list, b) : List.of(a, b));
        }
        data.put("server.request.headers.no_cookies", plain);
        String cookie = header.apply("Cookie");
        if (cookie != null && !cookie.isBlank()) {
            Map<String, Object> jar = new LinkedHashMap<>();
            for (String part : cookie.split(";")) {
                int equals = part.indexOf('=');
                if (equals > 0) jar.put(part.substring(0, equals).trim(), part.substring(equals + 1).trim());
            }
            data.put("server.request.cookies", jar);
        }
        data.put("server.request.query", WafInspector.parseQuery(split < 0 ? null : uri.substring(split + 1)));
        data.put("server.request.uri.raw", uri);
        data.put("server.request.method", method);
        if (ip != null) data.put("http.client_ip", ip);
        return SpringMvcSecurity.decide(state, WafInspector.run(state, data), reporter) && block(context, header.apply("Accept"), state, "rule", reporter, loader);
    }

    private static Object append(List<?> list, Object value) {
        var out = new java.util.ArrayList<Object>(list);
        out.add(value);
        return out;
    }

    /** Resposta de bloqueio escrita no canal; a conexão fecha depois do envio. */
    private static boolean block(Object context, String accept, WafInspector.State state, String by, LocalAttackReporter reporter, ClassLoader loader) throws Exception {
        var block = JavaProtection.blockResponse(accept);
        Class<?> version = Class.forName("io.netty.handler.codec.http.HttpVersion", false, loader);
        Class<?> status = Class.forName("io.netty.handler.codec.http.HttpResponseStatus", false, loader);
        Class<?> buffer = Class.forName("io.netty.buffer.ByteBuf", false, loader);
        Object content = Class.forName("io.netty.buffer.Unpooled", false, loader).getMethod("wrappedBuffer", byte[].class).invoke(null, (Object) block.body());
        Object response = Class.forName("io.netty.handler.codec.http.DefaultFullHttpResponse", false, loader).getConstructor(version, status, buffer)
            .newInstance(version.getField("HTTP_1_1").get(null), status.getMethod("valueOf", int.class).invoke(null, block.status()), content);
        Object headers = call(response, "headers", new Class<?>[]{});
        Class<?>[] set = {String.class, Object.class};
        if (block.location() != null) call(headers, "set", set, "Location", block.location());
        else call(headers, "set", set, "Content-Type", block.contentType());
        call(headers, "set", set, "Content-Length", block.body().length);
        call(headers, "set", set, "Connection", "close");
        // Pelo canal (fim do pipeline): o contexto do decodificador pularia o codificador HTTP do próprio codec.
        Object future = call(call(context, "channel", new Class<?>[]{}), "writeAndFlush", new Class<?>[]{Object.class}, response);
        Class<?> listener = Class.forName("io.netty.util.concurrent.GenericFutureListener", false, loader);
        Object close = Class.forName("io.netty.channel.ChannelFutureListener", false, loader).getField("CLOSE").get(null);
        call(future, "addListener", new Class<?>[]{listener}, close);
        state.blocked = true;
        if (!"rule".equals(by)) reporter.reportWaf("blocked", null, null, 0, WafInspector.engineVersion(), state.ip, state.method, state.path, state.userAgent, state.user, by, state.trace[0], state.trace[1]);
        return true;
    }

    /** Resposta codificada: status e liberação do contexto do WAF do canal. */
    public static void encoded(Object encoder, Object context, Object message) {
        try {
            ClassLoader loader = encoder.getClass().getClassLoader();
            if (!is(message, "io.netty.handler.codec.http.HttpResponse", loader)) return;
            WafInspector.State state = CHANNELS.remove(call(context, "channel", new Class<?>[]{}));
            if (state == null) return;
            try {
                var reporter = SpringMvcSecurity.wafReporter();
                if (reporter != null && !state.blocked) {
                    Object status = call(call(message, "status", new Class<?>[]{}), "code", new Class<?>[]{});
                    SpringMvcSecurity.decide(state, WafInspector.run(state, Map.of("server.response.status", String.valueOf(status))), reporter);
                }
            } finally { WafInspector.close(state); }
        } catch (Exception | LinkageError failure) { LocalAttackReporter.reportLoss("Netty status inspection failure"); }
    }

    public static class Decode {
        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static int enter(@Advice.Argument(2) List<Object> out) { return out == null ? 0 : out.size(); }
        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(@Advice.This Object decoder, @Advice.Argument(0) Object context, @Advice.Argument(2) List<Object> out, @Advice.Enter int start) {
            NettySecurity.decoded(decoder, context, out, start);
        }
    }

    public static class Encode {
        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.This Object encoder, @Advice.Argument(0) Object context, @Advice.Argument(1) Object message) { NettySecurity.encoded(encoder, context, message); }
    }
}
