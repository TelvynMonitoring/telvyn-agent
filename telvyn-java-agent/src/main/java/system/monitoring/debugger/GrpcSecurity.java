package system.monitoring.debugger;

import java.lang.instrument.Instrumentation;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.WeakHashMap;
import net.bytebuddy.asm.Advice;
import static net.bytebuddy.matcher.ElementMatchers.*;

/**
 * gRPC no servidor (grpc-java), como o Datadog, que só detecta (sem bloquear) no gRPC: no início da chamada, o
 * endereço do cliente, os metadados (como cabeçalhos) e o método ({@code grpc.server.method}); cada mensagem recebida
 * em {@code grpc.server.request.message} (protobuf convertido em mapa pelos nomes dos campos). Chamadas dos handlers
 * do grpc-stub (unárias e streaming).
 */
public final class GrpcSecurity {
    private static final Map<Object, WafInspector.State> CALLS = Collections.synchronizedMap(new WeakHashMap<>());

    private GrpcSecurity() {}

    public static void install(Instrumentation instrumentation) {
        Agents.builder()
            .type(namedOneOf("io.grpc.stub.ServerCalls$UnaryServerCallHandler", "io.grpc.stub.ServerCalls$StreamingServerCallHandler"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Start.class).on(named("startCall").and(takesArguments(2)))))
            .installOn(instrumentation);
        Agents.builder()
            .type(namedOneOf("io.grpc.stub.ServerCalls$UnaryServerCallHandler$UnaryServerCallListener",
                "io.grpc.stub.ServerCalls$StreamingServerCallHandler$StreamingServerCallListener"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(Message.class).on(named("onMessage").and(takesArguments(1))))
                .visit(Advice.to(End.class).on(namedOneOf("onComplete", "onCancel").and(takesArguments(0)))))
            .installOn(instrumentation);
    }

    private static Object call(Object target, String method, Class<?>[] types, Object... args) throws ReflectiveOperationException {
        return JavaProtection.call(target, method, types, args);
    }

    /** Início da chamada: estado do WAF, metadados, método e endereço do cliente (só detecção). */
    public static void start(Object serverCall, Object metadata) {
        var reporter = SpringMvcSecurity.wafReporter();
        if (reporter == null || serverCall == null) return;
        try {
            ClassLoader loader = serverCall.getClass().getClassLoader();
            String method = String.valueOf(call(call(serverCall, "getMethodDescriptor", new Class<?>[]{}), "getFullMethodName", new Class<?>[]{}));
            Map<String, Object> headers = new LinkedHashMap<>();
            Class<?> keyType = Class.forName("io.grpc.Metadata$Key", false, loader);
            Class<?> marshaller = Class.forName("io.grpc.Metadata$AsciiMarshaller", false, loader);
            Object ascii = Class.forName("io.grpc.Metadata", false, loader).getField("ASCII_STRING_MARSHALLER").get(null);
            for (Object name : (Iterable<?>) call(metadata, "keys", new Class<?>[]{})) {
                String key = String.valueOf(name).toLowerCase(Locale.ROOT);
                if (key.endsWith("-bin")) continue;
                Object metadataKey = keyType.getMethod("of", String.class, marshaller).invoke(null, key, ascii);
                Object value = call(metadata, "get", new Class<?>[]{keyType}, metadataKey);
                if (value != null) headers.put(key, value);
            }
            String ip = JavaProtection.clientIp(name -> headers.get(name) instanceof String value ? value : null, () -> {
                try {
                    Object attributes = call(serverCall, "getAttributes", new Class<?>[]{});
                    Object remoteKey = Class.forName("io.grpc.Grpc", false, loader).getField("TRANSPORT_ATTR_REMOTE_ADDR").get(null);
                    Object address = call(attributes, "get", new Class<?>[]{Class.forName("io.grpc.Attributes$Key", false, loader)}, remoteKey);
                    return address instanceof InetSocketAddress socket && socket.getAddress() != null ? socket.getAddress().getHostAddress() : null;
                } catch (ReflectiveOperationException | RuntimeException unavailable) { return null; }
            });
            var state = WafInspector.open(ip, "POST", "/" + method, headers.get("user-agent") instanceof String agent ? agent : null, SpringMvcSecurity.trace());
            WafInspector.State previous = CALLS.put(serverCall, state);
            if (previous != null) WafInspector.close(previous);
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("server.request.headers.no_cookies", headers);
            data.put("grpc.server.method", method);
            if (ip != null) data.put("http.client_ip", ip);
            SpringMvcSecurity.decide(state, WafInspector.run(state, data), reporter, false);
        } catch (Exception | LinkageError failure) { LocalAttackReporter.reportLoss("gRPC inspection failure"); }
    }

    private static Object serverCall(Object listener) throws ReflectiveOperationException {
        Field field = listener.getClass().getDeclaredField("call");
        field.setAccessible(true);
        return field.get(listener);
    }

    /** Mensagem recebida: convertida em mapa e inspecionada (só detecção). */
    public static void message(Object listener, Object message) {
        var reporter = SpringMvcSecurity.wafReporter();
        if (reporter == null || message == null) return;
        try {
            var state = CALLS.get(serverCall(listener));
            if (state == null) return;
            SpringMvcSecurity.decide(state, WafInspector.run(state, Map.of("grpc.server.request.message", convert(message, 0))), reporter, false);
        } catch (Exception | LinkageError failure) { LocalAttackReporter.reportLoss("gRPC message inspection failure"); }
    }

    public static void end(Object listener) {
        try { var state = CALLS.remove(serverCall(listener)); if (state != null) WafInspector.close(state); }
        catch (Exception | LinkageError failure) { /* estado liberado pelo coletor de lixo */ }
    }

    /** Mensagem protobuf em estrutura simples (campos pelo nome); outros tipos pela introspecção comum. */
    static Object convert(Object value, int depth) throws ReflectiveOperationException {
        if (value == null || depth > 20) return null;
        if (value instanceof List<?> list) {
            List<Object> out = new ArrayList<>();
            for (Object item : list) out.add(convert(item, depth + 1));
            return out;
        }
        if (hasType(value, "com.google.protobuf.MessageOrBuilder")) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (var entry : ((Map<?, ?>) call(value, "getAllFields", new Class<?>[]{})).entrySet())
                out.put(String.valueOf(call(entry.getKey(), "getName", new Class<?>[]{})), convert(entry.getValue(), depth + 1));
            return out;
        }
        if (hasType(value, "com.google.protobuf.Descriptors$EnumValueDescriptor")) return call(value, "getName", new Class<?>[]{});
        if (hasType(value, "com.google.protobuf.ByteString")) return call(value, "toStringUtf8", new Class<?>[]{});
        return WafInspector.introspect(value);
    }

    private static boolean hasType(Object value, String type) {
        try { return Class.forName(type, false, value.getClass().getClassLoader()).isInstance(value); }
        catch (ClassNotFoundException | LinkageError absent) { return false; }
    }

    public static class Start {
        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Argument(0) Object call, @Advice.Argument(1) Object metadata) { GrpcSecurity.start(call, metadata); }
    }

    public static class Message {
        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.This Object listener, @Advice.Argument(0) Object message) { GrpcSecurity.message(listener, message); }
    }

    public static class End {
        @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
        public static void exit(@Advice.This Object listener) { GrpcSecurity.end(listener); }
    }
}
