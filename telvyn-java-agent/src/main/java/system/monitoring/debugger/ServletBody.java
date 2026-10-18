package system.monitoring.debugger;

import com.google.gson.Gson;
import java.io.ByteArrayOutputStream;
import java.lang.instrument.Instrumentation;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;
import net.bytebuddy.asm.Advice;
import static net.bytebuddy.matcher.ElementMatchers.*;

/**
 * Corpo da requisição em qualquer servlet, como as instrumentações "Servlet Request Body" do Datadog: o corpo que a
 * aplicação lê do {@code ServletInputStream} (guardado até {@link #LIMIT} bytes e inspecionado quando a leitura chega
 * ao fim; JSON é interpretado) e o formulário lido por {@code getParameter*}. Vale para servlets puros e para os
 * frameworks sobre eles; quem já leu o corpo interpretado (Spring, JAX-RS) não é inspecionado de novo. Upload
 * multipart (como o Datadog): nomes dos arquivos enviados ({@code server.request.body.filenames}) pelo
 * {@code getParts} do servlet e pelo Commons FileUpload ({@code ServletFileUpload.parseRequest}), que também entrega
 * os campos de texto como corpo. O bloqueio
 * responde e interrompe a leitura com a exceção de bloqueio, tratada no fim da requisição.
 */
public final class ServletBody {
    static final int LIMIT = 64 * 1024;
    private static final ThreadLocal<int[]> DEPTH = ThreadLocal.withInitial(() -> new int[1]);

    private ServletBody() {}

    public static void install(Instrumentation instrumentation) {
        Agents.builder()
            .type(hasSuperType(namedOneOf("javax.servlet.ServletInputStream", "jakarta.servlet.ServletInputStream")).and(not(isAbstract())),
                LoaderMatchers.canSee("javax.servlet.ServletInputStream", "jakarta.servlet.ServletInputStream"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(ReadByte.class).on(named("read").and(takesArguments(0))))
                .visit(Advice.to(ReadArray.class).on(named("read").and(takesArguments(byte[].class))))
                .visit(Advice.to(ReadRange.class).on(named("read").and(takesArguments(byte[].class, int.class, int.class))))
                .visit(Advice.to(ReadRange.class).on(named("readLine").and(takesArguments(byte[].class, int.class, int.class)))))
            .installOn(instrumentation);
        Agents.builder()
            .type(hasSuperType(namedOneOf("javax.servlet.ServletRequest", "jakarta.servlet.ServletRequest")).and(not(isInterface())).and(not(isAbstract())),
                LoaderMatchers.canSee("javax.servlet.ServletRequest", "jakarta.servlet.ServletRequest"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Parameters.class)
                .on(namedOneOf("getParameter", "getParameterValues", "getParameterMap", "getParameterNames").and(isPublic())))
                .visit(Advice.to(Parts.class).on(named("getParts").and(isPublic()).and(takesArguments(0)))))
            .installOn(instrumentation);
        Agents.builder()
            .type(named("org.apache.commons.fileupload.servlet.ServletFileUpload"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(FileUpload.class)
                .on(named("parseRequest").and(isPublic()).and(takesArgument(0, named("javax.servlet.http.HttpServletRequest"))))))
            .installOn(instrumentation);
    }

    /** Nomes dos arquivos e campos de texto do upload: inspecionados uma vez; devolve true quando bloqueou. */
    static boolean upload(java.util.List<String> filenames, Map<String, Object> fields) {
        Object[] current = SpringMvcSecurity.current();
        var reporter = SpringMvcSecurity.wafReporter();
        if (current == null || reporter == null || !(current[2] instanceof WafInspector.State state) || state.blocked) return false;
        Map<String, Object> data = new java.util.LinkedHashMap<>();
        if (!filenames.isEmpty() && !state.filesInspected) { state.filesInspected = true; data.put("server.request.body.filenames", filenames); }
        if (fields != null && !fields.isEmpty() && !state.bodyInspected) { state.bodyInspected = true; data.put("server.request.body", fields); }
        return !data.isEmpty() && SpringMvcSecurity.decide(state, WafInspector.run(state, data), reporter) && block(current, state);
    }

    /** Partes do multipart (getParts): nomes dos arquivos enviados e campos de texto (corpo, até 4 KiB por campo). */
    public static void parts(Object parts) {
        if (--DEPTH.get()[0] > 0 || !(parts instanceof Iterable<?> all)) return;
        java.util.List<String> names = new java.util.ArrayList<>();
        Map<String, Object> fields = new java.util.LinkedHashMap<>();
        DEPTH.get()[0]++;
        try {
            for (Object part : all) {
                try {
                    if (JavaProtection.call(part, "getSubmittedFileName", new Class<?>[]{}) instanceof String name && !name.isEmpty()) { names.add(name); continue; }
                    String field = String.valueOf(JavaProtection.call(part, "getName", new Class<?>[]{}));
                    try (var input = (java.io.InputStream) JavaProtection.call(part, "getInputStream", new Class<?>[]{})) {
                        @SuppressWarnings("unchecked") var list = (java.util.List<Object>) fields.computeIfAbsent(field, key -> new java.util.ArrayList<>());
                        list.add(new String(input.readNBytes(4096), StandardCharsets.UTF_8));
                    }
                } catch (ReflectiveOperationException | RuntimeException | java.io.IOException unreadable) { /* parte ignorada */ }
            }
        } finally { DEPTH.get()[0]--; }
        if (upload(names, fields)) throw new SpringMvcSecurity.BlockedRequestException();
    }

    /** Commons FileUpload: arquivos (nomes) e campos de texto (corpo). */
    public static void fileItems(Object items) {
        if (--DEPTH.get()[0] > 0 || !(items instanceof Iterable<?> all)) return;
        java.util.List<String> names = new java.util.ArrayList<>();
        Map<String, Object> fields = new java.util.LinkedHashMap<>();
        for (Object item : all) {
            try {
                if (Boolean.TRUE.equals(JavaProtection.call(item, "isFormField", new Class<?>[]{}))) {
                    String field = String.valueOf(JavaProtection.call(item, "getFieldName", new Class<?>[]{}));
                    Object value = JavaProtection.call(item, "getString", new Class<?>[]{});
                    @SuppressWarnings("unchecked") var list = (java.util.List<Object>) fields.computeIfAbsent(field, key -> new java.util.ArrayList<>());
                    list.add(value);
                } else if (JavaProtection.call(item, "getName", new Class<?>[]{}) instanceof String name && !name.isEmpty()) names.add(name);
            } catch (ReflectiveOperationException | RuntimeException unreadable) { /* item ignorado */ }
        }
        if (upload(names, fields)) throw new SpringMvcSecurity.BlockedRequestException();
    }

    public static void enter() { DEPTH.get()[0]++; }

    /** Saída de uma leitura (só a mais externa conta): guarda os bytes; no fim do corpo, inspeciona. */
    public static void read(byte[] buffer, int offset, int result, boolean single) {
        if (--DEPTH.get()[0] > 0) return;
        Object[] current = SpringMvcSecurity.current();
        if (current == null || !(current[2] instanceof WafInspector.State state) || state.blocked || state.bodyInspected) return;
        if (result >= 0) {
            if (state.rawBody == null) state.rawBody = new ByteArrayOutputStream();
            int count = single ? 1 : result;
            int room = LIMIT - state.rawBody.size();
            if (room > 0) {
                if (single) state.rawBody.write(result);
                else if (buffer != null && result > 0) state.rawBody.write(buffer, offset, Math.min(result, room));
            }
            state.rawRead += count;
            // Fim do corpo: o tamanho declarado foi lido (a aplicação nem sempre lê até o fim do fluxo).
            if (count == 0 || state.rawRead < length(current[0])) return;
        }
        if (state.rawBody != null && state.rawBody.size() > 0) inspect(current, state);
    }

    private static long length(Object request) {
        try { return JavaProtection.call(request, "getContentLengthLong", new Class<?>[]{}) instanceof Long value ? value : -1; }
        catch (ReflectiveOperationException | RuntimeException older) {
            try { return JavaProtection.call(request, "getContentLength", new Class<?>[]{}) instanceof Integer value ? value : -1; }
            catch (ReflectiveOperationException | RuntimeException unavailable) { return -1; }
        }
    }

    private static void inspect(Object[] current, WafInspector.State state) {
        var reporter = SpringMvcSecurity.wafReporter();
        if (reporter == null) return;
        state.bodyInspected = true;
        String text = state.rawBody.toString(StandardCharsets.UTF_8);
        state.rawBody = null;
        Object body = text;
        try {
            Object type = JavaProtection.call(current[0], "getContentType", new Class<?>[]{});
            if (type != null && type.toString().toLowerCase(Locale.ROOT).contains("json")) body = WafInspector.introspect(new Gson().fromJson(text, Object.class));
        } catch (ReflectiveOperationException | RuntimeException notJson) { /* inspeciona como texto */ }
        if (SpringMvcSecurity.decide(state, WafInspector.run(state, Map.of("server.request.body", body)), reporter) && block(current, state))
            throw new SpringMvcSecurity.BlockedRequestException();
    }

    private static boolean block(Object[] current, WafInspector.State state) {
        if (JavaProtection.respond(current[0], current[1]) == null) return false;
        state.blocked = true;
        return true;
    }

    /** Formulário lido por getParameter*: os campos do corpo (urlencoded ou multipart), uma vez por requisição. */
    public static void parameters(Object request) {
        if (--DEPTH.get()[0] > 0) return;
        Object[] current = SpringMvcSecurity.current();
        if (current == null || !(current[2] instanceof WafInspector.State state) || state.blocked || state.bodyInspected) return;
        var reporter = SpringMvcSecurity.wafReporter();
        if (reporter == null) return;
        Object fields;
        DEPTH.get()[0]++;
        try {
            Object type = JavaProtection.call(request, "getContentType", new Class<?>[]{});
            String contentType = type == null ? "" : type.toString().toLowerCase(Locale.ROOT);
            if (!contentType.startsWith("application/x-www-form-urlencoded") && !contentType.startsWith("multipart/form-data")) return;
            fields = JavaProtection.call(request, "getParameterMap", new Class<?>[]{});
        } catch (ReflectiveOperationException | RuntimeException unavailable) { return; }
        finally { DEPTH.get()[0]--; }
        if (!(fields instanceof Map<?, ?> map) || map.isEmpty()) return;
        state.bodyInspected = true;
        if (SpringMvcSecurity.decide(state, WafInspector.run(state, Map.of("server.request.body", WafInspector.introspect(map))), reporter) && block(current, state))
            throw new SpringMvcSecurity.BlockedRequestException();
    }

    public static class ReadByte {
        @Advice.OnMethodEnter(suppress = Throwable.class) public static void enter() { ServletBody.enter(); }
        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Return int result, @Advice.Thrown Throwable thrown) { if (thrown == null) ServletBody.readSafely(null, 0, result, true); else ServletBody.leave(); }
    }

    public static class ReadArray {
        @Advice.OnMethodEnter(suppress = Throwable.class) public static void enter() { ServletBody.enter(); }
        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Argument(0) byte[] buffer, @Advice.Return int result, @Advice.Thrown Throwable thrown) { if (thrown == null) ServletBody.readSafely(buffer, 0, result, false); else ServletBody.leave(); }
    }

    public static class ReadRange {
        @Advice.OnMethodEnter(suppress = Throwable.class) public static void enter() { ServletBody.enter(); }
        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Argument(0) byte[] buffer, @Advice.Argument(1) int offset, @Advice.Return int result, @Advice.Thrown Throwable thrown) { if (thrown == null) ServletBody.readSafely(buffer, offset, result, false); else ServletBody.leave(); }
    }

    public static class Parameters {
        @Advice.OnMethodEnter(suppress = Throwable.class) public static void enter() { ServletBody.enter(); }
        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.This Object request, @Advice.Thrown Throwable thrown) { if (thrown == null) ServletBody.parametersSafely(request); else ServletBody.leave(); }
    }

    public static class Parts {
        @Advice.OnMethodEnter(suppress = Throwable.class) public static void enter() { ServletBody.enter(); }
        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Return Object parts, @Advice.Thrown Throwable thrown) { if (thrown == null) ServletBody.uploadSafely(parts, true); else ServletBody.leave(); }
    }

    /** O parse do Commons FileUpload lê o corpo: a leitura bruta dentro dele não é inspecionada (DEPTH). */
    public static class FileUpload {
        @Advice.OnMethodEnter(suppress = Throwable.class) public static void enter() { ServletBody.enter(); }
        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Return Object items, @Advice.Thrown Throwable thrown) { if (thrown == null) ServletBody.uploadSafely(items, false); else ServletBody.leave(); }
    }

    public static void uploadSafely(Object value, boolean parts) {
        try { if (parts) parts(value); else fileItems(value); }
        catch (SpringMvcSecurity.BlockedRequestException blocked) { throw blocked; }
        catch (RuntimeException | LinkageError failure) { LocalAttackReporter.reportLoss("upload inspection failure"); }
    }

    public static void leave() { DEPTH.get()[0]--; }

    public static void readSafely(byte[] buffer, int offset, int result, boolean single) {
        try { read(buffer, offset, result, single); }
        catch (SpringMvcSecurity.BlockedRequestException blocked) { throw blocked; }
        catch (RuntimeException | LinkageError failure) { LocalAttackReporter.reportLoss("servlet body inspection failure"); }
    }

    public static void parametersSafely(Object request) {
        try { parameters(request); }
        catch (SpringMvcSecurity.BlockedRequestException blocked) { throw blocked; }
        catch (RuntimeException | LinkageError failure) { LocalAttackReporter.reportLoss("servlet form inspection failure"); }
    }
}
