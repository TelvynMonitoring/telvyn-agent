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
 * frameworks sobre eles; quem já leu o corpo interpretado (Spring, JAX-RS) não é inspecionado de novo. O bloqueio
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
                .on(namedOneOf("getParameter", "getParameterValues", "getParameterMap", "getParameterNames").and(isPublic()))))
            .installOn(instrumentation);
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
