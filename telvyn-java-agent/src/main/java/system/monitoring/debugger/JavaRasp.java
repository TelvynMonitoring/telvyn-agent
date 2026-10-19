package system.monitoring.debugger;

import java.lang.instrument.Instrumentation;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import system.monitoring.debugger.bootstrap.RaspBridge;
import static net.bytebuddy.matcher.ElementMatchers.*;

/**
 * Exploit prevention: cada operação perigosa feita durante uma requisição é
 * comparada com a entrada dessa requisição pelas regras rasp-* (dados efêmeros do WAF). Arquivos
 * ({@code java.io} e {@code java.nio.file.Files}: {@code server.io.fs.file}); comandos ({@code ProcessImpl.start}, por onde passam
 * {@code ProcessBuilder} e {@code Runtime.exec}: {@code server.sys.exec.cmd}, ou {@code server.sys.shell.cmd} com sh/bash -c);
 * requisições de saída ({@code java.net.URL}, {@code java.net.http.HttpClient}, OkHttp, Apache HttpClient 4 e 5,
 * Commons HttpClient: {@code server.io.net.url}); SQL (JDBC: {@code server.db.statement} e {@code server.db.system}).
 * Regra em modo bloquear responde com a página de bloqueio e interrompe a operação com a exceção de bloqueio, tratada
 * no fim da requisição. As classes do JDK chamam o agente por uma ponte no bootstrap ({@link RaspBridge}).
 */
public final class JavaRasp {
    private static final ThreadLocal<Boolean> CHECKING = new ThreadLocal<>();
    private static final Set<String> SHELLS = Set.of("sh", "bash", "zsh", "dash", "ksh", "/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/bash", "cmd", "cmd.exe");

    private JavaRasp() {}

    public static void install(Instrumentation instrumentation) throws Exception {
        // Só pelo nome: o literal da classe a carregaria também no class loader do sistema (outra cópia, sem callback).
        String name = "system.monitoring.debugger.bootstrap.RaspBridge";
        String resource = name.replace('.', '/') + ".class";
        var file = Files.createTempFile("telvyn-rasp-", ".jar");
        file.toFile().deleteOnExit();
        try (var input = JavaRasp.class.getClassLoader().getResourceAsStream(resource);
             var output = new JarOutputStream(Files.newOutputStream(file))) {
            if (input == null) throw new IllegalStateException("missing exploit prevention bridge");
            output.putNextEntry(new JarEntry(resource));
            input.transferTo(output);
            output.closeEntry();
        }
        instrumentation.appendToBootstrapClassLoaderSearch(new JarFile(file.toFile()));
        Class<?> bridge = Class.forName(name, true, null);
        if (bridge.getClassLoader() != null) throw new IllegalStateException("exploit prevention bridge not on the bootstrap class loader");
        // java.base e java.net.http leem o módulo sem nome do bootstrap que tem a ponte.
        instrumentation.redefineModule(Object.class.getModule(), Set.of(bridge.getModule()), Map.of(), Map.of(), Set.of(), Map.of());
        ModuleLayer.boot().findModule("java.net.http").ifPresent(module ->
            instrumentation.redefineModule(module, Set.of(bridge.getModule()), Map.of(), Map.of(), Set.of(), Map.of()));
        bridge.getMethod("install", java.util.function.BiConsumer.class).invoke(null, (java.util.function.BiConsumer<String, Object>) JavaRasp::check);

        new AgentBuilder.Default().disableClassFormatChanges()
            .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
            .with(new AgentBuilder.Listener.Adapter() {
                @Override public void onError(String type, ClassLoader loader, net.bytebuddy.utility.JavaModule module, boolean loaded, Throwable error) {
                    System.err.println("[telvyn] instrumentation failed for " + type + TelvynDebuggerAgent.reason(error));
                }
            })
            .ignore(none())
            .type(namedOneOf("java.io.FileInputStream", "java.io.FileOutputStream", "java.io.RandomAccessFile"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(FileOpen.class)
                .on(isConstructor().and(takesArgument(0, namedOneOf("java.lang.String", "java.io.File"))))))
            .type(named("java.nio.file.Files"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(PathOperation.class)
                .on(isStatic().and(isPublic()).and(takesArgument(0, named("java.nio.file.Path"))).and(namedOneOf("newInputStream", "newOutputStream",
                    "newByteChannel", "newBufferedReader", "newBufferedWriter", "readAllBytes", "readString", "readAllLines", "lines", "write", "writeString",
                    "copy", "move", "delete", "deleteIfExists", "list", "walk", "newDirectoryStream", "createFile", "createDirectories")))))
            // ProcessImpl.start: ProcessBuilder.start e Runtime.exec passam por ele.
            .type(named("java.lang.ProcessImpl"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ProcessStart.class).on(named("start").and(isStatic()).and(takesArgument(0, String[].class)))))
            .type(named("java.net.URL"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(UrlOpen.class).on(named("openConnection"))))
            .type(named("jdk.internal.net.http.HttpClientImpl"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(JdkHttpSend.class).on(namedOneOf("send", "sendAsync").and(takesArgument(0, named("java.net.http.HttpRequest"))))))
            .installOn(instrumentation);

        Agents.builder()
            .type(namedOneOf("okhttp3.OkHttpClient", "com.squareup.okhttp.OkHttpClient"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(OkHttpCall.class).on(named("newCall").and(takesArguments(1)))))
            .type(namedOneOf("org.apache.http.impl.client.InternalHttpClient", "org.apache.http.impl.client.MinimalHttpClient",
                "org.apache.hc.client5.http.impl.classic.InternalHttpClient", "org.apache.hc.client5.http.impl.classic.MinimalHttpClient"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(ApacheExecute.class).on(named("doExecute").and(takesArguments(3)))))
            .type(named("org.apache.commons.httpclient.HttpClient"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(CommonsExecute.class).on(named("executeMethod").and(takesArguments(3)))))
            .installOn(instrumentation);
        Agents.builder()
            .type(hasSuperType(named("java.sql.Connection")).and(not(isInterface())), LoaderMatchers.canSee("java.sql.Connection"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(JdbcPrepare.class)
                .on(namedOneOf("prepareStatement", "prepareCall").and(takesArgument(0, String.class)))))
            .type(hasSuperType(named("java.sql.Statement")).and(not(isInterface())), LoaderMatchers.canSee("java.sql.Statement"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(JdbcExecute.class)
                .on(namedOneOf("execute", "executeQuery", "executeUpdate", "executeLargeUpdate", "addBatch").and(takesArgument(0, String.class)))))
            .installOn(instrumentation);
    }

    /** Operação perigosa: compara com a entrada da requisição em curso; regra em modo bloquear responde e interrompe. */
    public static void check(String address, Object value) {
        // Só a exceção de bloqueio sai daqui: qualquer outra falha da proteção não pode quebrar a operação da aplicação.
        try { inspect(address, value); }
        catch (SpringMvcSecurity.BlockedRequestException blocked) { throw blocked; }
        catch (RuntimeException | LinkageError failure) { LocalAttackReporter.reportLoss("exploit prevention failure"); }
    }

    private static void inspect(String address, Object value) {
        if ("telvyn.process".equals(address)) { if (value instanceof List<?> list) command(list.stream().map(String::valueOf).toList()); return; }
        if ("telvyn.url".equals(address)) { url(value); return; }
        // Reentrada (a própria verificação abre arquivos, carrega classes...): ignorada antes de qualquer trabalho.
        if (Boolean.TRUE.equals(CHECKING.get())) return;
        CHECKING.set(Boolean.TRUE);
        Object[] current;
        WafInspector.State state;
        try {
            current = SpringMvcSecurity.current();
            if (current == null) current = VertxSecurity.contextCurrent(Thread.currentThread().getContextClassLoader());
            if (current == null || !(current[2] instanceof WafInspector.State found) || found.blocked || found.closed) return;
            state = found;
            var reporter = SpringMvcSecurity.wafReporter();
            if (reporter == null) return;
            Map<String, Object> data = new java.util.LinkedHashMap<>();
            if ("server.db.statement".equals(address) && value instanceof Object[] sql) { data.put(address, sql[0]); data.put("server.db.system", sql[1]); }
            else data.put(address, value);
            if (!SpringMvcSecurity.decide(state, WafInspector.run(state, data, true), reporter)) return;
            if (JavaProtection.respond(current[0], current[1]) != null) state.blocked = true;
        } finally { CHECKING.remove(); }
        if (state.blocked) throw new SpringMvcSecurity.BlockedRequestException();
    }

    /** Comando: sh/bash -c vira comando de shell; senão programa com argumentos. */
    public static void command(List<String> command) {
        if (command == null || command.isEmpty()) return;
        String program = command.get(0);
        if (command.size() >= 3 && SHELLS.contains(program) && ("-c".equals(command.get(1)) || "/c".equalsIgnoreCase(command.get(1))))
            check("server.sys.shell.cmd", String.join(" ", command.subList(2, command.size())));
        else check("server.sys.exec.cmd", new ArrayList<>(command));
    }

    /** URL de saída: só HTTP(S) (recursos de jar e arquivos locais não são requisições de saída). */
    public static void url(Object url) {
        if (url == null) return;
        String text = url.toString();
        String lower = text.toLowerCase(Locale.ROOT);
        if (lower.startsWith("http://") || lower.startsWith("https://")) check("server.io.net.url", text);
    }

    private static String system(Object connection) {
        try {
            Object metadata = JavaProtection.call(connection, "getMetaData", new Class<?>[]{});
            String url = String.valueOf(JavaProtection.call(metadata, "getURL", new Class<?>[]{})).toLowerCase(Locale.ROOT);
            if (url.startsWith("jdbc:postgresql")) return "postgresql";
            if (url.startsWith("jdbc:mysql") || url.startsWith("jdbc:mariadb")) return "mysql";
            if (url.startsWith("jdbc:sqlite")) return "sqlite";
            if (url.startsWith("jdbc:oracle")) return "oracle";
            if (url.startsWith("jdbc:h2")) return "h2";
            if (url.startsWith("jdbc:hsqldb")) return "hsqldb";
            if (url.startsWith("jdbc:sqlserver")) return "sqlserver";
            return "sql";
        } catch (ReflectiveOperationException | RuntimeException unavailable) { return "sql"; }
    }

    public static void sql(Object connectionOrStatement, String sql, boolean statement) {
        if (sql == null || Boolean.TRUE.equals(CHECKING.get()) || SpringMvcSecurity.current() == null) return;
        Object connection = connectionOrStatement;
        if (statement) {
            try { connection = JavaProtection.call(connectionOrStatement, "getConnection", new Class<?>[]{}); }
            catch (ReflectiveOperationException | RuntimeException unavailable) { connection = null; }
        }
        String system;
        CHECKING.set(Boolean.TRUE);
        try { system = connection == null ? "sql" : system(connection); } finally { CHECKING.remove(); }
        check("server.db.statement", new Object[]{sql, system});
    }

    // ---- Advices -----------------------------------------------------------------------------------------------------

    public static class FileOpen {
        @Advice.OnMethodEnter
        public static void enter(@Advice.Argument(0) Object path) {
            if (path != null) RaspBridge.check("server.io.fs.file", path instanceof java.io.File file ? file.getPath() : path.toString());
        }
    }

    public static class PathOperation {
        @Advice.OnMethodEnter
        public static void enter(@Advice.Argument(0) Object path) { if (path != null) RaspBridge.check("server.io.fs.file", path.toString()); }
    }

    public static class ProcessStart {
        @Advice.OnMethodEnter
        public static void enter(@Advice.Argument(0) String[] command) { if (command != null) RaspBridge.check("telvyn.process", java.util.Arrays.asList(command)); }
    }

    public static class UrlOpen {
        @Advice.OnMethodEnter
        public static void enter(@Advice.This Object url) { RaspBridge.check("telvyn.url", url); }
    }

    public static class JdkHttpSend {
        @Advice.OnMethodEnter
        public static void enter(@Advice.Argument(0) java.net.http.HttpRequest request) { if (request != null) RaspBridge.check("telvyn.url", request.uri()); }
    }

    public static class OkHttpCall {
        @Advice.OnMethodEnter
        public static void enter(@Advice.Argument(0) Object request) { JavaRasp.okHttp(request); }
    }

    public static class ApacheExecute {
        @Advice.OnMethodEnter
        public static void enter(@Advice.Argument(0) Object host, @Advice.Argument(1) Object request) { JavaRasp.apache(host, request); }
    }

    public static class CommonsExecute {
        @Advice.OnMethodEnter
        public static void enter(@Advice.Argument(1) Object method) { JavaRasp.commons(method); }
    }

    public static class JdbcPrepare {
        @Advice.OnMethodEnter
        public static void enter(@Advice.This Object connection, @Advice.Argument(0) String sql) { JavaRasp.sql(connection, sql, false); }
    }

    public static class JdbcExecute {
        @Advice.OnMethodEnter
        public static void enter(@Advice.This Object statement, @Advice.Argument(0) String sql) { JavaRasp.sql(statement, sql, true); }
    }

    // ---- Clientes HTTP da aplicação ----------------------------------------------------------------------------------

    public static void okHttp(Object request) {
        try { url(JavaProtection.call(request, request.getClass().getName().startsWith("okhttp3") ? "url" : "urlString", new Class<?>[]{})); }
        catch (ReflectiveOperationException | RuntimeException unavailable) { /* requisição sem URL */ }
    }

    public static void apache(Object host, Object request) {
        try {
            Object uri;
            try { uri = JavaProtection.call(request, "getUri", new Class<?>[]{}); }
            catch (NoSuchMethodException version4) { uri = JavaProtection.call(request, "getURI", new Class<?>[]{}); }
            String text = String.valueOf(uri);
            if (!text.contains("://") && host != null) text = JavaProtection.call(host, "toURI", new Class<?>[]{}) + text;
            url(text);
        } catch (ReflectiveOperationException | RuntimeException unavailable) {
            try {
                Object line = JavaProtection.call(request, "getRequestLine", new Class<?>[]{});
                String uri = String.valueOf(JavaProtection.call(line, "getUri", new Class<?>[]{}));
                url(uri.contains("://") || host == null ? uri : JavaProtection.call(host, "toURI", new Class<?>[]{}) + uri);
            } catch (ReflectiveOperationException | RuntimeException noUri) { /* requisição sem URL */ }
        }
    }

    public static void commons(Object method) {
        try { url(JavaProtection.call(method, "getURI", new Class<?>[]{})); }
        catch (ReflectiveOperationException | RuntimeException unavailable) { /* método sem URL */ }
    }
}
