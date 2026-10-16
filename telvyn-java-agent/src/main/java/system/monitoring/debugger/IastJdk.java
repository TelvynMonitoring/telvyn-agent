package system.monitoring.debugger;

import java.lang.instrument.Instrumentation;
import java.nio.file.Files;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import static net.bytebuddy.matcher.ElementMatchers.*;
import system.monitoring.debugger.bootstrap.TaintBridge;

/**
 * Propagation through JDK classes loaded before the agent, which the call sites in application code cannot see into.
 * java.net.URI: every constructor marks the URI with the origin of its text arguments, and the text it returns (path,
 * string forms) keeps the origin of the URI. Only the JDK-only TaintBridge goes to the bootstrap class loader.
 */
public final class IastJdk {
    private static boolean installed;
    private IastJdk() {}
    public static synchronized void install(Instrumentation instrumentation) throws Exception {
        if (installed || !Boolean.getBoolean("telvyn.iast.enabled")) return;
        String name = "system.monitoring.debugger.bootstrap.TaintBridge";
        String resource = name.replace('.', '/') + ".class";
        var file = Files.createTempFile("telvyn-iast-jdk-", ".jar");
        file.toFile().deleteOnExit();
        try (var input = IastJdk.class.getClassLoader().getResourceAsStream(resource);
             var output = new JarOutputStream(Files.newOutputStream(file))) {
            if (input == null) throw new IllegalStateException("Missing IAST bootstrap bridge");
            output.putNextEntry(new JarEntry(resource));
            input.transferTo(output);
            output.closeEntry();
        }
        instrumentation.appendToBootstrapClassLoaderSearch(new JarFile(file.toFile()));
        Class<?> bridge = Class.forName(name, true, null);
        if (bridge.getClassLoader() != null) throw new IllegalStateException("IAST bridge not loaded by the bootstrap class loader");
        // java.base must read the unnamed bootstrap module that holds the bridge.
        instrumentation.redefineModule(java.net.URI.class.getModule(), Set.of(bridge.getModule()), Map.of(), Map.of(), Set.of(), Map.of());
        // The agent-side callback: the same propagation as every other call (request scope, limits).
        bridge.getMethod("install", java.util.function.BiConsumer.class).invoke(null, (java.util.function.BiConsumer<Object, Object>) IastRuntime::propagateFrom);
        new AgentBuilder.Default().disableClassFormatChanges()
            .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
            .with(new AgentBuilder.Listener.Adapter() {
                @Override public void onError(String type, ClassLoader loader, net.bytebuddy.utility.JavaModule module, boolean loaded, Throwable error) { LocalAttackReporter.reportLoss("IAST JDK transformation failure"); }
            })
            .ignore(none())
            .type(named("java.net.URI"))
            .transform((builder, type, loader, module, domain) -> builder
                .visit(Advice.to(UriCreated.class).on(isConstructor().and(takesArgument(0, String.class))))
                .visit(Advice.to(UriText.class).on(namedOneOf("getPath", "getRawPath", "getSchemeSpecificPart", "getRawSchemeSpecificPart", "getQuery", "getRawQuery", "toString", "toASCIIString").and(takesArguments(0)))))
            .installOn(instrumentation);
        installed = true;
    }
    public static class UriCreated {
        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(@Advice.This Object uri, @Advice.AllArguments Object[] arguments) { TaintBridge.propagateAll(arguments, uri); }
    }
    public static class UriText {
        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void exit(@Advice.This Object uri, @Advice.Return Object text) { TaintBridge.propagate(uri, text); }
    }
}
