package system.monitoring.debugger.profiler;

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
import system.monitoring.debugger.bootstrap.VirtualThreadRegistry;

final class VirtualThreadTracking {
    private static boolean installed;

    static synchronized void install(Instrumentation instrumentation) throws Exception {
        if (installed) return;
        String name = "system.monitoring.debugger.bootstrap.VirtualThreadRegistry";
        String resource = name.replace('.', '/') + ".class";
        var file = Files.createTempFile("telvyn-virtual-threads-", ".jar");
        file.toFile().deleteOnExit();
        try (var input = VirtualThreadTracking.class.getClassLoader().getResourceAsStream(resource);
             var output = new JarOutputStream(Files.newOutputStream(file))) {
            if (input == null) throw new IllegalStateException("Missing virtual-thread bridge");
            output.putNextEntry(new JarEntry(resource));
            input.transferTo(output);
            output.closeEntry();
        }
        // Inject only the JDK-only bridge, not the agent or its dependencies.
        instrumentation.appendToBootstrapClassLoaderSearch(new JarFile(file.toFile()));
        Class<?> bridge = Class.forName(name, true, null);
        instrumentation.redefineModule(Thread.class.getModule(), Set.of(bridge.getModule()),
            Map.of(), Map.of(), Set.of(), Map.of());
        Class<?> virtualThread = Class.forName("java.lang.VirtualThread", false, null);
        virtualThread.getDeclaredMethod("run", Runnable.class);
        new AgentBuilder.Default().disableClassFormatChanges()
            .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
            .with(AgentBuilder.Listener.StreamWriting.toSystemError().withErrorsOnly())
            .ignore(none())
            .type(named("java.lang.VirtualThread"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Lifecycle.class)
                .on(named("run").and(takesArguments(Runnable.class)))))
            .installOn(instrumentation);
        installed = true;
    }

    public static class Lifecycle {
        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.This Thread thread) { VirtualThreadRegistry.entered(thread); }

        @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
        public static void exit(@Advice.This Thread thread) { VirtualThreadRegistry.exited(thread); }
    }
}
