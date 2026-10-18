package system.monitoring.debugger;

import java.io.File;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Map;

/**
 * Motor do WAF (libddwaf) num class loader isolado do classpath da aplicação, como o Datadog isola o agente. A
 * biblioteca nativa escolhe o slf4j pelo nome ({@code org/slf4j} se o encontrar, senão a cópia relocada
 * {@code datadog/slf4j} do agente) pelo class loader que a carregou: no class loader do sistema, uma aplicação com
 * slf4j no classpath faria a escolha errada e o WAF não subiria. O loader isolado lê o próprio jar do agente e tem
 * como pai o class loader da plataforma (só o JDK); a ponte {@code wafengine.WafEngine} expõe o motor com tipos do JDK.
 */
final class WafEngines {
    private static MethodHandle build, version, open, run, close;

    private WafEngines() {}

    private static synchronized void load() throws Exception {
        if (run != null) return;
        ClassLoader loader = WafEngines.class.getClassLoader();
        var source = WafEngines.class.getProtectionDomain().getCodeSource();
        if (source != null) {
            File jar = new File(source.getLocation().toURI());
            if (jar.isFile()) loader = new URLClassLoader("telvyn-waf", new URL[]{jar.toURI().toURL()}, ClassLoader.getPlatformClassLoader());
        }
        Class<?> engine = Class.forName("system.monitoring.debugger.wafengine.WafEngine", true, loader);
        var lookup = MethodHandles.publicLookup();
        build = lookup.findStatic(engine, "build", MethodType.methodType(Object.class, Map.class, String.class, int.class));
        version = lookup.findStatic(engine, "version", MethodType.methodType(String.class));
        open = lookup.findStatic(engine, "open", MethodType.methodType(Object.class, Object.class));
        close = lookup.findStatic(engine, "close", MethodType.methodType(void.class, Object.class));
        run = lookup.findStatic(engine, "run", MethodType.methodType(Object[].class, Object.class, Map.class, int[].class));
    }

    /** Motor com as regras (expected > 0: número exato de regras carregadas). */
    static Object build(Map<String, Object> rules, String name, int expected) throws Throwable { load(); return build.invoke(rules, name, expected); }

    static String version() throws Throwable { load(); return (String) version.invoke(); }

    static Object open(Object handle) throws Throwable { return open.invoke(handle); }

    /** {resultado ("ok", "match", "error", "timeout"), dados do match em JSON ou null}. */
    static Object[] run(Object context, Map<String, Object> data, int[] limits) throws Throwable { return (Object[]) run.invoke(context, data, limits); }

    static void close(Object resource) throws Throwable { close.invoke(resource); }
}
