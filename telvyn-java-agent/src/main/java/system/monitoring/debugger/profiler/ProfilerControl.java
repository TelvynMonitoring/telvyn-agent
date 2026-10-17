package system.monitoring.debugger.profiler;

import java.lang.instrument.Instrumentation;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Partida de cada perfil, usada na inicialização do agente e pela configuração remota (ligar
 * pela tela um perfil que estava desligado). Cada tipo inicia uma vez só; falha nunca derruba a
 * aplicação.
 */
public final class ProfilerControl {
    private static final Set<String> STARTED = ConcurrentHashMap.newKeySet();
    private static volatile Instrumentation instrumentation;

    private ProfilerControl() {}

    public static void init(Instrumentation inst) { instrumentation = inst; }

    public static synchronized void startCpu() {
        if (!STARTED.add("cpu")) return;
        try {
            if (instrumentation != null) JfrCpuProfiler.start(instrumentation); else JfrCpuProfiler.start();
        } catch (Throwable t) {
            STARTED.remove("cpu");
            System.err.println("[telvyn-profiler] desligado (falha, app segue normal): " + t);
        }
    }

    /** Wall time roda junto do perfil de CPU (mesmo período e envio). */
    public static synchronized void startWall() {
        startCpu();
        if (!STARTED.add("wall")) return;
        if (!JfrCpuProfiler.startWall()) STARTED.remove("wall");
    }

    public static synchronized void startExceptions() {
        start("exceptions", () -> JfrGenericProfiler.start("exceptions", "jdk.JavaExceptionThrow", settings -> settings.withStackTrace(),
                event -> 1L, flushSec()));
    }

    public static synchronized void startAlloc() {
        start("alloc", () -> JfrGenericProfiler.start("alloc", "jdk.ObjectAllocationSample",
                settings -> {}, // throttle default da JVM (~150/s) — já pensado pra baixo overhead
                event -> event.hasField("weight") ? event.getLong("weight") : 1L, flushSec()));
    }

    public static synchronized void startLock() {
        long thresholdMs = parse(conf("telvyn.profiling.lock.threshold.ms", "TELVYN_PROFILING_LOCK_THRESHOLD_MS"), 10);
        start("lock", () -> JfrGenericProfiler.start("lock", "jdk.JavaMonitorEnter",
                settings -> settings.withThreshold(java.time.Duration.ofMillis(thresholdMs)),
                event -> event.getDuration().toNanos(), flushSec()));
    }

    private static void start(String type, Runnable starter) {
        if (!STARTED.add(type)) return;
        try { starter.run(); }
        catch (Throwable t) {
            STARTED.remove(type);
            System.err.println("[telvyn-profiler] " + type + " desligado (falha, app segue normal): " + t);
        }
    }

    static int flushSec() { return (int) parse(conf("telvyn.profiling.flush.sec", "TELVYN_PROFILING_FLUSH_SEC"), 15); }

    private static String conf(String property, String environment) {
        String value = System.getProperty(property);
        return value == null || value.isBlank() ? System.getenv(environment) : value;
    }

    private static long parse(String value, long fallback) {
        try { return value == null ? fallback : Long.parseLong(value.trim()); }
        catch (NumberFormatException invalid) { return fallback; }
    }
}
