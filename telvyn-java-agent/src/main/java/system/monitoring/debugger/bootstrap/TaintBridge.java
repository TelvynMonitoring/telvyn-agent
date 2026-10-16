package system.monitoring.debugger.bootstrap;

import java.util.function.BiConsumer;

/**
 * Loaded by the bootstrap class loader so that JDK classes (java.net.URI...) can report that a new object came from an
 * existing one. It holds only the callback the agent installs (IastRuntime, in the agent class loader); no agent type here.
 */
public final class TaintBridge {
    private static volatile BiConsumer<Object, Object> propagation;
    private TaintBridge() {}
    public static void install(BiConsumer<Object, Object> callback) { propagation = callback; }
    public static void propagate(Object source, Object target) {
        BiConsumer<Object, Object> callback = propagation;
        if (callback != null && source != null && target != null) callback.accept(source, target);
    }
    public static void propagateAll(Object[] sources, Object target) {
        BiConsumer<Object, Object> callback = propagation;
        if (callback == null || sources == null || target == null) return;
        for (Object source : sources) if (source instanceof String) callback.accept(source, target);
    }
}
