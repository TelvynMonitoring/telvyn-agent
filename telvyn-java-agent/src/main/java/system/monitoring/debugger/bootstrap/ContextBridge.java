package system.monitoring.debugger.bootstrap;

import java.util.function.BiConsumer;
import java.util.function.Consumer;

/**
 * Loaded by the bootstrap class loader so that OpenTelemetry context classes (the relocated copy inside the
 * OpenTelemetry Java agent lives there, and its SDK in a loader that cannot see the agent) can report scope changes to
 * the profiler. It holds only the callbacks the profiler installs; no agent type here.
 */
public final class ContextBridge {
    private static volatile BiConsumer<Object, Object> attached;
    private static volatile Consumer<Object> closed, ended;
    private ContextBridge() {}
    public static void install(BiConsumer<Object, Object> onAttach, Consumer<Object> onClose, Consumer<Object> onEnd) { attached = onAttach; closed = onClose; ended = onEnd; }
    public static void attached(Object context, Object scope) { BiConsumer<Object, Object> callback = attached; if (callback != null) callback.accept(context, scope); }
    public static void closed(Object scope) { Consumer<Object> callback = closed; if (callback != null) callback.accept(scope); }
    public static void ended(Object span) { Consumer<Object> callback = ended; if (callback != null) callback.accept(span); }
}
