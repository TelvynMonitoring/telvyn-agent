package system.monitoring.debugger.bootstrap;

import java.util.function.BiConsumer;

/**
 * Loaded by the bootstrap class loader so that JDK classes (java.io, java.nio.file, java.lang.ProcessBuilder, java.net)
 * can hand a dangerous operation to exploit prevention. It holds only the callback the agent installs (JavaRasp, in the
 * agent class loader); no agent type here. The callback may throw to abort the operation.
 */
public final class RaspBridge {
    private static volatile BiConsumer<String, Object> check;
    private RaspBridge() {}
    public static void install(BiConsumer<String, Object> callback) { check = callback; }
    public static void check(String address, Object value) {
        BiConsumer<String, Object> callback = check;
        if (callback != null && value != null) callback.accept(address, value);
    }
}
