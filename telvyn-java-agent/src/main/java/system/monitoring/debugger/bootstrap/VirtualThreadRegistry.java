package system.monitoring.debugger.bootstrap;

import java.util.Map;
import java.util.WeakHashMap;

/** Bootstrap-visible lifecycle bridge; never retains completed application threads. */
public final class VirtualThreadRegistry {
    private static final Map<Thread, Boolean> THREADS = new WeakHashMap<>();
    private static final java.lang.reflect.Method IS_VIRTUAL = virtualMethod();

    private static java.lang.reflect.Method virtualMethod() {
        try {return Thread.class.getMethod("isVirtual");}
        catch(NoSuchMethodException unavailable) {return null;}
    }

    private VirtualThreadRegistry() {}

    public static synchronized void entered(Thread thread) {
        if(IS_VIRTUAL!=null)try {if(Boolean.TRUE.equals(IS_VIRTUAL.invoke(thread)))THREADS.put(thread,Boolean.TRUE);}
        catch(ReflectiveOperationException unavailable) { /* Virtual-thread API unavailable. */ }
    }

    public static synchronized void exited(Thread thread) { THREADS.remove(thread); }

    public static synchronized Thread[] snapshot() { return THREADS.keySet().toArray(new Thread[0]); }
}
