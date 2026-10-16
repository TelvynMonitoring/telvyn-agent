package system.monitoring.debugger.profiler;

import java.lang.management.ManagementFactory;
import java.util.LinkedHashMap;
import java.util.Map;

/** Process counters measured over each recording window; never redistributed into stacks. */
final class ProfileWindowMeasurements {
    private static final java.lang.reflect.Method TOTAL_ALLOCATED = totalAllocatedMethod();
    private static java.lang.reflect.Method totalAllocatedMethod() {
        try {return com.sun.management.ThreadMXBean.class.getMethod("getTotalThreadAllocatedBytes");}
        catch(NoSuchMethodException|LinkageError unavailable) {return null;}
    }
    private record Point(long timeMs,long nano,long cpu,long allocated,long classes,long compilation,long startedThreads,long uptime,long deadlockedThreads,long gcBoundary) {}
    private Point start;
    long begin() {start=read();return start.timeMs();}
    Map<String,Object> drain() {
        var end=read();var previous=start;start=end;
        if(previous==null||end.nano()-previous.nano()<=0||end.timeMs()<previous.timeMs())return Map.of();
        var result=new LinkedHashMap<String,Object>();
        result.put("source","jvm_process_mxbeans");result.put("from_ms",previous.timeMs());result.put("to_ms",end.timeMs());
        result.put("duration_ns",end.nano()-previous.nano());
        if(previous.cpu()>=0&&end.cpu()>=previous.cpu())result.put("cpu_time_ns",end.cpu()-previous.cpu());
        if(previous.allocated()>=0&&end.allocated()>=previous.allocated())result.put("allocated_bytes",end.allocated()-previous.allocated());
        if(previous.classes()>=0&&end.classes()>=previous.classes())result.put("loaded_classes",end.classes()-previous.classes());
        if(previous.compilation()>=0&&end.compilation()>=previous.compilation())result.put("compilation_time_ns",end.compilation()-previous.compilation());
        if(previous.startedThreads()>=0&&end.startedThreads()>=previous.startedThreads())result.put("started_threads",end.startedThreads()-previous.startedThreads());
        if(end.uptime()>=0)result.put("uptime_ns",end.uptime());
        if(end.deadlockedThreads()>=0)result.put("deadlocked_threads",end.deadlockedThreads());
        result.putAll(ProfileGcMeasurements.between(previous.gcBoundary(),end.gcBoundary()));
        return result;
    }
    private static Point read() {
        long cpu=-1,allocated=-1,classes=-1,compilation=-1,startedThreads=-1,uptime=-1,deadlockedThreads=-1;
        // Respect profiling switches; reading counters never enables a management capability.
        if(enabled("telvyn.profiling.enabled","TELVYN_PROFILING_ENABLED"))try {
            if(ManagementFactory.getOperatingSystemMXBean() instanceof com.sun.management.OperatingSystemMXBean bean)cpu=bean.getProcessCpuTime();
        } catch(RuntimeException|LinkageError unavailable) { /* unsupported remains absent */ }
        if(enabled("telvyn.profiling.enabled","TELVYN_PROFILING_ENABLED")) {
            try {classes=ManagementFactory.getClassLoadingMXBean().getTotalLoadedClassCount();}
            catch(RuntimeException|LinkageError unavailable) { /* unsupported remains absent */ }
            try {
                var bean=ManagementFactory.getCompilationMXBean();
                if(bean!=null&&bean.isCompilationTimeMonitoringSupported())compilation=Math.multiplyExact(bean.getTotalCompilationTime(),1_000_000L);
            } catch(RuntimeException|LinkageError unavailable) { /* unsupported remains absent */ }
            try {startedThreads=ManagementFactory.getThreadMXBean().getTotalStartedThreadCount();}
            catch(RuntimeException|LinkageError unavailable) { /* unsupported remains absent */ }
            try {uptime=Math.multiplyExact(ManagementFactory.getRuntimeMXBean().getUptime(),1_000_000L);}
            catch(RuntimeException|LinkageError unavailable) { /* unsupported remains absent */ }
            try {
                var bean=ManagementFactory.getThreadMXBean();
                if(bean.isSynchronizerUsageSupported()) {
                    var threads=bean.findDeadlockedThreads();
                    deadlockedThreads=threads==null?0:threads.length;
                }
            } catch(RuntimeException|LinkageError unavailable) { /* unsupported remains absent */ }
        }
        if(enabled("telvyn.profiling.alloc.enabled","TELVYN_PROFILING_ALLOC_ENABLED"))try {
            if(ManagementFactory.getThreadMXBean() instanceof com.sun.management.ThreadMXBean bean
                    &&TOTAL_ALLOCATED!=null&&bean.isThreadAllocatedMemorySupported()&&bean.isThreadAllocatedMemoryEnabled())allocated=(long)TOTAL_ALLOCATED.invoke(bean);
        } catch(ReflectiveOperationException|RuntimeException|LinkageError unavailable) { /* unsupported remains absent */ }
        return new Point(System.currentTimeMillis(),System.nanoTime(),cpu,allocated,classes,compilation,startedThreads,uptime,deadlockedThreads,
                enabled("telvyn.profiling.enabled","TELVYN_PROFILING_ENABLED")?ProfileGcMeasurements.mark():0);
    }
    private static boolean enabled(String property,String environment) {
        String value=System.getProperty(property);if(value==null||value.isBlank())value=System.getenv(environment);
        return "true".equalsIgnoreCase(value);
    }
}
