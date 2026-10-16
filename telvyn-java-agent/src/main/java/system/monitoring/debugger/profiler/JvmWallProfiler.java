package system.monitoring.debugger.profiler;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadInfo;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/** Wall-time observations, including blocked/waiting stacks; not CPU samples. */
final class JvmWallProfiler {
    static final int MAX_THREADS = 256;
    static final int MAX_DEPTH = 64;
    private final LinkedProfileAccumulator samples = new LinkedProfileAccumulator();
    private final ProfileDetails details = new ProfileDetails();
    private final ProfileSink sink;
    private final int periodMs;
    private final ScheduledExecutorService executor;
    private long startMs = System.currentTimeMillis();

    JvmWallProfiler(int periodMs, int flushSec, ProfileSink sink) {
        this.periodMs = Math.max(100, periodMs);
        this.sink = sink;
        this.startMs = details.beginWindow();
        executor = Executors.newScheduledThreadPool(2, r -> {
            Thread thread = new Thread(r, "telvyn-profiler-wall");
            thread.setDaemon(true);
            return thread;
        });
        executor.scheduleAtFixedRate(this::sample, this.periodMs, this.periodMs, TimeUnit.MILLISECONDS);
        executor.scheduleWithFixedDelay(this::flushSafe, flushSec, flushSec, TimeUnit.SECONDS);
    }

    private synchronized void sample() {
        try {
            var bean = ManagementFactory.getThreadMXBean();
            long[] all = bean.getAllThreadIds();
            for (int offset=0;offset<all.length;offset+=MAX_THREADS) {
            long[] selected = java.util.Arrays.copyOfRange(all,offset,Math.min(all.length,offset+MAX_THREADS));
            var before = java.time.Instant.now();
            var infos = bean.getThreadInfo(selected, MAX_DEPTH);
            var after = java.time.Instant.now();
            for (ThreadInfo info : infos) {
                String stack = fold(info);
                if (!stack.isEmpty()) {
                    var first = ProfilerTraceContext.at(info.getThreadId(), before);
                    var last = ProfilerTraceContext.at(info.getThreadId(), after);
                    var proven = first != null && last != null && first.startNano() == last.startNano() ? first : null;
                    samples.add(stack, proven);
                    details.addWall(info, before.toEpochMilli(), periodMs);
                }
            }
            }
            sampleVirtualThreads();
        } catch (RuntimeException ignored) { /* monitoring must not interrupt the application */ }
    }

    private void sampleVirtualThreads() {
        for (Thread thread : system.monitoring.debugger.bootstrap.VirtualThreadRegistry.snapshot()) {
            if (!thread.isAlive()) continue;
            var before = java.time.Instant.now();
            var state = thread.getState();
            var frames = thread.getStackTrace();
            var after = java.time.Instant.now();
            if (frames.length == 0) continue;
            List<String> names = new ArrayList<>();
            for (var frame : frames) names.add(frame.getClassName() + "." + frame.getMethodName());
            var first = ProfilerTraceContext.at(ProfilerTraceContext.threadId(thread), before);
            var last = ProfilerTraceContext.at(ProfilerTraceContext.threadId(thread), after);
            var proven = first != null && last != null && first.startNano() == last.startNano() ? first : null;
            samples.add("[VIRTUAL];[" + state.name() + "];" + JfrCpuProfiler.foldFrames(names, MAX_DEPTH), proven);
            details.addWall(ProfilerTraceContext.threadId(thread), thread.getName(), state, frames, true, before.toEpochMilli(), periodMs);
        }
    }

    static String fold(ThreadInfo info) {
        if (info == null || info.getThreadName().startsWith("telvyn-profiler") || info.getThreadState() == Thread.State.TERMINATED) return "";
        List<String> frames = new ArrayList<>();
        for (StackTraceElement frame : info.getStackTrace()) frames.add(frame.getClassName() + "." + frame.getMethodName());
        if (frames.isEmpty()) return "";
        return "[" + info.getThreadState().name() + "];" + JfrCpuProfiler.foldFrames(frames, MAX_DEPTH);
    }

    private void flushSafe() {
        try {
            String folded;
            List<LinkedProfileAccumulator.LinkStack> links;
            ProfileDetails.Window events;
            long now, start;
            synchronized (this) {
                now = System.currentTimeMillis();
                var window = samples.drain();
                folded = window.folded();links = window.links();
                events = details.drain();
                now=((Number)events.window_metrics().getOrDefault("to_ms",now)).longValue();
                start = startMs;startMs = now;
            }
            // Network latency must not pause the sampling thread.
            if (!folded.isEmpty()) sink.send(folded, start, (int)Math.max(1, (now - start) / 1000), periodMs, "wall", links, events);
        } catch (RuntimeException ignored) { /* next observation window may still succeed */ }
    }

    void stop() { executor.shutdownNow(); flushSafe(); }
}
