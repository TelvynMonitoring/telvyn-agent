package system.monitoring.debugger.profiler;

import jdk.jfr.Recording;
import jdk.jfr.consumer.RecordingFile;
import java.nio.file.Files;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/** Periodic old-object observations; never forces GC or traverses paths to GC roots. */
public final class JfrRetentionProfiler {
    private JfrRetentionProfiler() {}

    public static void start() {
        var recording = new Recording();
        try {
        recording.enable("jdk.OldObjectSample").withStackTrace().with("cutoff", "0 ns");
        recording.setMaxAge(Duration.ofMinutes(2));
        recording.setMaxSize(8 * 1024 * 1024);
        recording.start();
        var sink = ProfileSink.fromEnv();
        var executor = Executors.newSingleThreadScheduledExecutor(r -> {
            var thread = new Thread(r, "telvyn-profiler-retention");
            thread.setDaemon(true);
            return thread;
        });
        executor.scheduleWithFixedDelay(new Runnable() {
            long previous;
            public void run() {
                java.nio.file.Path path = null;
                try {
                    path = Files.createTempFile("telvyn-retention-", ".jfr");
                    recording.dump(path);
                    if (Files.size(path) > 16 * 1024 * 1024) return;
                    var details = new ProfileDetails();
                    var stacks = new JfrCpuProfiler.FoldAccumulator();
                    long latest = previous, first = Long.MAX_VALUE;
                    try (var input = new RecordingFile(path)) {
                        while (input.hasMoreEvents()) {
                            var event = input.readEvent();
                            if (!event.getEventType().getName().equals("jdk.OldObjectSample")) continue;
                            long time = event.getStartTime().toEpochMilli();
                            if (time <= previous) continue;
                            latest = Math.max(latest, time);
                            if (event.getStackTrace() == null) continue;
                            String folded = JfrCpuProfiler.foldStack(event.getStackTrace(), JfrCpuProfiler.MAX_DEPTH);
                            if (folded.isEmpty()) continue;
                            first = Math.min(first, time);
                            stacks.add(folded, 1);
                            details.add(event, event.getThread(), 1, folded, null);
                        }
                    }
                    previous = latest;
                    String folded = stacks.drain();
                    if (!folded.isEmpty()) sink.send(folded, first, Math.max(1, (int)((System.currentTimeMillis()-first)/1000)), 0, "retention", List.of(), details.drain());
                } catch (Exception failure) {
                    System.err.println("[telvyn-profiler] retention window unavailable: " + failure.getClass().getSimpleName());
                } finally {
                    if (path != null) try { Files.deleteIfExists(path); } catch (Exception ignored) { }
                }
            }
        }, 60, 60, TimeUnit.SECONDS);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> { executor.shutdownNow(); recording.close(); }, "telvyn-retention-stop"));
        } catch (RuntimeException | Error failure) {
            recording.close();
            throw failure;
        }
    }
}
