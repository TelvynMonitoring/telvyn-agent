package system.monitoring.debugger.profiler;

import jdk.jfr.EventSettings;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordedStackTrace;
import jdk.jfr.consumer.RecordingStream;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.ToLongFunction;

/**
 * G3 — núcleo compartilhado dos profilers JFR de amostragem por pilha ALÉM de
 * CPU (memória/alocação, lock/contenção). O profiler de CPU original
 * ({@link JfrCpuProfiler}) fica intocado (zero risco pro que já funciona);
 * esta classe nasce só pros tipos NOVOS, reaproveitando a mesma mecânica
 * (acumula pilha→peso, drena por janela, manda pro {@link ProfileSink}) —
 * reusa {@link JfrCpuProfiler#foldStack}/{@code toFoldedText} (package-private).
 *
 * <p>"Peso" é genérico por tipo: contagem (cpu), bytes estimados (alloc),
 * nanossegundos bloqueado (lock) — o front rotula a unidade por
 * {@code profile_type}, a árvore/flame graph é a mesma estrutura.
 */
public final class JfrGenericProfiler {

    private final String profileType;
    private final ProfileSink sink;
    private final LinkedProfileAccumulator acc = new LinkedProfileAccumulator();
    private final ProfileDetails details = new ProfileDetails();
    private volatile long windowStartMs;
    private static RecordingStream sharedStream;
    private ScheduledExecutorService flusher;

    private JfrGenericProfiler(String profileType, ProfileSink sink) {
        this.profileType = profileType;
        this.sink = sink;
    }

    /**
     * Sobe um profiler JFR genérico. Nunca lança — falha = este tipo fica
     * desligado, o app (e os outros profilers) seguem normalmente.
     *
     * @param profileType rótulo enviado ao backend (alloc | lock | wall…)
     * @param eventName   evento JFR a habilitar (ex: jdk.ObjectAllocationSample)
     * @param configure   ajusta período/threshold daquele evento (pode ser no-op)
     * @param weightOf    peso de cada ocorrência (bytes, nanos…); <=0 descarta
     * @param flushSec    intervalo de envio da janela agregada
     */
    public static void start(String profileType, String eventName,
                       Consumer<EventSettings> configure,
                       ToLongFunction<RecordedEvent> weightOf,
                       int flushSec) {
        start(profileType, java.util.List.of(eventName), configure, weightOf, flushSec);
    }

    public static synchronized void start(String profileType, java.util.List<String> eventNames,
                       Consumer<EventSettings> configure,
                       ToLongFunction<RecordedEvent> weightOf, int flushSec) {
        try {
            // ProfileSink é package-private (mesmo desenho do JfrCpuProfiler) — só é
            // construído aqui dentro, nunca exposto pro chamador (outro pacote).
            JfrGenericProfiler p = new JfrGenericProfiler(profileType, ProfileSink.fromEnv());
            p.windowStartMs = p.details.beginWindow();

            // Each reader duplicates JFR constant pools; share one reader across event types.
            boolean first = sharedStream == null;
            RecordingStream rs = first ? new RecordingStream() : sharedStream;
            if (first) {
                rs.setReuse(true);
                rs.setOrdered(false);
            }
            for (String eventName : eventNames) {
            configure.accept(rs.enable(eventName));
            rs.onEvent(eventName, event -> {
                try {
                    RecordedStackTrace st = event.getStackTrace();
                    if (st == null) return;
                    long weight = weightOf.applyAsLong(event);
                    if (weight <= 0) return;
                    String folded = JfrCpuProfiler.foldStack(st, JfrCpuProfiler.MAX_DEPTH);
                    if (folded.isEmpty()) return;
                    var context=contextFor(event);
                    synchronized (p) {
                        p.acc.add(folded,context,weight);
                        p.details.add(event,event.getThread(),weight,folded,context);
                    }
                } catch (Throwable ignore) {
                    // uma amostra com problema nunca pode derrubar o stream
                }
            });
            }
            if (first) {
                rs.startAsync();
                sharedStream = rs;
                Runtime.getRuntime().addShutdownHook(new Thread(rs::close, "telvyn-profiler-events-stop"));
            }

            p.flusher = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "telvyn-profiler-" + profileType + "-flush");
                t.setDaemon(true);
                return t;
            });
            p.flusher.scheduleAtFixedRate(p::flushSafe, flushSec, flushSec, TimeUnit.SECONDS);
            Runtime.getRuntime().addShutdownHook(new Thread(p::flushSafe, "telvyn-profiler-" + profileType + "-shutdown"));
            System.out.println("[telvyn-profiler] " + profileType + " profiler ligado (JFR " + eventNames
                    + ", flush=" + flushSec + "s) " + p.sink.describe());
        } catch (Throwable t) {
            System.err.println("[telvyn-profiler] " + profileType + " desligado (falha ao iniciar, app segue normal): " + t);
        }
    }

    private void flushSafe() {
        try { flush(); }
        catch (Throwable t) { System.err.println("[telvyn-profiler] " + profileType + " flush falhou (app segue normal): " + t); }
    }
    static ProfilerTraceContext.Link contextFor(RecordedEvent event) {
        var thread=event.getThread();
        // eventThread is the allocating/blocked application thread, not the JFR consumer.
        return thread==null?null:ProfilerTraceContext.at(thread.getJavaThreadId(),event.getStartTime());
    }

    private void flush() {
        long now = System.currentTimeMillis();
        long start;
        LinkedProfileAccumulator.Window window;
        ProfileDetails.Window eventDetails;
        synchronized (this) {
            start = windowStartMs;
            window=acc.drain();
            eventDetails=details.drain();
            now=((Number)eventDetails.window_metrics().getOrDefault("to_ms",now)).longValue();windowStartMs=now;
        }
        String folded=window.folded();
        if (folded.isEmpty()) return;
        int windowSeconds = (int) Math.max(1, (now - start) / 1000);
        // period_ms=0: não é amostragem periódica (throttle/threshold) — o front já
        // trata 0 como "—" em vez de "1 a cada 0ms".
        sink.send(folded, start, windowSeconds, 0, profileType,window.links(),eventDetails);
    }
}
