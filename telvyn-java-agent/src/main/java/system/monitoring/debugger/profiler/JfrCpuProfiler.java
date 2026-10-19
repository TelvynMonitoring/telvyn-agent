package system.monitoring.debugger.profiler;

import jdk.jfr.consumer.RecordedFrame;
import jdk.jfr.consumer.RecordedMethod;
import jdk.jfr.consumer.RecordedStackTrace;
import jdk.jfr.consumer.RecordingStream;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.LongAdder;

/**
 * Profiler contínuo de CPU, 100% JFR (Java Flight Recorder),
 * embutido no JDK, sem dependência nativa. Para CPU:
 * só observa os eventos {@code jdk.ExecutionSample} (uma amostra da pilha de cada
 * thread em execução a cada ~10ms), dobra as pilhas em formato "collapsed"
 * (folded stacks, padrão Brendan Gregg) e, a cada janela (~15s), envia o agregado
 * pro backend via {@link ProfileSink}. Os hooks de correlação e ciclo de vida de
 * threads virtuais usam Byte Buddy; o custo depende da carga da aplicação.
 *
 * <p>Empilhando milhares de amostras → flame graph (largura ∝ tempo de CPU).
 *
 * <p>Config (system property OU env), todas opcionais:
 * <ul>
 *   <li>{@code telvyn.profiling.period.ms} / {@code TELVYN_PROFILING_PERIOD_MS} (default 10)</li>
 *   <li>{@code telvyn.profiling.flush.sec} / {@code TELVYN_PROFILING_FLUSH_SEC} (default 15)</li>
 * </ul>
 * A flag de liga/desliga ({@code TELVYN_PROFILING_ENABLED}) é checada no premain do
 * agent — aqui {@link #start()} apenas inicia (já decidido que está ligado).
 */
public final class JfrCpuProfiler {

    private static final int DEFAULT_PERIOD_MS = 10;
    private static final int DEFAULT_FLUSH_SEC = 15;
    /** Teto de profundidade da pilha (anti-recursão patológica). Trunca do lado da folha. */
    static final int MAX_DEPTH = 256;
    /**
     * Teto de BYTES por janela (anti-explosão de memória). CPU converge pros mesmos
     * pontos quentes (poucas pilhas curtas, contagem alta) — raramente chega perto.
     * Alocação (G3) amostra em toda parte do código (cada campo do Jackson, cada
     * proxy CDI gerado, cada lambda do Vert.x — nomes de classe/método longos): já
     * vimos <2000 pilhas distintas ainda assim passar de 1-4MB numa janela de 15s —
     * cortar por CONTAGEM não bastava, cada pilha em si já é grande. Corta por
     * tamanho total mesmo (mantém as mais pesadas até estourar o teto) — o
     * suficiente pra uma janela de 60min inteira (o default da tela) não chegar
     * perto de estourar o heap na leitura.
     */
    static final int MAX_FOLDED_BYTES = 200_000;

    private static volatile boolean started = false;
    private static volatile JfrCpuProfiler instance;

    private final int periodMs;
    private final int flushSec;
    private final ProfileSink sink;
    private final LinkedProfileAccumulator acc = new LinkedProfileAccumulator();
    private final ProfileDetails details = new ProfileDetails();
    private volatile long windowStartMs;
    private RecordingStream stream;
    private ScheduledExecutorService flusher;
    private JvmWallProfiler wall;

    private JfrCpuProfiler(int periodMs, int flushSec, ProfileSink sink) {
        this.periodMs = periodMs;
        this.flushSec = flushSec;
        this.sink = sink;
    }

    /** Inicia o profiler (idempotente). Nunca lança — falha = profiler desligado, app segue. */
    public static void start(java.lang.instrument.Instrumentation instrumentation) {
        try { ProfilerTraceContext.install(instrumentation); }
        catch (Throwable unavailable) { System.err.println("[telvyn-profiler] trace correlation hook unavailable"); }
        try { VirtualThreadTracking.install(instrumentation); }
        catch (Throwable unavailable) { System.err.println("[telvyn-profiler] virtual-thread tracking unavailable: " + unavailable.getClass().getSimpleName()); }
        start();
    }

    public static synchronized void start() {
        if (started) return;
        try {
            int periodMs = intConf("telvyn.profiling.period.ms", "TELVYN_PROFILING_PERIOD_MS", DEFAULT_PERIOD_MS, 1, 1000);
            int flushSec = intConf("telvyn.profiling.flush.sec", "TELVYN_PROFILING_FLUSH_SEC", DEFAULT_FLUSH_SEC, 2, 600);
            ProfileSink sink = ProfileSink.fromEnv();
            JfrCpuProfiler p = new JfrCpuProfiler(periodMs, flushSec, sink);
            p.startInternal();
            instance = p;
            started = true;
            System.out.println("[telvyn-profiler] CPU profiler ligado (JFR, periodo=" + periodMs
                    + "ms, flush=" + flushSec + "s) " + sink.describe());
        } catch (Throwable t) {
            System.err.println("[telvyn-profiler] desligado (falha ao iniciar, app segue normal): " + t);
        }
    }

    /** Liga o wall time com o perfil de CPU já rodando (configuração remota). Idempotente. */
    static synchronized boolean startWall() {
        JfrCpuProfiler p = instance;
        if (p == null) return false;
        if (p.wall != null) return true;
        try { p.wall = new JvmWallProfiler(p.periodMs, p.flushSec, p.sink); return true; }
        catch (RuntimeException failure) {
            System.err.println("[telvyn-profiler] wall profiler unavailable: " + failure.getClass().getSimpleName());
            return false;
        }
    }

    /** Para o profiler (usado em testes/self-check). */
    public static synchronized void stop() {
        JfrCpuProfiler p = instance;
        if (p == null) return;
        try { if (p.flusher != null) p.flusher.shutdownNow(); } catch (Throwable ignore) {}
        try { if (p.stream != null) p.stream.close(); } catch (Throwable ignore) {}
        try { if (p.wall != null) p.wall.stop(); } catch (Throwable ignore) {}
        try { p.flush(); } catch (Throwable ignore) {}
        instance = null;
        started = false;
    }

    private void startInternal() {
        this.windowStartMs = details.beginWindow();

        RecordingStream rs = new RecordingStream();
        try {ProfileGcMeasurements.attach(rs,flushSec);}
        catch(RuntimeException|LinkageError unavailable) { /* GC metrics remain absent; CPU profiling continues. */ }
        // Amostra de execução de CPU: a JVM tira uma "foto" da pilha de cada thread
        // RUNNABLE a cada `periodMs`. Não escreve arquivo — consumimos em memória.
        rs.enable("jdk.ExecutionSample").withPeriod(Duration.ofMillis(periodMs));
        rs.setReuse(true);     // reaproveita o objeto de evento (menos lixo) — lemos na hora
        rs.setOrdered(false);  // não precisamos de ordem temporal pra agregar
        rs.onEvent("jdk.ExecutionSample", event -> {
            try {
                RecordedStackTrace st = event.getStackTrace();
                if (st == null) return;
                var thread = event.getThread("sampledThread");
                if(thread!=null && thread.getJavaName().startsWith("telvyn-profiler"))return;
                String folded = foldStack(st, MAX_DEPTH);
                var context=thread == null ? null : ProfilerTraceContext.at(thread.getJavaThreadId(), event.getStartTime());
                synchronized(this){acc.add(folded,context);details.add(event,thread,1,folded,context);}
            } catch (Throwable ignore) {
                // uma amostra com problema nunca pode derrubar o stream
            }
        });
        this.stream = rs;
        rs.startAsync();
        if ("true".equalsIgnoreCase(firstNonBlank(System.getProperty("telvyn.profiling.wall.enabled"), System.getenv("TELVYN_PROFILING_WALL_ENABLED"), "false"))) {
            try { wall = new JvmWallProfiler(periodMs, flushSec, sink); }
            catch (RuntimeException failure) { System.err.println("[telvyn-profiler] wall profiler unavailable: " + failure.getClass().getSimpleName()); }
        }

        this.flusher = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "telvyn-profiler-flush");
            t.setDaemon(true);
            return t;
        });
        flusher.scheduleAtFixedRate(this::flushSafe, flushSec, flushSec, TimeUnit.SECONDS);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            flushSafe();
            if (wall != null) wall.stop();
        }, "telvyn-profiler-shutdown"));
    }

    private void flushSafe() {
        try { flush(); }
        catch (Throwable t) { System.err.println("[telvyn-profiler] flush falhou (app segue normal): " + t); }
    }

    private void flush() {
        long now = System.currentTimeMillis();
        long start;
        LinkedProfileAccumulator.Window window;
        ProfileDetails.Window eventDetails;
        synchronized(this){start=windowStartMs;window=acc.drain();eventDetails=details.drain();now=((Number)eventDetails.window_metrics().getOrDefault("to_ms",now)).longValue();windowStartMs=now;}
        String folded = window.folded();
        if (folded.isEmpty()) return;
        int windowSeconds = (int) Math.max(1, (now - start) / 1000);
        sink.send(folded, start, windowSeconds, periodMs, "cpu", window.links(),eventDetails);
    }

    // ---------------------------------------------------------------------
    // Helpers puros (testáveis sem JVM/JFR ao vivo) — ver ProfilerSelfCheck.
    // ---------------------------------------------------------------------

    /** Extrai os nomes de método de uma pilha JFR (topo→raiz) e dobra. */
    static String foldStack(RecordedStackTrace st, int maxDepth) {
        List<RecordedFrame> frames = st.getFrames();
        if (frames == null || frames.isEmpty()) return "";
        List<String> topFirst = new ArrayList<>(frames.size());
        for (RecordedFrame f : frames) {
            if (f == null || !f.isJavaFrame()) continue;
            RecordedMethod m = f.getMethod();
            if (m == null) continue;
            String type = (m.getType() != null && m.getType().getName() != null) ? m.getType().getName() : "";
            String name = m.getName() != null ? m.getName() : "";
            if (type.isEmpty() && name.isEmpty()) continue;
            topFirst.add(type.isEmpty() ? name : type + "." + name);
        }
        return foldFrames(topFirst, maxDepth);
    }

    /**
     * Dobra uma lista de quadros (na ordem topo→raiz, como o JFR entrega) em uma
     * string "raiz;...;folha". A raiz fica ancorada (essencial pra mesclar pilhas
     * iguais entre janelas); se passar de {@code maxDepth}, trunca do lado da folha
     * e marca {@code ;(truncated)}.
     */
    static String foldFrames(List<String> framesTopFirst, int maxDepth) {
        if (framesTopFirst == null || framesTopFirst.isEmpty()) return "";
        int n = framesTopFirst.size();
        int keep = Math.min(n, Math.max(1, maxDepth));
        boolean truncated = n > keep;
        StringBuilder sb = new StringBuilder(keep * 24);
        // raiz está no fim da lista (topo→raiz); ancoramos a raiz e descemos `keep`.
        for (int i = n - 1; i >= n - keep; i--) {
            if (sb.length() > 0) sb.append(';');
            sb.append(sanitizeFrame(framesTopFirst.get(i)));
        }
        if (truncated) sb.append(";(truncated)");
        return sb.toString();
    }

    /** ';' separa quadros, ' ' separa pilha da contagem, '\n' separa linhas — neutraliza. */
    static String sanitizeFrame(String f) {
        if (f == null || f.isEmpty()) return "?";
        StringBuilder b = new StringBuilder(f.length());
        for (int i = 0; i < f.length(); i++) {
            char c = f.charAt(i);
            b.append((c == ';' || c == ' ' || c == '\n' || c == '\r' || c == '\t') ? '_' : c);
        }
        return b.toString();
    }

    /**
     * Serializa o mapa pilha→contagem no formato folded ("pilha contagem\n"), maior
     * peso primeiro, parando ao chegar em {@link #MAX_FOLDED_BYTES} (ver nota na
     * constante) — descarta a cauda de baixo peso que sobrar.
     */
    static String toFoldedText(Map<String, LongAdder> counts) {
        List<Map.Entry<String, LongAdder>> sorted = new ArrayList<>(counts.entrySet());
        sorted.sort(Comparator.<Map.Entry<String, LongAdder>>comparingLong(e -> e.getValue().sum()).reversed());
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, LongAdder> e : sorted) {
            long c = e.getValue().sum();
            if (c <= 0) continue;
            if (sb.length() >= MAX_FOLDED_BYTES) break;
            sb.append(e.getKey()).append(' ').append(c).append('\n');
        }
        return sb.toString();
    }

    /** Acumulador concorrente pilha→contagem. Uma thread (JFR) soma, outra (flush) drena. */
    static final class FoldAccumulator {
        private final ConcurrentHashMap<String, LongAdder> m = new ConcurrentHashMap<>();

        synchronized void add(String key) {
            add(key, 1);
        }
        synchronized void add(String key, long weight) {
            if (key == null || key.isEmpty() || weight <= 0) return;
            m.computeIfAbsent(key, k -> new LongAdder()).add(weight);
        }

        synchronized int size() { return m.size(); }

        synchronized String drain() {
            String s = toFoldedText(m);
            m.clear();
            return s;
        }
    }

    // ---- config helpers ----

    private static int intConf(String prop, String env, int def, int min, int max) {
        String v = firstNonBlank(System.getProperty(prop), System.getenv(env));
        if (v == null) return def;
        try {
            int n = Integer.parseInt(v.trim());
            return Math.max(min, Math.min(max, n));
        } catch (Exception e) {
            return def;
        }
    }

    private static String firstNonBlank(String... vs) {
        for (String v : vs) if (v != null && !v.isBlank()) return v;
        return null;
    }
}
