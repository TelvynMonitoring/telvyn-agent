package system.monitoring.debugger;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

/**
 * Recebe os valores capturados, monta a "foto" (snapshot) JSON com limites de
 * tamanho/profundidade, e ENTREGA: se houver destino configurado, enfileira e
 * uma thread de fundo envia em lote pro coletor Telvyn local (POST /v1/debug), que repassa
 * ao backend com a credencial dele; a aplicação não guarda credencial.
 *
 * <p>Princípio: NUNCA atrasar nem derrubar o app. A captura só monta string e
 * enfileira (não-bloqueante, descarta se a fila encher); o HTTP roda fora do
 * caminho crítico. Todo render é try/catch.
 *
 * <p>Config (system property ou env): {@code TELVYN_AGENT_URL} (coletor; senão
 * {@code OTEL_EXPORTER_OTLP_ENDPOINT}; senão http://localhost:4318), {@code TELVYN_SERVICE}.
 */
public final class SnapshotSink {

    private static final int MAX_DEPTH = 3;
    private static final int MAX_STRING = 200;
    private static final int MAX_COLLECTION = 10;
    private static final int BATCH_MAX = 200;
    private static final int QUEUE_MAX = 10_000;

    // ---- Guarda-corpo 1: redação de segredos ------------------------------
    /** Marcador único do que foi mascarado (não aparece em valor real). */
    private static final String REDACTED = "•••"; // "•••"
    private static final Pattern P_NAMED_SECRET = Pattern.compile("(?i)(password|senha|secret|token|authorization|api[-_]?key)\\s*[:=]\\s*\\S+");
    /**
     * Nomes de chave/campo (case-insensitive) cujo VALOR é sempre mascarado,
     * independente do conteúdo. Verificamos por "contém" (ex.: "cardNumber"
     * contém "card"). Defensivo: nunca lança.
     */
    private static final Set<String> SENSITIVE_KEYS = new HashSet<>(List.of(
            "senha", "password", "secret", "token", "authorization", "apikey",
            "api_key", "accesstoken", "refreshtoken", "cartao", "card",
            "cardnumber", "cvv", "cvc", "pin", "ssn", "cpf", "creditcard"));

    // ---- Guarda-corpo 2: rate-limit (token bucket por segundo) -------------
    private static final int MAX_PER_SEC;
    private static final AtomicLong RL_WINDOW = new AtomicLong(0);   // segundo atual (epoch/1000)
    private static final AtomicInteger RL_COUNT = new AtomicInteger(0); // emitidos na janela
    private static final AtomicInteger RL_DROPPED = new AtomicInteger(0); // descartados acumulados
    private static final AtomicLong RL_LAST_LOG = new AtomicLong(0); // última vez que avisamos do drop

    private static final String URL;       // endpoint completo no coletor
    private static final String SERVICE;
    private static final String HOST;
    private static final LinkedBlockingQueue<String> QUEUE = new LinkedBlockingQueue<>(QUEUE_MAX);

    // ---- padrões de VALOR sensível (compilados uma vez) -------------------
    /** "Bearer xxx" / "Basic xxx" (qualquer credencial em header de auth). */
    private static final Pattern P_AUTH = Pattern.compile(
            "(?i)\\b(?:bearer|basic)\\s+[A-Za-z0-9._~+/=-]{8,}");
    /** JWT-like: três segmentos base64url separados por ponto. */
    private static final Pattern P_JWT = Pattern.compile(
            "\\b[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b");
    /** Cartão: 13–19 dígitos, podendo ter espaços/hífens entre grupos. */
    private static final Pattern P_CARD = Pattern.compile(
            "\\b(?:\\d[ -]?){13,19}\\b");
    /** CPF: xxx.xxx.xxx-xx (formatado). 11 dígitos crus caem no P_CARD. */
    private static final Pattern P_CPF = Pattern.compile(
            "\\b\\d{3}\\.\\d{3}\\.\\d{3}-\\d{2}\\b");
    /** Segredo opaco longo: 24+ chars base64/hex contíguos. */
    private static final Pattern P_OPAQUE = Pattern.compile(
            "\\b[A-Za-z0-9+/=_-]{24,}\\b");

    static {
        URL = Collector.url() + "/v1/debug";
        SERVICE = firstNonBlank(env("TELVYN_SERVICE"), env("OTEL_SERVICE_NAME"), "java-app");
        HOST = hostname();

        // Rate-limit: teto de fotos por segundo (default 50). Tudo defensivo.
        MAX_PER_SEC = parsePositiveInt(
                firstNonBlank(prop("telvyn.debug.max_per_sec"), env("TELVYN_DEBUG_MAX_PER_SEC")), 50);

        // Redação: chaves extras opcionais (CSV) via env.
        try {
            String extra = env("TELVYN_DEBUG_REDACT_EXTRA");
            if (extra != null) {
                for (String k : extra.split(",")) {
                    String t = k.trim().toLowerCase();
                    if (!t.isEmpty()) SENSITIVE_KEYS.add(t);
                }
            }
        } catch (Throwable ignore) {
            // redação nunca pode derrubar o boot
        }
        System.out.println("[telvyn-debugger] enviando fotos pra " + URL + " (service=" + SERVICE + ")");
        Thread t = new Thread(SnapshotSink::senderLoop, "telvyn-debugger-sender");
        t.setDaemon(true);
        t.start();
        // Esvazia a fila no desligamento (apps curtos/graceful shutdown).
        Runtime.getRuntime().addShutdownHook(new Thread(SnapshotSink::flushRemaining, "telvyn-debugger-flush"));
    }

    private SnapshotSink() {}

    // ---- usados pela config remota (ConfigPoller) -------------------------
    /** Endpoint de config remota no coletor (.../v1/debug/config). */
    static String configUrl() { return URL + "/config"; }
    static String host() { return HOST; }
    static String service() { return SERVICE; }

    public static void onEnter(String method, Object[] args) {
        onEnter(method, args, null);
    }

    public static void onEnter(String method, Object[] args, java.lang.reflect.Method reflected) {
        try {
            String[] names = paramNames(reflected, args);
            StringBuilder sb = new StringBuilder(256);
            sb.append("{\"phase\":\"enter\",\"method\":");
            quote(sb, method);
            sb.append(",\"captured_unix_ms\":").append(System.currentTimeMillis());
            appendTrace(sb);
            sb.append(",\"payload\":[");
            if (args != null) {
                for (int i = 0; i < args.length; i++) {
                    if (i > 0) sb.append(',');
                    render(sb, args[i], 0, names == null ? null : names[i]);
                }
            }
            sb.append(']');
            appendArgNames(sb, names);
            sb.append('}');
            deliver(sb.toString());
        } catch (Throwable ignore) {
            // Nunca derruba o app por causa da foto.
        }
    }

    public static void onExit(String method, Object returned, Throwable thrown, long durationNanos) {
        try {
            StringBuilder sb = new StringBuilder(256);
            sb.append("{\"phase\":\"exit\",\"method\":");
            quote(sb, method);
            sb.append(",\"captured_unix_ms\":").append(System.currentTimeMillis());
            appendTrace(sb);
            sb.append(",\"duration_ms\":").append(durationNanos / 1_000_000.0);
            if (thrown != null) {
                sb.append(",\"error\":");
                quote(sb, exceptionLabel(thrown));
            } else {
                sb.append(",\"payload\":");
                render(sb, returned, 0);
            }
            sb.append('}');
            deliver(sb.toString());
        } catch (Throwable ignore) {
            // idem
        }
    }

    /**
     * Probe de método (foto única por CHAMADA): junta entrada (args) e saída
     * (retorno OU erro) + duração num só snapshot {@code phase:"call"}. Entrada e
     * saída ficam DENTRO de {@code payload} ({@code {"args":[...],"arg_names":[...],
     * "returned":...}}) porque o backend guarda o payload como está (jsonb) — assim
     * não precisa de coluna nova. Substitui o par enter/exit.
     */
    public static void onCall(String method, Object[] args, Object returned, Throwable thrown,
                              long durationNanos, java.lang.reflect.Method reflected) {
        try {
            ProbeApplicationStatus.called(method);
            if(!ProbePolicies.observe(method,args,returned,thrown,durationNanos))return;
            String[] names = paramNames(reflected, args);
            StringBuilder sb = new StringBuilder(256);
            sb.append("{\"phase\":\"call\",\"method\":");
            quote(sb, method);
            sb.append(",\"captured_unix_ms\":").append(System.currentTimeMillis());
            appendTrace(sb);
            sb.append(",\"duration_ms\":").append(durationNanos / 1_000_000.0);
            if (thrown != null) {
                sb.append(",\"error\":");
                quote(sb, exceptionLabel(thrown));
            }
            sb.append(",\"payload\":{\"args\":[");
            if (args != null) {
                for (int i = 0; i < args.length; i++) {
                    if (i > 0) sb.append(',');
                    render(sb, args[i], 0, names == null ? null : names[i]);
                }
            }
            sb.append(']');
            if (names != null && names.length > 0) {
                sb.append(",\"arg_names\":[");
                for (int i = 0; i < names.length; i++) {
                    if (i > 0) sb.append(',');
                    quote(sb, names[i]);
                }
                sb.append(']');
            }
            if (thrown == null) {
                sb.append(",\"returned\":");
                render(sb, returned, 0, null);
            }
            sb.append("}}"); // fecha payload + snapshot
            deliver(sb.toString());
        } catch (Throwable ignore) {
            // nunca derruba o app
        }
    }

    /**
     * Exception Replay (Passo 3): chamado automaticamente quando um método sai por
     * exceção. Fotografa os args daquele método + o erro. Não precisa de probe.
     */
    public static void onException(String method, Object[] args, Throwable thrown) {
        onException(method, args, thrown, null);
    }

    public static void onException(String method, Object[] args, Throwable thrown,
                                   java.lang.reflect.Method reflected) {
        try {
            String[] names = paramNames(reflected, args);
            StringBuilder sb = new StringBuilder(256);
            sb.append("{\"phase\":\"exception\",\"method\":");
            quote(sb, method);
            sb.append(",\"captured_unix_ms\":").append(System.currentTimeMillis());
            appendTrace(sb);
            // Mesmo objeto de exceção sobe por vários métodos → mesmo error_id
            // liga os degraus de UM erro (pro "caminho do erro" na tela).
            sb.append(",\"error_id\":");
            quote(sb, Integer.toHexString(System.identityHashCode(thrown)));
            sb.append(",\"error\":");
            quote(sb, exceptionLabel(thrown));
            sb.append(",\"payload\":[");
            if (args != null) {
                for (int i = 0; i < args.length; i++) {
                    if (i > 0) sb.append(',');
                    render(sb, args[i], 0, names == null ? null : names[i]);
                }
            }
            sb.append(']');
            appendArgNames(sb, names);
            sb.append('}');
            deliver(sb.toString());
        } catch (Throwable ignore) {
            // nunca derruba o app
        }
    }

    /** Trace da requisição em que a foto foi tirada, para abrir o snapshot a partir do trace e vice-versa. */
    private static void appendTrace(StringBuilder sb) {
        String[] ids = SpringMvcSecurity.trace();
        if (ids[0] == null || ids[1] == null) return;
        sb.append(",\"trace_id\":");
        quote(sb, ids[0]);
        sb.append(",\"span_id\":");
        quote(sb, ids[1]);
    }

    /** Entrega a foto: enfileira (não-bloqueante). */
    private static void deliver(String snapshotJson) {
        if (!allowByRate()) return; // rate-limit: descarta o excesso, sem bloquear/lançar
        QUEUE.offer(snapshotJson); // descarta silenciosamente se a fila encher
    }

    /**
     * Guarda-corpo 2 — rate-limit: no máximo {@link #MAX_PER_SEC} fotos por
     * segundo no agente inteiro. Janela de 1s; ao virar o segundo, zera o
     * contador. Nunca bloqueia nem lança. Excesso é descartado em silêncio
     * (com um aviso de 1 linha no máximo a cada ~5s).
     */
    private static boolean allowByRate() {
        try {
            if (MAX_PER_SEC <= 0) return true; // 0/negativo = sem limite
            long nowSec = System.currentTimeMillis() / 1000L;
            long win = RL_WINDOW.get();
            if (nowSec != win && RL_WINDOW.compareAndSet(win, nowSec)) {
                RL_COUNT.set(0); // virou o segundo → nova janela
            }
            if (RL_COUNT.incrementAndGet() <= MAX_PER_SEC) {
                return true;
            }
            // estourou o teto: conta o drop e, no máximo a cada ~5s, avisa 1 linha
            int dropped = RL_DROPPED.incrementAndGet();
            long nowMs = System.currentTimeMillis();
            long last = RL_LAST_LOG.get();
            if (nowMs - last >= 5000L && RL_LAST_LOG.compareAndSet(last, nowMs)) {
                int n = RL_DROPPED.getAndSet(0);
                System.err.println("[telvyn-debugger] rate-limit: dropped " + n);
            }
            return false;
        } catch (Throwable t) {
            return true; // se a contabilidade falhar, não engole a foto
        }
    }

    // ---- envio em lote (thread de fundo) ----------------------------------

    private static void senderLoop() {
        List<String> batch = new ArrayList<>(BATCH_MAX);
        while (true) {
            try {
                String first = QUEUE.poll(2, TimeUnit.SECONDS);
                if (first == null) continue;
                batch.clear();
                batch.add(first);
                QUEUE.drainTo(batch, BATCH_MAX - 1);
                send(batch);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                return;
            } catch (Throwable t) {
                System.err.println("[telvyn-debugger] envio falhou: " + t);
            }
        }
    }

    /** Drena e envia o que sobrou (chamado no shutdown hook). */
    private static void flushRemaining() {
        try {
            List<String> batch = new ArrayList<>(BATCH_MAX);
            while (QUEUE.drainTo(batch, BATCH_MAX) > 0) {
                send(batch);
                batch.clear();
            }
        } catch (Throwable ignore) {
            // shutdown best-effort
        }
    }

    private static void send(List<String> snapshots) throws Exception {
        StringBuilder sb = new StringBuilder(512);
        sb.append("{\"service\":");
        quote(sb, SERVICE);
        sb.append(",\"host\":");
        quote(sb, HOST);
        sb.append(",\"environment\":").append(new com.google.gson.Gson().toJson(ProbeMetricSink.environment()));
        sb.append(",\"service_version\":").append(new com.google.gson.Gson().toJson(ProbeMetricSink.version()));
        sb.append(",\"snapshots\":[");
        for (int i = 0; i < snapshots.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(snapshots.get(i));
        }
        sb.append("]}");
        CollectorHttp.post(URL, sb.toString(), 10000);
    }

    // ---- render seguro ----------------------------------------------------

    private static void render(StringBuilder sb, Object v, int depth) {
        render(sb, v, depth, null);
    }

    /**
     * Render seguro com redação. {@code keyHint} é o nome da chave/campo/parâmetro
     * sob o qual este valor aparece (ou null) — se for sensível, o valor inteiro
     * vira {@link #REDACTED}, qualquer que seja o conteúdo. Strings também passam
     * por redação por PADRÃO de valor (cartão, JWT, Bearer, CPF, segredo opaco).
     */
    private static void render(StringBuilder sb, Object v, int depth, String keyHint) {
        if (v == null) { sb.append("null"); return; }

        // Redação por NOME de chave: mascara o valor inteiro, seja qual for.
        if (isSensitiveKey(keyHint)) { quote(sb, REDACTED); return; }

        if (depth >= MAX_DEPTH) { quote(sb, "…(" + v.getClass().getSimpleName() + ")"); return; }

        if (v instanceof String s) { quote(sb, redactValue(cap(s))); return; }
        if (v instanceof Byte || v instanceof Short || v instanceof Integer || v instanceof Long || v instanceof Boolean) { sb.append(v); return; }
        if(v instanceof Double n){sb.append(Double.isFinite(n)?n.toString():"null");return;}
        if(v instanceof Float n){sb.append(Float.isFinite(n)?n.toString():"null");return;}
        if (v instanceof Character) { quote(sb, v.toString()); return; }

        if (v.getClass().isArray()) {
            sb.append('[');
            int len = java.lang.reflect.Array.getLength(v);
            int show = Math.min(len, MAX_COLLECTION);
            for (int i = 0; i < show; i++) {
                if (i > 0) sb.append(',');
                render(sb, java.lang.reflect.Array.get(v, i), depth + 1);
            }
            if (len > show) sb.append(",\"…+").append(len - show).append("\"");
            sb.append(']');
            return;
        }
        if (v instanceof Collection<?> col) {
            sb.append('[');
            int i = 0;
            for (Object e : col) {
                if (i >= MAX_COLLECTION) { sb.append(",\"…+").append(col.size() - MAX_COLLECTION).append("\""); break; }
                if (i > 0) sb.append(',');
                render(sb, e, depth + 1);
                i++;
            }
            sb.append(']');
            return;
        }
        if (v instanceof Map<?, ?> map) {
            sb.append('{');
            int i = 0;
            for (Map.Entry<?, ?> e : map.entrySet()) {
                if (i >= MAX_COLLECTION) break;
                if (i > 0) sb.append(',');
                String key = e.getKey() instanceof String text ? text : e.getKey()==null ? "null" : "["+e.getKey().getClass().getSimpleName()+"]";
                quote(sb, cap(key));
                sb.append(':');
                render(sb, e.getValue(), depth + 1, key); // chave sensível → valor mascarado
                i++;
            }
            sb.append('}');
            return;
        }

        quote(sb, "["+v.getClass().getName()+"]");
    }

    // ---- Item 3: nomes de parâmetro ---------------------------------------

    /**
     * Extrai os nomes reais dos parâmetros via reflection (precisa de {@code
     * -parameters} na compilação do app-alvo). Retorna null se indisponível ou
     * se a contagem não bate com os args (varargs/synthetic etc.). Defensivo:
     * qualquer falha → null (cai no modo posicional de sempre).
     */
    private static String[] paramNames(java.lang.reflect.Method reflected, Object[] args) {
        try {
            if (reflected == null || args == null) return null;
            java.lang.reflect.Parameter[] ps = reflected.getParameters();
            if (ps.length != args.length) return null;
            String[] names = new String[ps.length];
            for (int i = 0; i < ps.length; i++) {
                String n = ps[i].getName();
                names[i] = (n == null || n.isEmpty()) ? ("arg" + i) : n;
            }
            return names;
        } catch (Throwable t) {
            return null;
        }
    }

    /** Adiciona o array opcional "arg_names" (não altera o "payload" posicional). */
    private static void appendArgNames(StringBuilder sb, String[] names) {
        try {
            if (names == null || names.length == 0) return;
            sb.append(",\"arg_names\":[");
            for (int i = 0; i < names.length; i++) {
                if (i > 0) sb.append(',');
                quote(sb, names[i]);
            }
            sb.append(']');
        } catch (Throwable ignore) {
            // nunca derruba a foto
        }
    }

    // ---- Guarda-corpo 1: redação ------------------------------------------

    /** True se o nome da chave (case-insensitive) contém algum termo sensível. */
    private static boolean isSensitiveKey(String key) {
        try {
            if (key == null || key.isEmpty()) return false;
            String k = key.toLowerCase();
            for (String s : SENSITIVE_KEYS) {
                if (k.contains(s)) return true;
            }
            return false;
        } catch (Throwable t) {
            return true; // falha fecha a redação, nunca revela o original
        }
    }

    /**
     * Mascara um VALOR string que parece segredo (cartão, JWT, Bearer/Basic, CPF,
     * segredo opaco longo). Se casar qualquer padrão, devolve {@link #REDACTED}
     * (mascara o valor inteiro — mais seguro que tentar redigir só o trecho).
     * Defensivo: qualquer erro mascara o valor inteiro.
     */
    private static String redactValue(String s) {
        try {
            if (s == null || s.isEmpty()) return s;
            if (P_AUTH.matcher(s).find()) return REDACTED;
            if (P_NAMED_SECRET.matcher(s).find()) return REDACTED;
            if (P_JWT.matcher(s).find()) return REDACTED;
            if (P_CPF.matcher(s).find()) return REDACTED;
            if (looksLikeCard(s)) return REDACTED;
            if (P_OPAQUE.matcher(s).find()) return REDACTED;
            return s;
        } catch (Throwable t) {
            return REDACTED;
        }
    }
    public static void onLine(String method,int line,String[] names,Object[] values,boolean localsAvailable){
        try{
            String target=method+"@"+line;ProbeApplicationStatus.called(target);
            if(!ProbePolicies.observe(target,null,null,null,0))return;
            var sb=new StringBuilder(256);sb.append("{\"phase\":\"line\",\"method\":");quote(sb,method);sb.append(",\"captured_unix_ms\":").append(System.currentTimeMillis());sb.append(",\"payload\":{\"source_line\":").append(line).append(",\"locals_available\":").append(localsAvailable).append(",\"locals\":{");
            for(int i=0;i<Math.min(10,Math.min(names.length,values.length));i++){if(i>0)sb.append(',');quote(sb,names[i]);sb.append(':');render(sb,values[i],0,names[i]);}
            sb.append("}}}");deliver(sb.toString());
        }catch(Throwable ignored){}
    }

    /**
     * Cartão = 13–19 dígitos (com espaços/hífens opcionais). Conferimos a
     * contagem de dígitos pra não mascarar números curtos (ex.: um valor inteiro).
     */
    private static boolean looksLikeCard(String s) {
        try {
            java.util.regex.Matcher m = P_CARD.matcher(s);
            while (m.find()) {
                int digits = 0;
                String g = m.group();
                for (int i = 0; i < g.length(); i++) if (Character.isDigit(g.charAt(i))) digits++;
                if (digits >= 13 && digits <= 19) return true;
            }
            return false;
        } catch (Throwable t) {
            return true;
        }
    }

    static String exceptionLabel(Throwable thrown) {
        try { return thrown.getClass().getName()+": "+redactValue(cap(thrown.getMessage())); }
        catch(Throwable failure){return REDACTED;}
    }

    private static String cap(String s) {
        if (s == null) return "null";
        return s.length() <= MAX_STRING ? s : s.substring(0, MAX_STRING) + "…";
    }

    private static void quote(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        sb.append('"');
    }

    // ---- config helpers ---------------------------------------------------

    private static String hostname() {
        try {
            return java.net.InetAddress.getLocalHost().getHostName();
        } catch (Throwable t) {
            return "unknown";
        }
    }

    private static String prop(String k) { return blankToNull(System.getProperty(k)); }
    private static String env(String k) { return blankToNull(System.getenv(k)); }
    private static String blankToNull(String s) { return (s == null || s.isBlank()) ? null : s.trim(); }

    private static String firstNonBlank(String... vs) {
        for (String v : vs) if (v != null && !v.isBlank()) return v;
        return null;
    }

    private static int parsePositiveInt(String s, int dflt) {
        try {
            if (s == null || s.isBlank()) return dflt;
            int v = Integer.parseInt(s.trim());
            return v >= 0 ? v : dflt; // 0 = sem limite; negativo cai no default
        } catch (Throwable t) {
            return dflt;
        }
    }
}
