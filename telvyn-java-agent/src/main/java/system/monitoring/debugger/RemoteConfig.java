package system.monitoring.debugger;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Configuração remota feita na tela do Telvyn:
 * perfis e segurança por serviço e ambiente, aplicados sem reiniciar. Consulta o coletor a cada
 * 30 s ({@code /v1/sdk/remote-config}). Opção ausente = vale a configuração local da aplicação.
 *
 * <p>O que dá para mudar com a aplicação rodando: ligar/desligar cada perfil e a detecção de
 * ataques. O IAST só pode ser desligado: a instrumentação dele é instalada quando a classe carrega.
 */
public final class RemoteConfig {
    static final Set<String> PROFILING = Set.of("enabled", "alloc", "wall", "lock", "exceptions");
    static final Set<String> SECURITY = Set.of("attack", "iast");
    private static final AtomicBoolean STARTED = new AtomicBoolean();
    private static volatile long revision;
    private static volatile Map<String, Boolean> profiling = Map.of();
    private static volatile Map<String, Boolean> security = Map.of();

    private RemoteConfig() {}

    public static long revision() { return revision; }

    /** Valor definido na tela para a opção de perfil, ou null (vale a local). */
    public static Boolean profiling(String key) { return profiling.get(key); }

    /** Valor definido na tela para a opção de segurança, ou null (vale a local). */
    public static Boolean security(String key) { return security.get(key); }

    /** Se o envio de um tipo de perfil está liberado pela tela. */
    public static boolean profileAllowed(String profileType) {
        if (Boolean.FALSE.equals(profiling.get("enabled"))) return false;
        String key = switch (profileType == null ? "" : profileType) {
            case "alloc" -> "alloc";
            case "lock" -> "lock";
            case "wall", "wall_events" -> "wall";
            case "exceptions" -> "exceptions";
            default -> null;
        };
        return key == null || !Boolean.FALSE.equals(profiling.get(key));
    }

    static void start() {
        if (!STARTED.compareAndSet(false, true)) return;
        Thread thread = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try { poll(); }
                catch (Exception ignored) { /* A configuração remota nunca interrompe a aplicação. */ }
                try { Thread.sleep(30000); } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
            }
        }, "telvyn-remote-config");
        thread.setDaemon(true);
        thread.start();
    }

    private static void poll() throws Exception {
        String url = Collector.url() + "/v1/sdk/remote-config?service=" + encode(SnapshotSink.service())
                + "&env=" + encode(ProbeMetricSink.environment());
        var response = CollectorHttp.get(url, 10000);
        if (response.status() != 200) return;
        JsonObject body = JsonParser.parseString(response.body()).getAsJsonObject();
        long next = body.get("revision").getAsLong();
        // Bloqueio (proteção do tenant e modo das regras) tem revisão própria: aplicado a cada consulta.
        JavaProtection.update(body.has("protection") && body.get("protection").isJsonObject() ? body.getAsJsonObject("protection") : null,
                body.has("rules") && body.get("rules").isJsonObject() ? body.getAsJsonObject("rules") : null);
        if (next == revision) return;
        Map<String, Boolean> nextProfiling = flags(body.getAsJsonObject("profiling"), PROFILING);
        Map<String, Boolean> nextSecurity = flags(body.getAsJsonObject("security"), SECURITY);
        profiling = nextProfiling;
        security = nextSecurity;
        apply(nextProfiling, nextSecurity);
        revision = next;
        System.out.println("[telvyn] configuração remota aplicada (revisão " + next + ")");
    }

    private static void apply(Map<String, Boolean> profiling, Map<String, Boolean> security) {
        // Ligar pela tela inicia o perfil que estava desligado na aplicação; desligar bloqueia o envio.
        if (!Boolean.FALSE.equals(profiling.get("enabled"))) {
            if (Boolean.TRUE.equals(profiling.get("enabled"))) system.monitoring.debugger.profiler.ProfilerControl.startCpu();
            if (Boolean.TRUE.equals(profiling.get("wall"))) system.monitoring.debugger.profiler.ProfilerControl.startWall();
            if (Boolean.TRUE.equals(profiling.get("alloc"))) system.monitoring.debugger.profiler.ProfilerControl.startAlloc();
            if (Boolean.TRUE.equals(profiling.get("lock"))) system.monitoring.debugger.profiler.ProfilerControl.startLock();
            if (Boolean.TRUE.equals(profiling.get("exceptions"))) system.monitoring.debugger.profiler.ProfilerControl.startExceptions();
        }
        Boolean attack = security.get("attack");
        if (attack != null) SpringMvcSecurity.remoteAttack(attack);
    }

    private static Map<String, Boolean> flags(JsonObject object, Set<String> allowed) {
        Map<String, Boolean> out = new ConcurrentHashMap<>();
        if (object == null) return out;
        for (var entry : object.entrySet()) {
            if (allowed.contains(entry.getKey()) && entry.getValue().isJsonPrimitive() && entry.getValue().getAsJsonPrimitive().isBoolean())
                out.put(entry.getKey(), entry.getValue().getAsBoolean());
        }
        return out;
    }

    private static String encode(String value) { return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8); }
}
