package system.monitoring.debugger;

import java.util.List;
import java.util.Map;
import system.monitoring.debugger.waf.Engine;
import system.monitoring.debugger.waf.Values;

/**
 * Ponte entre os sensores e o motor do WAF do Telvyn ({@link Engine}, Java puro). Mantém o contrato usado pelos
 * sensores: resultado ("ok", "match", "error", "timeout"), eventos em JSON (regra, endereço e chave; sem valores) e
 * os atributos da execução (esquemas da API Security).
 */
final class WafEngines {
    private WafEngines() {}

    /** Motor com as regras (expected > 0: número exato de regras carregadas). */
    static Object build(Map<String, Object> rules, String name, int expected) {
        Engine engine = Engine.load(rules);
        if (expected > 0 && engine.size() != expected) throw new IllegalStateException("invalid WAF rules: " + name);
        return engine;
    }

    static String version() { return Engine.VERSION; }

    static Object open(Object handle) { return ((Engine) handle).open(); }

    /** {resultado, eventos em JSON ou null, atributos}. limits: profundidade, elementos, texto, tempo do WAF, tempo total (µs). */
    static Object[] run(Object context, Map<String, Object> data, int[] limits) { return run(context, data, limits, false); }

    static Object[] run(Object context, Map<String, Object> data, int[] limits, boolean ephemeral) {
        try {
            var result = ((Engine.Context) context).run(data, new Values.Limits(limits[0], limits[1], limits[2]), Math.min(limits[3], limits[4]), ephemeral);
            List<Map<String, Object>> events = result.events();
            String json = events.isEmpty() ? null : GSON.toJson(events);
            // Estourou o tempo depois de achar: o que achou vale (o resto da requisição não foi visto).
            if ("timeout".equals(result.outcome())) return json == null ? new Object[]{"timeout", null} : new Object[]{"match", json, null};
            return new Object[]{json == null ? "ok" : "match", json, result.attributes()};
        } catch (RuntimeException | LinkageError failure) {
            logFailure(failure);
            return new Object[]{"error", null};
        }
    }

    private static final com.google.gson.Gson GSON = new com.google.gson.Gson();

    /** Uma linha por tipo de falha do motor e no máximo uma por minuto: o resultado "error" não diz o motivo. */
    private static final java.util.concurrent.ConcurrentHashMap<String, Long> LOGGED = new java.util.concurrent.ConcurrentHashMap<>();

    private static void logFailure(Throwable failure) {
        String type = failure.getClass().getName();
        long now = System.currentTimeMillis();
        Long last = LOGGED.get(type);
        if (last != null && now - last < 60_000) return;
        LOGGED.put(type, now);
        System.err.println("[telvyn] WAF analysis failed: " + type + (failure.getMessage() == null ? "" : " (" + failure.getMessage() + ")"));
    }

    static void close(Object resource) { /* o motor e o contexto são objetos Java: o coletor de lixo libera */ }
}
