package system.monitoring.debugger.wafengine;

import com.datadog.ddwaf.Waf;
import com.datadog.ddwaf.WafBuilder;
import com.datadog.ddwaf.WafContext;
import com.datadog.ddwaf.WafHandle;
import com.datadog.ddwaf.WafMetrics;
import com.datadog.ddwaf.exception.TimeoutWafException;
import java.util.Map;

/**
 * Ponte para o motor do WAF (libddwaf), carregada num class loader isolado do classpath da aplicação (ver
 * {@code WafEngines}). Só tipos do JDK atravessam a fronteira. Não referencia nenhuma outra classe do agente.
 */
public final class WafEngine {
    private static boolean initialized;

    private WafEngine() {}

    /** Motor com as regras; expected > 0 exige exatamente esse número de regras carregadas. */
    public static synchronized Object build(Map<String, Object> rules, String name, int expected) throws Exception {
        if (!initialized) { Waf.initialize(false); initialized = true; }
        var builder = new WafBuilder();
        try {
            var diagnostics = builder.addOrUpdateConfig(name, rules);
            int loaded = diagnostics.rules.getLoaded().size();
            if (diagnostics.getNumConfigError() != 0 || loaded == 0 || expected > 0 && loaded != expected) throw new IllegalStateException("invalid WAF rules");
            return builder.buildWafHandleInstance();
        } finally { builder.close(); }
    }

    public static String version() { return Waf.getVersion(); }

    public static Object open(Object handle) { return new WafContext((WafHandle) handle); }

    /** {resultado ("ok", "match", "error", "timeout"), dados do match em JSON ou null}. limits: profundidade, elementos, texto, tempo do WAF, tempo total (µs). */
    public static Object[] run(Object context, Map<String, Object> data, int[] limits) { return run(context, data, limits, false); }

    /** ephemeral: dados de uma operação (exploit prevention), que não ficam no contexto da requisição. */
    public static Object[] run(Object context, Map<String, Object> data, int[] limits, boolean ephemeral) {
        try {
            var waf = (WafContext) context;
            var bounds = new Waf.Limits(limits[0], limits[1], limits[2], limits[3], limits[4]);
            var result = ephemeral ? waf.runEphemeral(data, bounds, new WafMetrics()) : waf.run(data, bounds, new WafMetrics());
            if (result.result == Waf.Result.OK) return new Object[]{"ok", null};
            if (result.result == Waf.Result.MATCH) return new Object[]{"match", result.data};
            return new Object[]{"error", null};
        } catch (TimeoutWafException timeout) {
            return new Object[]{"timeout", null};
        } catch (Exception | LinkageError failure) {
            return new Object[]{"error", null};
        }
    }

    public static void close(Object resource) throws Exception { ((AutoCloseable) resource).close(); }
}
