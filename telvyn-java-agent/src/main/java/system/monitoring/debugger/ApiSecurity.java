package system.monitoring.debugger;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Supplier;

/**
 * API Security: no fim da requisição, numa amostra por método, rota e status a cada 30 segundos, o
 * WAF extrai o esquema do endpoint — tipos dos cabeçalhos, query, parâmetros de rota, corpo e cabeçalhos da resposta,
 * com dados sensíveis e credenciais marcados pelos scanners — e o agente envia ao coletor. Nunca os valores.
 */
final class ApiSecurity {
    static final long SAMPLE_MS = 30_000;
    private static final Map<String, Long> SAMPLED = new LinkedHashMap<>(256, 0.75f, true) {
        @Override protected boolean removeEldestEntry(Map.Entry<String, Long> eldest) { return size() > 4096; }
    };
    private static volatile LocalAttackReporter reporter;

    private ApiSecurity() {}

    private static synchronized boolean sample(String key) {
        long now = System.currentTimeMillis();
        Long last = SAMPLED.get(key);
        if (last != null && last > now - SAMPLE_MS) return false;
        SAMPLED.put(key, now);
        return true;
    }

    private static LocalAttackReporter reporter() {
        var current = reporter;
        if (current != null) return current;
        synchronized (ApiSecurity.class) {
            if (reporter == null) reporter = new LocalAttackReporter(Collector.url() + "/v1/security/api", SnapshotSink.service(), SnapshotSink.host(), ProbeMetricSink.environment(), ProbeMetricSink.version(), null);
            return reporter;
        }
    }

    /**
     * Fim da requisição: status da resposta inspecionado e, na amostra, o esquema extraído e enviado.
     * headers: cabeçalhos da resposta (só lidos na amostra).
     */
    static void finish(WafInspector.State state, Object status, Supplier<Map<String, Object>> headers, LocalAttackReporter attacks) {
        if (state == null || state.blocked || attacks == null) return;
        String code = String.valueOf(status);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("server.response.status", code);
        boolean schema = sample(state.method + " " + (state.route != null ? state.route : state.path) + " " + code);
        if (schema) {
            try {
                Map<String, Object> response = headers == null ? null : headers.get();
                if (response != null && !response.isEmpty()) data.put("server.response.headers.no_cookies", response);
            } catch (RuntimeException unavailable) { /* sem cabeçalhos da resposta */ }
            data.put("waf.context.processor", Map.of("extract-schema", true));
        }
        state.derivatives = null;
        SpringMvcSecurity.decide(state, WafInspector.run(state, data), attacks);
        if (!schema || state.derivatives == null) return;
        Map<String, Object> schemas = new LinkedHashMap<>();
        for (var entry : state.derivatives.entrySet())
            if (entry.getKey().startsWith("schema.")) schemas.put(entry.getKey().substring("schema.".length()), entry.getValue());
        if (!schemas.isEmpty()) reporter().reportApi(state.method, state.route != null ? state.route : state.path, code, schemas);
    }

    /** Cabeçalhos de um mapa nome → valor(es) (WebFlux, Vert.x, Netty), sem set-cookie. */
    static Map<String, Object> headers(Iterable<?> entries) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Object item : entries) {
            if (!(item instanceof Map.Entry<?, ?> entry)) continue;
            String name = String.valueOf(entry.getKey()).toLowerCase(Locale.ROOT);
            if ("set-cookie".equals(name)) continue;
            Object value = entry.getValue() instanceof List<?> list && list.size() == 1 ? list.get(0) : entry.getValue();
            out.merge(name, String.valueOf(value), (a, b) -> {
                List<Object> list = new ArrayList<>(a instanceof List<?> previous ? previous : List.of(a));
                list.add(b);
                return list;
            });
        }
        return out;
    }

    /** Cabeçalhos da resposta do servlet ou do Grizzly (getHeaderNames + getHeaders/getHeaderValues). */
    static Map<String, Object> servletHeaders(Object response) {
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            Object names = JavaProtection.call(response, "getHeaderNames", new Class<?>[]{});
            Iterable<?> all = names instanceof Iterable<?> iterable ? iterable : names instanceof Object[] array ? List.of(array) : List.of();
            for (Object name : all) {
                String key = String.valueOf(name).toLowerCase(Locale.ROOT);
                if ("set-cookie".equals(key)) continue;
                Object values;
                try { values = JavaProtection.call(response, "getHeaders", new Class<?>[]{String.class}, String.valueOf(name)); }
                catch (NoSuchMethodException grizzly) { values = JavaProtection.call(response, "getHeaderValues", new Class<?>[]{String.class}, String.valueOf(name)); }
                List<String> list = new ArrayList<>();
                if (values instanceof Iterable<?> iterable) for (Object value : iterable) list.add(String.valueOf(value));
                else if (values instanceof Object[] array) for (Object value : array) list.add(String.valueOf(value));
                out.put(key, list.size() == 1 ? list.get(0) : list);
            }
        } catch (ReflectiveOperationException | RuntimeException unavailable) { /* sem cabeçalhos */ }
        return out;
    }
}
