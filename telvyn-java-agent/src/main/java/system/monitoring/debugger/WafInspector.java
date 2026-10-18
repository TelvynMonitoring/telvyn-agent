package system.monitoring.debugger;

import com.datadog.ddwaf.Waf;
import com.datadog.ddwaf.WafBuilder;
import com.datadog.ddwaf.WafContext;
import com.datadog.ddwaf.WafHandle;
import com.datadog.ddwaf.WafMetrics;
import com.datadog.ddwaf.exception.TimeoutWafException;
import com.google.gson.Gson;
import com.google.gson.JsonParser;

import java.io.InputStreamReader;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Detecção de ataques como o Datadog App and API Protection: o conjunto recomendado de regras do Datadog
 * (/telvyn/waf-rules.json) sobre toda requisição, num contexto de WAF por requisição alimentado por fases
 * (início, rota, corpo, resposta). Reporta a regra e onde ela encontrou o ataque (endereço e chave),
 * nunca o valor recebido.
 */
public final class WafInspector {
    public static final String RULES_VERSION;
    private static final Map<String, Object> RULES;
    private static volatile WafHandle handle;
    private static volatile String engine;
    private static final Waf.Limits LIMITS = new Waf.Limits(20, 256, 4096, 10000, 10000);

    static {
        Map<String, Object> rules;
        try (var stream = WafInspector.class.getResourceAsStream("/telvyn/waf-rules.json")) {
            if (stream == null) throw new IllegalStateException("missing WAF rules");
            @SuppressWarnings("unchecked") Map<String, Object> parsed = new Gson().fromJson(new InputStreamReader(stream, StandardCharsets.UTF_8), Map.class);
            rules = parsed;
        } catch (Exception failure) { throw new IllegalStateException("WAF rules unavailable", failure); }
        RULES = rules;
        @SuppressWarnings("unchecked") var metadata = (Map<String, Object>) rules.get("metadata");
        RULES_VERSION = "datadog-" + metadata.get("rules_version");
    }

    private WafInspector() {}

    static synchronized WafHandle engine() throws Exception {
        if (handle != null) return handle;
        Waf.initialize(false);
        var builder = new WafBuilder();
        try {
            var diagnostics = builder.addOrUpdateConfig("telvyn-recommended", RULES);
            if (diagnostics.getNumConfigError() != 0 || diagnostics.rules.getLoaded().isEmpty()) throw new IllegalStateException("invalid WAF rules");
            handle = builder.buildWafHandleInstance();
            engine = Waf.getVersion();
            return handle;
        } finally { builder.close(); }
    }

    static String engineVersion() { return engine; }

    /** Estado de uma requisição: contexto do WAF, identidade da requisição e o que já foi reportado. */
    static final class State {
        final WafContext context;
        final String ip, method, path, userAgent;
        final String[] trace;
        final Set<String> reported = new LinkedHashSet<>();
        String user;
        boolean blocked, closed, routeInspected, bodyInspected, timeoutReported;
        /** Chamadas aninhadas da mesma requisição (cadeia de filtros, servlet, DispatcherServlet): fecha na última. */
        int depth = 1;
        State(WafContext context, String ip, String method, String path, String userAgent, String[] trace) {
            this.context = context; this.ip = ip; this.method = method; this.path = path; this.userAgent = userAgent; this.trace = trace;
        }
    }

    record Match(String rule, String address) {}
    record Evaluation(String outcome, List<Match> matches, long elapsedUs) {}

    static State open(String ip, String method, String path, String userAgent, String[] trace) throws Exception {
        return new State(new WafContext(engine()), ip, method, path, userAgent, trace);
    }

    /** Roda uma fase no contexto da requisição; devolve só as regras novas (sem as desligadas). */
    static Evaluation run(State state, Map<String, Object> data) {
        synchronized (state) { return runLocked(state, data); }
    }

    private static Evaluation runLocked(State state, Map<String, Object> data) {
        long start = System.nanoTime();
        if (state.closed || data.isEmpty()) return new Evaluation("no_match", List.of(), 0);
        try {
            var result = state.context.run(data, LIMITS, new WafMetrics());
            long elapsed = (System.nanoTime() - start) / 1000;
            if (result.result == Waf.Result.OK) return new Evaluation("no_match", List.of(), elapsed);
            if (result.result != Waf.Result.MATCH) return new Evaluation("error", List.of(), elapsed);
            List<Match> matches = new ArrayList<>();
            // Os dados de match trazem o valor recebido: só a regra, o endereço e a chave saem daqui.
            for (var item : JsonParser.parseString(result.data).getAsJsonArray()) {
                var event = item.getAsJsonObject();
                String rule = event.getAsJsonObject("rule").get("id").getAsString();
                if (state.reported.contains(rule) || "disabled".equals(JavaProtection.ruleMode(rule))) continue;
                state.reported.add(rule);
                String address = null;
                var ruleMatches = event.getAsJsonArray("rule_matches");
                if (ruleMatches != null && !ruleMatches.isEmpty()) {
                    var parameters = ruleMatches.get(0).getAsJsonObject().getAsJsonArray("parameters");
                    if (parameters != null && !parameters.isEmpty()) {
                        var parameter = parameters.get(0).getAsJsonObject();
                        address = parameter.get("address").getAsString();
                        List<String> keys = new ArrayList<>();
                        if (parameter.has("key_path")) for (var key : parameter.getAsJsonArray("key_path")) keys.add(key.getAsString());
                        String key = String.join(".", keys).replaceAll("\\p{Cntrl}", "");
                        if (!key.isEmpty()) address = address + ":" + (key.length() > 200 ? key.substring(0, 200) : key);
                    }
                }
                matches.add(new Match(rule, address));
            }
            return new Evaluation(matches.isEmpty() ? "no_match" : "match", matches, elapsed);
        } catch (TimeoutWafException timeout) {
            return new Evaluation("timeout", List.of(), (System.nanoTime() - start) / 1000);
        } catch (Exception | LinkageError failure) {
            return new Evaluation("error", List.of(), (System.nanoTime() - start) / 1000);
        }
    }

    static void close(State state) {
        synchronized (state) {
            if (state.closed) return;
            state.closed = true;
            try { state.context.close(); } catch (RuntimeException ignored) { /* contexto já liberado */ }
        }
    }

    // ---- Leitura da requisição do servlet (javax ou jakarta), por reflexão --------------------------------------

    static Map<String, Object> requestStart(Object request) throws ReflectiveOperationException {
        var type = request.getClass();
        Map<String, Object> data = new LinkedHashMap<>();
        Map<String, Object> headers = new LinkedHashMap<>();
        var names = (Enumeration<?>) type.getMethod("getHeaderNames").invoke(request);
        var getHeaders = type.getMethod("getHeaders", String.class);
        while (names != null && names.hasMoreElements()) {
            String name = String.valueOf(names.nextElement()).toLowerCase(java.util.Locale.ROOT);
            if ("cookie".equals(name)) continue;
            List<String> values = new ArrayList<>();
            var all = (Enumeration<?>) getHeaders.invoke(request, name);
            while (all != null && all.hasMoreElements()) values.add(String.valueOf(all.nextElement()));
            headers.put(name, values.size() == 1 ? values.get(0) : values);
        }
        data.put("server.request.headers.no_cookies", headers);
        Object cookies = type.getMethod("getCookies").invoke(request);
        if (cookies != null && Array.getLength(cookies) > 0) {
            Map<String, Object> jar = new LinkedHashMap<>();
            for (int i = 0; i < Array.getLength(cookies); i++) {
                Object cookie = Array.get(cookies, i);
                jar.put((String) cookie.getClass().getMethod("getName").invoke(cookie), cookie.getClass().getMethod("getValue").invoke(cookie));
            }
            data.put("server.request.cookies", jar);
        }
        String query = (String) type.getMethod("getQueryString").invoke(request);
        data.put("server.request.query", parseQuery(query));
        String uri = (String) type.getMethod("getRequestURI").invoke(request);
        data.put("server.request.uri.raw", query == null ? uri : uri + "?" + query);
        data.put("server.request.method", type.getMethod("getMethod").invoke(request));
        return data;
    }

    /** Query a partir do texto bruto, sem ler o corpo (getParameterMap leria um formulário). */
    static Map<String, List<String>> parseQuery(String raw) {
        Map<String, List<String>> out = new LinkedHashMap<>();
        if (raw == null || raw.isEmpty()) return out;
        for (String pair : raw.split("&")) {
            if (pair.isEmpty()) continue;
            int split = pair.indexOf('=');
            try {
                String key = URLDecoder.decode(split < 0 ? pair : pair.substring(0, split), StandardCharsets.UTF_8);
                String value = split < 0 ? "" : URLDecoder.decode(pair.substring(split + 1), StandardCharsets.UTF_8);
                out.computeIfAbsent(key, k -> new ArrayList<>()).add(value);
            } catch (IllegalArgumentException malformed) {
                out.computeIfAbsent(pair, k -> new ArrayList<>()).add("");
            }
        }
        return out;
    }

    /** Objeto do corpo (DTO, Map, lista) em estrutura simples para o WAF, com limite de profundidade e tamanho. */
    static Object introspect(Object value) { return introspect(value, 0, new int[]{0}, new IdentityHashMap<>()); }

    private static Object introspect(Object value, int depth, int[] count, IdentityHashMap<Object, Boolean> seen) {
        if (value == null || depth > 20 || ++count[0] > 256) return null;
        if (value instanceof CharSequence text) return text.length() > 4096 ? text.subSequence(0, 4096).toString() : text.toString();
        if (value instanceof Number || value instanceof Boolean) return value;
        if (value instanceof Character || value instanceof Enum<?>) return value.toString();
        if (seen.put(value, Boolean.TRUE) != null) return null;
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (var entry : map.entrySet()) { if (count[0] > 256) break; out.put(String.valueOf(entry.getKey()), introspect(entry.getValue(), depth + 1, count, seen)); }
            return out;
        }
        if (value instanceof Collection<?> collection) {
            List<Object> out = new ArrayList<>();
            for (Object item : collection) { if (count[0] > 256) break; out.add(introspect(item, depth + 1, count, seen)); }
            return out;
        }
        if (value.getClass().isArray()) {
            List<Object> out = new ArrayList<>();
            for (int i = 0; i < Array.getLength(value) && count[0] <= 256; i++) out.add(introspect(Array.get(value, i), depth + 1, count, seen));
            return out;
        }
        String name = value.getClass().getName();
        // JSON do Vert.x: o conteúdo, não os campos internos.
        // Formulário do JAX-RS (Form): os campos.
        if (name.equals("jakarta.ws.rs.core.Form") || name.equals("javax.ws.rs.core.Form")) {
            try { return introspect(value.getClass().getMethod("asMap").invoke(value), depth, count, seen); }
            catch (ReflectiveOperationException | RuntimeException unavailable) { return value.toString(); }
        }
        if (name.equals("io.vertx.core.json.JsonObject") || name.equals("io.vertx.core.json.JsonArray")) {
            try { return introspect(value.getClass().getMethod(name.endsWith("Object") ? "getMap" : "getList").invoke(value), depth, count, seen); }
            catch (ReflectiveOperationException | RuntimeException unavailable) { return value.toString(); }
        }
        if (name.startsWith("java.") || name.startsWith("javax.") || name.startsWith("jakarta.") || name.startsWith("sun.")) return value.toString();
        Map<String, Object> out = new LinkedHashMap<>();
        for (Class<?> type = value.getClass(); type != null && type != Object.class; type = type.getSuperclass()) {
            for (Field field : type.getDeclaredFields()) {
                if (Modifier.isStatic(field.getModifiers()) || field.isSynthetic() || count[0] > 256) continue;
                try { field.setAccessible(true); out.put(field.getName(), introspect(field.get(value), depth + 1, count, seen)); }
                catch (RuntimeException | IllegalAccessException inaccessible) { /* campo inacessível é ignorado */ }
            }
        }
        return out;
    }
}
