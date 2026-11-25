package system.monitoring.debugger;

import com.google.gson.JsonObject;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Evidência de um ataque: o valor que casou, a consulta e alguns cabeçalhos da requisição.
 * A redação acontece aqui, antes de qualquer dado sair da aplicação; o backend valida e redige de novo pela mesma regra
 * (mesma lista de campos sensíveis e de padrões que o agent Node).
 */
final class AttackEvidence {
    static final int VALUE_MAX = 256, QUERY_MAX = 1024, HEADER_VALUE_MAX = 256;
    static final String REDACTED = "<redacted>";
    private static final Pattern SENSITIVE_KEY = Pattern.compile("(?i)(pass(word|wd|phrase)?|pwd|secret|token|authorization|auth|api[-_]?key|cookie|session|csrf|xsrf|credential|private|signature|otp|cvv|cvc|card|ssn|cpf|cnpj)");
    /** Só estes cabeçalhos são considerados, e mesmo assim os sensíveis ficam de fora. */
    static final List<String> SAFE_HEADERS = List.of("user-agent", "content-type", "content-length", "accept", "accept-language", "referer", "origin", "host", "x-forwarded-for", "x-forwarded-proto", "x-real-ip", "x-request-id");
    private static final Pattern JWT = Pattern.compile("eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]*");
    private static final Pattern BEARER = Pattern.compile("(?i)\\bbearer\\s+[A-Za-z0-9._~+/=-]{8,}");
    private static final Pattern AWS_KEY = Pattern.compile("\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b");
    private static final Pattern CARD = Pattern.compile("(?<![\\d])(?:\\d[ -]?){12,18}\\d(?![\\d])");
    private static final Pattern CONTROL = Pattern.compile("[\\p{Cntrl}&&[^\\n\\r\\t]]");

    private AttackEvidence() {}

    /** Ligado por padrão; TELVYN_SECURITY_EVIDENCE=false ou a configuração remota do serviço desligam. */
    static boolean enabled() {
        String local = System.getProperty("telvyn.security.evidence", System.getenv("TELVYN_SECURITY_EVIDENCE"));
        return !"false".equalsIgnoreCase(local) && !Boolean.FALSE.equals(RemoteConfig.security("evidence"));
    }

    /** Cabeçalhos permitidos de um mapa de cabeçalhos do WAF (nomes em minúsculas; valor texto ou lista). */
    static Map<String, String> safeHeaders(Object headers) {
        Map<String, String> out = new LinkedHashMap<>();
        if (!(headers instanceof Map<?, ?> map)) return out;
        for (String name : SAFE_HEADERS) {
            Object raw = map.get(name);
            if (raw == null || SENSITIVE_KEY.matcher(name).find() || RemoteConfig.excludedHeaders().contains(name)) continue;
            String value = raw instanceof List<?> list ? String.join(", ", list.stream().map(String::valueOf).toList()) : String.valueOf(raw);
            if (value.isEmpty()) continue;
            value = redactValue(clean(value));
            out.put(name, value.length() > HEADER_VALUE_MAX ? value.substring(0, HEADER_VALUE_MAX) : value);
        }
        return out;
    }

    /** Monta a evidência de um match do WAF; devolve null quando não há nada a mostrar. */
    static JsonObject build(String value, String location, String query, Map<String, String> headers) {
        return build(value, location, query, headers, null, false);
    }

    /**
     * highlight: trecho do valor que a regra casou. input: a entrada já é, por definição, da requisição.
     * Sem input, só endereços server.request.* têm valor a mostrar: um match na resposta (server.response.status) não é um payload.
     */
    static JsonObject build(String value, String location, String query, Map<String, String> headers, String highlight, boolean input) {
        JsonObject evidence = new JsonObject();
        if (value != null && (input || location != null && location.startsWith("server.request."))) {
            String text = clean(value);
            boolean truncated = false, redacted = false;
            if (text.length() > VALUE_MAX) { text = text.substring(0, VALUE_MAX); truncated = true; }
            if (sensitiveLocation(location)) { text = REDACTED; redacted = true; }
            else { String cleaned = redactValue(text); if (!cleaned.equals(text)) { text = cleaned; redacted = true; } }
            JsonObject payload = new JsonObject();
            payload.addProperty("value", text); payload.addProperty("truncated", truncated); payload.addProperty("redacted", redacted);
            // Trecho exato que casou: só vale se o valor não foi alterado pela redação e o trecho está nele (sem diferenciar maiúsculas).
            if (!redacted && highlight != null) {
                String fragment = clean(highlight);
                if (fragment.length() > 128) fragment = fragment.substring(0, 128);
                if (!fragment.isBlank() && text.toLowerCase(java.util.Locale.ROOT).contains(fragment.toLowerCase(java.util.Locale.ROOT))) payload.addProperty("highlight", fragment);
            }
            evidence.add("payload", payload);
        }
        String redactedQuery = query == null ? "" : redactQuery(clean(query));
        if (!redactedQuery.isEmpty()) evidence.addProperty("query", redactedQuery);
        if (headers != null && !headers.isEmpty()) {
            JsonObject object = new JsonObject();
            headers.forEach(object::addProperty);
            evidence.add("headers", object);
        }
        return evidence.size() == 0 ? null : evidence;
    }

    /** "server.request.query:password": a parte depois dos dois pontos é o nome do campo; cookies nunca vão. */
    static boolean sensitiveLocation(String location) {
        if (location == null) return false;
        if (location.toLowerCase(java.util.Locale.ROOT).contains("cookie")) return true;
        int colon = location.indexOf(':');
        return colon >= 0 && SENSITIVE_KEY.matcher(location.substring(colon + 1)).find();
    }

    static String redactQuery(String query) {
        StringBuilder out = new StringBuilder();
        for (String pair : query.split("&", -1)) {
            if (pair.isEmpty()) continue;
            int equals = pair.indexOf('=');
            if (equals < 0) { if (out.length() > 0) out.append('&'); out.append(redactValue(pair)); continue; }
            String key = pair.substring(0, equals), decoded;
            try { decoded = URLDecoder.decode(key, StandardCharsets.UTF_8); } catch (IllegalArgumentException invalid) { decoded = key; }
            if (RemoteConfig.excludedParameters().contains(decoded)) continue;
            if (out.length() > 0) out.append('&');
            out.append(key).append('=').append(SENSITIVE_KEY.matcher(decoded).find() ? REDACTED : redactValue(pair.substring(equals + 1)));
        }
        return out.length() > QUERY_MAX ? out.substring(0, QUERY_MAX) : out.toString();
    }

    static String redactValue(String text) {
        String result = JWT.matcher(text).replaceAll(REDACTED);
        result = BEARER.matcher(result).replaceAll(REDACTED);
        result = AWS_KEY.matcher(result).replaceAll(REDACTED);
        Matcher card = CARD.matcher(result);
        StringBuilder out = new StringBuilder();
        while (card.find()) card.appendReplacement(out, Matcher.quoteReplacement(luhn(card.group()) ? REDACTED : card.group()));
        card.appendTail(out);
        return out.toString();
    }

    private static String clean(String text) { return CONTROL.matcher(text).replaceAll("?"); }

    private static boolean luhn(String candidate) {
        int sum = 0; boolean alternate = false, any = false;
        for (int i = candidate.length() - 1; i >= 0; i--) {
            char c = candidate.charAt(i);
            if (c < '0' || c > '9') continue;
            any = true;
            int digit = c - '0';
            if (alternate) { digit *= 2; if (digit > 9) digit -= 9; }
            sum += digit; alternate = !alternate;
        }
        return any && sum % 10 == 0;
    }
}
