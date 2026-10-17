package system.monitoring.debugger;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Bloqueio de ataques definido na tela do Telvyn (como o App and API Protection do Datadog): chave
 * geral "permitir bloqueio", resposta de bloqueio, listas de IPs/CIDR (bloqueio com prazo e
 * liberação) e o modo de cada regra (monitoring, blocking, disabled). O bloqueio exige a detecção de
 * ataques ligada, como no Datadog. Responde pelo objeto de resposta do servlet (javax ou jakarta).
 */
public final class JavaProtection {
    record Range(byte[] network, int prefix, Long expiresAtMs) {}

    private static volatile String revision = "";
    private static volatile boolean allow = true;
    private static volatile int status = 403;
    private static volatile String redirect;
    private static volatile List<Range> deny = List.of(), pass = List.of();
    private static volatile Map<String, String> rules = Map.of();

    private JavaProtection() {}

    static void update(JsonObject protection, JsonObject ruleModes) {
        Map<String, String> modes = new ConcurrentHashMap<>();
        if (ruleModes != null) for (var e : ruleModes.entrySet())
            if (e.getValue().isJsonPrimitive()) modes.put(e.getKey(), e.getValue().getAsString());
        rules = modes;
        if (protection == null || !protection.has("revision")) return;
        String next = protection.get("revision").getAsString();
        if (next.equals(revision)) return;
        allow = !protection.has("allow_blocking") || protection.get("allow_blocking").getAsBoolean();
        JsonObject response = protection.has("response") && protection.get("response").isJsonObject() ? protection.getAsJsonObject("response") : new JsonObject();
        int code = response.has("status") ? response.get("status").getAsInt() : 403;
        status = List.of(200, 403, 404, 301, 302).contains(code) ? code : 403;
        redirect = response.has("redirect_url") && !response.get("redirect_url").isJsonNull() ? response.get("redirect_url").getAsString() : null;
        deny = ranges(protection.get("denylist"));
        pass = ranges(protection.get("passlist"));
        revision = next;
    }

    private static List<Range> ranges(JsonElement list) {
        List<Range> out = new ArrayList<>();
        if (list == null || !list.isJsonArray()) return out;
        for (var item : list.getAsJsonArray()) {
            try {
                var object = item.getAsJsonObject();
                String[] parts = object.get("cidr").getAsString().split("/");
                byte[] address = literal(parts[0]);
                if (address == null) continue;
                int prefix = parts.length > 1 ? Integer.parseInt(parts[1]) : address.length * 8;
                Long expires = object.has("expires_at_ms") && !object.get("expires_at_ms").isJsonNull() ? object.get("expires_at_ms").getAsLong() : null;
                out.add(new Range(address, prefix, expires));
            } catch (RuntimeException invalid) { /* entrada inválida é ignorada */ }
        }
        return List.copyOf(out);
    }

    /** Endereço literal (IPv4 ou IPv6) sem consulta de DNS; null se não for IP. */
    static byte[] literal(String value) {
        if (value == null) return null;
        String ip = value.trim();
        if (ip.startsWith("[") && ip.endsWith("]")) ip = ip.substring(1, ip.length() - 1);
        if (ip.matches("(\\d{1,3}\\.){3}\\d{1,3}")) {
            byte[] out = new byte[4];
            String[] parts = ip.split("\\.");
            for (int i = 0; i < 4; i++) { int octet = Integer.parseInt(parts[i]); if (octet > 255) return null; out[i] = (byte) octet; }
            return out;
        }
        if (!ip.contains(":") || !ip.matches("[0-9A-Fa-f:.]{2,45}")) return null;
        try {
            byte[] address = InetAddress.getByName(ip).getAddress();
            // ::ffff:a.b.c.d é IPv4
            if (address.length == 16) {
                boolean mapped = true;
                for (int i = 0; i < 10; i++) mapped &= address[i] == 0;
                if (mapped && address[10] == (byte) 0xff && address[11] == (byte) 0xff) return new byte[]{address[12], address[13], address[14], address[15]};
            }
            return address;
        } catch (Exception invalid) { return null; }
    }

    private static boolean matches(List<Range> list, byte[] ip) {
        if (ip == null) return false;
        long now = System.currentTimeMillis();
        for (Range range : list) {
            if (range.expiresAtMs() != null && range.expiresAtMs() <= now) continue;
            if (range.network().length != ip.length) continue;
            int bits = range.prefix(), i = 0;
            boolean ok = true;
            while (bits >= 8 && ok) { ok = range.network()[i] == ip[i]; i++; bits -= 8; }
            if (ok && bits > 0) { int mask = 0xff << (8 - bits) & 0xff; ok = (range.network()[i] & mask) == (ip[i] & mask); }
            if (ok) return true;
        }
        return false;
    }

    static boolean allowBlocking() { return allow; }
    static boolean denied(String ip) { byte[] address = literal(ip); return matches(deny, address) && !matches(pass, address); }
    static boolean passed(String ip) { return matches(pass, literal(ip)); }
    /** Modo da regra; sem escolha na tela, a regra só monitora (padrão do Datadog). */
    static String ruleMode(String rule) {
        String mode = rules.get(rule);
        return "blocking".equals(mode) || "disabled".equals(mode) ? mode : "monitoring";
    }
    static boolean anyBlocking() { return rules.containsValue("blocking"); }

    private static final String[] HEADERS = {"x-forwarded-for", "x-real-ip", "true-client-ip", "x-client-ip", "x-forwarded", "forwarded-for",
            "x-cluster-client-ip", "fastly-client-ip", "cf-connecting-ip", "cf-connecting-ipv6"};

    /** IP de origem como o Datadog: o primeiro público nos cabeçalhos de proxy; senão o da conexão. */
    static String clientIp(Object request) {
        String fallback = null;
        try {
            var getHeader = request.getClass().getMethod("getHeader", String.class);
            for (String name : HEADERS) {
                Object header = getHeader.invoke(request, name);
                if (!(header instanceof String value)) continue;
                for (String part : value.split(",")) {
                    String ip = part.trim();
                    if (ip.matches("\\d+\\.\\d+\\.\\d+\\.\\d+:\\d+")) ip = ip.substring(0, ip.indexOf(':'));
                    byte[] address = literal(ip);
                    if (address == null) continue;
                    String normalized = InetAddress.getByAddress(address).getHostAddress();
                    if (!isPrivate(address)) return normalized;
                    if (fallback == null) fallback = normalized;
                }
            }
            if (fallback != null) return fallback;
            Object remote = request.getClass().getMethod("getRemoteAddr").invoke(request);
            byte[] address = remote instanceof String value ? literal(value) : null;
            return address == null ? null : InetAddress.getByAddress(address).getHostAddress();
        } catch (ReflectiveOperationException | RuntimeException | java.net.UnknownHostException unavailable) { return fallback; }
    }

    private static boolean isPrivate(byte[] ip) {
        if (ip.length == 4) {
            int a = ip[0] & 0xff, b = ip[1] & 0xff;
            return a == 10 || a == 127 || a == 172 && b >= 16 && b <= 31 || a == 192 && b == 168 || a == 169 && b == 254 || a == 100 && b >= 64 && b <= 127;
        }
        boolean loopback = true;
        for (int i = 0; i < 15; i++) loopback &= ip[i] == 0;
        return loopback && ip[15] == 1 || (ip[0] & 0xfe) == 0xfc || (ip[0] & 0xff) == 0xfe && (ip[1] & 0xc0) == 0x80;
    }

    private static final String TITLE = "You've been blocked";
    private static final String DETAIL = "Sorry, you cannot access this page. Please contact the customer service team. Security provided by Telvyn.";

    /** Escreve a resposta de bloqueio. Devolve o id da resposta, ou null se não foi possível responder. */
    static String respond(Object request, Object response) {
        String id = UUID.randomUUID().toString();
        try {
            var type = response.getClass();
            if (Boolean.TRUE.equals(type.getMethod("isCommitted").invoke(response))) return null;
            type.getMethod("reset").invoke(response);
            if ((status == 301 || status == 302) && redirect != null) {
                String target = redirect + (redirect.contains("?") ? "&" : "?") + "security_response_id=" + id;
                type.getMethod("setStatus", int.class).invoke(response, status);
                type.getMethod("setHeader", String.class, String.class).invoke(response, "Location", target);
                return id;
            }
            Object accept = request.getClass().getMethod("getHeader", String.class).invoke(request, "Accept");
            boolean html = accept instanceof String value && value.toLowerCase(java.util.Locale.ROOT).contains("text/html");
            String body = html
                    ? "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>" + TITLE + "</title></head><body><h1>" + TITLE + "</h1><p>" + DETAIL + "</p><p>Security Response ID: " + id + "</p></body></html>"
                    : "{\"errors\":[{\"title\":\"" + TITLE + "\",\"detail\":\"" + DETAIL + "\"}],\"security_response_id\":\"" + id + "\"}";
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            type.getMethod("setStatus", int.class).invoke(response, status);
            type.getMethod("setContentType", String.class).invoke(response, html ? "text/html;charset=UTF-8" : "application/json");
            type.getMethod("setContentLength", int.class).invoke(response, bytes.length);
            Object out = type.getMethod("getOutputStream").invoke(response);
            out.getClass().getMethod("write", byte[].class).invoke(out, (Object) bytes);
            type.getMethod("flushBuffer").invoke(response);
            return id;
        } catch (ReflectiveOperationException | RuntimeException failure) { return null; }
    }
}
