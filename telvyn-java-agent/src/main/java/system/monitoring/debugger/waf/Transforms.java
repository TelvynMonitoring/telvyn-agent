package system.monitoring.debugger.waf;

import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.function.UnaryOperator;

/**
 * Transformações aplicadas ao valor antes do operador (decodificação e normalização), na ordem da regra.
 * Cada uma é tolerante: entrada malformada fica como está em vez de falhar a regra.
 */
final class Transforms {
    private Transforms() {}

    /** Transformação pelo nome; null para nome desconhecido (a regra é rejeitada na carga). */
    static UnaryOperator<String> of(String name) {
        return switch (name) {
            case "length" -> value -> String.valueOf(value.length());
            case "lowercase" -> value -> value.toLowerCase(Locale.ROOT);
            case "removeNulls" -> value -> value.indexOf('\0') < 0 ? value : value.replace("\0", "");
            case "urlDecode" -> value -> urlDecode(value, false);
            case "urlDecodeUni" -> value -> urlDecode(value, true);
            case "htmlEntityDecode" -> Transforms::htmlEntityDecode;
            case "jsDecode" -> Transforms::jsDecode;
            case "cssDecode" -> Transforms::cssDecode;
            case "base64Decode" -> Transforms::base64Decode;
            case "compressWhitespace" -> value -> value.replaceAll("[\\s\\x0b]+", " ");
            case "removeWhitespace" -> value -> value.replaceAll("[\\s\\x0b]+", "");
            case "normalizePath" -> value -> normalizePath(value, false);
            case "normalizePathWin" -> value -> normalizePath(value, true);
            case "removeComments" -> value -> comments(value, "");
            case "replaceComments" -> value -> comments(value, " ");
            case "removeCommentsChar" -> value -> value.replace("/*", "").replace("*/", "").replace("--", "").replace("#", "");
            case "cmdLine" -> Transforms::cmdLine;
            case "unicode_normalize" -> value -> Normalizer.normalize(value, Normalizer.Form.NFKC);
            case "escapeSeqDecode" -> Transforms::escapeSeqDecode;
            // Strings Java já são Unicode: as duas são identidade aqui.
            case "utf8toUnicode" -> Transforms::utf8toUnicode;
            case "none" -> value -> value;
            default -> null;
        };
    }

    /** Seleção das chaves ou dos valores dos mapas (não transforma o texto). */
    static boolean selector(String name) { return "keys_only".equals(name) || "values_only".equals(name); }

    static String apply(List<UnaryOperator<String>> chain, String value) {
        for (var step : chain) value = step.apply(value);
        return value;
    }

    static String urlDecode(String value, boolean unicode) {
        if (value.indexOf('%') < 0 && value.indexOf('+') < 0) return value;
        var out = new StringBuilder(value.length());
        var bytes = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '%' && unicode && i + 5 < value.length() && (value.charAt(i + 1) == 'u' || value.charAt(i + 1) == 'U') && hex(value, i + 2, 4) >= 0) {
                flush(bytes, out);
                out.append(fromUnicodeEscape(hex(value, i + 2, 4)));
                i += 5;
            } else if (c == '%' && i + 2 < value.length() && hex(value, i + 1, 2) >= 0) {
                bytes.write(hex(value, i + 1, 2));
                i += 2;
            } else {
                flush(bytes, out);
                out.append(c == '+' ? ' ' : c);
            }
        }
        flush(bytes, out);
        return out.toString();
    }

    /** %uHHHH como o ModSecurity: largura total (FFxx) vira ASCII (xx + 0x20), até 0xFF é o byte, o resto fica como está. */
    private static char fromUnicodeEscape(int code) {
        if ((code & 0xFF00) == 0xFF00) return (char) ((code & 0xFF) + 0x20);
        return (char) code;
    }

    /** Cada caractere fora do ASCII vira %uHHHH (a transformação urlDecodeUni que vem depois o reduz). */
    static String utf8toUnicode(String value) {
        boolean ascii = true;
        for (int i = 0; i < value.length() && ascii; i++) ascii = value.charAt(i) < 0x80;
        if (ascii) return value;
        var out = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x80) out.append(c); else out.append(String.format("%%u%04x", (int) c));
        }
        return out.toString();
    }

    private static void flush(java.io.ByteArrayOutputStream bytes, StringBuilder out) {
        if (bytes.size() == 0) return;
        out.append(bytes.toString(StandardCharsets.UTF_8));
        bytes.reset();
    }

    private static int hex(String value, int from, int length) {
        if (from + length > value.length()) return -1;
        int result = 0;
        for (int i = from; i < from + length; i++) {
            int digit = Character.digit(value.charAt(i), 16);
            if (digit < 0) return -1;
            result = result * 16 + digit;
        }
        return result;
    }

    static String htmlEntityDecode(String value) {
        if (value.indexOf('&') < 0) return value;
        var out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c != '&') { out.append(c); continue; }
            int end = i + 1;
            while (end < value.length() && end - i <= 10 && (Character.isLetterOrDigit(value.charAt(end)) || value.charAt(end) == '#')) end++;
            String entity = value.substring(i + 1, end);
            int code = entity(entity);
            if (code < 0) { out.append(c); continue; }
            out.appendCodePoint(code);
            i = end < value.length() && value.charAt(end) == ';' ? end : end - 1;
        }
        return out.toString();
    }

    private static int entity(String entity) {
        try {
            if (entity.startsWith("#x") || entity.startsWith("#X")) return entity.length() > 2 ? Integer.parseInt(entity.substring(2), 16) : -1;
            if (entity.startsWith("#")) return entity.length() > 1 ? Integer.parseInt(entity.substring(1)) : -1;
        } catch (NumberFormatException invalid) { return -1; }
        return switch (entity.toLowerCase(Locale.ROOT)) {
            case "lt" -> '<'; case "gt" -> '>'; case "amp" -> '&'; case "quot" -> '"'; case "apos" -> '\'';
            case "nbsp" -> ' '; case "colon" -> ':'; case "lpar" -> '('; case "rpar" -> ')'; case "sol" -> '/';
            case "tab" -> '\t'; case "newline" -> '\n'; case "grave" -> '`'; case "equals" -> '='; case "bsol" -> '\\';
            default -> -1;
        };
    }

    static String jsDecode(String value) {
        if (value.indexOf('\\') < 0) return value;
        var out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c != '\\' || i + 1 >= value.length()) { out.append(c); continue; }
            char next = value.charAt(i + 1);
            if (next == 'u' && hex(value, i + 2, 4) >= 0) { out.append((char) hex(value, i + 2, 4)); i += 5; }
            else if (next == 'x' && hex(value, i + 2, 2) >= 0) { out.append((char) hex(value, i + 2, 2)); i += 3; }
            else if (next >= '0' && next <= '7') {
                int end = i + 1, code = 0;
                while (end < value.length() && end < i + 4 && value.charAt(end) >= '0' && value.charAt(end) <= '7') code = code * 8 + (value.charAt(end++) - '0');
                out.append((char) code);
                i = end - 1;
            } else { out.append(escape(next)); i++; }
        }
        return out.toString();
    }

    static String escapeSeqDecode(String value) { return jsDecode(value); }

    private static char escape(char c) {
        return switch (c) { case 'n' -> '\n'; case 'r' -> '\r'; case 't' -> '\t'; case 'b' -> '\b'; case 'f' -> '\f'; case 'v' -> '\u000b'; case 'a' -> '\u0007'; default -> c; };
    }

    static String cssDecode(String value) {
        if (value.indexOf('\\') < 0) return value;
        var out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c != '\\' || i + 1 >= value.length()) { out.append(c); continue; }
            int end = i + 1;
            while (end < value.length() && end < i + 7 && Character.digit(value.charAt(end), 16) >= 0) end++;
            if (end == i + 1) { if (value.charAt(end) != '\n') out.append(value.charAt(end)); i = end; continue; }
            out.appendCodePoint(Math.min(Integer.parseInt(value.substring(i + 1, end), 16), Character.MAX_CODE_POINT));
            i = end < value.length() && Character.isWhitespace(value.charAt(end)) ? end : end - 1;
        }
        return out.toString();
    }

    static String base64Decode(String value) {
        // Só decodifica o que é base64 inteiro (quebras de linha à parte); texto com outro caractere fica como está.
        String clean = value.replaceAll("[\r\n]", "");
        if (clean.length() < 4 || !clean.matches("[A-Za-z0-9+/_-]+={0,2}")) return value;
        try {
            byte[] decoded = clean.indexOf('-') >= 0 || clean.indexOf('_') >= 0 ? Base64.getUrlDecoder().decode(clean.replace("=", "")) : Base64.getMimeDecoder().decode(clean);
            return new String(decoded, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException invalid) { return value; }
    }

    static String normalizePath(String value, boolean windows) {
        String path = windows ? value.replace('\\', '/') : value;
        if (path.indexOf('/') < 0 && path.indexOf('.') < 0) return path;
        var parts = new java.util.ArrayDeque<String>();
        boolean absolute = path.startsWith("/"), trailing = path.endsWith("/");
        for (String part : path.split("/+")) {
            if (part.isEmpty() || part.equals(".")) continue;
            if (part.equals("..")) { if (!parts.isEmpty() && !parts.peekLast().equals("..")) parts.removeLast(); else if (!absolute) parts.addLast(part); }
            else parts.addLast(part);
        }
        String joined = String.join("/", parts);
        return (absolute ? "/" : "") + joined + (trailing && !joined.isEmpty() ? "/" : "");
    }

    static String comments(String value, String replacement) {
        if (value.indexOf("/*") < 0 && value.indexOf("--") < 0 && value.indexOf('#') < 0 && value.indexOf("<!--") < 0) return value;
        var out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            if (value.startsWith("/*", i)) { int end = value.indexOf("*/", i + 2); out.append(replacement); if (end < 0) break; i = end + 1; }
            else if (value.startsWith("<!--", i)) { int end = value.indexOf("-->", i + 4); out.append(replacement); if (end < 0) break; i = end + 2; }
            else if (value.startsWith("--", i) || value.charAt(i) == '#') { int end = value.indexOf('\n', i); out.append(replacement); if (end < 0) break; i = end - 1; }
            else out.append(value.charAt(i));
        }
        return out.toString();
    }

    /** Linha de comando: tira escapes e aspas que o shell ignora, junta espaços antes de / e (, minúsculas. */
    static String cmdLine(String value) {
        var out = new StringBuilder(value.length());
        boolean space = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\' || c == '"' || c == '\'' || c == '^') continue;
            if (c == ' ' || c == ',' || c == ';' || c == '\t' || c == '\n' || c == '\r') { space = true; continue; }
            if (space && c != '/' && c != '(' && out.length() > 0) out.append(' ');
            space = false;
            out.append(Character.toLowerCase(c));
        }
        return out.toString();
    }
}
