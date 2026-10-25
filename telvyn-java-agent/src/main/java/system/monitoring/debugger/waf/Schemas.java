package system.monitoring.debugger.waf;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * API Security: esquema de cada parte da requisição e da resposta (tipos, nunca valores), com os campos sensíveis
 * marcados pelos scanners. Codificação: escalar [tipo] (1 nulo, 2 booleano, 4 inteiro, 8 texto, 16 decimal), mapa
 * [{chave: esquema}], lista [[esquemas dos itens], {"len": n}], e a marca do scanner como segundo item {"category", "type"}.
 */
final class Schemas {
    private static final int MAX_DEPTH = 18, MAX_KEYS = 256, MAX_ITEMS = 10;

    record Scanner(String category, String type, Pattern key, Pattern value, int minLength, String validator) {}
    record Mapping(String address, String output, Set<String> categories) {}

    private final List<Scanner> scanners;
    private final List<Mapping> mappings;

    private Schemas(List<Scanner> scanners, List<Mapping> mappings) { this.scanners = scanners; this.mappings = mappings; }

    @SuppressWarnings("unchecked")
    static Schemas load(List<Object> rawScanners, Map<String, Object> config) {
        List<Scanner> scanners = new ArrayList<>();
        for (Object raw : rawScanners) {
            var scanner = (Map<String, Object>) raw;
            var tags = (Map<String, Object>) scanner.get("tags");
            var key = (Map<String, Object>) scanner.get("key");
            var value = (Map<String, Object>) scanner.get("value");
            scanners.add(new Scanner((String) tags.get("category"), (String) tags.get("type"),
                    key == null ? null : Engine.regex((String) key.get("regex"), false),
                    value == null ? null : Engine.regex((String) value.get("regex"), Boolean.TRUE.equals(value.get("case_sensitive"))),
                    value != null && value.get("min_length") instanceof Number n ? n.intValue() : 0,
                    value == null ? null : (String) value.get("validator")));
        }
        List<Mapping> mappings = new ArrayList<>();
        if (config != null) for (Object raw : (List<Object>) config.getOrDefault("mappings", List.of())) {
            var mapping = (Map<String, Object>) raw;
            mappings.add(new Mapping((String) mapping.get("address"), (String) mapping.get("output"), new LinkedHashSet<>(Phrases.list(mapping.get("scanners")))));
        }
        return new Schemas(List.copyOf(scanners), List.copyOf(mappings));
    }

    Map<String, Object> extract(Map<String, Object> data, Values.Limits limits, Values.Budget budget) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Mapping mapping : mappings) {
            Object value = data.get(mapping.address());
            if (value == null) continue;
            out.put("schema." + mapping.output(), schema(value, null, mapping.categories(), 0, budget));
        }
        return out;
    }

    private Object schema(Object value, String key, Set<String> categories, int depth, Values.Budget budget) {
        budget.check();
        if (depth > MAX_DEPTH) return List.of(0);
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> fields = new LinkedHashMap<>();
            for (var entry : map.entrySet()) {
                if (fields.size() >= MAX_KEYS) break;
                String name = String.valueOf(entry.getKey());
                fields.put(name, schema(entry.getValue(), name, categories, depth + 1, budget));
            }
            return List.of(fields);
        }
        if (value instanceof Collection<?> items || value instanceof Object[]) {
            Collection<?> list = value instanceof Collection<?> c ? c : List.of((Object[]) value);
            List<Object> kinds = new ArrayList<>();
            for (Object item : list) {
                Object kind = schema(item, key, categories, depth + 1, budget);
                if (!kinds.contains(kind)) kinds.add(kind);
                if (kinds.size() >= MAX_ITEMS) break;
            }
            return List.of(kinds, Map.of("len", list.size()));
        }
        int type = value == null ? 1 : value instanceof Boolean ? 2
                : value instanceof Integer || value instanceof Long || value instanceof Short || value instanceof Byte ? 4
                : value instanceof Number number ? (number.doubleValue() == Math.rint(number.doubleValue()) && !Double.isInfinite(number.doubleValue()) ? 4 : 16) : 8;
        Scanner match = scan(key, value == null ? null : String.valueOf(value), categories);
        return match == null ? List.of(type) : List.of(type, Map.of("category", match.category(), "type", match.type()));
    }

    private Scanner scan(String key, String value, Set<String> categories) {
        for (Scanner scanner : scanners) {
            if (!categories.contains(scanner.category())) continue;
            if (scanner.key() != null && (key == null || !scanner.key().matcher(key).find())) continue;
            if (scanner.value() != null) {
                if (value == null || value.length() < scanner.minLength() || !scanner.value().matcher(value).find()) continue;
                if ("luhn".equals(scanner.validator()) && !luhn(value)) continue;
                if ("iban".equals(scanner.validator()) && !iban(value)) continue;
            }
            return scanner;
        }
        return null;
    }

    static boolean luhn(String text) {
        int sum = 0, digits = 0;
        boolean twice = false;
        for (int i = text.length() - 1; i >= 0; i--) {
            char c = text.charAt(i);
            if (c == ' ' || c == '-') continue;
            if (c < '0' || c > '9') return false;
            int digit = c - '0';
            if (twice && (digit *= 2) > 9) digit -= 9;
            sum += digit;
            twice = !twice;
            digits++;
        }
        return digits >= 9 && sum % 10 == 0;
    }

    static boolean iban(String text) {
        String clean = text.replace(" ", "").toUpperCase(java.util.Locale.ROOT);
        if (clean.length() < 15 || clean.length() > 34) return false;
        String rearranged = clean.substring(4) + clean.substring(0, 4);
        int remainder = 0;
        for (char c : rearranged.toCharArray()) {
            int value = Character.isDigit(c) ? c - '0' : Character.isLetter(c) ? c - 'A' + 10 : -1;
            if (value < 0) return false;
            remainder = (int) (((long) remainder * (value >= 10 ? 100 : 10) + value) % 97);
        }
        return remainder == 1;
    }
}
