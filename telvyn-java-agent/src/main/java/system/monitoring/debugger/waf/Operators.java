package system.monitoring.debugger.waf;

import java.math.BigInteger;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** Operadores das condições. Os de valor casam se algum valor das entradas satisfaz o teste. */
final class Operators {
    private Operators() {}

    /** Teste de um valor; o orçamento de tempo vai junto para a regex conferir o prazo enquanto roda. */
    interface Test { boolean test(String value, Values.Budget budget); }

    @SuppressWarnings("unchecked")
    static Engine.Operator compile(String name, Map<String, Object> parameters) {
        String operator = name.contains("@") ? name.substring(0, name.indexOf('@')) : name;
        boolean negated = operator.startsWith("!");
        if (negated) operator = operator.substring(1);
        var options = (Map<String, Object>) parameters.getOrDefault("options", Map.of());
        int minLength = options.get("min_length") instanceof Number number ? number.intValue() : 0;
        Test test = switch (operator) {
            case "match_regex" -> {
                Pattern pattern = Engine.regex((String) parameters.get("regex"), Boolean.TRUE.equals(options.get("case_sensitive")));
                yield (value, budget) -> value.length() >= minLength && pattern.matcher(value.length() > 64 ? budget.guard(value) : value).find();
            }
            case "phrase_match" -> {
                var phrases = new Phrases(Phrases.list(parameters.get("list")), Boolean.TRUE.equals(options.get("enforce_word_boundary")));
                yield (value, budget) -> phrases.find(value);
            }
            case "exact_match" -> {
                Set<String> list = new HashSet<>(Phrases.list(parameters.get("list")));
                yield (value, budget) -> list.contains(value);
            }
            case "ip_match" -> { var ip = ipMatch(Phrases.list(parameters.get("list"))); yield (value, budget) -> ip.test(value); }
            case "equals" -> {
                String expected = String.valueOf(parameters.get("value"));
                yield (value, budget) -> expected.equalsIgnoreCase(value);
            }
            case "greater_than", "lower_than" -> {
                double limit = ((Number) parameters.get("value")).doubleValue();
                boolean greater = operator.equals("greater_than");
                yield (value, budget) -> { try { double parsed = Double.parseDouble(value.trim()); return greater ? parsed > limit : parsed < limit; } catch (NumberFormatException no) { return false; } };
            }
            case "is_sqli" -> (value, budget) -> Injection.isSqli(value);
            case "is_xss" -> (value, budget) -> Injection.isXss(value);
            case "lfi_detector", "ssrf_detector", "sqli_detector", "shi_detector", "cmdi_detector" -> null;
            default -> throw new IllegalArgumentException("unknown operator " + name);
        };
        if (test == null) return exploit(operator, parameters);
        Test finalTest = test;
        return negated ? (condition, data, limits, budget) -> negatedHit(condition, data, limits, budget, finalTest)
                : (condition, data, limits, budget) -> hit(condition, data, limits, budget, finalTest);
    }

    private static Engine.Hit hit(Engine.Condition condition, Map<String, Object> data, Values.Limits limits, Values.Budget budget, Test test) {
        for (Engine.Input input : condition.inputs()) {
            Object value = data.get(input.address());
            if (value == null) continue;
            Engine.Hit[] found = new Engine.Hit[1];
            Values.walk(value, input.keyPath(), input.keys(), limits, budget, leaf -> {
                String text = Transforms.apply(input.transforms(), leaf.text());
                if (!test.test(text, budget)) return false;
                found[0] = new Engine.Hit(input.address(), leaf.path(), null);
                return true;
            });
            if (found[0] != null) return found[0];
        }
        return null;
    }

    /** Negado: casa quando a entrada existe e nenhum valor dela satisfaz o teste. */
    private static Engine.Hit negatedHit(Engine.Condition condition, Map<String, Object> data, Values.Limits limits, Values.Budget budget, Test test) {
        for (Engine.Input input : condition.inputs()) {
            Object value = data.get(input.address());
            if (value == null) continue;
            boolean[] any = {false}, seen = {false};
            Values.walk(value, input.keyPath(), input.keys(), limits, budget, leaf -> {
                seen[0] = true;
                if (test.test(Transforms.apply(input.transforms(), leaf.text()), budget)) { any[0] = true; return true; }
                return false;
            });
            if (seen[0] && !any[0]) return new Engine.Hit(input.address(), input.keyPath() == null ? List.of() : List.copyOf(input.keyPath()), null);
        }
        return null;
    }

    private static java.util.function.Predicate<String> ipMatch(List<String> list) {
        record Range(BigInteger network, int bits, int size) {}
        List<Range> ranges = new ArrayList<>();
        for (String item : list) {
            String[] parts = item.split("/");
            byte[] address = literal(parts[0]);
            if (address == null) throw new IllegalArgumentException("invalid ip " + item);
            int size = address.length * 8;
            int bits = parts.length > 1 ? Integer.parseInt(parts[1]) : size;
            ranges.add(new Range(new BigInteger(1, address).shiftRight(size - bits), bits, size));
        }
        return value -> {
            byte[] address = literal(value.trim());
            if (address == null) return false;
            BigInteger number = new BigInteger(1, address);
            for (Range range : ranges) if (range.size() == address.length * 8 && number.shiftRight(range.size() - range.bits()).equals(range.network())) return true;
            return false;
        };
    }

    /** Endereço IP literal sem consulta de DNS (texto que não é IP volta null). */
    static byte[] literal(String text) {
        if (text.isEmpty() || !(text.matches("[0-9.]+") || text.matches("[0-9a-fA-F:.]+") && text.indexOf(':') >= 0)) return null;
        try { return InetAddress.getByName(text).getAddress(); } catch (Exception invalid) { return null; }
    }

    private static Engine.Operator exploit(String operator, Map<String, Object> parameters) {
        return (condition, data, limits, budget) -> {
            for (Engine.Input resource : condition.resource()) {
                Object operation = data.get(resource.address());
                if (operation == null) continue;
                String system = data.get("server.db.system") instanceof String db ? db.toLowerCase(Locale.ROOT) : "";
                for (Engine.Input input : condition.inputs()) {
                    Object value = data.get(input.address());
                    if (value == null) continue;
                    Engine.Hit[] found = new Engine.Hit[1];
                    Values.walk(value, input.keyPath(), false, limits, budget, leaf -> {
                        if (!Exploits.detect(operator, operation, leaf.text(), system)) return false;
                        found[0] = new Engine.Hit(input.address(), leaf.path(), resource.address());
                        return true;
                    });
                    if (found[0] != null) return found[0];
                }
            }
            return null;
        };
    }
}
