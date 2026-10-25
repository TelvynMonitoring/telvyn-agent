package system.monitoring.debugger.waf;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Motor do WAF do Telvyn, em Java puro: carrega o conjunto de regras (telvyn/waf-rules.json), e cada requisição
 * abre um {@link Context} que acumula os dados das fases e avalia as regras cujos endereços chegaram.
 * Os resultados trazem a regra e onde ela casou (endereço e caminho de chaves), nunca o valor recebido.
 */
public final class Engine {
    public static final String VERSION = "telvyn-waf/1.0.0";

    /** Uma condição compilada: endereços de entrada, operador e a seleção (chaves ou valores). */
    record Condition(String operator, List<Input> inputs, Operator test, List<Input> resource) {}

    record Input(String address, List<String> keyPath, boolean keys, List<UnaryOperator<String>> transforms) {}

    record Rule(String id, String name, Map<String, Object> tags, List<Condition> conditions, List<String> actions, Set<String> addresses) {}

    /** Onde um operador casou. */
    record Hit(String address, List<Object> keyPath, String resourceAddress) {}

    /** Operador sobre os dados acumulados: devolve onde casou ou null. */
    interface Operator { Hit test(Condition condition, Map<String, Object> data, Values.Limits limits, Values.Budget budget); }

    private final List<Rule> rules;
    private final Schemas schemas;
    private final Map<String, List<Rule>> byAddress = new HashMap<>();
    private final String rulesVersion;

    private Engine(List<Rule> rules, Schemas schemas, String rulesVersion) {
        this.rules = rules;
        this.schemas = schemas;
        this.rulesVersion = rulesVersion;
        for (Rule rule : rules) for (String address : rule.addresses()) byAddress.computeIfAbsent(address, k -> new ArrayList<>()).add(rule);
    }

    public int size() { return rules.size(); }

    public String rulesVersion() { return rulesVersion; }

    /** Compila o conjunto de regras; regra inválida falha a carga inteira (não sobe WAF pela metade). */
    @SuppressWarnings("unchecked")
    public static Engine load(Map<String, Object> document) {
        var metadata = (Map<String, Object>) document.getOrDefault("metadata", Map.of());
        List<Rule> compiled = new ArrayList<>();
        Set<String> ids = new LinkedHashSet<>();
        for (Object raw : (List<Object>) document.getOrDefault("rules", List.of())) {
            var rule = (Map<String, Object>) raw;
            if (Boolean.FALSE.equals(rule.get("enabled"))) continue;
            String id = (String) rule.get("id");
            if (id == null || !ids.add(id)) throw new IllegalArgumentException("rule without id or duplicated: " + id);
            try { compiled.add(compile(rule)); }
            catch (RuntimeException invalid) { throw new IllegalArgumentException("invalid rule " + id + ": " + invalid.getMessage(), invalid); }
        }
        if (compiled.isEmpty()) throw new IllegalArgumentException("no rules");
        Schemas schemas = Schemas.load((List<Object>) document.getOrDefault("scanners", List.of()), (Map<String, Object>) document.get("schemas"));
        return new Engine(List.copyOf(compiled), schemas, String.valueOf(metadata.getOrDefault("rules_version", "unknown")));
    }

    @SuppressWarnings("unchecked")
    private static Rule compile(Map<String, Object> rule) {
        List<UnaryOperator<String>> transforms = new ArrayList<>();
        boolean keys = false;
        for (Object name : (List<Object>) rule.getOrDefault("transformers", List.of())) {
            if ("keys_only".equals(name)) { keys = true; continue; }
            if ("values_only".equals(name)) continue;
            var step = Transforms.of(String.valueOf(name));
            if (step == null) throw new IllegalArgumentException("unknown transformer " + name);
            transforms.add(step);
        }
        List<Condition> conditions = new ArrayList<>();
        Set<String> addresses = new LinkedHashSet<>();
        for (Object raw : (List<Object>) rule.get("conditions")) {
            var condition = (Map<String, Object>) raw;
            String operator = (String) condition.get("operator");
            var parameters = (Map<String, Object>) condition.getOrDefault("parameters", Map.of());
            List<Input> inputs = inputs(parameters.get(parameters.containsKey("params") ? "params" : "inputs"), keys, transforms);
            List<Input> resource = inputs(parameters.get("resource"), false, List.of());
            for (Input input : resource) addresses.add(input.address());
            // Detector de exploit avalia quando a operação (resource) chega; a regra comum, quando chega a entrada.
            if (resource.isEmpty()) for (Input input : inputs) addresses.add(input.address());
            conditions.add(new Condition(operator, inputs, Operators.compile(operator, parameters), resource));
        }
        if (conditions.isEmpty()) throw new IllegalArgumentException("no conditions");
        var tags = (Map<String, Object>) rule.getOrDefault("tags", Map.of());
        return new Rule((String) rule.get("id"), (String) rule.getOrDefault("name", ""), tags, conditions, Phrases.list(rule.get("on_match")), addresses);
    }

    @SuppressWarnings("unchecked")
    private static List<Input> inputs(Object raw, boolean keys, List<UnaryOperator<String>> ruleTransforms) {
        List<Input> out = new ArrayList<>();
        if (!(raw instanceof List<?> list)) return out;
        for (Object item : list) {
            var input = (Map<String, Object>) item;
            boolean selectKeys = keys;
            List<UnaryOperator<String>> transforms = ruleTransforms;
            if (input.get("transformers") instanceof List<?> own) {
                transforms = new ArrayList<>();
                for (Object name : own) {
                    if ("keys_only".equals(name)) { selectKeys = true; continue; }
                    if ("values_only".equals(name)) { selectKeys = false; continue; }
                    var step = Transforms.of(String.valueOf(name));
                    if (step == null) throw new IllegalArgumentException("unknown transformer " + name);
                    transforms.add(step);
                }
            }
            List<String> path = input.get("key_path") instanceof List<?> keysPath ? keysPath.stream().map(String::valueOf).toList() : null;
            out.add(new Input((String) input.get("address"), path, selectKeys, List.copyOf(transforms)));
        }
        return out;
    }

    /** Regex compilada para o motor: sem diferenciar maiúsculas por padrão, como as regras esperam. */
    static Pattern regex(String source, boolean caseSensitive) {
        try { return Pattern.compile(source, caseSensitive ? 0 : Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE); }
        catch (PatternSyntaxException invalid) { throw new IllegalArgumentException("invalid regex: " + invalid.getDescription()); }
    }

    public Context open() { return new Context(this); }

    /** Estado do WAF de uma requisição: dados acumulados por endereço e regras que já casaram. */
    public static final class Context {
        private final Engine engine;
        private final Map<String, Object> data = new LinkedHashMap<>();
        private final Set<String> matched = new LinkedHashSet<>();

        private Context(Engine engine) { this.engine = engine; }

        /**
         * Avalia o que chegou nesta fase. ephemeral: dados de uma operação (exploit prevention), que valem só nesta
         * chamada. Devolve os eventos novos e, quando pedido, os esquemas da API.
         */
        public Result run(Map<String, Object> phase, Values.Limits limits, long timeoutUs, boolean ephemeral) {
            var budget = new Values.Budget(timeoutUs);
            Map<String, Object> view = data;
            if (ephemeral) { view = new LinkedHashMap<>(data); view.putAll(phase); }
            else data.putAll(phase);
            List<Map<String, Object>> events = new ArrayList<>();
            Set<Rule> candidates = new LinkedHashSet<>();
            for (String address : phase.keySet()) candidates.addAll(engine.byAddress.getOrDefault(address, List.of()));
            try {
                for (Rule rule : candidates) {
                    if (!ephemeral && matched.contains(rule.id())) continue;
                    List<Hit> hits = new ArrayList<>();
                    for (Condition condition : rule.conditions()) {
                        Hit hit = condition.test().test(condition, view, limits, budget);
                        if (hit == null) { hits = null; break; }
                        hits.add(hit);
                    }
                    if (hits == null) continue;
                    if (!ephemeral) matched.add(rule.id());
                    events.add(event(rule, hits));
                }
                Map<String, Object> attributes = null;
                if (phase.get("waf.context.processor") instanceof Map<?, ?> processor && Boolean.TRUE.equals(processor.get("extract-schema")))
                    attributes = engine.schemas.extract(view, limits, budget);
                return new Result(events.isEmpty() ? "ok" : "match", events, attributes);
            } catch (Values.Budget.Exceeded timeout) {
                return new Result("timeout", events, null);
            }
        }

        private static Map<String, Object> event(Rule rule, List<Hit> hits) {
            Map<String, Object> ruleInfo = new LinkedHashMap<>();
            ruleInfo.put("id", rule.id());
            ruleInfo.put("name", rule.name());
            ruleInfo.put("tags", rule.tags());
            ruleInfo.put("on_match", rule.actions());
            List<Map<String, Object>> matches = new ArrayList<>();
            for (int i = 0; i < hits.size(); i++) {
                Hit hit = hits.get(i);
                Map<String, Object> parameter = new LinkedHashMap<>();
                if (hit.resourceAddress() != null) {
                    parameter.put("resource", Map.of("address", hit.resourceAddress()));
                    parameter.put("params", Map.of("address", hit.address(), "key_path", stringPath(hit.keyPath())));
                } else {
                    parameter.put("address", hit.address());
                    parameter.put("key_path", stringPath(hit.keyPath()));
                }
                matches.add(Map.of("operator", rule.conditions().get(i).operator(), "parameters", List.of(parameter)));
            }
            return Map.of("rule", ruleInfo, "rule_matches", matches);
        }

        private static List<String> stringPath(List<Object> path) { return path == null ? List.of() : path.stream().map(String::valueOf).toList(); }
    }

    /** Resultado de uma fase: "ok", "match" ou "timeout"; eventos novos; esquemas da API quando pedidos. */
    public record Result(String outcome, List<Map<String, Object>> events, Map<String, Object> attributes) {}
}
