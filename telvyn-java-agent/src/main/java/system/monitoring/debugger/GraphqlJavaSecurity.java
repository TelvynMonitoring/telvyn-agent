package system.monitoring.debugger;

import java.lang.instrument.Instrumentation;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.bytebuddy.asm.Advice;
import static net.bytebuddy.matcher.ElementMatchers.*;

/**
 * GraphQL no graphql-java (que só detecta, sem bloquear, nesse framework): na execução, os argumentos
 * de todos os resolvers da operação, com variáveis resolvidas, no endereço {@code graphql.server.all_resolvers}
 * ({@code {campo: [{argumento: valor}]}}). O documento é lido pelo parser do próprio graphql-java. Precisa da
 * requisição em curso (servlet ou Vert.x na mesma thread).
 */
public final class GraphqlJavaSecurity {
    private GraphqlJavaSecurity() {}

    public static void install(Instrumentation instrumentation) {
        Agents.builder()
            .type(named("graphql.GraphQL"))
            .transform((builder, type, loader, module, domain) -> builder.visit(Advice.to(Execute.class)
                .on(named("executeAsync").and(takesArguments(1)).and(takesArgument(0, named("graphql.ExecutionInput"))))))
            .installOn(instrumentation);
    }

    private static Object call(Object target, String method) throws ReflectiveOperationException {
        return JavaProtection.call(target, method, new Class<?>[]{});
    }

    private static String kind(Object node) { return node == null ? "" : node.getClass().getSimpleName(); }

    public static void execute(Object input) {
        Object[] current = SpringMvcSecurity.current();
        if (current == null) current = VertxSecurity.contextCurrent(input.getClass().getClassLoader());
        var reporter = SpringMvcSecurity.wafReporter();
        if (current == null || reporter == null || !(current[2] instanceof WafInspector.State state) || state.blocked) return;
        try {
            String query = (String) call(input, "getQuery");
            if (query == null || query.isBlank()) return;
            @SuppressWarnings("unchecked") Map<String, Object> variables = call(input, "getVariables") instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
            Object operation = call(input, "getOperationName");
            Class<?> parser = Class.forName("graphql.parser.Parser", false, input.getClass().getClassLoader());
            Object document = parser.getMethod("parseDocument", String.class).invoke(parser.getConstructor().newInstance(), query);
            Map<String, List<Object>> resolvers = resolvers(document, variables, operation instanceof String name ? name : null);
            if (!resolvers.isEmpty()) SpringMvcSecurity.decide(state, WafInspector.run(state, Map.of("graphql.server.all_resolvers", resolvers)), reporter, false);
        } catch (ReflectiveOperationException | RuntimeException | LinkageError unparsable) { /* documento inválido: o próprio graphql-java responde */ }
    }

    static Map<String, List<Object>> resolvers(Object document, Map<String, Object> variables, String operationName) throws ReflectiveOperationException {
        Map<String, List<Object>> out = new LinkedHashMap<>();
        Map<String, Object> fragments = new HashMap<>();
        List<?> definitions = (List<?>) call(document, "getDefinitions");
        for (Object definition : definitions) if ("FragmentDefinition".equals(kind(definition))) fragments.put((String) call(definition, "getName"), definition);
        for (Object definition : definitions) {
            if (!"OperationDefinition".equals(kind(definition))) continue;
            if (operationName != null && !operationName.equals(call(definition, "getName"))) continue;
            visit(call(definition, "getSelectionSet"), variables, fragments, new HashSet<>(), out);
        }
        return out;
    }

    private static void visit(Object selectionSet, Map<String, Object> variables, Map<String, Object> fragments, Set<String> seen, Map<String, List<Object>> out) throws ReflectiveOperationException {
        if (selectionSet == null) return;
        for (Object selection : (List<?>) call(selectionSet, "getSelections")) {
            switch (kind(selection)) {
                case "Field" -> {
                    List<?> arguments = (List<?>) call(selection, "getArguments");
                    if (arguments != null && !arguments.isEmpty()) {
                        Map<String, Object> values = new LinkedHashMap<>();
                        for (Object argument : arguments) values.put((String) call(argument, "getName"), value(call(argument, "getValue"), variables));
                        out.computeIfAbsent((String) call(selection, "getName"), key -> new ArrayList<>()).add(values);
                    }
                    visit(call(selection, "getSelectionSet"), variables, fragments, seen, out);
                }
                case "InlineFragment" -> visit(call(selection, "getSelectionSet"), variables, fragments, seen, out);
                case "FragmentSpread" -> {
                    String name = (String) call(selection, "getName");
                    if (seen.add(name) && fragments.get(name) != null) visit(call(fragments.get(name), "getSelectionSet"), variables, fragments, seen, out);
                }
                default -> { /* outro tipo de seleção */ }
            }
        }
    }

    private static Object value(Object node, Map<String, Object> variables) throws ReflectiveOperationException {
        return switch (kind(node)) {
            case "VariableReference" -> WafInspector.introspect(variables.get((String) call(node, "getName")));
            case "StringValue" -> call(node, "getValue");
            case "IntValue", "FloatValue" -> String.valueOf(call(node, "getValue"));
            case "BooleanValue" -> JavaProtection.call(node, "isValue", new Class<?>[]{});
            case "EnumValue" -> call(node, "getName");
            case "ArrayValue" -> {
                List<Object> list = new ArrayList<>();
                for (Object item : (List<?>) call(node, "getValues")) list.add(value(item, variables));
                yield list;
            }
            case "ObjectValue" -> {
                Map<String, Object> map = new LinkedHashMap<>();
                for (Object field : (List<?>) call(node, "getObjectFields")) map.put((String) call(field, "getName"), value(call(field, "getValue"), variables));
                yield map;
            }
            default -> null;
        };
    }

    public static class Execute {
        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Argument(0) Object input) { GraphqlJavaSecurity.execute(input); }
    }
}
