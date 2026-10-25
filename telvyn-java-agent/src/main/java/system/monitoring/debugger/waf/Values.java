package system.monitoring.debugger.waf;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Percorre o dado de um endereço (texto, número, mapa, lista) e entrega cada valor folha com o caminho de chaves,
 * dentro dos limites de profundidade, de elementos e de tamanho de texto.
 */
public final class Values {
    /** Valor folha: o texto (já cortado no limite) e o caminho até ele. */
    record Leaf(String text, List<Object> path) {}

    interface Visitor { boolean visit(Leaf leaf); }

    private Values() {}

    /**
     * Visita as folhas de value seguindo keyPath; keys: visita as chaves dos mapas em vez dos valores.
     * Devolve true se o visitante pediu para parar (achou).
     */
    static boolean walk(Object value, List<String> keyPath, boolean keys, Limits limits, Budget budget, Visitor visitor) {
        Object start = value;
        List<Object> prefix = new ArrayList<>();
        if (keyPath != null) for (String key : keyPath) {
            if (start instanceof Map<?, ?> map) { start = map.get(key); prefix.add(key); }
            else if (start instanceof List<?> list && key.matches("\\d{1,6}") && Integer.parseInt(key) < list.size()) { start = list.get(Integer.parseInt(key)); prefix.add(Integer.parseInt(key)); }
            else return false;
            if (start == null) return false;
        }
        return visit(start, prefix, 0, keys, limits, budget, new int[]{0}, visitor);
    }

    private static boolean visit(Object value, List<Object> path, int depth, boolean keys, Limits limits, Budget budget, int[] count, Visitor visitor) {
        if (value == null || depth > limits.depth() || ++count[0] > limits.elements()) return false;
        budget.check();
        if (value instanceof Map<?, ?> map) {
            for (var entry : map.entrySet()) {
                List<Object> next = append(path, String.valueOf(entry.getKey()));
                if (keys && visitor.visit(new Leaf(cut(String.valueOf(entry.getKey()), limits), next))) return true;
                if (visit(entry.getValue(), next, depth + 1, keys, limits, budget, count, visitor)) return true;
                if (count[0] > limits.elements()) return false;
            }
            return false;
        }
        if (value instanceof Collection<?> items) {
            int index = 0;
            for (Object item : items) {
                if (visit(item, append(path, index++), depth + 1, keys, limits, budget, count, visitor)) return true;
                if (count[0] > limits.elements()) return false;
            }
            return false;
        }
        if (value instanceof Object[] items) return visit(List.of(items), path, depth, keys, limits, budget, count, visitor);
        if (keys) return false;
        return visitor.visit(new Leaf(cut(String.valueOf(value), limits), path));
    }

    private static List<Object> append(List<Object> path, Object key) {
        List<Object> next = new ArrayList<>(path.size() + 1);
        next.addAll(path);
        next.add(key);
        return next;
    }

    private static String cut(String text, Limits limits) { return text.length() > limits.text() ? text.substring(0, limits.text()) : text; }

    /** Limites de uma execução: profundidade, elementos visitados por endereço e tamanho máximo de texto. */
    public record Limits(int depth, int elements, int text) {}

    /** Tempo da execução: estourou, a análise para com timeout (sem resultado parcial reportado como limpo). */
    static final class Budget {
        static final class Exceeded extends RuntimeException {
            Exceeded() { super("WAF time limit", null, false, false); }
        }

        private final long deadline;
        Budget(long timeoutUs) { this.deadline = System.nanoTime() + timeoutUs * 1000L; }
        void check() { if (System.nanoTime() > deadline) throw new Exceeded(); }

        /** Texto que confere o tempo durante a regex: regex patológica não trava a thread da aplicação. */
        CharSequence guard(CharSequence text) {
            Budget budget = this;
            return new CharSequence() {
                int reads;
                @Override public int length() { return text.length(); }
                @Override public char charAt(int index) { if ((++reads & 1023) == 0) budget.check(); return text.charAt(index); }
                @Override public CharSequence subSequence(int start, int end) { return budget.guard(text.subSequence(start, end)); }
                @Override public String toString() { return text.toString(); }
            };
        }
    }
}
