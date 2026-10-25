package system.monitoring.debugger.waf;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Busca de várias frases de uma vez (Aho-Corasick), sem diferenciar maiúsculas; opcionalmente só em palavra inteira. */
final class Phrases {
    private static final class Node {
        final Map<Character, Node> next = new HashMap<>(4);
        Node fail;
        int length = -1; // tamanho da frase que termina aqui (-1: nenhuma)
        int suffix = -1; // a maior frase que termina num sufixo deste nó
    }

    private final Node root = new Node();
    private final boolean wordBoundary;

    Phrases(List<String> phrases, boolean wordBoundary) {
        this.wordBoundary = wordBoundary;
        for (String phrase : phrases) {
            if (phrase == null || phrase.isEmpty()) continue;
            Node node = root;
            for (char c : phrase.toLowerCase(Locale.ROOT).toCharArray()) node = node.next.computeIfAbsent(c, k -> new Node());
            node.length = Math.max(node.length, phrase.length());
        }
        var queue = new ArrayDeque<Node>();
        for (Node child : root.next.values()) { child.fail = root; queue.add(child); }
        while (!queue.isEmpty()) {
            Node node = queue.poll();
            node.suffix = node.length >= 0 ? node.length : node.fail.suffix;
            for (var entry : node.next.entrySet()) {
                Node fail = node.fail;
                while (fail != null && !fail.next.containsKey(entry.getKey())) fail = fail.fail;
                entry.getValue().fail = fail == null ? root : fail.next.get(entry.getKey());
                queue.add(entry.getValue());
            }
        }
        root.suffix = -1;
    }

    boolean find(String text) {
        Node node = root;
        for (int i = 0; i < text.length(); i++) {
            char c = Character.toLowerCase(text.charAt(i));
            while (node != root && !node.next.containsKey(c)) node = node.fail;
            node = node.next.getOrDefault(c, root);
            for (Node at = node; at != null && at != root; at = at.fail) {
                if (at.length < 0) continue;
                if (!wordBoundary || boundary(text, i - at.length + 1, i + 1)) return true;
            }
        }
        return false;
    }

    private static boolean boundary(String text, int start, int end) {
        return (start == 0 || !Character.isLetterOrDigit(text.charAt(start - 1)) && text.charAt(start - 1) != '_')
                && (end == text.length() || !Character.isLetterOrDigit(text.charAt(end)) && text.charAt(end) != '_');
    }

    static List<String> list(Object raw) {
        List<String> out = new ArrayList<>();
        if (raw instanceof List<?> items) for (Object item : items) if (item != null) out.add(String.valueOf(item));
        return out;
    }
}
