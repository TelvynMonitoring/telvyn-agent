package system.monitoring.debugger;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Hardcoded secrets in the application's code: string literals that match, as a whole, one of the formats the
 * Datadog Java tracer looks for (iast-secret-patterns.tsv). Judged when the class is instrumented; the finding names
 * the class, the method and the line, never the value.
 */
final class IastSecrets {
    static final int MIN_LENGTH = 10;
    private static volatile List<Pattern> patterns;

    private IastSecrets() {}

    private static List<Pattern> patterns() {
        var loaded = patterns;
        if (loaded != null) return loaded;
        synchronized (IastSecrets.class) {
            if (patterns != null) return patterns;
            var list = new ArrayList<Pattern>();
            try (var input = IastSecrets.class.getClassLoader().getResourceAsStream("iast-secret-patterns.tsv")) {
                if (input != null) {
                    var reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
                    for (String line; (line = reader.readLine()) != null; ) {
                        int tab = line.indexOf('\t');
                        if (line.startsWith("#") || tab < 0) continue;
                        list.add(Pattern.compile(line.substring(tab + 1)));
                    }
                }
            } catch (java.io.IOException | RuntimeException unavailable) {
                LocalAttackReporter.reportLoss("IAST secret formats unavailable");
            }
            patterns = List.copyOf(list);
            return patterns;
        }
    }

    static boolean secret(String literal) {
        if (literal == null || literal.length() < MIN_LENGTH || literal.length() > 4096) return false;
        for (Pattern pattern : patterns()) if (pattern.matcher(literal).matches()) return true;
        return false;
    }

    /** Construtores e inicializadores estáticos ficam com o nome da JVM ({@code <init>}, {@code <clinit>}), como os demais achados. */
    static void report(String type, String method, int line) {
        IastRuntime.once("HARDCODED_SECRET", type + "#" + method, line, null);
    }
}
