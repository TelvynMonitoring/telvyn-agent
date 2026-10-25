package system.monitoring.debugger.waf;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.io.InputStreamReader;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

/**
 * Mede a cobertura do motor contra os testes de regressão do OWASP CRS, convertidos por tools/crs-convert/corpus.py.
 * Só roda com -Dtelvyn.waf.corpus=<corpus.json>; escreve o relatório em -Dtelvyn.waf.report (padrão target/waf-corpus.txt).
 */
class CorpusReport {
    record Case(String file, String test, String method, String uri, Map<String, String> headers, String body, List<String> expect, List<String> forbid) {}

    @Test
    @SuppressWarnings("unchecked")
    void report() throws Exception {
        String corpusPath = System.getProperty("telvyn.waf.corpus");
        assumeTrue(corpusPath != null, "sem corpus");
        List<Case> cases = new Gson().fromJson(Files.readString(Path.of(corpusPath)), new TypeToken<List<Case>>() {}.getType());
        Engine engine;
        try (var stream = CorpusReport.class.getResourceAsStream("/telvyn/waf-rules.json")) {
            engine = Engine.load(new Gson().fromJson(new InputStreamReader(stream, StandardCharsets.UTF_8), Map.class));
        }
        Set<String> loaded = new LinkedHashSet<>();
        try (var stream = CorpusReport.class.getResourceAsStream("/telvyn/waf-rules.json")) {
            for (Object rule : (List<Object>) new Gson().fromJson(new InputStreamReader(stream, StandardCharsets.UTF_8), Map.class).get("rules"))
                loaded.add(((String) ((Map<String, Object>) rule).get("id")).substring("crs-".length()));
        }
        // Gabarito opcional (fora do repositório): o conjunto anterior, medido no mesmo corpus por "casos de ataque que disparam algo".
        String baselinePath = System.getProperty("telvyn.waf.baseline");
        Engine baseline = baselinePath == null ? null : tolerant(new Gson().fromJson(Files.readString(Path.of(baselinePath)), Map.class));
        Map<String, int[]> byGroup = new TreeMap<>(); // [casos de ataque, detectados, casos limpos, falsos positivos, não convertidos, ataques com qualquer disparo (novo), idem (gabarito), total de ataques]
        List<String> misses = new ArrayList<>(), falsePositives = new ArrayList<>();
        var limits = new Values.Limits(20, 256, 4096);
        for (Case c : cases) {
            int[] counts = byGroup.computeIfAbsent(c.file().substring(0, c.file().indexOf('/')), k -> new int[8]);
            Set<String> fired = new LinkedHashSet<>();
            try {
                for (var event : engine.open().run(request(c), limits, 500_000, false).events())
                    fired.add(((String) ((Map<String, Object>) event.get("rule")).get("id")).substring("crs-".length()));
            } catch (RuntimeException failure) { fired.add("ERRO:" + failure.getMessage()); }
            if (!c.expect().isEmpty()) {
                counts[7]++;
                if (!fired.isEmpty()) counts[5]++;
                if (baseline != null) {
                    try { if (!baseline.open().run(request(c), limits, 500_000, false).events().isEmpty()) counts[6]++; } catch (RuntimeException ignored) { /* conta como sem disparo */ }
                }
                if (!loaded.containsAll(c.expect())) { counts[4]++; continue; }
                counts[0]++;
                if (fired.containsAll(c.expect())) counts[1]++; else misses.add(c.test() + " (" + c.file() + ")");
            }
            if (!c.forbid().isEmpty()) {
                counts[2]++;
                if (c.forbid().stream().anyMatch(fired::contains)) { counts[3]++; falsePositives.add(c.test() + " (" + c.file() + ")"); }
            }
        }
        var out = new StringBuilder("grupo\tataques\tdetectados\tlimpos\tfalsos positivos\tregra não convertida\tataques totais\tqualquer disparo (novo)\tqualquer disparo (gabarito)\n");
        int[] total = new int[8];
        byGroup.forEach((group, n) -> { out.append(group).append('\t').append(n[0]).append('\t').append(n[1]).append('\t').append(n[2]).append('\t').append(n[3]).append('\t').append(n[4]).append('\t').append(n[7]).append('\t').append(n[5]).append('\t').append(n[6]).append('\n'); for (int i = 0; i < 8; i++) total[i] += n[i]; });
        out.append("TOTAL\t").append(total[0]).append('\t').append(total[1]).append('\t').append(total[2]).append('\t').append(total[3]).append('\t').append(total[4]).append('\t').append(total[7]).append('\t').append(total[5]).append('\t').append(total[6]).append("\n\nnão detectados:\n");
        misses.forEach(m -> out.append("  ").append(m).append('\n'));
        out.append("\nfalsos positivos:\n");
        falsePositives.forEach(m -> out.append("  ").append(m).append('\n'));
        Files.writeString(Path.of(System.getProperty("telvyn.waf.report", "target/waf-corpus.txt")), out.toString());
    }

    /** Gabarito: carrega o que o motor consegue ler, descartando regra cuja regex a JVM não compila (conta no relatório). */
    @SuppressWarnings("unchecked")
    private static Engine tolerant(Map<String, Object> document) {
        document = new LinkedHashMap<>(document);
        document.remove("scanners"); // outro formato; só as regras de ataque entram na comparação
        List<Object> usable = new ArrayList<>();
        int dropped = 0;
        for (Object rule : (List<Object>) document.get("rules")) {
            Map<String, Object> single = new LinkedHashMap<>(document);
            single.put("rules", List.of(rule));
            try { Engine.load(single); usable.add(rule); } catch (RuntimeException unreadable) { dropped++; }
        }
        System.out.println("gabarito: regras lidas=" + usable.size() + " descartadas=" + dropped);
        Map<String, Object> filtered = new LinkedHashMap<>(document);
        filtered.put("rules", usable);
        return Engine.load(filtered);
    }

    private static Map<String, Object> request(Case c) {
        Map<String, Object> data = new LinkedHashMap<>();
        Map<String, Object> headers = new LinkedHashMap<>();
        Map<String, Object> cookies = new LinkedHashMap<>();
        String contentType = "";
        for (var header : c.headers().entrySet()) {
            String name = header.getKey().toLowerCase(java.util.Locale.ROOT);
            if (name.equals("cookie")) { for (String pair : header.getValue().split(";\\s*")) { int i = pair.indexOf('='); cookies.put(i < 0 ? pair : pair.substring(0, i), i < 0 ? "" : pair.substring(i + 1)); } continue; }
            if (name.equals("content-type")) contentType = header.getValue().toLowerCase(java.util.Locale.ROOT);
            headers.put(name, header.getValue());
        }
        data.put("server.request.headers.no_cookies", headers);
        if (!cookies.isEmpty()) data.put("server.request.cookies", cookies);
        data.put("server.request.method", c.method());
        data.put("server.request.uri.raw", c.uri());
        int question = c.uri().indexOf('?');
        data.put("server.request.query", form(question < 0 ? "" : c.uri().substring(question + 1)));
        if (c.body() != null) data.put("server.request.body", contentType.contains("x-www-form-urlencoded") ? form(c.body()) : c.body());
        return data;
    }

    private static Map<String, List<String>> form(String raw) {
        Map<String, List<String>> out = new LinkedHashMap<>();
        for (String pair : raw.split("&")) {
            if (pair.isEmpty()) continue;
            int i = pair.indexOf('=');
            try {
                out.computeIfAbsent(URLDecoder.decode(i < 0 ? pair : pair.substring(0, i), StandardCharsets.UTF_8), k -> new ArrayList<>())
                        .add(i < 0 ? "" : URLDecoder.decode(pair.substring(i + 1), StandardCharsets.UTF_8));
            } catch (IllegalArgumentException malformed) { out.computeIfAbsent(pair, k -> new ArrayList<>()).add(""); }
        }
        return out;
    }
}
