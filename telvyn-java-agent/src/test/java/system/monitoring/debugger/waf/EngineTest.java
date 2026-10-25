package system.monitoring.debugger.waf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class EngineTest {
    static Engine engine;
    static final Values.Limits LIMITS = new Values.Limits(20, 256, 4096);

    @BeforeAll
    @SuppressWarnings("unchecked")
    static void load() throws Exception {
        try (var stream = EngineTest.class.getResourceAsStream("/telvyn/waf-rules.json")) {
            assertNotNull(stream);
            engine = Engine.load(new Gson().fromJson(new InputStreamReader(stream, StandardCharsets.UTF_8), Map.class));
        }
    }

    private static Engine.Result run(Map<String, Object> data) { return engine.open().run(data, LIMITS, 200_000, false); }

    @Test
    void conjuntoDoCrsCarregaInteiro() {
        assertTrue(engine.size() >= 150, "regras carregadas: " + engine.size());
        assertTrue(engine.rulesVersion().startsWith("crs-"));
    }

    @Test
    void trafegoComumNaoCasa() {
        var result = run(Map.of(
                "server.request.headers.no_cookies", Map.of("user-agent", "Mozilla/5.0 (X11; Linux x86_64)", "accept", "application/json", "host", "app.example.com"),
                "server.request.query", Map.of("page", List.of("2"), "q", List.of("monitoramento de redes")),
                "server.request.uri.raw", "/api/hosts?page=2&q=monitoramento+de+redes",
                "server.request.method", "GET",
                "server.request.body", Map.of("name", "João da Silva", "note", "Troca de equipamento na sexta-feira")));
        assertEquals("ok", result.outcome(), String.valueOf(result.events()));
    }

    @Test
    void eventoNaoCarregaOValorRecebido() {
        var result = run(Map.of("server.request.query", Map.of("q", List.of("../../etc/passwd"))));
        assertEquals("match", result.outcome());
        assertFalse(new Gson().toJson(result.events()).contains("passwd"));
    }

    @Test
    void esquemaDaApiMarcaCamposSensiveisSemValores() {
        var context = engine.open();
        var result = context.run(Map.of(
                "server.request.body", Map.of("email", "ana@example.com", "password", "x", "age", 31, "tags", List.of("a", "b")),
                "waf.context.processor", Map.of("extract-schema", true)), LIMITS, 200_000, false);
        assertNotNull(result.attributes());
        String json = new Gson().toJson(result.attributes());
        assertTrue(json.contains("\"email\""), json);
        assertTrue(json.contains("password"), json);
        assertFalse(json.contains("ana@example.com"), json);
    }

    @Test
    void prevencaoDeExploitComparaOperacaoComEntrada() {
        var context = engine.open();
        Map<String, Object> query = Map.of("server.request.query", Map.of("file", List.of("../../etc/shadow")));
        context.run(query, LIMITS, 200_000, false);
        var attack = context.run(Map.of("server.io.fs.file", "/srv/app/uploads/../../etc/shadow"), LIMITS, 200_000, true);
        assertEquals("match", attack.outcome(), String.valueOf(attack.events()));
        var clean = context.run(Map.of("server.io.fs.file", "/srv/app/uploads/photo.png"), LIMITS, 200_000, true);
        assertEquals("ok", clean.outcome());
        var sql = engine.open();
        sql.run(Map.of("server.request.query", Map.of("id", List.of("1' OR '1'='1"))), LIMITS, 200_000, false);
        var injected = sql.run(Map.of("server.db.statement", "SELECT * FROM t WHERE id = '1' OR '1'='1'", "server.db.system", "mysql"), LIMITS, 200_000, true);
        assertTrue(injected.events().stream().anyMatch(e -> String.valueOf(e).contains("rasp-942-100")), String.valueOf(injected.events()));
    }
}
