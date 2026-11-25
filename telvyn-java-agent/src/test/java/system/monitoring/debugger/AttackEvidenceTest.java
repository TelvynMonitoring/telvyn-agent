package system.monitoring.debugger;

import org.junit.jupiter.api.Test;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class AttackEvidenceTest {
    @Test
    void guardaOPayloadDoAtaqueSemMexer() {
        var evidence = AttackEvidence.build("') UNION SELECT sql FROM sqlite_master--", "server.request.query:q.0", null, null);
        var payload = evidence.getAsJsonObject("payload");
        assertEquals("') UNION SELECT sql FROM sqlite_master--", payload.get("value").getAsString());
        assertFalse(payload.get("redacted").getAsBoolean());
        assertFalse(payload.get("truncated").getAsBoolean());
    }

    @Test
    void campoSensivelOuCookieNaoEnviaOValor() {
        for (String location : new String[]{"server.request.query:password", "server.request.body:user.token", "server.request.headers.no_cookies:authorization", "server.request.cookies:sid"}) {
            var payload = AttackEvidence.build("hunter2", location, null, null).getAsJsonObject("payload");
            assertEquals("<redacted>", payload.get("value").getAsString(), location);
            assertTrue(payload.get("redacted").getAsBoolean(), location);
        }
    }

    @Test
    void redigeJwtBearerChaveAwsECartao() {
        String text = AttackEvidence.redactValue("x eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk y Bearer abcdefghijklmnop z AKIA" + "ABCDEFGHIJKLMNOP w 4111 1111 1111 1111");
        for (String secret : new String[]{"eyJ", "abcdefghijklmnop", "AKIA" + "ABCDEFGHIJKLMNOP", "4111"}) assertFalse(text.contains(secret), text);
    }

    @Test
    void numeroLongoQueNaoEhCartaoFicaComoEstava() {
        assertEquals("1234567890123456", AttackEvidence.build("1234567890123456", "server.request.query:id", null, null).getAsJsonObject("payload").get("value").getAsString());
    }

    @Test
    void truncaEmDuzentosECinquentaESeis() {
        var payload = AttackEvidence.build("a".repeat(600), "server.request.query:q", null, null).getAsJsonObject("payload");
        assertEquals(256, payload.get("value").getAsString().length());
        assertTrue(payload.get("truncated").getAsBoolean());
    }

    @Test
    void consultaRedigeSoOsCamposSensiveis() {
        assertEquals("q=%27%20OR%201%3D1--&password=<redacted>&Token=<redacted>&page=2", AttackEvidence.redactQuery("q=%27%20OR%201%3D1--&password=abc&Token=zzz&page=2"));
    }

    @Test
    void cabecalhosSoDaListaPermitidaENuncaAutorizacaoOuCookie() {
        var headers = AttackEvidence.safeHeaders(Map.of("user-agent", "curl/8", "authorization", "Bearer abcdefghijkl", "cookie", "s=1", "x-session-id", "abc", "referer", "https://a.example/x", "x-custom", "y", "accept", List.of("a", "b")));
        assertEquals("curl/8", headers.get("user-agent"));
        assertEquals("https://a.example/x", headers.get("referer"));
        assertEquals("a, b", headers.get("accept"));
        assertEquals(3, headers.size());
    }

    @Test
    void matchNaRespostaNaoEhPayload() {
        assertNull(AttackEvidence.build("500", "server.response.status", null, Map.of()));
    }

    @Test
    void guardaOTrechoDestacadoQuandoEstaNoValor() {
        var payload = AttackEvidence.build("') UNION SELECT sql FROM t--", "server.request.query:q.0", null, null, "union select", false).getAsJsonObject("payload");
        assertEquals("union select", payload.get("highlight").getAsString());
    }

    @Test
    void descartaOTrechoAusenteOuRedigido() {
        assertFalse(AttackEvidence.build("abc", "server.request.query:q", null, null, "xyz", false).getAsJsonObject("payload").has("highlight"));
        assertFalse(AttackEvidence.build("abc", "server.request.query:password", null, null, "abc", false).getAsJsonObject("payload").has("highlight"));
    }

    @Test
    void iastSemPrefixoDeRequisicao() {
        assertEquals("1' OR '1'='1", AttackEvidence.build("1' OR '1'='1", "query:q", null, null, null, true).getAsJsonObject("payload").get("value").getAsString());
    }

    @Test
    void contextoDoIastTrazSoConsultaECabecalhos() {
        var evidence = AttackEvidence.build(null, null, "q=a&password=x", Map.of("user-agent", "curl/8"));
        assertFalse(evidence.has("payload"));
        assertEquals("q=a&password=<redacted>", evidence.get("query").getAsString());
        assertEquals("curl/8", evidence.getAsJsonObject("headers").get("user-agent").getAsString());
    }

    @Test
    void semNadaAMostrarDevolveNulo() {
        assertNull(AttackEvidence.build(null, null, "", Map.of()));
    }
}
