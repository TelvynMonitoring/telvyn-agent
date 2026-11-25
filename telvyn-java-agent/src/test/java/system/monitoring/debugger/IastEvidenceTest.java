package system.monitoring.debugger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import java.util.ArrayList;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class IastEvidenceTest {
    private final List<IastRuntime.Finding> findings = new ArrayList<>();

    @AfterEach
    void limpa() { IastRuntime.configure(null); }

    private Object abre() {
        IastRuntime.configure(findings::add);
        return IastRuntime.openRequest();
    }

    @Test
    void oAchadoLevaOValorDaEntradaQueChegouAoPontoSensivel() {
        abre();
        String entrada = new String("admin' OR 1=1--");
        IastRuntime.sourceParameter("q", entrada);
        IastRuntime.jdbc(entrada, "app.Repo#find", 10, "java.sql.Statement.executeQuery");
        assertEquals(1, findings.size());
        assertEquals("parameter:q", findings.get(0).source());
        assertEquals("admin' OR 1=1--", findings.get(0).value());
    }

    @Test
    void oValorSaiRedigidoQuandoOCampoESensivel() {
        abre();
        String entrada = new String("hunter2' OR 1=1--");
        IastRuntime.sourceParameter("password", entrada);
        IastRuntime.jdbc(entrada, "app.Repo#login", 20, "java.sql.Statement.executeQuery");
        var finding = findings.get(0);
        var payload = AttackEvidence.build(finding.value(), finding.source(), null, null, null, true).getAsJsonObject("payload");
        assertEquals("<redacted>", payload.get("value").getAsString());
        assertTrue(payload.get("redacted").getAsBoolean());
    }

    @Test
    void semFonteNaoHaValor() {
        abre();
        IastRuntime.jdbc(new String("SELECT 1"), "app.Repo#x", 5, "java.sql.Statement.executeQuery");
        assertTrue(findings.isEmpty());
    }
}
