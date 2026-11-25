package system.monitoring.debugger;

import jakarta.ws.rs.QueryParam;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

/** O IAST deve acompanhar a entrada de um handler seja qual for o tipo que ele retorna (objeto próprio, mapa, void...). */
class IastHandlerReturnTypeTest {
    record Resultado(String texto) {}
    private final List<IastRuntime.Finding> findings = new ArrayList<>();

    public Resultado devolveObjetoProprio(@QueryParam("account") String account) { return new Resultado(account); }
    public java.util.Map<String, String> devolveMapa(@QueryParam("account") String account) { return java.util.Map.of("a", account); }
    public void naoDevolveNada(@QueryParam("account") String account) { }
    public String devolveTexto(@QueryParam("account") String account) { return account; }

    @AfterEach
    void limpa() { IastRuntime.configure(null); IastRuntime.configureSources(null); }

    private void acompanhaAEntrada(String handler) throws Exception {
        IastRuntime.configure(findings::add);
        IastRuntime.configureSources(method -> true);
        Method method = null;
        for (Method candidate : getClass().getMethods()) if (candidate.getName().equals(handler)) method = candidate;
        String entrada = new String("Smith' OR '1'='1");
        Object anterior = IastRuntime.enter(method, new Object[]{entrada});
        try { IastRuntime.jdbc(entrada, "app.Repo#find", 10, "java.sql.Statement.executeQuery"); }
        finally { IastRuntime.exit(anterior); }
    }

    @Test
    void handlerQueDevolveTexto() throws Exception {
        acompanhaAEntrada("devolveTexto");
        assertEquals(1, findings.size());
    }

    @Test
    void handlerQueDevolveObjetoProprio() throws Exception {
        acompanhaAEntrada("devolveObjetoProprio");
        assertEquals(1, findings.size(), "o handler que devolve um objeto próprio não foi acompanhado");
        assertEquals("query:account", findings.get(0).source());
        assertEquals("Smith' OR '1'='1", findings.get(0).value());
    }

    @Test
    void handlerQueDevolveMapa() throws Exception {
        acompanhaAEntrada("devolveMapa");
        assertEquals(1, findings.size());
    }

    @Test
    void handlerSemRetorno() throws Exception {
        acompanhaAEntrada("naoDevolveNada");
        assertEquals(1, findings.size());
    }
}
