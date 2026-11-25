package system.monitoring.debugger;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IastRouteScopeTest {
    @Test
    void semListaDeRotasASomaDaFlagLigaTodasAsRotas() {
        String before = System.getProperty("telvyn.iast.enabled");
        try {
            System.clearProperty("telvyn.iast.enabled");
            assertFalse(SpringMvcSecurity.inScope("GET", "/users/{id}"));
            System.setProperty("telvyn.iast.enabled", "true");
            assertTrue(SpringMvcSecurity.inScope("GET", "/users/{id}"));
            assertTrue(SpringMvcSecurity.servletSelected("POST", "/login"));
        } finally {
            if (before == null) System.clearProperty("telvyn.iast.enabled"); else System.setProperty("telvyn.iast.enabled", before);
        }
    }
}
