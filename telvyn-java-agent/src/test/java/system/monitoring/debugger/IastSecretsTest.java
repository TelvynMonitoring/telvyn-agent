package system.monitoring.debugger;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class IastSecretsTest {
    @Test
    void reconheceFormatosDeToken() {
        // montados em pedaços para o repositório não conter tokens inteiros
        String[] tokens = {
            "AKIA" + "I".repeat(16),
            "ghp_" + "a".repeat(36),
            "github_pat_" + "A".repeat(82),
            "glpat-" + "x".repeat(20),
            "AIza" + "B".repeat(35),
            "sk_live_" + "a".repeat(24),
            "xoxb-" + "1".repeat(11) + "-" + "2".repeat(11) + "-abc",
            "SG." + "a".repeat(66),
            "npm_" + "a".repeat(36),
            "shpat_" + "a".repeat(32),
            "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
            "eyJ" + "a".repeat(18) + ".eyJ" + "b".repeat(18) + "." + "c".repeat(12),
        };
        for (String token : tokens) assertTrue(IastSecrets.secret(token), token);
    }

    @Test
    void textoComumNaoEhSegredo() {
        for (String text : new String[]{"hello world, this is a log message", "AKIA-not-a-key", "ghp_curto", "https://example.com/path?a=1", "12345678901234567890"})
            assertFalse(IastSecrets.secret(text), text);
    }
}
