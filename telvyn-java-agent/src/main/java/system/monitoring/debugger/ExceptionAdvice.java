package system.monitoring.debugger;

import net.bytebuddy.asm.Advice;

/**
 * Advice do "Exception Replay" (Passo 3): aplicado a TODOS os métodos de um
 * pacote configurado, mas só FAZ algo quando o método sai por uma exceção. Em
 * caminho de sucesso o custo é praticamente nulo (só checa {@code thrown==null}
 * e volta) — não renderiza nem envia nada. Quando quebra, fotografa os args
 * daquele método + o erro; como cada método do pacote tem isto, um erro que
 * sobe por N métodos gera N fotos (uma por degrau).
 */
public final class ExceptionAdvice {

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    static void exit(@Advice.Origin("#t.#m") String method,
                     @Advice.Origin java.lang.reflect.Method reflected,
                     @Advice.AllArguments Object[] args,
                     @Advice.Thrown Throwable thrown) {
        if (thrown != null) {
            SnapshotSink.onException(method, args, thrown, reflected);
        }
    }
}
