package system.monitoring.debugger;

import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

/**
 * Código injetado (inline) no início e no fim de cada método com probe. Ele NÃO
 * para o método — só lê os valores e entrega pro {@link SnapshotSink}, que faz a
 * "foto" fora do caminho crítico. Mantido minúsculo de propósito (ByteBuddy
 * copia este bytecode pra dentro do método-alvo).
 */
public final class CaptureAdvice {

    @Advice.OnMethodEnter(suppress = Throwable.class)
    static long enter() {
        // Só marca o início; a foto é tirada UMA vez na saída (entrada + saída juntas).
        return System.nanoTime();
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    static void exit(@Advice.Origin("#t.#m") String method,
                     @Advice.Origin java.lang.reflect.Method reflected,
                     @Advice.Enter long startNanos,
                     @Advice.AllArguments Object[] args,
                     @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object returned,
                     @Advice.Thrown Throwable thrown) {
        SnapshotSink.onCall(method, args, returned, thrown, System.nanoTime() - startNanos, reflected);
    }
}
