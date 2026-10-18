package system.monitoring.debugger;

import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.pool.TypePool;

/**
 * Base das instrumentações por hierarquia (hasSuperType): um cache de tipos compartilhado por class loader, como o
 * OpenTelemetry e o Datadog fazem. Sem ele, cada classe carregada faz o ByteBuddy reler os arquivos de classe de
 * toda a hierarquia em cada instrumentação, o que multiplicava o tempo de subida (Spring Boot de 5,6 s para 23,7 s).
 * O class loader fica em referência fraca e o cache em referência suave: sem vazamento quando a aplicação descarta
 * class loaders, e a JVM pode liberar o cache sob pressão de memória.
 */
final class Agents {
    private static final AgentBuilder.PoolStrategy SHARED = new AgentBuilder.PoolStrategy.WithTypePoolCache(TypePool.Default.ReaderMode.FAST) {
        private final Map<ClassLoader, TypePool.CacheProvider> caches = Collections.synchronizedMap(new WeakHashMap<>());
        private final TypePool.CacheProvider bootstrap = new TypePool.CacheProvider.Simple.UsingSoftReference();

        @Override
        protected TypePool.CacheProvider locate(ClassLoader classLoader) {
            return classLoader == null ? bootstrap : caches.computeIfAbsent(classLoader, loader -> new TypePool.CacheProvider.Simple.UsingSoftReference());
        }
    };

    private Agents() {}

    /** Falha ao instrumentar uma classe: uma linha por classe, para não passar despercebida (o ByteBuddy é silencioso). */
    private static final AgentBuilder.Listener ERRORS = new AgentBuilder.Listener.Adapter() {
        @Override
        public void onError(String typeName, ClassLoader classLoader, net.bytebuddy.utility.JavaModule module, boolean loaded, Throwable throwable) {
            // Tipo que não se resolve durante a checagem de hierarquia não é falha de instrumentação.
            if (throwable instanceof TypePool.Resolution.NoSuchTypeException) return;
            System.err.println("[telvyn] instrumentation failed for " + typeName + TelvynDebuggerAgent.reason(throwable));
        }
    };

    static AgentBuilder builder() {
        return new AgentBuilder.Default().disableClassFormatChanges().with(SHARED).with(ERRORS)
            // Classes de outros agentes (OpenTelemetry) e do próprio ByteBuddy nunca são alvo.
            .ignore(net.bytebuddy.matcher.ElementMatchers.any(), net.bytebuddy.matcher.ElementMatchers.isBootstrapClassLoader())
            .or(net.bytebuddy.matcher.ElementMatchers.nameStartsWith("io.opentelemetry.javaagent.")
                .or(net.bytebuddy.matcher.ElementMatchers.nameStartsWith("net.bytebuddy."))
                .or(net.bytebuddy.matcher.ElementMatchers.nameStartsWith("system.monitoring.debugger."))
                .or(net.bytebuddy.matcher.ElementMatchers.isSynthetic()));
    }
}
