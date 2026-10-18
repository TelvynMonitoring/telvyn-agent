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

    static AgentBuilder builder() {
        return new AgentBuilder.Default().disableClassFormatChanges().with(SHARED);
    }
}
