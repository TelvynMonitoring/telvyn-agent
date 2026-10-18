package system.monitoring.debugger;

import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;
import net.bytebuddy.matcher.ElementMatcher;

/**
 * Pré-filtro por class loader para as instrumentações por hierarquia (hasSuperType): só examina as classes de um
 * class loader que enxerga o tipo-alvo (por exemplo, o Servlet ou o Spring Security), com o resultado em cache por
 * class loader. Sem ele, a hierarquia de toda classe carregada é resolvida em cada instrumentação, o que multiplica
 * o tempo de subida da aplicação.
 */
final class LoaderMatchers {
    private LoaderMatchers() {}

    /** Class loader que enxerga ao menos um dos tipos (nomes completos). */
    static ElementMatcher<ClassLoader> canSee(String... types) {
        Map<ClassLoader, Boolean> cache = Collections.synchronizedMap(new WeakHashMap<>());
        return loader -> {
            if (loader == null) return false;
            return cache.computeIfAbsent(loader, candidate -> {
                for (String type : types) if (candidate.getResource(type.replace('.', '/') + ".class") != null) return true;
                return false;
            });
        };
    }
}
