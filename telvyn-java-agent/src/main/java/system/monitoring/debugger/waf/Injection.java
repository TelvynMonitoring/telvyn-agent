package system.monitoring.debugger.waf;

import com.dylibso.chicory.runtime.ExportFunction;
import com.dylibso.chicory.runtime.Instance;
import com.dylibso.chicory.runtime.Memory;
import java.nio.charset.StandardCharsets;

/**
 * Detecção de SQL injection e XSS pelo libinjection (sem modificação), compilado para WebAssembly
 * (tools/libinjection-wasm) e convertido em bytecode Java no build: roda na JVM, sem biblioteca nativa.
 * Uma instância por thread (a memória do módulo não é compartilhada).
 */
final class Injection {
    private static final int MAX_INPUT = 64 * 1024;

    private static final class Module {
        final Instance instance;
        final Memory memory;
        final ExportFunction alloc, free, sqli, xss;

        Module() {
            instance = Instance.builder(LibInjectionModule.load()).withMachineFactory(LibInjectionModule::create).build();
            memory = instance.memory();
            alloc = instance.export("tlv_alloc");
            free = instance.export("tlv_free");
            sqli = instance.export("tlv_sqli");
            xss = instance.export("tlv_xss");
        }

        boolean run(ExportFunction function, String value) {
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            if (bytes.length == 0) return false;
            int length = Math.min(bytes.length, MAX_INPUT);
            int pointer = (int) alloc.apply(length)[0];
            if (pointer == 0) return false;
            try {
                memory.write(pointer, bytes, 0, length);
                return function.apply(pointer, length)[0] == 1;
            } finally { free.apply(pointer); }
        }
    }

    private static final ThreadLocal<Module> MODULE = ThreadLocal.withInitial(Module::new);

    private Injection() {}

    static boolean isSqli(String value) { return MODULE.get().run(MODULE.get().sqli, value); }

    static boolean isXss(String value) { return MODULE.get().run(MODULE.get().xss, value); }
}
