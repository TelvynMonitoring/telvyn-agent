package runner;

import java.lang.reflect.Method;

/**
 * Driver de teste em OUTRO pacote (não com.example.) — fica chamando
 * com.example.demo.DemoApp.processarPedido() por fora. Serve pra isolar a config
 * remota: nenhum método de com.example. fica preso na pilha durante a espera, só
 * runner.Loop.main (que NÃO é instrumentado). Assim, quando o ponto liga e a
 * classe é reescrita ao vivo, as chamadas seguintes são invocações novas.
 */
public class Loop {
    public static void main(String[] a) throws Exception {
        Object app = Class.forName("com.example.demo.DemoApp")
                .getDeclaredConstructor().newInstance();
        Method m = app.getClass().getDeclaredMethod("processarPedido", String.class, int.class);
        m.setAccessible(true);

        long secs = Long.parseLong(System.getenv().getOrDefault("DEMO_LOOP_SECONDS", "14"));
        long end = System.currentTimeMillis() + secs * 1000L;
        int n = 0;
        while (System.currentTimeMillis() < end) {
            try { m.invoke(app, "xx", -5); } catch (Exception e) { n++; }
            Thread.sleep(2000);
        }
        System.out.println("=> loop terminou (" + n + " quebras). aguardando envio…");
        Thread.sleep(3000);
    }
}
