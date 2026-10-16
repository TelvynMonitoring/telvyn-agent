package com.example.demo;

import java.util.List;

/**
 * Programa de teste do Exception Replay (Passo 3). Roda SEM probe explícito —
 * só apontando o pacote:
 *   java -Dtelvyn.debug.exceptions=com.example.demo \
 *        -javaagent:target/telvyn-debugger-0.1.0.jar \
 *        -cp target/classes com.example.demo.DemoApp
 * Esperado: no caminho de sucesso, NADA é fotografado. Quando cobrar() quebra, o
 * erro sobe por cobrar() e processarPedido() — e o plugin tira UMA foto por
 * degrau (cada um com os seus args), automaticamente.
 */
public class DemoApp {

    public static void main(String[] args) throws Exception {
        DemoApp app = new DemoApp();

        // Modo loop (DEMO_LOOP_SECONDS): fica chamando processarPedido() que quebra,
        // a cada 2s, por N segundos. Serve pra provar a config remota: começa SEM
        // ponto (nenhuma foto) e, quando alguém liga o ponto na tela, as fotos
        // passam a sair sozinhas — sem reiniciar.
        String loop = System.getenv("DEMO_LOOP_SECONDS");
        if (loop != null && !loop.isBlank()) {
            long end = System.currentTimeMillis() + Long.parseLong(loop.trim()) * 1000L;
            int n = 0;
            while (System.currentTimeMillis() < end) {
                try { app.processarPedido("4111111111111111", -5, "hunter2"); } catch (RuntimeException e) { n++; }
                Thread.sleep(2000);
            }
            System.out.println("=> loop terminou (" + n + " quebras). aguardando envio…");
            Thread.sleep(3000); // deixa a thread de envio esvaziar a fila
            return;
        }

        // Caminho de sucesso: passa um cartão real (deve aparecer mascarado) e uma
        // senha (nome de parâmetro sensível → mascarada pelo nome), além de um
        // valor normal (250) que DEVE continuar visível.
        System.out.println("=> sucesso: " + app.processarPedido("4111111111111111", 250, "hunter2"));
        try {
            app.processarPedido("4111111111111111", -5, "hunter2");
        } catch (RuntimeException e) {
            System.out.println("=> caiu como esperado: " + e.getMessage());
        }
    }

    String processarPedido(String cartao, int valor, String senha) {
        return "pedido[" + cobrar(cartao, valor, List.of("nota"), senha) + "]";
    }

    String cobrar(String cartao, int valor, List<String> anexos, String senha) {
        if (valor < 0) {
            throw new IllegalArgumentException("valor inválido: " + valor);
        }
        return "ok:" + cartao.substring(cartao.length() - 4) + ":" + valor + ":anexos=" + anexos.size();
    }
}
