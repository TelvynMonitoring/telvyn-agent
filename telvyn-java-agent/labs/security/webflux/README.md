# WebFlux: segurança pelo Javaagent

## Estado atual — 12/10/2026

A configuração abaixo continua vigente; registros anteriores de preparação/ativação não são checklists atuais. O mesmo Javaagent foi validado com Java17/Boot3.3.13,3.4.13,3.5.6,3.5.16 e Java21/Boot3.5.6,3.5.16, em Netty. Sem nova dependência de segurança na aplicação.

- Cobertos nos ensaios: controllers Mono/Flux, RouterFunctions diretas/aninhadas via DispatcherHandler e `toHttpHandler`, corpo adiado, cancelamento, concorrência, R2DBC SPI/DatabaseClient String/Supplier/PreparedOperation dinâmico e vinculado, repositories/EntityTemplate, retry, cache compartilhado e múltiplas assinaturas frias dentro da mesma requisição.
- Micrometer context-propagation compatível continua obrigatório. Consultas vinculadas/Criteria/derivadas/@Query estática e constantes não geraram IAST. Um finding por estado/requisição; compartilhar publishers entre requests ou SpEL dinâmico não foi certificado.
- A referência externa mostrou SQL Injection em `FluxLab#query`, também observado no Telvyn. Não apresentou achados R2DBC nessa rodada; não inferir equivalência ou ausência universal de suporte. API98f9b904 permaneceu ativa sem novo restart; regra R2DBC/RLS/retenção existentes foram reutilizadas.
- JavaagentSHA256 `b5f4fcc0b9a7b9c709f70d0ec0a9422758112f3a4212e963986642d3b857edb1`, somente laboratórios. Flags/pacote/rotas explícitos, apenas `q`, sem corpo/cookies/headers/SQL exportado ou bloqueio. Sem deploy. Matriz, limites de versões/drivers e fila de envio no [roteiro vigente](../../../../docs/APM-PARITY-REMAINING.md).

`lab.tracing.enabled=false` desliga filtro/contexto/exportação OTel auxiliares do laboratório para comparar outro tracer; não altera o sensor. O padrão mantém tracing Telvyn. Biblioteca e inicialização reativa da aplicação real continuam as descritas abaixo.

A configuração é a mesma do [Spring MVC](../spring/README.md), incluindo `telvyn.security.spring.enabled=true`, pacote explícito e rotas `GET /search` permitidas. Reutiliza detecção SQLi/XSS, IAST JDBC, ingest, RLS, retenção e painel. Não requer lógica de segurança em cada controller. Não lê body/cookies/headers; somente `q` permitido, em memória; exporta achado, método/linha e IDs reais de trace.

Validado: Java21, Spring Boot3.5.6/Framework6.2.11, Reactor3.7.11, Micrometer context-propagation1.1.3 e servidor Netty. Este laboratório usa H2 e consultas JDBC em `boundedElastic`; **não valida R2DBC**.

Para IAST reativo, a aplicação deve ter `io.micrometer:context-propagation` (versão compatível com seu Reactor). O agente registra dois ThreadLocalAccessor e ativa `Hooks.enableAutomaticContextPropagation`, mecanismo global suportado por Reactor, com estado de requisição armazenado no Context de cada assinatura. Sem essa biblioteca, a integração registra erro; não afirmar cobertura. Essa ativação deve ser avaliada junto aos accessors existentes da aplicação antes de rollout.

O hook de `RequestMappingHandlerAdapter.handle` usa método/rota reconhecidos por Spring; `Mono` e `Flux` retornados pelo controller propagam proveniência em mudanças de scheduler. `doFinally` libera o estado em conclusão, erro ou cancelamento. IDs são capturados do contexto OTel válido, nunca inventados. `FluxTracing` é tracing real do laboratório, não sensor de segurança.

Rodada `flux-accepted`:14 chamadas (13x200/1x500 controlado),14 detecções sem sinal e6 IAST (duas consultas concatenadas Mono/Flux e quatro concorrentes), todos20 eventos ligados aos14 spans reais. Parâmetros vinculados, erro→parametrizada e oito chamadas simultâneas não contaminaram outros fluxos. Cancelamento validado em diagnóstico de assinatura Reactor, não por desconexão HTTP. `flux-disabled`:4x200/4spans e nenhum evento. Tela claro/escuro, método/linha/trace e estados de sensor conferidos.

Limites: controllers anotados e fontes/transformações/sinks já descritos; rotas funcionais, R2DBC, múltiplas assinaturas/retry/share, outros adaptadores e versões não validados. Não é paridade integral, proteção ou overhead certificado.

Build: `mvn -Dmaven.test.skip=true package`, sem suíte. AgentSHA43edaae9ad05a6c1852c884deb583f39634b9a3858c1f62f71b1a2db7fcb486e, somente nas JVMs Spring locais. Backend Quarkus74c3764c e produção preservados. Evidências em `artifacts/apm-spring-expanded-20261012`.

## R2DBC — implementado, aguardando ativação/aceite (12/10/2026)

Reutiliza o mesmo Javaagent e contexto Reactor. Hooks no pacote explícito para `io.r2dbc.spi.Connection.createStatement(String)` e `org.springframework.r2dbc.core.DatabaseClient.sql(String/Supplier<String>)`; valores de `bind` não são SQL. Supplier é avaliado no contexto da assinatura, mantém retorno/exceção e informa o método/linha da chamada registrada. PreparedOperation preservado como objeto original para não perder bindTo; caso vinculado executou sem alteração. PreparedOperation com SQL dinâmico e outros wrappers não está comprovado por esse caso.

Regra sanitizada própria `iast-q-r2dbc-1`, sem representar R2DBC como JDBC. API foi ampliada para aceitar a regra, mantendo autenticação, schema, RLS e retenção; nenhum novo campo, endpoint ou migration. SHAagentc054f12ca8e4682fadadfac560ddf77850a3ac155bf58ca0cc09e57721149a21. Java21/Spring6.2.11/R2DBC-SPI1.0.0.RELEASE/H21.0.0.RELEASE. Laboratório usa R2DBC-H2 real, somente consultas locais SELECT.

Baseline r2dbc-before: nove chamadas executadas com200, nove spans, nove detecções no_match e nenhum IAST; lacuna confirmada na tela. Agent novo r2dbc-prepared:dez chamadas200/consulta completed (SPI, DatabaseClient String/Supplier, concatenadas/vinculadas/constantes e PreparedOperation vinculado). API74c3764c rejeitou nova regra com400; **não houve aceite IAST no painel ainda**. Diagnóstico pontual passou em proveniência Supplier, negativo vinculado, identidade PreparedOperation/null e descarte do estado finalizado. Backend/agent compilaram, frontend TypeScript passou, sem suítes.

Pacote preparado98f9b904 em security-r2dbc-20261012. Nenhum deploy/restart; backend74c3764c saudável, Javaagents existentes preservados, preflight passou. Próximo passo exclusivo: autorização de uma única ativação da API local e então repetir positivos/negativos, erro/concorrência/desligado e validar método/linha/trace em claro/escuro. Não avançar de ponto antes desse aceite. Configuração de aplicação real mantém flags/pacote/rotas do README; rota de laboratório `/flux-lab/r2dbc` adicionada somente ao laboratório/allowlist local.

## R2DBC concluído localmente em12/10/2026

A pendência de ativação acima foi cumprida: API98f9b904 ativa, único restart autorizado consumido; migration incremental V20261012160000 ampliou o CHECK omitido na preparação, aplicada por Flyway separado, sem outro restart, perda de dados/RLS ou alteração de migration anterior. Validação das definições do pacote ativo passou; próxima compilação deve incluir o novo arquivo.

31 chamadas reais (25x200/6x500 controlados),12IAST esperados nas três APIs/linhas18/28/29,43eventos ligados aos31spans. Parâmetros vinculados, constantes e PreparedOperation seguros sem achados; erros/12concorrentes e19sequenciais sem contaminação. Dez consultas com sensor desligado geraram dez spans e nenhum evento. Tela claro/escuro, métodos/linhas/trace/span, Atualizar e SDK ligado/desligado conferidos. Um timeout do detector separado foi exposto no painel; IAST passou, proteção integral não declarada. Conteúdo de query/SQL não encontrado nos eventos, RLS preservado.

Evidências completas no roteiro e artifacts/apm-r2dbc-20261012. Java21/Spring6.2.11/R2DBC-SPI/H21.0.0.RELEASE, mesmoJavaagent acima. Limites de outros drivers/versões/wrappers/PreparedOperation dinâmico/repositories e comparação interativa permanecem explícitos. Laboratórios encerrados; backend saudável, sem deploy/restart de outros serviços.

## WebFlux funcional — concluído localmente em12/10/2026

Mesmo Javaagent e configuração Spring/Micrometer acima. Suporte validado em Spring Boot3.5.6/Spring6.2.11/Java21 para RouterFunctions de paths, diretas/aninhadas, integradas ao DispatcherHandler. Configure rotas pelo padrão reconhecido pelo framework, inclusive GET /orders/{id}; somente q é fonte permitida. queryParam("q") e queryParams().getFirst("q") do ServerRequest padrão foram exercitados. Sem lógica de segurança nos handlers.

FunctionalWebFluxSecurity instrumenta HandlerFunctionAdapter, ServerRequest/DefaultServerRequest e ServerResponseResultHandler. O escopo existente de método/rota/parser é reaproveitado; proveniência pertence ao ServerWebExchange, não a um mapa global. Captura cobre montagem da resposta e sua escrita posterior, inclusive query adiada em boundedElastic. Contexto anterior restaurado no despacho; estado liberado em escrita concluída/erro/cancelamento, handler vazio/cancelado ou exceção síncrona. Diagnóstico assert-based confirmou que completar Mono<ServerResponse> não libera prematuramente o corpo. Biblioteca Micrometer e seus limites globais continuam os mesmos.

Baseline anterior:12HTTP200/consultas reais/12spans, nenhum evento funcional; primeiro hook detectou seis positivos, mas getFirst do mapa ainda não era fonte. Uma consulta real por mapa confirmou a lacuna; hook adicional captura exclusivamente a entrada q única, com limites existentes. Não inspeciona body/cookies/headers, outros parâmetros ou exporta SQL/q.

Aceite functional-final/1791821448–1791821500:45requisições reais (43HTTP200/um500 controlado/uma resposta cancelada).12IAST funcionais esperados +3da regressão anotada;42detecções (38no_match,duasmatch SQLi/XSS em consultas vinculadas,doislimit por duplicado/2049).57eventos ligados aos45spans;26sequenciais sem achados inesperados. Rotas aninhadas, mapa/Optional, SQL rejeitado, resposta vazia, oito concorrentes, POST/rota fora do escopo e parâmetro não permitido passaram. Cancelamento HTTP terminou span em351ms, antes da query adiada2s, sem IAST. Dez consultas anotadas anteriores continuaram passando.

functional-disabled:12HTTP200/12spans, nenhum evento; SDK disabled/disabled e active/active, detalhes reais, Atualizar IAST e tela claro/escuro/KIT conferidos. Valores de entrada/SQL ausentes dos eventos; spans apenas identidade/rota/status/host. Nenhuma suíte. Primeiro fluxo teve elapsed IAST1311884µs incluindo inicialização lazy, sem medição isolada ou sustentada de overhead.

Agentcode0c6ccfe2/SHAad0a65cb07651b70ff29ff402c6ac5fb2539c6e27763abee01b87dcb3bf7c950 somente nos laboratórios, encerrados após aceite. Backend98f9b904 saudável e sem restart desde2026-10-12T15:37:26.816548282Z; nenhuma nova autorização consumida, migration, deploy ou restart de serviços. Evidências artifacts/apm-functional-20261012. Referência de contrato: https://docs.spring.io/spring-framework/reference/web/webflux-functional.html .

O conjunto Spring pedido (MVC,async,JPA,WebFlux anotado/funcional,R2DBC) foi exercitado nos recortes documentados. Não declarar todo ecossistema/versões ou paridade integral: toHttpHandler direto sem DispatcherHandler, requests customizados, Kotlin, retry/share, outros drivers e APIs não exercitados mantêm limites explícitos.

## PreparedOperation dinâmico aceito
O Javaagent preserva a interface PreparedOperation e delega bindTo, examinando somente o SQL solicitado pelo DatabaseClient. Casos dinâmico/vinculado/constante, erro, concorrência e desligamento passaram em prepared-final: sete achados esperados ligados aos spans reais. Método/linha referem-se à chamada DatabaseClient.sql. Sem SQL ou bindings exportados; mesma configuração opt-in e versões acima. Provas e limites no roteiro.

## RouterFunctions.toHttpHandler direto aceito
Mesmo pacote/configuração, agora no servidor direto sem DispatcherHandler. Hook do RouterFunctionWebHandler cobre despacho e escrita reativos, incluindo métodos sintéticos pelas assinaturas Spring6.2.11.35chamadas reais/12IAST esperados; consultas vinculadas, erros, corpo adiado/cancelado, mapa, concorrência e desligamento passaram. Dois timeouts de detecção na inicialização expostos; não proteção integral. Outras versões e requests customizados exigem validação própria. Provas no roteiro.

## Spring Data R2DBC validado
Repositories findByName/@Query vinculada e R2dbcEntityTemplate Criteria executam consultas vinculadas e não geram IAST. SQL concatenado pelo DatabaseClient do template usa o sink existente:27chamadas reais/seisIAST esperados; negativos, erros, concorrência e desligamento aceitos. Não foi necessário alterar o sensor. Não comprova SpEL dinâmico em @Query. Mesmo opt-in,pacote e q permitido; provas no roteiro.
