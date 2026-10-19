# Spring MVC: segurança pelo Javaagent

## Estado atual — 12/10/2026

Integração reutilizável validada no Telvyn, com o Javaagent existente. A configuração abaixo continua vigente; registros de rodadas anteriores neste arquivo não são pendências atuais.

- Java17: Boot3.3.13/Framework6.1.21, Boot3.4.13/Framework6.2.15 e Boot3.5.6/3.5.16 (Framework6.2.11/6.2.19). Java21: Boot3.5.6/3.5.16. O Javaagent agora usa bytecode17; APIs de threads virtuais e contadores opcionais dependem da JVM efetiva.
- MVC, JDBC/JdbcTemplate, JPA/HQL/native, repositories vinculados, Callable/Future/DeferredResult/@Async, WebAsyncTask e Executor.execute/submit foram exercitados com positivos, negativos e desligamento. Callbacks da aplicação são preservados. PostgreSQL16.14/JDBC42.7.7 e MySQL8.4.11/Connector9.4.0 foram validados em Java17/Boot3.5.6, além de H2.
- A referência externa ficou operacional em laboratório separado; JdbcTemplate e consultas async mostraram os mesmos métodos/linhas observados no Telvyn. O Telvyn mantém ocorrências por trace; a referência agrega vulnerabilidades por localização. Não inferir equivalência de toda a plataforma.
- Carga: todas2600chamadas por JVM terminaram HTTP200/consulta concluída; p95 local6,67ms ligado/5,35ms desligado. A rajada atingiu a fila64:211eventos abaixo do total esperado, com descarte registrado; vinte novas chamadas após drenagem recuperaram20detecções/dezIAST. Sem spool/retry/garantia de entrega integral. IAST limita um finding por estado/requisição.
- Escopo continua somente `q`, pacote e rotas explícitos, sem bloqueio ou conteúdo bruto exportado. Não certifica Boot2/Spring5/Java8–11, native-image, callbacks externos/Scheduled, todos os patches/servidores/drivers ou produção. Boot3.3/3.4 encerraram suporte open-source segundo Spring; os ensaios não atualizam essas aplicações.

Pacote validado: SHA256 `b5f4fcc0b9a7b9c709f70d0ec0a9422758112f3a4212e963986642d3b857edb1`, somente JVMs de laboratório. Aceites, runtime e evidências em [roteiro vigente](../../../../docs/APM-PARITY-REMAINING.md). Nenhum deploy/restart do backend ocorreu nesta conclusão. O filtro `LabTracing` pode ser desligado com `lab.tracing.enabled=false` para referências com outro tracer; padrão preserva o tracing Telvyn.

Integração opt-in no `telvyn-debugger`, sem dependência adicional de segurança nem alterações em cada controller. Validada localmente com Java21, Spring Boot3.5.6, Spring Framework6.2.11, Tomcat10.1.46 e H2. Não é declaração de suporte a todo o ecossistema Spring.

Configuração para aplicações reais:

```text
TELVYN_AGENT_URL=http://<coletor-Telvyn>:4318   # opcional; senão OTEL_EXPORTER_OTLP_ENDPOINT, senão http://localhost:4318
TELVYN_SERVICE=<servico>
TELVYN_ENV=<ambiente>
TELVYN_VERSION=<versao>
```

```sh
java -javaagent:/path/telvyn-debugger-0.1.0.jar \
  -Dtelvyn.security.spring.enabled=true \
  -Dtelvyn.security.enabled=true \
  -Dtelvyn.iast.enabled=true \
  -Dtelvyn.iast.application-package=com.company.application. \
  '-Dtelvyn.security.query-routes=GET /search,GET /items' \
  -jar application.jar
```

O hook de despacho Spring MVC usa a rota reconhecida pelo framework e o método HTTP real. Somente `q` das rotas explicitamente selecionadas é processado; `@RequestParam("q")` e `@RequestParam(name="q")` são fontes. Não inspeciona corpo, cookies, headers ou SQL/valores vinculados para exportação. Os eventos vão ao coletor Telvyn local, que repassa ao backend com a credencial dele. Sem bloqueio de tráfego.

Reutiliza detector, duas regras SQLi/XSS, filas64, exportador sanitizado, APIs, RLS, retenção e estados do SDK. O código de aplicação é instrumentado pelo pacote explícito. IAST preserva identidade pela concatenação/trim/toLowerCase suportados; sinks JDBC e os métodos síncronos do JdbcTemplate com primeiro argumento SQL String (`execute/query/queryForList/queryForObject/update/batchUpdate`). Parâmetros vinculados não são texto SQL. Para JdbcTemplate, método/linha vêm da pilha de execução do chamador no pacote configurado.

Sensor desligado (`telvyn.security.enabled=false`, `telvyn.iast.enabled=false`) não analisa/exporta eventos de segurança; relatórios SDK de estado continuam disponíveis. A integração é registrada ao primeiro despacho MVC; relatórios anteriores à inicialização permanecem ausentes/não reportados conforme o instante observado. Inicialização tem custo no primeiro despacho: nesta validação houve fluxo IAST de602585µs, não representa overhead isolado. Falhas de análise/transporte e limites permanecem explícitos; envio não tem spool/retry/garantia de entrega.

A correlação reutiliza contexto OpenTelemetry válido da aplicação; sem ele, IDs ficam ausentes. `LabTracing` é somente a instrumentação real de traces da aplicação de laboratório, não um sensor de segurança ou fallback de trace fictício. O SLF4J do jar foi isolado no namespace previsto pela biblioteca nativa WAF, para não substituir o Logback do Spring Boot.

Limites: métodos síncronos String/List/ResponseEntity; uso de ResponseEntity, outros overloads JdbcTemplate, herança/proxies, Spring Data/JPA, async/Callable/DeferredResult, WebFlux e outras versões não foram validados nesta rodada. Não declarar cobertura universal. O agent novo foi exercitado no laboratório, não ativado no backend Quarkus nem implantado em produção.

## Ampliação validada em 12/10/2026: async e Spring Data/JPA

Mesmo Javaagent, flags, ingest e allowlist acima. Java21/Boot3.5.6/Spring6.2.11, Hibernate6.6.29.Final. Sem código de segurança nos controllers/repositories.

- Async: retorno `Callable`, `CompletableFuture`/`CompletionStage`, `DeferredResult` e serviço `@Async`; captura por tarefa e restauração em `finally`. Chamadas `supplyAsync`, `runAsync`, `thenApplyAsync` dentro do pacote configurado são instrumentadas. A finalização libera a proveniência; Future cancelado, exceção de Callable e cancelamento Reactor passaram em diagnóstico pontual. Não cobre automaticamente todo Executor, operador Future, callback externo, thread criada manualmente ou `WebAsyncTask`.
- JPA: texto concatenado em `EntityManager.createQuery/createNativeQuery` usa sinks existentes. Consultas parametrizadas, método derivado de repository e `@Query` estática foram negativos reais. Entrega do texto à API é o achado, não prova exploração. Não instrumenta conteúdo de parâmetros vinculados.
- Rodada final `batch-accepted`:27 chamadas (24x200/3x500 controlados),27 detecções sem sinal e10 IAST: dois JPA e oito async (quatro modos iniciais + quatro chamadas concorrentes). Sequência erro→parametrizada e oito chamadas simultâneas passaram, todos37 eventos ligados aos spans reais. `batch-disabled`:13x200/13spans, nenhum evento.

WebFlux tem laboratório e requisitos próprios em [../webflux/README.md](../webflux/README.md). Evidências e diagnósticos em `artifacts/apm-spring-expanded-20261012`. AgentSHA43edaae9ad05a6c1852c884deb583f39634b9a3858c1f62f71b1a2db7fcb486e, ativado somente nas JVMs Spring de validação. Backend Quarkus74c3764c preservado. Esta ampliação substitui as pendências async/JPA da rodada síncrona anterior; não declara cobertura universal nem medição sustentada de overhead.

## WebAsyncTask e Executor aceitos localmente
O mesmo agente captura Callable construído em WebAsyncTask e Executor.execute/ExecutorService.submit com Runnable,Callable ou Runnable+resultado no pacote configurado. Usa fonte q/rotas explícitas e preserva callbacks da aplicação: a limpeza de DeferredResult compõe marcadores com callbacks existentes, sem substituir setters normais.32chamadas instrumentadas/noveIAST esperados,20callbacks reais preservados; vinculadas,constantes,timeout controlado,erros,concorrência e desligamento aceitos. Método/linha/IDs e claro/escuro conferidos. Java21/Boot3.5.6/Spring6.2.11; limites de timeout interrompido,exteriores/Scheduled/terceiros e versões no roteiro. Sem alteração de API/backend/produção.
