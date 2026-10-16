> Atualização 12/10: o laboratório Quarkus agora consome o pacote reutilizável
> [`telvyn-security-quarkus`](../../../telvyn-security-quarkus/README.md).
> Os comandos e evidências `quarkus-filter-1` abaixo são históricos; o adaptador
> manual `SecurityLab.java` mantém o contrato antigo. Para a integração atual,
> use `-Dtelvyn.security.enabled=true`, as dependências do POM e a nova recepção
> `/api/ingest/v1/security/events`. O laboratório permite HTTP somente na rede local.
> A recepção nova foi ativada e validada localmente no backend f57c9f39; produção não foi alterada.
# Laboratório de detecção sem bloqueio

Escopo autorizado: somente `GET /security-lab/search`, parâmetro `q`, ambiente
`security-lab`. Há um adaptador explícito Java 21 e um filtro Quarkus 3.31.2 em
`quarkus/`. O filtro executa automaticamente antes do endpoint após ser instalado
na aplicação; não é instrumentação automática por Javaagent nem implementa IAST.
Não há ações de bloqueio nem leitura de corpo, cookies ou cabeçalhos de autenticação.

`LocalAttackDetection` usa `io.sqreen:libsqreen:17.5.0` / libddwaf 2.0.1, com duas
regras locais versionadas (`is_sqli`, `is_xss`). Não é o conjunto de regras do
produto Datadog. A resposta nativa contém entradas: só IDs conhecidos são extraídos,
sem registrar a resposta ou mensagens de exceção. Licenças ficam em
`src/main/resources/META-INF/licenses/libddwaf`.

Limites: query bruta até 8192 caracteres, q até 2048, orçamento nativo de 10 ms.
Carregamento inicial da biblioteca fica fora desse orçamento. Execuções são
serializadas no pequeno laboratório. Fila de envio: 64 eventos; falha/lotação é
explicitada na resposta ou no status HTTP do exportador. Não há promessa de entrega
completa, retenção automática, cobertura geral ou desempenho de produção. Query
com `q` repetido é reportada como limite, sem escolher silenciosamente um valor;
percent-encoding inválido em `q` é erro. Outros parâmetros não são decodificados.

Compilar o Javaagent com `mvn -Dmaven.test.skip=true package`. O diagnóstico pontual
`java -cp target/telvyn-debugger-0.1.0.jar labs/security/DetectorCheck.java` verifica
negativo, SQLi, XSS, desligado e limite; não é suíte nem substitui a tela.

`SecurityLab.java` reutiliza o SDK OpenTelemetry e o relay do laboratório existente.
Compilar com o Javaagent e os jars OpenTelemetry no classpath. Executar com a
identidade/token do laboratório existente, sem compartilhá-lo com outros hosts,
`TELVYN_ENV=security-lab` e `-Dtelvyn.security.lab.enabled=true` (padrão false).
Publicar porta somente em loopback. Não anexar o Javaagent nem habilitar snapshots
nessa JVM: o adaptador já chama o detector e não deve capturar valores de entrada.

A API receptora `/api/ingest/v1/security/lab` exige token de agente com escopo traces
e a opção local `telvyn.security.lab.ingest-enabled=true` (padrão false). Aceita
somente identificação, resultado, regras/engine, duração e contexto real do trace.
Tabela com RLS; leitura exige plano VULN e OPS_VULNERABILITIES_VIEW, conservando
serviço/ambiente/versão/período. Tags primárias não coletadas são explicitamente
incompatíveis. Instante exibido é o recebimento, não horário de um ataque inferido.

Validação manual realizada em12/10/2026 após uma ativação autorizada: chamadas normal, SQLi, XSS,
fora da rota/query permitida, excesso e detector desligado; todas as chamadas
válidas devem concluir sem bloqueio. Conferidos eventos e traces reais, ausência de
conteúdo bruto, filtros e temas claro/escuro em Serviço → Segurança. Laboratório encerrado; evidências no item3 do roteiro. Não marcar
o item 3 inteiro como concluído por este laboratório.

## Filtro Quarkus

`SearchResource` não chama o detector nem lê a query. `AttackFilter` usa o filtro
de requisição pós-matching do Quarkus, no worker da rota `@Blocking`, sem abortar
requisições. Compartilha detector, parser e exportador sanitizado com o laboratório
manual. Cria spans apenas com a rota normalizada, resultado HTTP e identidade do
serviço; não usa instrumentação HTTP que serialize a URL com query.

Depois de compilar o detector, registre o jar somente no cache Maven local:

```sh
mvn install:install-file -Dfile=target/telvyn-debugger-0.1.0.jar -DgroupId=system.monitoring -DartifactId=telvyn-debugger-lab -Dversion=quarkus-filter-1 -Dpackaging=jar -DgeneratePom=true
mvn -f labs/security/quarkus/pom.xml -Dmaven.test.skip=true package
java -Dtelvyn.security.lab.enabled=true -jar labs/security/quarkus/target/quarkus-app/quarkus-run.jar
```

Use a identidade privada do laboratório, `TELVYN_SERVICE=telvyn-security-lab`,
`TELVYN_ENV=security-lab` e `TELVYN_VERSION=quarkus-filter-1`, na rede do relay
existente. Porta8089 somente em loopback; não anexar Javaagent. Omitir a propriedade
desliga a inspeção e não carrega a engine nativa. Exportação pode perder eventos
em falhas/fila cheia/encerramento; o endpoint mantém sua resposta normal.

Aceite12/10: sete eventos reais (normal, SQLi, XSS, outro parâmetro, `q` duplicado,
`q` acima do limite e desligado por padrão), todos correlacionados a spans reais.
`GET /security-lab/outside` retornou200 sem evento; POST retornou405 pelo framework
sem evento. Sete GETs autorizados retornaram200 e o mesmo corpo. Tela, detalhes,
claro/escuro e recarga conferidos. Backend547bb59c permaneceu ativo sem restart;
laboratório encerrado. Ver item3 do roteiro para evidências e limites pendentes.

## Diagnóstico das classes e entradas do IAST além de SQL (15/10)

`IastSinksCheck.java` exercita, sem executar nada de verdade, as classes comando, caminho de arquivo, SSRF, código, NoSQL, redirecionamento, cabeçalho, hash fraco, cifra fraca e cookies, e as entradas query, rota, cabeçalho e cookie, com o agente em modo só IAST. Comandos inexistentes, arquivos inexistentes, URLs só construídas; servlet, script e expressão são `Proxy` que não processam nada; `stubs/org/bson/Document.java` substitui o driver do MongoDB (não é o driver). Não é suíte e não substitui a tela.

```sh
mvn -Dmaven.test.skip=true package        # na pasta telvyn-debugger
J=target/telvyn-debugger-0.1.0.jar
CP=$J:jakarta.ws.rs-api-3.1.0.jar:jakarta.servlet-api-6.0.0.jar:spring-expression-6.2.19.jar
javac -d out labs/security/stubs/org/bson/Document.java
javac -d out -cp $CP:out labs/security/IastSinksCheck.java
java -ea -javaagent:$J=iast-only -Dtelvyn.iast.enabled=true \
  -Dtelvyn.iast.application-package=system.monitoring.securitylab. \
  -cp out:$CP system.monitoring.securitylab.IastSinksCheck
```

O mesmo comando sem `-javaagent` deve falhar com `AssertionError` (controle negativo). Se `JAVA_TOOL_OPTIONS` apontar para outro agente, limpe-o antes (`unset JAVA_TOOL_OPTIONS`).
