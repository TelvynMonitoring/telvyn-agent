# Agente Java Telvyn

Agente `-javaagent` com profiling contínuo (JFR), IAST, detecção de ataques e debugger dinâmico. Roda ao lado
do agente OpenTelemetry Java e envia tudo ao coletor Telvyn local (`TELVYN_AGENT_URL`, senão
`OTEL_EXPORTER_OTLP_ENDPOINT`, senão `http://localhost:4318`); a aplicação não guarda credencial.

Distribuição: `/opt/telvyn/java/telvyn-javaagent.jar` no bundle `ghcr.io/telvynmonitoring/telvyn-runtime-agents`.
No Kubernetes o webhook do coletor copia o jar e acrescenta `-javaagent:/opt/telvyn/java/telvyn-javaagent.jar`
aos pods Java habilitados (`webhook.javaAgentImageRef`, por padrão o bundle). Os recursos seguem desligados até
as flags de cada um (`TELVYN_PROFILING_ENABLED`, `-Dtelvyn.iast.enabled=true` etc.).

Build: `mvn -Dmaven.test.skip=true package` (gera `target/telvyn-debugger-<versão>.jar`). Os diagnósticos em
`labs/` vieram do repositório da plataforma e citam caminhos de lá.

## Configuração remota

O agente consulta o coletor a cada 30 s (`/v1/sdk/remote-config`) e aplica, sem reiniciar, o que foi definido na tela do serviço (cartão "SDK e configuração", por serviço e ambiente): ligar/desligar os perfis de CPU, wall, alocação, lock e exceções e a detecção de ataques (Spring e Servlet); o IAST só pode ser desligado. Opção não definida na tela = vale a variável de ambiente. A revisão aplicada vai no relatório de configuração (`telvyn.remote_config.revision`).

Detecção e bloqueio de ataques (como o Datadog App and API Protection), em Spring MVC e Spring WebFlux: com a detecção ligada, o agente aplica o conjunto recomendado de regras do Datadog (`src/main/resources/telvyn/waf-rules.json`, ver `WAF-RULES-NOTICE.md`) a toda requisição — cabeçalhos, cookies, query, endereço, IP, parâmetros de rota, formulário, corpo do `@RequestBody`, status — e barra a requisição quando o IP ou o usuário (Spring Security, inclusive reativo) está bloqueado ou quando uma regra está em modo "bloquear". Fora do Spring, qualquer `HttpServlet` (Tomcat, Jetty, Undertow, servidores de aplicação, Jersey/RESTEasy sobre servlet) passa pela inspeção de cabeçalhos, cookies, query, endereço, IP e status desde a cadeia de filtros (requisições respondidas só por filtros também); corpo e parâmetros de rota fora do Spring ainda não são lidos.

IP do cliente: o primeiro IP público dos cabeçalhos de proxy comuns, como o Datadog. Com `-Dtelvyn.client-ip-header=x-real-ip` (ou `TELVYN_CLIENT_IP_HEADER`, como o `DD_TRACE_CLIENT_IP_HEADER`), só esse cabeçalho vale e os demais são ignorados — use atrás de um proxy conhecido para que o cliente não forje o IP.

Atividade de usuários (como os eventos automáticos do Datadog para Spring Security): login com sucesso, login com falha com `usr_exists` (pelo `UserDetailsService`) e cadastro (`UserDetailsManager.createUser`), só para login por usuário e senha; o login com sucesso de um usuário bloqueado recebe a resposta de bloqueio. Modo de coleta: `-Dtelvyn.security.user-tracking` / `TELVYN_SECURITY_USER_TRACKING` = `identification` (padrão), `anonymization` (`anon_` + SHA-256 truncado, formato do Datadog) ou `disabled`; a tela pode trocar o modo e `disabled` local sempre vale. Logins próprios: a dependência `system.monitoring:telvyn-java-api` (`TelvynSecurity.trackUserLoginSuccess/trackUserLoginFailure/trackUserSignup/setUser/isUserBlocked`, como o `EventTrackerV2` e o `Blocking` do Datadog) não faz nada sem o agente; com ele, o evento sai com o IP e o trace da requisição, e o usuário bloqueado é barrado. Nunca envia a senha. O Datadog não documenta eventos automáticos de login no Spring Security reativo, e este agente também não os coleta.

## Fora do Kubernetes (Docker, Portainer, Compose, AWS ECS/EC2)

Nada exige Kubernetes. Suba o coletor Telvyn como um container ou serviço acessível pela aplicação (como o
Datadog Agent) e configure a JVM com os dois agentes:

```text
JAVA_TOOL_OPTIONS=-javaagent:/opt/otel/opentelemetry-javaagent.jar -javaagent:/opt/telvyn/java/telvyn-javaagent.jar
OTEL_EXPORTER_OTLP_ENDPOINT=http://<coletor>:4318
OTEL_SERVICE_NAME=<serviço>
OTEL_RESOURCE_ATTRIBUTES=deployment.environment=<ambiente>,service.version=<versão>
```

Traces, logs e métricas saem pelo agente OpenTelemetry (qualquer SDK ou agente OpenTelemetry pode apontar
para o mesmo coletor); perfis, IAST, ataques, debugger e o relato de configuração saem pelo agente Telvyn.
O agente Telvyn envia por um cliente HTTP próprio, para que o agente OpenTelemetry não transforme esses envios
em traces da aplicação, e lê o trace atual tanto da API OpenTelemetry da aplicação quanto da cópia interna do
agente OpenTelemetry, de modo que o achado de IAST cai no trace da requisição mesmo em aplicações sem a API.
