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

O agente consulta o coletor a cada 30 s (`/v1/sdk/remote-config`) e aplica, sem reiniciar, o que foi definido na tela do serviço (cartão "SDK e configuração", por serviço e ambiente): ligar/desligar os perfis de CPU, wall, alocação, lock e exceções e a detecção de ataques (Spring); o IAST só pode ser desligado. Ligar a detecção de ataques exige `TELVYN_SECURITY_QUERY_ROUTES` definido na aplicação. Opção não definida na tela = vale a variável de ambiente. A revisão aplicada vai no relatório de configuração (`telvyn.remote_config.revision`).

Bloqueio de ataques (como o Datadog), em Spring MVC: com a detecção de ataques ligada, o agente barra a requisição quando o IP está na lista de bloqueio (no `DispatcherServlet`) ou quando uma regra está em modo "bloquear" (antes do controller). Spring WebFlux segue só com detecção.

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
