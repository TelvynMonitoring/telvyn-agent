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
