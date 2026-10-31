# Docker Compose com agentes de linguagem (imagem única)

A imagem `ghcr.io/telvynmonitoring/telvyn-agent` já traz os agentes de Java e Node. Com
`TELVYN_LANGUAGE_AGENTS=java,node`, o entrypoint copia `/opt/telvyn/java` e `/opt/telvyn/node`
para o volume compartilhado em `/opt/telvyn-shared` antes de subir o coletor. Versões antigas
são sobrescritas a cada início. Um único serviço do Telvyn basta.

```yaml
services:
  telvyn-agent:
    image: ghcr.io/telvynmonitoring/telvyn-agent:latest
    restart: unless-stopped
    environment:
      TELVYN_INGEST_URL: ${TELVYN_INGEST_URL}
      TELVYN_INGEST_TOKEN: ${TELVYN_INGEST_TOKEN}
      TELVYN_AGENT_KIND: docker
      TELVYN_LANGUAGE_AGENTS: java,node
    volumes:
      - telvyn-agents:/opt/telvyn-shared
      - telvyn-state:/var/lib/telvyn

  minha-app-java:
    image: minha-empresa/app-java
    depends_on: [telvyn-agent]
    volumes:
      - telvyn-agents:/opt/telvyn:ro
    environment:
      JAVA_TOOL_OPTIONS: -javaagent:/opt/telvyn/java/telvyn-javaagent.jar
      OTEL_EXPORTER_OTLP_ENDPOINT: http://telvyn-agent:4318

  minha-app-node:
    image: minha-empresa/app-node
    depends_on: [telvyn-agent]
    volumes:
      - telvyn-agents:/opt/telvyn:ro
    environment:
      NODE_OPTIONS: --require=/opt/telvyn/node/bootstrap.cjs
      OTEL_EXPORTER_OTLP_ENDPOINT: http://telvyn-agent:4318

volumes:
  telvyn-agents:
  telvyn-state:
```

Notas:

- Use um volume nomeado novo: o Docker herda a posse `10001:10001` de `/opt/telvyn-shared` da imagem.
  Se montar um diretório do host, ajuste a posse para `10001:10001`; senão o entrypoint aborta com mensagem clara.
- As aplicações só leem (`:ro`). O agente publica `java/` (com `telvyn-javaagent.jar` e
  `opentelemetry-javaagent.jar`) e `node/`.
- A variável `TELVYN_LANGUAGE_AGENTS` aceita `java`, `node` ou `java,node`.
