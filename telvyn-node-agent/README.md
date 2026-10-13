# Agente Telvyn para Node.js — primeira integração

Injeção Kubernetes: o coletor Telvyn pode montar este pacote sem alterar a imagem/comando da aplicação. Construa `docker build -f telvyn-node-agent/Dockerfile -t <imagem> .` na raiz; configure essa imagem em `webhook.nodeAgentImageRef` do chart do coletor e a annotation do template do pod `instrumentation.telvyn.io/node-containers: "nome-do-container"`. A imagem precisa estar acessível nos nós. Opt-in explícito, sem inferir runtime pelo nome da imagem. Node 20/CommonJS validado em 13/10; preserve e confira opções herdadas da imagem/envFrom, que o admission controller não consegue ler.

Pacote carregado antes da aplicação, reutilizando as instrumentações oficiais HTTP/Express do OpenTelemetry. O coletor Go continua recebendo OTLP e coletando stdout; não é substituído. Esta versão cobre CommonJS e HTTP/Express, não IAST, profiling ou todos os frameworks do DD.

Instale o pacote a partir da fonte ou de um tarball criado com `npm pack`; ele ainda não foi publicado no npm. Em aplicações existentes, não carregue simultaneamente outro SDK/tracer para as mesmas bibliotecas.

```sh
npm install /caminho/telvyn-node-agent-0.1.0.tgz
export OTEL_SERVICE_NAME=minha-api
export OTEL_EXPORTER_OTLP_ENDPOINT=http://coletor:4318
export OTEL_RESOURCE_ATTRIBUTES=deployment.environment.name=development,service.version=1.0.0
export OTEL_METRICS_EXPORTER=none
export OTEL_LOGS_EXPORTER=none
NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--require @telvyn/node-agent/register" node app.cjs
```

O preload precisa preceder os imports de HTTP/Express. A aplicação não importa a API de tracing: requisições e respostas são instrumentadas automaticamente, incluindo HTTP 500. Um log JSON de conclusão usa os IDs reais do span SERVER. Logs de negócio existentes não recebem injeção automática nesta versão. Valores de query são removidos dos atributos de URL antes da exportação; corpo, cookies e headers de autenticação não são capturados pelo pacote. Não habilite captura adicional por inferência.

`OTEL_SDK_DISABLED=true` desliga SDK, patches e logs do pacote na próxima inicialização, preservando a aplicação. `SIGTERM` solicita o flush; aplicações com handler próprio conservam o controle da saída. Uma falha de flush gera aviso sem mudar o resultado da aplicação. Use um init no container (a fixture usa tini) e conceda tempo para o flush no prazo de término. Uma interrupção abrupta ou coletor indisponível pode perder spans ainda em memória; o WAL do coletor protege apenas dados que ele recebeu. Configuração de endpoint, recursos e batch usa o padrão OTel existente, sem token do host embutido na aplicação.

Referências: [inicialização antecipada do DD](https://docs.datadoghq.com/tracing/trace_collection/dd_libraries/nodejs/), [SDK Node OTel](https://opentelemetry.io/docs/languages/js/getting-started/nodejs/). ESM, bancos, outros loggers, outras versões e desligamento remoto ainda não comprovados.

## Validação de 12/10/2026

Node 20.20.2/Express 5.3.0: API sem imports de tracing, rotas normal/lenta/erro retornaram 200/200/500 com agente ligado e desligado. Ligado gerou logs com contextos válidos; desligado não gerou logs do pacote. No K3s, o mesmo pacote enviou HTTP/Express pelo coletor existente: log de erro abriu trace com span SERVER `/error`, HTTP 500, exceção no handler e um log correlacionado. Requisição controlada com query mostrou `/error` sem `url.query` ou valor enviado nos atributos de URL. O pacote foi empacotado com `npm pack`, sem publicação no registry.

Pacote final ativo na imagem `telvyn-language-lab-node:20261012-agent2` (manifest `c1f8c67a5dbdee1c39c21d4bae22ef79b4d542a5d2297892702733212b3aebe3`), pod `node-5d74f749d7-2cvxh`. Trace `8cbd3dc43514fb0ac6bc86fef90c3a15` e seu log conferidos em claro/escuro. O contador de logs do drawer respeita seu período APM: foi usado o intervalo da chamada; uma janela anterior não comprova ausência de correlação. Backend local e coletores não foram reiniciados. A comparação com DD nesta unidade é documental; não houve nova comparação interativa com um tracer DD para esses casos.
