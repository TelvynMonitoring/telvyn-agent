# Agente Telvyn para Node.js

## SDK 0.2.0 — bundle público

O mesmo pacote oferece CPU/heap V8, workers, origem de arquivo/revisão, Debugger e segurança. Está distribuído em `ghcr.io/telvynmonitoring/telvyn-runtime-agents:0.2.0` (linux/amd64); a imagem 0.1.0 não contém esse conjunto. O coletor precisa dos contratos da release 0.4.40, cuja publicação é separada. As verificações abaixo distinguem conferências pontuais de aceite no painel.

| Configuração explícita | Comportamento da candidata |
| --- | --- |
| `TELVYN_PROFILING_ENABLED=true` | CPU a cada 15 s e heap vivo amostrado; cada worker com preload envia sua própria identidade. Heap é média por gravação de uma thread, não taxa de alocação ou soma do heap do processo. |
| `TELVYN_PROFILE_SOURCE_ROOT=/app` | Limita caminhos de origem e módulos elegíveis para Debugger/IAST ao diretório da aplicação. `node_modules` fica fora da reescrita. |
| `TELVYN_GIT_REPOSITORY_URL`, `TELVYN_GIT_COMMIT_SHA`, `TELVYN_GIT_SOURCE_ROOT` | Vinculam profiles ao commit exato e diretório relativo do repositório. Não há fallback para main. JavaScript gerado não é apresentado como TypeScript original. |
| `TELVYN_DEBUGGER_ENABLED=true` | Consulta probes pelo coletor. Métodos/funções exportados em CommonJS/ESM: snapshot, condição tipada, contagem, duração e gauge. Linha explícita usa o inspector interno, sem porta de rede. Valores capturados limitam-se a números/booleanos; strings e objetos são ocultados. Configuração sem renovação expira em 60 s. |
| `TELVYN_SECURITY_ENABLED=true` e `TELVYN_SECURITY_ROUTES=/search,/lookup` | Engine libddwaf nas rotas exatas permitidas, somente parâmetro `q`; observa, sem bloquear tráfego. Não captura corpo, cookies, autenticação ou valores no relatório. |
| `TELVYN_IAST_ENABLED=true` | Rastreamento nativo de `q` até `pg.Client/Pool.query`, com propagação por operadores/string e contexto assíncrono. Consultas parametrizadas não são tratadas como SQL concatenado. Requer rotas e raiz explícitas. Não implica cobertura de todos os bancos, fontes, operações ou frameworks. |

O coletor precisa conter os novos endpoints de segurança/SDK/Debugger; o backend precisa aceitar os contratos Node e a identidade de worker. A instrumentação ESM usa o loader OTel existente e exige `module.register` (Node 20.6+). Não carregar outro tracer/rewriter no mesmo processo: conflitos de contexto impedem a ativação do IAST, preservando a aplicação.

Conferências pontuais: CPU/heap com main e dois workers nas versões Node 20.20.2, 22.23.3 e 24.21.0 (sem thread interna do loader); PostgreSQL concatenado/parametrizado/literal/assíncrono em CommonJS e ESM; oito chamadas do Debugger em cada formato. No painel local: SQLi/XSS, IAST com arquivo/linha/trace, snapshot, condição numérica, locais por linha e exceção; ACK de instalação e cinco chamadas observadas. Métricas reais recebidas: contagem 5, gauge 8 e histograma de duração. Fonte no commit exato `43a70d4f` comprovada em claro/escuro pelo repositório autorizado do Telvyn, sem ampliar permissões GitHub. Heap médio e comparação por gravação exercitados na tela. Imagem de instalação copiada para volume limpo e carregada em Node 22; todos os módulos presentes. Distribuição pública em andamento; desempenho sustentado e cobertura universal não certificados.

Relatórios têm limites de tamanho, concorrência e timeout. Perfis/eventos/snapshots que não alcançam o coletor podem ser perdidos com aviso; o WAL de logs não os protege. Probes de linha podem aumentar o custo de execução, especialmente em loops. Native addons de segurança vêm dos projetos Apache-2.0 `@datadog/native-appsec`, `@datadog/native-iast-taint-tracking` e `@datadog/wasm-js-rewriter`; são usados localmente, sem envio ao Datadog. Licenças acompanham as dependências.

## Distribuição anterior e evidências históricas

Injeção Kubernetes: o coletor Telvyn pode montar este pacote sem alterar a imagem/comando da aplicação. Construa `docker build -f telvyn-node-agent/Dockerfile -t <imagem> .` na raiz; configure essa imagem em `webhook.nodeAgentImageRef` do chart do coletor e a annotation do template do pod `instrumentation.telvyn.io/node-containers: "nome-do-container"`. A imagem precisa estar acessível nos nós. Opt-in explícito, sem inferir runtime pelo nome da imagem. Node 20/CommonJS validado em 13/10; preserve e confira opções herdadas da imagem/envFrom, que o admission controller não consegue ler.

Pacote carregado antes da aplicação, reutilizando as instrumentações oficiais HTTP/Express do OpenTelemetry. O coletor Go continua recebendo OTLP e coletando stdout; não é substituído. Esta versão cobre CommonJS e HTTP/Express, com profiling de CPU opcional; não cobre IAST ou todos os frameworks do DD.

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

## Profiling de CPU V8

`TELVYN_PROFILING_ENABLED=true` habilita o profiler nativo do V8 no mesmo preload. O padrão é desligado; `OTEL_SDK_DISABLED=true` também o desliga. O endpoint OTLP HTTP do coletor existente recebe `/v1/profile`; não há token do host na aplicação nem porta de inspector exposta. A aplicação precisa reiniciar para carregar a configuração.

Janelas de 15 segundos, intervalo solicitado de 10 ms. O Flame Graph usa contagem real de amostras da thread principal, excluindo idle, sem estimar segundos de CPU. Não cobre worker threads, pilhas nativas completas, alocações, associação com traces nem código-fonte nesta unidade. Nomes de funções iguais são agregados. Nenhum argumento, variável local ou conteúdo de requisição é capturado.

O envio tem limite de 4 MiB e timeout de 5 segundos; uma falha gera aviso e descarta essa janela, sem fila ilimitada na aplicação. O WAL de logs não protege profiles. A última janela incompleta não é exportada no encerramento. A API de consulta precisa aceitar a fonte `v8`; ingestão isolada não comprova visualização.

Em 13/10, Node 20.20.2 capturou uma função real sob carga e enviou profiles ao backend local pelo coletor existente. Controle desligado não enviou profiles. Flame Graph validado em claro/escuro: 14 janelas, 1.460 amostras, `hotLoop` com 1.289; filtro, detalhe, zoom e troca JFR/V8 exercitados. A distribuição pública ainda não inclui esta alteração. Workers, outras versões e equivalência numérica com o profiler DD não foram comprovados.

## Validação de 12/10/2026

Node 20.20.2/Express 5.3.0: API sem imports de tracing, rotas normal/lenta/erro retornaram 200/200/500 com agente ligado e desligado. Ligado gerou logs com contextos válidos; desligado não gerou logs do pacote. No K3s, o mesmo pacote enviou HTTP/Express pelo coletor existente: log de erro abriu trace com span SERVER `/error`, HTTP 500, exceção no handler e um log correlacionado. Requisição controlada com query mostrou `/error` sem `url.query` ou valor enviado nos atributos de URL. O pacote foi empacotado com `npm pack`, sem publicação no registry.

Pacote final ativo na imagem `telvyn-language-lab-node:20261012-agent2` (manifest `c1f8c67a5dbdee1c39c21d4bae22ef79b4d542a5d2297892702733212b3aebe3`), pod `node-5d74f749d7-2cvxh`. Trace `8cbd3dc43514fb0ac6bc86fef90c3a15` e seu log conferidos em claro/escuro. O contador de logs do drawer respeita seu período APM: foi usado o intervalo da chamada; uma janela anterior não comprova ausência de correlação. Backend local e coletores não foram reiniciados. A comparação com DD nesta unidade é documental; não houve nova comparação interativa com um tracer DD para esses casos.
