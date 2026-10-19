# Agente Telvyn para PHP HTTP

Pacote Composer reutilizável: o autoload inicia o span HTTP, e o shutdown do request registra status/duração e log com IDs reais, exportando ao coletor Telvyn. A aplicação mantém seu `vendor/autoload.php`, sem bootstrap OTLP específico. Não é uma extensão Zend nem certifica sua lista completa de frameworks/bancos.

Para consumo local, use o repositório Composer `path` da fixture como exemplo; o pacote ainda não está no Packagist. Configure antes de iniciar a aplicação:

```sh
export OTEL_SERVICE_NAME=minha-api
export OTEL_EXPORTER_OTLP_ENDPOINT=http://coletor:4318
export OTEL_RESOURCE_ATTRIBUTES=deployment.environment.name=development,service.version=1.0.0
```

`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, quando definido, é o endereço completo de traces. Sem destino definido, usa o receiver HTTP local `localhost:4318/v1/traces`, não gRPC. O token pertence ao coletor, não ao código PHP.

Somente o path é usado nos atributos; a query não é exportada. O propagador lê apenas traceparent/tracestate, sem corpo, cookies ou headers de autenticação. Rotas templadas de frameworks ainda não são detectadas: o nome é método/path real, não uma rota inventada. Logs de negócio são preservados sem injeção automática.

Para um Throwable tratado pela aplicação, use `Telvyn\Agent\HttpAgent::recordException($error)`; status HTTP 500 já é observado pelo sensor. O pacote não substitui handlers de erro, não lê o corpo da resposta e não transforma respostas da aplicação. `OTEL_SDK_DISABLED=true` impede SDK e logs do pacote na próxima inicialização; o helper vira no-op.

A exportação PHP é síncrona ao finalizar o request, com prazo explícito de dois segundos e sem retries. Coletor indisponível pode acrescentar esse tempo ao encerramento e perder o span, sem proteção pelo WAL antes de recebê-lo. PHP 8.3/cli-server são os alvos comprovados da fixture; FPM, Apache, workers persistentes, frameworks, IAST, profiling e outras versões continuam sem validação específica. CLI sem REQUEST_METHOD não é instrumentado. Não configure outro tracer provider simultaneamente.

Validação: 200/200/500 ligado/desligado, três logs do pacote ligado e nenhum desligado. Imagem `20261012-agent1`, pod `php-658b786984-477vh`; log→trace `393f27e5ed76f085304be31461de3292` com SERVER `/error`, Throwable real e um log correlacionado conferidos no portal. SDK ResourceInfoFactory reportou PHP e metadados reais, sem ambiente fixo na biblioteca. Evidência local `artifacts/polyglot-20261012/php-agent-trace-light.png`. Backend e coletores preservados.

## Injeção Kubernetes

Construa `docker build -f telvyn-php-agent/Dockerfile -t SEU_REGISTRY/telvyn-php-agent:VERSAO .`, configure `webhook.phpAgentImageRef` no coletor e a annotation `instrumentation.telvyn.io/php-containers: app`. O preload usa `PHP_INI_SCAN_DIR`/`auto_prepend_file`, sem alterar fonte ou comando. As configurações PHP padrão e os diretórios explícitos da aplicação são carregados depois do INI Telvyn; um auto_prepend_file próprio tem precedência e exige integração manual com o autoload, sem sobrescrevê-lo automaticamente. Não combine agentes.

Validação adicional em 13/10: imagem PHP 8.3 sem Composer/SDK na aplicação; Kubernetes montou o pacote, 200/200/500 preservados com e sem annotation. Trace `93380d777f2e1399e56502ad4adf291e`, GET /error, status 500 e um log correlacionado (11:42:41 UTC), claro/escuro. Sem helper no aplicativo, Throwable tratado não é capturado; o status 500 é real. Esta prova usa cli-server com index.php, não certifica FPM/Apache ou workers persistentes.
