# Agente Telvyn para Rack / Sinatra

Gem reutilizável com inicialização antecipada e middleware Rack, apoiado no SDK OTel já usado no laboratório. Esta integração cobre Rack/Sinatra, não sua cobertura universal.

Instale por source/path no Gemfile (como na fixture) ou empacote com `gem build`; RubyGems não foi publicado.

```ruby
# config.ru
require 'telvyn/auto'
require_relative 'app'
use Telvyn::Middleware
run MinhaAplicacao
```

Configure `OTEL_SERVICE_NAME`, `OTEL_EXPORTER_OTLP_ENDPOINT=http://coletor:4318`, `OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf`, `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_METRICS_EXPORTER=none` e `OTEL_LOGS_EXPORTER=none` antes de iniciar. Não configure outro SDK/tracer para as mesmas bibliotecas. A instrumentação é carregada antes da aplicação, e a fonte Sinatra não importa tracing.

O wrapper preserva status, headers e o body, usando o BodyProxy oficial Rack para registrar conclusão após fechar o body sem ler seu conteúdo. Usa IDs reais do span SERVER, rota realmente reportada pelo Sinatra e o objeto `sinatra.error` quando existente. Remove query dos atributos de URL exportados; não captura corpo/auth/cookies. Logs de negócio não recebem injeção nesta unidade.

`OTEL_SDK_DISABLED=true` preserva o app sem SDK/middleware de tracing nem logs do pacote. A aplicação/servidor controlam sinais, e o SDK faz flush ao encerrar normalmente; término abrupto ou receiver indisponível pode perder dados antes do WAL. Ruby 3.3/Rack 3/Sinatra 4.2.1 são os alvos da rodada; Rails, outros servidores/versões, IAST e profiling não foram certificados.

Validação: 200/200/500 ligado/desligado, três logs de conclusão ligados e nenhum desligado. Imagem `20261012-agent1`, pod `ruby-847c77d764-4vgbv`; log→trace `23680d537bad2a8787f383c0a705414b`, SERVER `/error`, rota Sinatra real, exceção e um log correlacionado exercitados no portal. Rodada conjunta de 18 chamadas das seis APIs concluída com os códigos esperados. Evidência local `artifacts/polyglot-20261012/ruby-agent-trace-light.png`; sem restart backend/coletor/produção.

## Injeção Kubernetes

O pacote de injeção é construído com `docker build -f telvyn-ruby-agent/Dockerfile -t SEU_REGISTRY/telvyn-ruby-agent:VERSAO .`. Configure `webhook.rubyAgentImageRef` no coletor e a annotation `instrumentation.telvyn.io/ruby-containers: app` no template do pod. O coletor monta a gem e acrescenta o preload a `RUBYOPT`; não muda o comando nem o Gemfile da aplicação.

A imagem deve corresponder ao Ruby/arquitetura/libc e às versões de gems já ativadas pelo aplicativo. Esta imagem usa Ruby 3.3/Alpine e Rack 3. Não aplique a outro ABI por inferência. O loader envolve os builders Rack e o middleware evita duplicar telemetria em aplicações aninhadas. Para instalação manual com Gemfile, mantenha o fluxo anterior; não combine dois agentes no mesmo processo.
