# Agente Telvyn para ASP.NET Core

Pacote reutilizável de inicialização `IHostingStartup`, usando a [extensão oficial ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/host/platform-specific-configuration?view=aspnetcore-8.0). Instala tracing ASP.NET Core, exportação HTTP/protobuf e logs JSON correlacionados sem configurar telemetria no `Program.cs` ou nas rotas.

Referencie `Telvyn.Agent.csproj` (ou o pacote gerado com `dotnet pack`) no projeto da aplicação e configure antes de iniciar:

```sh
export ASPNETCORE_HOSTINGSTARTUPASSEMBLIES=Telvyn.Agent
export OTEL_SERVICE_NAME=minha-api
export OTEL_EXPORTER_OTLP_ENDPOINT=http://coletor:4318
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
export OTEL_RESOURCE_ATTRIBUTES=deployment.environment.name=development,service.version=1.0.0
export OTEL_METRICS_EXPORTER=none
export OTEL_LOGS_EXPORTER=none
dotnet MinhaApi.dll
```

Se já houver outras hosting startup assemblies, acrescente `;Telvyn.Agent` à lista, preservando-as. Aplicações que impedem hosting startup não são alteradas por inferência. Não carregue outro SDK/tracer para as mesmas bibliotecas. O pacote é ASP.NET Core/net8.0; não é um profiler CLR universal.

Logs de conclusão usam os IDs reais da Activity SERVER. Query é removida dos atributos de URL antes da exportação; corpo/cookies/headers de autenticação não são capturados. Logs de negócio não recebem injeção nesta unidade. `OTEL_SDK_DISABLED=true` impede a configuração do SDK e dos logs do pacote na próxima inicialização. Sem configuração de destino, o default explícito é o coletor HTTP local `localhost:4318`, nunca gRPC.

O host ASP.NET encerra o SDK ao parar. Uma interrupção abrupta ou coletor indisponível pode perder spans em memória. NuGet não foi publicado. Outros frameworks/versões, bancos, CLR profiler, IAST e profiling permanecem fora do aceite dessa integração HTTP.

## Validação

ASP.NET Core/.NET 8, Linux Alpine: 200/200/500 com pacote ligado e desligado; desligado não gerou logs do pacote. `UseExceptionHandler` preserva a resposta JSON e o pacote observa o evento oficial `HandledException`, mantendo a exceção real sem código de tracing na API. Imagem final `20261012-agent2`, pod `dotnet-6cb45b5798-4cftx`; log→trace `5f147dc6344de501cf9357c5b147f021`, SERVER `/error`, exceção e um log correlacionado conferidos no portal. Job de 18 chamadas concluído, sem restart backend/coletor. A navegação do log passou a transportar seu período para não consultar a janela antiga do drawer; correção de frontend separada do pacote.

## Injeção Kubernetes sem referência no projeto

Construa `docker build -f telvyn-dotnet-agent/Dockerfile -t SEU_REGISTRY/telvyn-dotnet-agent:VERSAO .` e configure `webhook.dotnetAgentImageRef` no chart do coletor. No template do pod, `instrumentation.telvyn.io/dotnet-containers: app` seleciona o container.

O coletor monta o pacote e configura `DOTNET_ADDITIONAL_DEPS`, `DOTNET_SHARED_STORE` e `ASPNETCORE_HOSTINGSTARTUPASSEMBLIES`, preservando entradas explícitas existentes. A imagem é específica de .NET 8/Linux e da arquitetura usada no build. O código da aplicação não precisa referenciar Telvyn. Conflitos/valores indiretos são recusados com aviso no webhook; o pod continua sem injeção. Configuração herdada da imagem/envFrom precisa ser conferida pelo operador.

Comprovado em 13/10: aplicação ASP.NET Core sem referência Telvyn, injetada pelo apiserver, respostas 200/200/500 e trace `4ec9bc64aec0e3c2b2402290ff0febbf`, GET /error, 211,5 ms, erro real e um log correlacionado no portal claro/escuro. Controle sem annotation preservou respostas sem logs do pacote. Sem restart do backend ou dos coletores existentes.
