# Agente Telvyn para Go

Integração compilada, usando o SDK OTel HTTP existente e o coletor Telvyn. Esta forma exige inicialização e integração da biblioteca à aplicação; não injeta código em qualquer binário pronto.

O módulo está no repositório do agente: `github.com/TelvynMonitoring/telvyn-agent/telvyn-go-agent`. Os SDKs são distribuídos junto do coletor; a plataforma permanece separada. Para build local, use o `replace` da fixture. Não há tag de release deste módulo ainda.

```go
shutdown, err := telvyn.Start(context.Background())
// Trate err de configuração; não esconda ausência de telemetria.
// Ao parar, drene o HTTP e chame shutdown com um contexto e prazo definidos.
server := &http.Server{Addr: ":8080", Handler: telvyn.Handler(mux)}
```

Configure `OTEL_SERVICE_NAME`, `OTEL_EXPORTER_OTLP_ENDPOINT=http://coletor:4318`, `OTEL_RESOURCE_ATTRIBUTES` e os parâmetros de batch padrão. O transporte é HTTP/protobuf. `Handler` reutiliza `otelhttp`, conservando as interfaces do ResponseWriter, e usa o padrão real do ServeMux para a rota. Registra conclusão/status com IDs válidos, sem ler corpo ou headers de autenticação. Remove query dos atributos de URL exportados. Routers externos ainda não foram exercitados.

Go não possui um fluxo universal de exceções: quando a aplicação trata um `error`, use `telvyn.RecordError(ctx, err)` para registrar o objeto real. HTTP 500 já é observado pelo wrapper. Logs de negócio não recebem injeção nesta unidade.

`OTEL_SDK_DISABLED=true` faz Start/Handler/RecordError preservarem a aplicação sem SDK nem logs do pacote. Não registre outro tracer provider simultaneamente para as mesmas bibliotecas. A aplicação controla os sinais e chama o shutdown, como a fixture, sem o pacote assumir o ciclo de vida do servidor.

Go 1.26/net/http são os alvos da rodada; outros runtimes/routers/versões, IAST, profiling e injeção eBPF não fazem parte deste aceite. O WAL só protege dados já recebidos pelo coletor; interromper a aplicação antes do flush pode perder spans em memória.

Validação: 200/200/500 ligado/desligado; três logs de conclusão ligados e nenhum desligado. Imagem `20261012-agent1`, pod `go-975d48f59-plx2d`; log→trace `e77803b07df75c2d4b4a357ed1980e2b` com SERVER `/error`, objeto error registrado pelo helper e um log correlacionado comprovados no portal. Evidência local `artifacts/polyglot-20261012/go-agent-trace-light.png`. Backend e coletores preservados.

## Instrumentação durante o build

`Dockerfile` fornece `telvyn-go build`, apoiado no compilador OpenTelemetry com revisão fixada `2b6d03bb6752ea528f6c67bbb89b9682d645fabe`. As regras selecionam somente servidor/client HTTP e a inicialização do SDK Telvyn. A fonte da API não precisa importar Telvyn nem envolver handlers; o provider/exporter continua usando o pacote existente, incluindo remoção de query e logs de conclusão.

Construa a imagem `docker build -f telvyn-go-agent/Dockerfile -t telvyn-go-builder:VERSAO .` e use-a como estágio de build da aplicação, executando `telvyn-go build -o /out/api .`. Copie somente o binário para a imagem de execução. Execute o build em uma cópia descartável: o wrapper e o compilador atualizam go.mod/go.sum e arquivos auxiliares de instrumentação. Não use simultaneamente Handler/Start manuais na mesma aplicação. Os caminhos de replace são internos ao builder e não devem ser publicados no go.mod da aplicação.

A aplicação continua responsável por sinais e drenagem HTTP; o bootstrap descarrega o SDK quando main retorna normalmente. os.Exit, SIGKILL e encerramentos abruptos não executam esse defer. `OTEL_SDK_DISABLED=true` desliga SDK e hooks. Recompilação é necessária para inserir/remover hooks; não existe preload universal em um binário Go pronto. HTTP client só usa os contextos fornecidos pela aplicação, sem atribuir parentesco por heurística. Esta integração não certifica automaticamente outros hooks disponíveis no compilador upstream.
