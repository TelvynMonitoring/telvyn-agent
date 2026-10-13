# Injeção dos agentes de runtime

O coletor continua recebendo OTLP e calculando stats antes da amostragem. O modo
`collector --webhook` também instala os pacotes Telvyn nas aplicações selecionadas,
sem substituir o coletor do host, seu token ou seu WAL. Não instala automaticamente
um runtime em todas as imagens do cluster.

## Ativação pela tela

No Telvyn, abra um pod de um Deployment e **Instrumentar aplicação**. O coletor confirma a linguagem do container; a API salva a seleção por tenant, cluster, namespace, Deployment, container e imagem. Novos pods recebem o pacote após a sincronização (15 s). Faça o rollout no fluxo habitual da aplicação; salvar a seleção não reinicia o workload.

O painel separa configuração salva de **SDK observado**, confirmado por spans reais do mesmo pod/container/cluster nos últimos 15 minutos. Desativar remove a seleção para novos pods; pods existentes mantêm o SDK até serem recriados. Uma imagem diferente exige nova seleção. O cache de seleções expira após um minuto sem comunicação.

O pacote atual é linux/amd64. Seleção central de Python requer 3.13/musl, Ruby requer 3.3/musl e .NET requer runtime 8; outras versões aparecem como não cobertas. Node requer 20+ e PHP 8.3+ no bootstrap. Esses limites não certificam todos os frameworks dessas versões. Go continua exigindo compilação; Java preserva a integração anterior.

Os seis SDKs e `.github/workflows/publish-runtime-agents.yml` pertencem a este repositório. A plataforma não precisa conter suas fontes. A imagem compartilhada inclui os cinco runtimes injetáveis; não inclui backend, frontend ou credenciais.

## Configuração pelo operador

Com `webhook.enabled=true`, o chart gera TLS/caBundle pelo Helm, válido por 365 dias e renovado em upgrades. `webhook.certificateProvider=cert-manager` mantém a renovação automática por cert-manager como opção. `webhook.runtimeBundleImageRef` configura o pacote compartilhado; os overrides por linguagem continuam disponíveis:

| Annotation no template do Pod | Valor Helm | Variável do webhook |
| --- | --- | --- |
| `instrumentation.telvyn.io/node-containers` | `webhook.nodeAgentImageRef` | `TELVYN_NODE_AGENT_IMAGE` |
| `instrumentation.telvyn.io/python-containers` | `webhook.pythonAgentImageRef` | `TELVYN_PYTHON_AGENT_IMAGE` |
| `instrumentation.telvyn.io/dotnet-containers` | `webhook.dotnetAgentImageRef` | `TELVYN_DOTNET_AGENT_IMAGE` |
| `instrumentation.telvyn.io/ruby-containers` | `webhook.rubyAgentImageRef` | `TELVYN_RUBY_AGENT_IMAGE` |
| `instrumentation.telvyn.io/php-containers` | `webhook.phpAgentImageRef` | `TELVYN_PHP_AGENT_IMAGE` |

Valor da annotation: nomes exatos dos containers, separados por vírgula. Exemplo:

```yaml
spec:
  template:
    metadata:
      annotations:
        instrumentation.telvyn.io/node-containers: api
```

A imagem é escolhida pelo operador, nunca pela annotation. Construa os Dockerfiles
`telvyn-{linguagem}-agent` deste repositório, publique em seu registry e
fixe uma versão/digest. Não há release pública desses pacotes nesta entrega.
Confirme acesso ao registry antes do rollout: falha no download do init container
impede a aplicação de iniciar, mesmo com failurePolicy Ignore no webhook.

O webhook copia o pacote para emptyDir e monta somente nos containers selecionados.
Preserva comando, argumentos, sidecars e referências a segredos. Acrescenta preload
e, quando ausentes, service name, endpoint OTLP do host e protocolo HTTP/protobuf.
Defina explicitamente OTEL_SERVICE_NAME e OTEL_RESOURCE_ATTRIBUTES na aplicação
para a identidade desejada. Reiniciar/recriar o Pod é necessário para aplicar ou
remover a injeção; mudar a annotation não modifica processos existentes.

Conflitos de volume/init/preload, container desconhecido, variável de preload por
valueFrom, envFrom ou seleção de linguagens conflitantes deixam o Pod sem alteração,
com motivo no log do webhook. Não lê Secrets/ConfigMaps para tentar resolver o
conflito. Configure a instrumentação explicitamente nesses casos. Configuração
ENV embutida na imagem não é visível ao admission controller: declare o valor a
preservar no Pod antes de habilitar a injeção. Não combine dois instrumentadores
para as mesmas bibliotecas. OTEL_SDK_DISABLED=true desliga o SDK na aplicação.

## Matriz exercitada

- Node 20/CommonJS/HTTP e Express: NODE_OPTIONS.
- Python 3.13/Alpine/Flask: sitecustomize e distro Telvyn; preserva sitecustomize da aplicação.
- .NET 8/Alpine/ASP.NET Core: additional deps/shared store/hosting startup.
- Ruby 3.3/Alpine/Rack 3/Sinatra: RUBYOPT e middleware Rack, sem duplicar builders aninhados.
- PHP 8.3/cli-server: PHP_INI_SCAN_DIR e auto_prepend_file; configuração da aplicação tem precedência.

ABI, libc e dependências precisam corresponder à aplicação; não é uma matriz
universal de versões. Go usa o builder `telvyn-go-agent` deste repositório e hooks
net/http durante compilação; não existe annotation para injetar em binário pronto.
O caminho Java já existente e seu controle pelo backend permanecem separados.

## Verificação e diagnóstico

Confira o init container, mount, imagem e variáveis não secretas do Pod admitido.
Envie uma requisição real e confira serviço/trace/log no Telvyn. A aba SDK identifica
agente e runtime pelos spans recebidos nos últimos 15 minutos; ausência de amostra
não significa agente desligado. Identidade recebida não comprova profiling ou IAST.
Use os logs do webhook para skips e os da aplicação para falha de bootstrap/exportação.
Não confunda HTTP 200 da aplicação com telemetria entregue ao backend.

Em 13/10 foram exercitadas aplicações sem SDK embutido, controles sem injeção,
200/200/500, correlação de logs, preservação de configuração e dry-run real do
apiserver para conflitos. A matriz e evidências completas ficam em
`ispwacthinfra/docs/APM-RUNTIME-AGENTS.md`. Nenhuma suíte automatizada foi executada,
conforme instrução do usuário; não foram removidos testes existentes.
