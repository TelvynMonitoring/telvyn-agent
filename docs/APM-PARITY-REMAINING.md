# Python — inventário do candidato e aceite pendente

15/10/2026. Agente: branch `codex/parity-python`, base `origin/main` atualizada por fetch em `a53ddb1`. Plataforma: `codex/sdk-configuration-python`, base `a96132a5`. Worktrees irmãos `telvyn-agent-parity-python` e `ispwacthinfra-parity-python`. Checkouts originais e alterações da outra frente preservados. Sem commit/publicação.

**Estado de todos os itens novos: código escrito; ativo em runtime não verificado; distribuído não; validado não.** Nenhum código de aplicação/SDK executado, teste criado/rodado, build, instalação, container, serviço, navegador ou medição. Revisão apenas por leitura dos fontes/diffs e documentação oficial. Autorização de contrato inclui outras linguagens; seus SDKs não foram implementados nesta rodada.

## Antes/depois e fontes

Antes: módulo `telvyn-python-agent/telvyn_python_agent.py` em `a53ddb1`, linhas 11–60, e dependências do `pyproject.toml:10`: launcher/Flask/exporter/logs. Não havia os novos módulos listados abaixo. Referências depois são do candidato local; não são evidências de execução.

| Ponto | Antes | Depois e limite | Fonte depois |
| --- | --- | --- | --- |
| Configurações | Ausente | Sete campos, startup/periódico, fork, identidade; valor solicitado não prova sensor | `telvyn_runtime.py:36`, `:50`, `:101`; `telvyn_python_agent.py:96` |
| Profiling | Ausente | CPU por callback, Wall por pilhas, heap vivo; linhas Wall/heap, contexto real só CPU. Alocação opcional Memray com bytes de eventos; heap_objects ausente | `telvyn_profiler.py:15`, `:31`, `:43`; `telvyn_allocation.py:10` |
| Security / IAST | Ausente | Allowlist, padrões SQLi/XSS, fontes e 15 classes de sinks/falhas. Propagação parcial | `telvyn_security.py:22`, `:92`, `:116`, `:151`, `:180`; `telvyn_python_data/security-rules.json` |
| Debugger | Ausente | Polling, snapshots de saída/linha/exceção, count/duration/gauge e condições tipadas; somente funções síncronas | `telvyn_debugger.py:15`, `:25`, `:70`, `:130` |
| Bancos | Nenhum driver no pacote | 6 drivers, request ativo, aliases e SQL mascarado no exporter; status/erro original | `telvyn_context.py:18`, `:52`, `:71`; `telvyn_privacy.py:5`; `telvyn_python_agent.py:70`; `pyproject.toml` |
| Privacidade HTTP | Remove query de 4 atributos | URLs/headers/cookies/bodies padronizados, eventos/links; sem sanitização universal de texto/logs | `telvyn_privacy.py:81`, `:92`; `telvyn_python_agent.py:36` |
| Frameworks | Flask | Instrumentações Flask, Django/DRF, FastAPI, Starlette, aiohttp, Tornado, Falcon WSGI, Pyramid; wrappers explícitos para outros ASGI/WSGI | `pyproject.toml`; `telvyn_python_agent.py:22`, `:29`, `:70` |

Os nomes de arquivo da tabela são relativos a `telvyn-python-agent/`. Matriz detalhada de fontes/frameworks, flags, limites, transporte e exemplos em [README](../telvyn-python-agent/README.md). Não classificar middleware genérico como integração nativa. Sanic nativo, Falcon ASGI e fontes específicas Quart/Litestar/Bottle/CherryPy ficam fora da cobertura escrita.

## Contratos escritos na plataforma

- `SdkConfigurationResource`: nomes python/dotnet/ruby/php/go com exatamente sete entradas, tipos/origens explícitos; formatos Node e Java mantidos.
- `AttackLabIngestResource`: regras `python-input-patterns-1` e `iast-python-1`, arquivo `.py#nome.qualificado`, quinze classes IAST. Migration incremental `V20261015230000__iast_python_findings.sql`; deve integrar o backend candidato antes do SDK. Sem alteração de migration aplicada/RLS/tabela nova.
- `DebugProbePolicy`: alvos Python com linha opcional. O SDK implementa snapshot/count/duration/gauge e snapshots de exceções com condições tipadas; não mede coroutines/generators.
- `ProfileExplorerResource`, `ServiceProfileResource`, `ProfileFrameLinesResource`: source Python e Wall em nanossegundos; arquivos relativos e linhas observadas, CPU com linha desconhecida. Frontend usa o seletor existente, limita tipos Python a CPU/Wall/heap/alloc e informa limitações. Somente Flame Graph continua habilitado.
- Coletor existente encaminha sinais pelos endpoints locais; não foi modificado. SDK não recebe token do backend. Não alterado `ApmPayloadSanitizer`, que participa da outra frente; exibição final de SQL precisa de conferência com a composição escolhida.

## Roteiro de execução futura pelo responsável

**Não executado pelo agente.** Usar ambiente descartável e registrar versões exatas de Python/framework/servidor/driver, branch/commit, env não sensível, janelas e evidências. Não interpretar passos abaixo como aceite já feito. Baseline sugerida para comparar com histórico: CPython 3.13 e Flask 3.1.3; para cada outra combinação selecionar versão compatível com as dependências OTel 0.66b1 antes de instalar. Validar também 3.10, 3.11/3.12 e 3.14 antes de prometer suporte à faixa declarada. Não usar binários musl em glibc/Windows.

Preparar backend Java 21/Quarkus candidato com migration nova, coletor compatível e API existente do responsável. Seguir o exemplo de instalação/launcher do README; esta rodada não provisionou esse ambiente. Usar `OTEL_SERVICE_NAME=python-acceptance`, ambiente `sdk-acceptance`, versão identificável, endpoint local do coletor e source root absoluto correto. Nenhum segredo real nas entradas.

### 1. Configurações

Iniciar sem tráfego e aguardar 125 s. Conferir sete campos, identidade e atualizações em `/v1/sdk/configuration`, tabela `noc_apm_sdk_configuration` e painel SDK. Repetir flags default/true/false, números com sinal/zeros, texto inválido e limites. Esperado: origem e valor solicitado corretos, inválido sem conteúdo bruto, estados de sensores coerentes com configuração/erros de inicialização. Sem service explícito não há reporter. SDK desligado não envia. Falha: sensor ausente declarado ativo, entrada secreta no relatório ou dependência de requests para atualizar.

Repetir em Gunicorn com/sem preload, Uvicorn multiprocess e coletor fora do ar; conferir ausência de deadlock, limites de fila e perda declarada. Mesmo host não prova quantidade de workers. No backend exercitar os cinco nomes novos, campos faltantes/duplicados/desconhecidos e compatibilidade Node 3/5/7 e Java.

### 2. Frameworks e bancos

Em cada framework da matriz, chamar uma rota parametrizada normal, uma com erro real e duas concorrentes com IDs diferentes. Conferir um SERVER por request, rota quando a instrumentação a fornece, código HTTP e erro real. Repetir streaming, handler de erro, sync/async, worker e desligamento do SDK. Para adaptadores, envolver só uma vez e conferir separadamente servidor ASGI/WSGI; não inferir suporte do Sanic nativo.

Em PostgreSQL (psycopg2, psycopg3 sync/async e asyncpg), MySQL (PyMySQL/mysqlclient) e SQLite: executar pela API uma consulta parametrizada e uma com literais sentinela, além de erro real de coluna/tabela inexistente. Conferir span filho correto, SQL normalizado sem literais/comentários/parâmetros, aliases `db.system`, `db.statement`, `db.name`, duração real e causa do driver. Conferir o payload antes do backend, não apenas a tela. Repetir consulta no boot, abertura de conexão, job sem request e tarefa após fim do request: não deve haver span de banco órfão. SQLAlchemy/Django ORM precisam usar drivers listados e não duplicar instrumentação.

### 3. Privacidade

Enviar sentinelas diferentes em query, fragmento de URL produzida pela aplicação, Authorization, cookies, headers customizados e JSON. Conferir payload OTLP de spans/eventos/links e log de conclusão: sem esses valores nos atributos padronizados. Conferir que stream/body ainda chega intacto à aplicação. Inspecionar mensagens reais de exceção e logs próprios separadamente: podem conter valores emitidos pelo driver/app, sem garantia de redação universal. Falha de privacidade deve permanecer aberta, nunca ocultada por mensagem de erro inventada.

### 4. Profiling

Ligar profiling e Wall; manter workload real por pelo menos três flushes com operações CPU contendo chamadas, espera síncrona, async e alocação/soltura de objetos. Conferir registros `source=python`, identidade, janelas, pesos positivos e source root sem caminho absoluto. CPU usa amostras; Wall usa nanossegundos; heap bytes vivos rastreados. Não esperar CPU fiel em tight loop/native ou Wall de coroutine suspensa. `heap_objects` deve continuar vazio. Com allocation desligado/extra ausente não deve surgir `alloc`; com extra compatível e flags ligadas conferir bytes de eventos que incluem objetos já liberados, sem extrapolar gaps. CPU por callbacks fica desativado nesse modo. Conferir interrupção por limite de arquivo e ausência de captura retomada após fork.

Na mesma janela, conferir CPU com e sem request: links só com IDs efetivamente ativos e rota real quando disponível. Wall/heap devem ficar não atribuídos. Conferir linhas reais Wall/heap e linha desconhecida CPU, sem redistribuir peso para simular cobertura. No Explorer/Comparação selecionar Python, agrupar por método/arquivo/linha e comparar janelas/unidades no claro/escuro. Heap não deve ganhar nome de função fabricado. Registrar overhead, limite de stacks, perda e uso de memória antes de habilitar em produção. Repetir com outro profiler/tracer já instalado e após fork.

### 5. Security / IAST

Usar rotas de laboratório do responsável explicitamente incluídas em `TELVYN_SECURITY_ROUTES`, sem tráfego real sensível. Ler query/body/headers/cookies/path nas APIs descritas no README, comparar entrada benigna, padrão SQLi/XSS e mesma chamada fora da allowlist. Só matches reais devem gerar eventos. Inspecionar regras/versionamento, campo de origem sem valor, arquivo/linha/pilha reais, trace e request sem query. Nenhum payload bruto de ataque deve sair.

Para SQL, comparar concatenação de `InputString` até execute com consulta parametrizada: somente a primeira deve apontar fluxo da entrada ao SQL. Repetir controladamente outros sinks; evitar efeitos externos usando ambiente descartável. Falhas de hash/cifra/cookie não exigem taint. Verificar f-string, Pydantic, conversão e template comum como controles de cobertura ausente; não aceitar vínculo inferido por substring. Repetir entrada igual em dois requests concorrentes e uso após request: nenhuma contaminação entre contextos. Métodos não suportados continuam lacuna. Conferir gravação e painel IAST com migration nova, inclusive ausência de SQL bruto.

### 6. Debugger

Ligar debugger e criar probe para arquivo/função real sob source root; conferir unmatched antes de chamada e instrumented apenas após observação. Usar `@linha` existente e condição numérica de argumento. Snapshot deve mostrar linha/pilha, números seguros e strings/objetos/sensíveis redigidos, sem chamar `repr`, getters ou código de expressão. Conferir IDs só quando presentes no contexto. Mudar ambiente/versão e provar isolamento de configuração.

Configurar count, duration (ms) e gauge numérico de argumento/retorno com OTEL_METRICS_EXPORTER=otlp, conferir Meter OTel telvyn.debugger e métricas debug.* na ingest/tela. Com exporter none não esperar exportação. Conferir condições de duração, argumento de entrada e exceção observada (inclui exceção tratada). Criar kind=errors para arquivo.py ou arquivo.py#prefixo e conferir snapshots exception com classe, UUID e locais redigidos, sem mensagem. Coroutines/generators devem ficar unmatched, sem simular chamadas completas. Políticas inválidas devem gerar error. Desativar probe e perder coletor por mais de 60 s: nenhuma captura de política expirada. Repetir debugger externo já instalado, worker preloaded, async, métodos de classe e Python 3.10 (sem nome qualificado), distinguindo retomada de coroutine de nova invocação. Estado visual precisa corresponder à evidência recebida.

## Pendências explícitas

Aceite de todas as combinações, overhead e privacidade de erros; alocação sem extra/plataforma compatível ou depois de fork, heap_objects, native stacks e async Wall completo; propagação IAST completa/fontes e sinks faltantes, NoSQL aggregate/Motor/operadores estruturais; debugger async/generators, replay completo de execução e correlação de uma mesma exceção entre frames; publicação compatível por ABI e distribuição; visualização de fonte remota com revision metadata (não enviada). Nenhuma destas pendências foi substituída por dados sintéticos.

## Fontes oficiais consultadas

- [OTel contrib v0.66b1](https://github.com/open-telemetry/opentelemetry-python-contrib/tree/v0.66b1/instrumentation): implementações/versionamento dos hooks e drivers.
- [Dependência wrapt oficial 0.66b1](https://github.com/open-telemetry/opentelemetry-python-contrib/blob/v0.66b1/opentelemetry-instrumentation/pyproject.toml): intervalo declarado também como dependência direta do SDK.
- [Python sys.setprofile](https://docs.python.org/3/library/sys.html#sys.setprofile), [sys.settrace](https://docs.python.org/3/library/sys.html#sys.settrace), [tracemalloc](https://docs.python.org/3/library/tracemalloc.html): limites dos mecanismos; documentação não certifica este candidato.

## Complemento desta rodada: aceite ainda pendente

Alocação: extra `allocation` fixa Memray 1.19.1 e só o declara para Linux/macOS. Verificar ABI/versão real antes da instalação futura; Windows nativo fica sem captura. A fila transporta somente perfis agregados, sem o arquivo Memray, que contém metadados locais de paths/comando. Diretório temporário privado, remoção após leitura; término abrupto pode deixar arquivo. Janela interrompida por arquivo acima de 16 MiB/erro ou mais de 1 milhão de registros não é enviada e encerra o coletor de alocação; o limite de arquivo é verificado a cada 100 ms e não é um limite rígido de disco ou memória nativa. Até 4096 pilhas são preservadas, com seleção limitada; não declarar cobertura total. O leitor Memray pode fazer processamento interno antes do laço de exportação. Sem contexto trace/span nessa captura. Parsing e reinício deixam gaps; nunca reescalar os pesos como se houvesse captura nesses períodos. CPU por callbacks é desativado para reservar o hook; se o extra faltar a flag deve ser desligada para retomar CPU. Workers precisam inicializar SDK depois do fork, sem preload. Conferir limpeza, erros, interferência com outro profiler e overhead antes de ativar.

IAST: propagação adicionada para lstrip/rstrip/casefold, split/rsplit, partition/rpartition, join com separador marcado e remoção de prefixo/sufixo. Formulários Starlette via _get_form. Fontes de estruturas/objetos não viram origem por igualdade textual. Novos sinks: PyMongo sync/async apenas strings marcadas em $where/$regex/$function.body; comparação normal como controle negativo. LDAP em ldap3.Connection.search, XPath em lxml.XPath, fonte de template em Jinja Environment.from_string. Todas as bibliotecas continuam opcionais da aplicação. São 15 classes IAST; testar cada hook com versões exatas e sinalizar erros de instalação. Novos labels CWE LDAP/XPath no componente existente, sem mudança visual de layout. Formulário DRF que vira QueryDict e conversões Pydantic continuam controles de propagação incompleta.

Debugger: métricas seguem o MeterProvider OTel existente, sem alterar a escolha explícita de exporter. Até 200 instrumentos, 4096 chamadas simultâneas acompanhadas e uma captura por segundo/alvo (até 400 alvos de captura). Condições e gauge recebem argumentos escalares seguros da entrada; não leem propriedades de objetos. Contagem de método acontece ao retorno (normal ou excepcional), contagem de linha a cada passagem. Condição exception significa exceção observada, incluindo tratada; snapshots exception capturam ocorrência, sem afirmar erro não tratado. Métodos suspensíveis são ignorados para preservar significado de chamada/duração. UUID por captura não permite unir a mesma exceção em frames diferentes. TTL 60 s também invalida escopos de erro. Threads anteriores à instalação continuam sem hook; escopos de erro não têm prova individual na tabela de aplicação de method probes existente.

Migration Python nova ainda não aplicada foi renumerada para `V20261015230000__iast_python_findings.sql`, depois da ampliação de regras da outra frente em 15/10. Obtém a expressão CHECK instalada e acrescenta somente as alternativas Python, preservando as demais regras. A versão candidata anterior não tinha sido aplicada/publicada; nenhuma migration aplicada foi editada. Rebase/merge com a main mais recente continua pendente, sem copiar alterações da outra frente para este worktree.

Fontes adicionais: [API Memray](https://bloomberg.github.io/memray/api.html), [API tipada v1.19.1](https://github.com/bloomberg/memray/blob/v1.19.1/src/memray/_memray.pyi), [implementação do leitor v1.19.1](https://github.com/bloomberg/memray/blob/v1.19.1/src/memray/_memray.pyx), [plataformas Memray](https://bloomberg.github.io/memray/supported_environments.html). Leitura dessas fontes não valida integração local.
Referências dos novos sinks: [PyMongo AsyncCollection](https://pymongo.readthedocs.io/en/stable/api/pymongo/asynchronous/collection.html), [ldap3 search](https://ldap3.readthedocs.io/en/latest/searches.html), [lxml XPath](https://lxml.de/xpathxslt.html). APIs de biblioteca foram conferidas por leitura; hooks e versões de aplicações permanecem sem execução local.
