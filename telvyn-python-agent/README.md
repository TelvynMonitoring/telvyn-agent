# Agente Telvyn para Python

Validado em 19/10/2026 num Ubuntu 24.04 (Python 3.12) com Flask em gunicorn (2 workers) e FastAPI em uvicorn, contra o Agent Telvyn e o backend locais. Não publicado nem ativado. O que foi medido:

- traces e estatísticas com rota parametrizada, ambiente e erros; spans de PostgreSQL (psycopg); relatório de configuração do SDK;
- perfis de CPU (com vínculo ao trace) e Wall nos dois servidores, inclusive nos workers do gunicorn; heap com a flag própria;
- detecção de XSS nos dois; IAST de SQL injection no Flask (origem `query:q`, ponto `dbapi.execute`); depurador com snapshots de método.

Lacunas medidas, ainda abertas: o SQLi clássico `' OR '1'='1` não é detectado (as regras de ataque são dois padrões locais, não o conjunto recomendado, e não bloqueiam); spans de banco ficam com o nome só da operação (`SELECT`, sem a tabela); no FastAPI, parâmetros convertidos pelo Pydantic perdem a marcação do IAST; o custo por requisição com todos os recursos ligados não foi otimizado. Inventário e roteiro em [APM-PARITY-REMAINING](../docs/APM-PARITY-REMAINING.md).

## Inicialização

Use o `telvyn-python` da mesma venv da aplicação; ele acha o launcher do OpenTelemetry e o servidor (gunicorn, uvicorn) na venv mesmo sem ela estar ativada, como num serviço systemd com o caminho completo:

```sh
pip install /caminho/telvyn-python-agent
export OTEL_SERVICE_NAME=minha-api
export OTEL_EXPORTER_OTLP_ENDPOINT=http://coletor:4318
export OTEL_RESOURCE_ATTRIBUTES=deployment.environment.name=development,service.version=1.0.0
export OTEL_METRICS_EXPORTER=none
export OTEL_LOGS_EXPORTER=none
telvyn-python gunicorn meu_modulo:app
# ASGI: telvyn-python uvicorn meu_modulo:app
```

A inicialização precisa anteceder imports da aplicação. Frameworks, servidores e drivers pertencem à aplicação; o pacote declara as instrumentações OTel 0.66b1. Não instrumente a mesma biblioteca novamente. `OTEL_SDK_DISABLED=true` preserva o comando original, sem sensores Telvyn. Outro `OTEL_PYTHON_CONFIGURATOR` explícito prevalece e não instala os sensores deste configurator.

| HTTP | Código de integração | Limite |
| --- | --- | --- |
| Flask | OTel Flask, exceção real, fontes Werkzeug/Flask | Validar handlers, async e workers |
| Django / DRF | OTel Django, fontes Django e JSON DRF | DRF usa span Django; serializers podem perder taint |
| FastAPI / Starlette | Instrumentações próprias, fontes Starlette | Validar ausência de SERVER duplicado; Pydantic pode perder taint; forms via _get_form; uploads permanecem objetos redigidos |
| aiohttp | OTel servidor, query/headers/cookies/JSON/form | Validar middleware, streaming e tarefas de fundo |
| Tornado | OTel e getters de query/body/cookie | Fontes não abrangem todo acesso direto ao request |
| Falcon | OTel Falcon e fontes Request | Caminho WSGI; ASGI não presumido |
| Pyramid | OTel Pyramid e fontes WebOb | Validar request extensions e roteamento |
| Quart / Litestar / Sanic em ASGI | Adaptador ASGI explícito | Sem integração nativa ou fontes IAST específicas |
| Bottle / CherryPy em WSGI | Adaptador WSGI explícito | Sem integração nativa ou fontes IAST específicas |

Para frameworks sem instrumentação própria, exporte a aplicação envolvida por **um** adaptador, mantendo o launcher:

```python
from telvyn_python_agent import instrument_asgi
app = instrument_asgi(app)
# WSGI: from telvyn_python_agent import instrument_wsgi
# app = instrument_wsgi(app)
```

Middleware genérico não garante rota parametrizada, reconhecimento de erros tratados ou fontes IAST. Sanic no servidor nativo não é coberto por esse adaptador. CPU/heap/configuração/debugger não dependem de um framework; correlação requer spans reais.

## Configuração e transporte

O reporter envia inicialmente e a cada aproximadamente 60 s, sem depender de tráfego, sete campos ao coletor `/v1/sdk/configuration`. Identidade: Resource (`service.name`, ambiente, versão), `POD_NAME`/`host.name`/hostname; versão do SDK instalada e Python real. Exige serviço explícito. Não enumera ambiente nem usa token do backend.

| Variável | Padrão e significado |
| --- | --- |
| `TELVYN_PROFILING_ENABLED` | `false`; habilita CPU (Linux) |
| `TELVYN_PROFILE_HEAP_ENABLED` | `false`; acrescenta heap vivo se profiling habilitado. Caro: o `tracemalloc` rastreia toda alocação (não amostra); medido, a subida do Flask de teste foi de 1,5 s para 29,5 s |
| `TELVYN_PROFILE_WALL_ENABLED` | `false`; acrescenta Wall se profiling habilitado |
| `TELVYN_PROFILE_ALLOCATION_ENABLED` | `false`; captura eventos de alocação com extra Memray compatível |
| `TELVYN_PROFILING_PERIOD_MS` | `10`; coleta usa clamp 1–1000 |
| `TELVYN_PROFILING_FLUSH_SEC` | `15`; coleta usa clamp 2–600 |
| `TELVYN_PROFILE_SOURCE_ROOT` | Diretório absoluto da aplicação; exigido por profiling, security e debugger |
| `TELVYN_SECURITY_ENABLED` | `false`; padrões SQLi/XSS sobre entradas lidas |
| `TELVYN_IAST_ENABLED` | `false`; rastreio parcial de origem e sinks |
| `TELVYN_SECURITY_ROUTES` | Sem padrão: allowlist obrigatória, separada por vírgulas, ex. `/api/search,/api/items/*`; `*` cobre um segmento |
| `TELVYN_DEBUGGER_ENABLED` | `false`; snapshots remotos de método/linha |

Flags Telvyn só aceitam texto exato `true`. As cinco configurações de profiling reportam valor solicitado/origem, não comprovam sensor ativo. Inteiros válidos signed64 são normalizados; texto inválido vira `invalid`, nunca é exportado cru. O sampler aceita signed32, usa defaults para inválidos e clamp acima. Os dois estados security são `disabled`, `active` (hooks registrados) ou `error`; active não certifica cobertura dos frameworks carregados.

Transporte HTTP/HTTPS pelo endpoint base do coletor, sem redirects, credenciais em URL, query ou fragmento. HTTPS verifica certificado padrão. Timeout de socket 5 s; sem deadline total de DNS, proxy/CA privada/configuração nova de autenticação. Fila em memória de 32 relatórios, limites por payload, sem retry persistente. Sob falha/saturação ou saída abrupta há perda. Threads daemon reiniciam após fork; configuração agrega por serviço/host, não PID. Não foi medido overhead.

## Sinais e limites

- **CPU:** sem gancho na aplicação: a thread do profiler amostra as pilhas a cada período e conta uma amostra para cada thread que usou CPU no período (tempo de CPU por thread lido de `/proc/self/task/<id>/schedstat`; só Linux). Unidade: amostras; não duração exata. Não fabrica amostras perdidas ou linhas de execução. Vincula trace/span/rota quando a thread tem exatamente uma requisição ativa (servidores síncronos); num event loop com várias requisições ao mesmo tempo a amostra vai sem vínculo, em vez de adivinhar. Depois de fork (workers do gunicorn) o profiler reinicia no filho com o id nativo correto da thread. A versão anterior, com `sys.setprofile`, fazia uma chamada de sistema por função executada e a aplicação não terminava de subir.
- **Wall:** observa pilhas reais de threads, peso igual ao período em nanossegundos. Não cobre coroutines suspensas nem toda espera async; não associa trace por suposição. Linhas observadas são preservadas.
- **Heap:** bytes vivos rastreados por `tracemalloc`, limitados a pilhas da aplicação. Não é RSS, histórico de alocação ou contagem de objetos. Arquivo/linha disponíveis; nome de função ausente. Não envia `heap_objects` nem IDs de trace para heap. Alocação usa a captura independente abaixo. Snapshots podem custar memória/CPU e observam objetos repetidos entre janelas.
- **Alocação:** `pip install "/caminho/telvyn-python-agent[allocation]"` instala o extra opcional Memray 1.19.1 para Linux/macOS. Exige profiling e flag allocation. Captura eventos reais, soma seus bytes (inclui blocos já liberados e bytes solicitados em realloc) e envia `alloc` com arquivos/funções/linhas observados, sem trace atribuído. Não extrapola períodos sem coleta. CPU, Wall e heap continuam independentes. Windows nativo sem esse mecanismo. Capturas em diretório temporário privado são removidas após leitura; podem conter paths/comando localmente e permanecer após término abrupto. O arquivo não é enviado. Limite observado de 16 MiB por arquivo, verificado a cada 100 ms (pode ultrapassar entre verificações); até 1 milhão de registros e 4096 pilhas exportadas. Limite/erro omite a janela e encerra essa coleta; reinício requer novo processo. Há lacunas entre janelas durante parsing/reinício. Capture size, buffers nativos e overhead precisam de medição. Após fork a coleta não é retomada: inicialize o SDK no worker, sem preload. Não equivale a contagem de objetos Python ou memória física total.
- **Debugger:** snapshots de saída/linha, `count`, histograma `duration` em ms e `gauge` numérico de argumento/retorno. Alvos `arquivo.py#funcao`, `arquivo.py#Classe.metodo` ou `@linha`. Condições numéricas de argumento/duração e booleanas de exceção observada na chamada; exceções tratadas também contam como observadas. Argumentos são os valores escalares seguros da entrada. Strings/objetos/sensíveis são redigidos, sem `repr`, getters ou expressões executáveis. Capturas no máximo uma/segundo/alvo, até 400 alvos de captura e 4096 chamadas simultâneas acompanhadas; até 200 instrumentos métricos. As métricas usam o MeterProvider OTel configurado: `OTEL_METRICS_EXPORTER=none` as mantém sem exportação; para aceite configure `otlp` e o coletor. Escopos de erro remotos (`kind=errors`, alvo `arquivo.py` ou `arquivo.py#prefixo`) geram snapshots na ocorrência de exceções, incluindo tratadas, com classe/UUID e locais redigidos; não enviam mensagem bruta. UUID identifica captura, não deduplica uma exceção entre frames. Não é gravação/reprodução completa de execução. Coroutines, generators e async generators são ignorados, permanecem unmatched; não simula duração inteira a partir de retomadas. Instala hooks só na thread atual/futuras, sem substituir trace hook existente. Configuração expira em 60 s, polling 15 s. Python 3.10 só fornece `co_name`, sem nomes qualificados de classe; closures/lambdas ficam fora. Funciona com código síncrono em frameworks ASGI, sem declarar cobertura async completa.
- **Banco:** psycopg2/psycopg, asyncpg, PyMySQL, mysqlclient e SQLite via drivers OTel. ORM Django/SQLAlchemy só é coberto quando usa esses drivers, sem segunda camada de spans. Só cria spans com request ativo; conexão/boot e tarefas após fim do request não geram spans de banco. Preserva status/exceção real do driver. SQL é mascarado no exporter antes da rede, parâmetros removidos e aliases legados preenchidos. O SQL bruto pode existir no buffer interno OTel até exportação. Máscara conservadora remove literais/comentários e aspas duplas (mesmo quando identificadores); não é parser completo de todos os dialetos.
- **HTTP:** remove query, fragmento e userinfo de URLs; remove atributos padrão de headers, cookies e bodies (exceto tamanho), inclusive eventos/links. Não lê streams para capturar corpo. Logs de conclusão contêm método/status/trace, sem corpo. Não sanitiza logs de negócio nem texto arbitrário; exceções reais podem conter valores que o próprio driver inclui na mensagem. Essas mensagens exigem revisão no aceite de privacidade.

## Segurança e IAST

Opt-in, ambiente explícito, source root e rotas obrigatórios. Entradas são examinadas quando a aplicação as lê. Regras `python-input-patterns-1`/engine `python-patterns-1` são padrões locais SQLi/XSS, **não o motor WAF dos agentes Java/Node** e não bloqueiam requests. Só enviam matches reais; ausência de evento não é prova de requisição analisada.

IAST `iast-python-1` acompanha `InputString` no request atual, com propagação parcial por concatenação e alguns métodos. F-strings, template str comum com `%`/`format`, `join`, serialização, conversões Pydantic/C e acessos não envolvidos podem perder taint. Não compara substrings para inventar vínculo. Fora da allowlist, após o request ou entre requests não deve atribuir fontes.

Sinks escritos: SQL nos drivers, subprocess com shell/os.system, caminhos open/io.open, URLs requests/httpx/urllib/aiohttp, eval/exec e Jinja Environment.from_string, redirect/headers, hash/cifra fracos, cookies sem flags, lxml.XPath e ldap3.Connection.search. PyMongo sync/async acompanha apenas valores com origem preservada em $where, $regex e $function.body; parâmetros normais de igualdade não são classificados como código. Reportam classe, arquivo/linha, pilha, campo de origem, request sem query, sink e SQL mascarado quando aplicável; nunca valor bruto da entrada. Hash/cifra/cookies são falhas de configuração, não exigem taint. Cobertura de APIs/argumentos é parcial, detalhada no inventário. NoSQL não cobre operadores enviados como JSON numérico/booleano, pipelines aggregate ou Motor. Não é scanner geral.

O backend candidato e a migration incremental `V20261015230000__iast_python_findings.sql` são necessários antes de receber regras Python. Nenhuma migration existente foi alterada, nem aplicada nesta rodada.

## Distribuição e histórico

O Dockerfile existente usa CPython 3.13/Alpine musl. Injeção por `webhook.pythonAgentImageRef` e annotation `instrumentation.telvyn.io/python-containers` permanece; imagem/ABI/arquitetura precisam coincidir com a aplicação. Não foi gerada imagem nova, pacote PyPI ou bundle.

O aceite de 12/10 usou somente Flask, SDK anterior, imagem `telvyn-language-lab-python:20261012-agent1`, evidência `artifacts/polyglot-20261012/python-agent-trace-light.png`. Não estender esse aceite à versão candidata, frameworks, bancos, profiler, security ou debugger atuais.
