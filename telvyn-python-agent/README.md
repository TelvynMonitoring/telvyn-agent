# Agente Telvyn para Python

Injeção Kubernetes: construa `docker build -f telvyn-python-agent/Dockerfile -t <imagem> .` na raiz e configure `webhook.pythonAgentImageRef` no chart do coletor. A annotation do template `instrumentation.telvyn.io/python-containers: "nome-do-container"` instala a distro via `PYTHONPATH/sitecustomize`, preservando o comando. A imagem atual é CPython 3.13/Alpine musl; escolha ABI/arquitetura compatíveis com a aplicação. Flask sem SDK instalado foi validado ligado/sem annotation, 200/200/500 e log→trace na tela em claro/escuro. Não substituir configuração herdada de imagem/envFrom sem conferência.

Distribuição OTel reutilizável, carregada antes da aplicação pelo comando `telvyn-python`, como o modelo de launcher do [DD](https://docs.datadoghq.com/tracing/trace_collection/dd_libraries/python/). Usa os pontos de extensão oficiais de [auto-instrumentação Python](https://opentelemetry.io/docs/zero-code/python/) para Flask e exportação HTTP/OTLP ao coletor Telvyn existente. Não envia ao Datadog.

```sh
pip install /caminho/telvyn-python-agent
export OTEL_SERVICE_NAME=minha-api
export OTEL_EXPORTER_OTLP_ENDPOINT=http://coletor:4318
export OTEL_RESOURCE_ATTRIBUTES=deployment.environment.name=development,service.version=1.0.0
export OTEL_METRICS_EXPORTER=none
export OTEL_LOGS_EXPORTER=none
telvyn-python python app.py
# ou: telvyn-python gunicorn meu_modulo:app
```

A aplicação não importa tracing. O pacote instala a instrumentação Flask, registra exceções reais da aplicação e escreve um log de conclusão HTTP com contexto válido. Remove valores de query dos atributos de URL exportados. Não captura corpo, cookies ou headers de autenticação. Logs de negócio não recebem injeção nesta unidade.

`OTEL_SDK_DISABLED=true` executa o comando original sem auto-instrumentação nem logs do pacote. Não carregue outro SDK/tracer simultaneamente para as mesmas bibliotecas. A instrumentação exige inicialização anterior aos imports da aplicação. Os componentes SDK estão fixados no pyproject; uma atualização exige conferir os pontos de extensão e validar de novo.

Validação usa Python 3.13/Flask 3.1.3 com a mesma fonte reutilizável, 200/200/500 ligada/desligada. Imagem `telvyn-language-lab-python:20261012-agent1`, pod `python-66f9f54854-4kcl5`: rodada real com 18 códigos esperados concluída; log→trace `7f30c4ee810f2e1bcd15711b17030b16`, SERVER `/error`, exceção e um log correlacionado exercitados no portal. Evidência local `artifacts/polyglot-20261012/python-agent-trace-light.png`. Sem restart backend/coletor. Outros frameworks, versões, servidores e bibliotecas de banco não são certificados por essa rodada; Gunicorn é exemplo de inicialização, não aceite já exercitado. IAST/profiling não fazem parte desta entrega. O registry PyPI não foi publicado. Uma parada abrupta ou coletor indisponível pode perder spans ainda em memória.
