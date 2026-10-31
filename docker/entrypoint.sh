#!/bin/sh
# Launches the Telvyn agent (certless-only). The agent ships telemetry over
# HTTP/OTLP with a Bearer ingest token — no enrollment, no mTLS, no per-agent
# cert.
#
# Two boot modes:
#
# (1) Ingest (DaemonSet / docker / linux / cluster-agent):
#     Required envs — TELVYN_INGEST_URL, TELVYN_INGEST_TOKEN.
#     Optional      — TELVYN_CLUSTER, TELVYN_AGENT_KIND, NODE_NAME and the
#                     per-capability toggles (TELVYN_EBPF_TRACING, …).
#     The binary detects TELVYN_INGEST_URL and runs this mode.
#
# (2) Webhook (mutating admission controller): runs as a separate Deployment,
#     triggered by the --webhook arg. Also uses TELVYN_INGEST_URL/TOKEN for
#     the Bearer the injected agents receive.
#
# Optional always: COLLECTOR_LOG_LEVEL (default: info; read from env by the binary).

set -eu

# Modo webhook (admission controller): roda como Deployment separado, não
# DaemonSet. Repassa os args pro binário (--webhook).
for a in "$@"; do
  if [ "$a" = "--webhook" ] || [ "$a" = "-webhook" ]; then
    echo "entrypoint: webhook mode (mutating admission controller)" >&2
    exec /usr/local/bin/telvyn-agent "$@"
  fi
done

# Agentes de linguagem: TELVYN_LANGUAGE_AGENTS=java,node publica os agentes embutidos
# na imagem no volume compartilhado (/opt/telvyn-shared), que os containers da
# aplicação montam somente leitura. Versões antigas são substituídas.
if [ -n "${TELVYN_LANGUAGE_AGENTS:-}" ]; then
  shared="${TELVYN_LANGUAGE_AGENTS_DIR:-/opt/telvyn-shared}"
  if [ ! -w "$shared" ]; then
    echo "entrypoint: $shared não é gravável pelo usuário $(id -u); monte um volume nomeado novo ou ajuste a posse para 10001:10001" >&2
    exit 1
  fi
  for lang in $(printf '%s' "$TELVYN_LANGUAGE_AGENTS" | tr ',' ' '); do
    case "$lang" in
      java|node)
        tmp="$shared/.$lang.new"
        rm -rf "$tmp"
        cp -R "/opt/telvyn/$lang" "$tmp"
        chmod -R a+rX,go-w "$tmp"
        rm -rf "${shared:?}/$lang"
        mv "$tmp" "$shared/$lang"
        echo "entrypoint: agente $lang publicado em $shared/$lang" >&2
        ;;
      "") ;;
      *) echo "entrypoint: linguagem '$lang' não suportada em TELVYN_LANGUAGE_AGENTS (java,node)" >&2 ;;
    esac
  done
fi

# Modo ingest certless: manda OTLP com token Bearer pro gateway. O binário
# detecta TELVYN_INGEST_URL e roda esse modo (e aborta se estiver ausente).
: "${TELVYN_INGEST_URL:?Missing TELVYN_INGEST_URL (certless ingest mode)}"
echo "entrypoint: ingest mode (certless OTLP -> gateway)" >&2
exec /usr/local/bin/telvyn-agent
