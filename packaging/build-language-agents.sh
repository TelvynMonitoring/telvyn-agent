#!/usr/bin/env bash
# Monta telvyn-language-agents-<versão>.tar.gz: os agentes Telvyn de linguagem para máquinas comuns, instalados pelo
# install.sh com ISPWATCH_LANGUAGE_AGENTS=java,node em /opt/telvyn/<linguagem>. É o mesmo conteúdo que a imagem
# telvyn-runtime-agents leva ao Kubernetes:
#   java/opentelemetry-javaagent.jar  o tracer (distribuição OpenTelemetry, mesma versão do Dockerfile do coletor)
#   java/telvyn-javaagent.jar         perfis, segurança, IAST e depurador da Telvyn
#   node/                             o SDK Node (bootstrap.cjs) com as dependências de produção
# Requer: JDK 21 + Maven, Node 20 + npm, curl e sha256sum.
#
# Uso: packaging/build-language-agents.sh <versão> [diretório de saída, padrão dist]
set -euo pipefail

VERSION="${1:?informe a versão, ex.: v0.9.9}"
OUT_DIR="${2:-dist}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

OTEL_JAVAAGENT_VERSION=2.10.0
# O projeto OpenTelemetry não publica o sha256 do jar; este é o do asset oficial da v2.10.0, conferido ao fixar a
# versão. Trocar a versão exige recalcular.
OTEL_JAVAAGENT_SHA256=d05f6e36fac8db629263a6aaec2841cc934d064d7b19bfe38425b604b8b54926

NAME="telvyn-language-agents-${VERSION}"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
STAGE="${OUT_DIR}/${NAME}"
rm -rf "$STAGE"
mkdir -p "$STAGE/java" "$STAGE/node"

echo "==> Java: agente Telvyn"
(cd "$ROOT/telvyn-java-agent" && mvn -B -q -Dmaven.test.skip=true package)
jars=("$ROOT"/telvyn-java-agent/target/telvyn-debugger-*.jar)
if [[ ${#jars[@]} -ne 1 || ! -f "${jars[0]}" ]]; then
    echo "ERROR: esperava um único target/telvyn-debugger-*.jar, encontrei: ${jars[*]}" >&2
    exit 1
fi
cp "${jars[0]}" "$STAGE/java/telvyn-javaagent.jar"

echo "==> Java: OpenTelemetry javaagent ${OTEL_JAVAAGENT_VERSION}"
curl --proto '=https' --retry 5 --retry-delay 5 -fsSL -o "$STAGE/java/opentelemetry-javaagent.jar" \
    "https://github.com/open-telemetry/opentelemetry-java-instrumentation/releases/download/v${OTEL_JAVAAGENT_VERSION}/opentelemetry-javaagent.jar"
echo "${OTEL_JAVAAGENT_SHA256}  $STAGE/java/opentelemetry-javaagent.jar" | sha256sum -c -

echo "==> Node: SDK e dependências de produção"
cp "$ROOT"/telvyn-node-agent/package.json "$ROOT"/telvyn-node-agent/package-lock.json \
   "$ROOT"/telvyn-node-agent/*.cjs "$ROOT"/telvyn-node-agent/loader.mjs \
   "$ROOT"/telvyn-node-agent/waf-rules.json "$ROOT"/telvyn-node-agent/WAF-RULES-NOTICE.md "$STAGE/node/"
(cd "$STAGE/node" && npm ci --omit=dev --no-audit --no-fund --loglevel=error)

cp "$ROOT/LICENSE" "$ROOT/THIRD_PARTY_NOTICES.md" "$STAGE/"
(cd "$OUT_DIR" && tar -czf "${NAME}.tar.gz" "$NAME" && sha256sum "${NAME}.tar.gz" > "${NAME}.tar.gz.sha256")
echo "==> Built: ${OUT_DIR}/${NAME}.tar.gz"
cat "${OUT_DIR}/${NAME}.tar.gz.sha256"
