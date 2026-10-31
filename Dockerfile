# Production Dockerfile for the Telvyn Collector.
# Multi-stage: build a static binary in a Go toolchain image, then ship it
# in a minimal distroless image. Image is published as
# ghcr.io/telvynmonitoring/telvyn-agent by the publish-collector GitHub Actions
# workflow on every release tag.

# ---------- Stage 1: protoc + go build ----------
FROM golang:1.25-alpine AS build

ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache git protoc protobuf-dev make ca-certificates

# Pre-install protoc Go plugin (messages only — certless, sem serviço gRPC).
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest

WORKDIR /src

# Cache deps separately from source to keep rebuilds fast.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Regenerate proto stubs (cheap if up to date) — keeps the image
# self-contained even if the committed *.pb.go drift from the .proto.
ENV PATH="/go/bin:${PATH}"
RUN protoc --proto_path=proto/v1 \
           --go_out=proto/v1 --go_opt=paths=source_relative \
           proto/v1/collector.proto proto/v1/apm_stats.proto

# Static build (CGO_ENABLED=0) so we can run on distroless/scratch.
# -trimpath strips local paths from the binary; -s -w shrinks size; -X stamps
# the Version variable consumed by main.go for the startup log.
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath \
      -ldflags "-s -w -X main.Version=${VERSION}" \
      -o /out/telvyn-agent \
      ./cmd/collector

RUN go run ./cmd/package-proxmox -out /out/integrations -arch ${TARGETARCH:-amd64}

# ---------- Stage 1b: agentes de linguagem (Java/Node) ----------
# Mesma imagem que o webhook usa no Kubernetes; aqui seu conteúdo viaja dentro da
# imagem única do agent e é copiado pelo entrypoint para o volume compartilhado.
FROM ghcr.io/telvynmonitoring/telvyn-runtime-agents:0.5.5 AS runtime-agents

# ---------- Stage 2: runtime ----------
# Alpine (not distroless) so the entrypoint shell can expand env vars into
# CLI flags — keeps the Go binary simple (flag-only, no env-aware config)
# and the env-var contract documented in install-collector.sh's compose file.
FROM alpine:3.20

LABEL org.opencontainers.image.title="Telvyn Collector"
LABEL org.opencontainers.image.description="On-prem agent that connects via mTLS to the Telvyn central server."
LABEL org.opencontainers.image.source="https://github.com/telvynmonitoring/telvyn-agent"
LABEL org.opencontainers.image.licenses="proprietary"

RUN apk add --no-cache ca-certificates tini python3 \
 && addgroup -S telvyn \
 && adduser -S -G telvyn -u 10001 telvyn

# OpenTelemetry Java auto-instrumentation jar — embarcado na imagem do agent
# pra ser servido pra pods Java instrumentados (via initContainer injetado
# pelo nosso webhook). Versão fixa pra reprodutibilidade. Apache-2.0.
ARG OTEL_JAVAAGENT_VERSION=2.10.0
RUN apk add --no-cache --virtual .otel-build wget \
 && mkdir -p /opt/otel \
 && wget -q -O /opt/otel/javaagent.jar \
      "https://github.com/open-telemetry/opentelemetry-java-instrumentation/releases/download/v${OTEL_JAVAAGENT_VERSION}/opentelemetry-javaagent.jar" \
 && apk del .otel-build

# Trivy — scanner de SBOM (vulnerabilidade de aplicação, camada 2/3). Embarcado
# ao lado do binário do agent (decisão: binário leve, só GERAÇÃO de SBOM, SEM
# banco de CVE — o casamento com o catálogo roda no backend). Apache-2.0. Só é
# usado quando o toggle sbomScan está ligado. Versão fixa pra reprodutibilidade.
ARG TRIVY_VERSION=0.71.2
ARG TARGETARCH
RUN apk add --no-cache --virtual .trivy-build wget tar \
 && case "${TARGETARCH:-amd64}" in \
      arm64) TRIVY_ARCH="Linux-ARM64" ;; \
      *)     TRIVY_ARCH="Linux-64bit" ;; \
    esac \
 && wget -q -O /tmp/trivy.tar.gz \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${TRIVY_ARCH}.tar.gz" \
 && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
 && chmod 755 /usr/local/bin/trivy \
 && rm -f /tmp/trivy.tar.gz \
 && apk del .trivy-build

COPY --from=build /out/telvyn-agent /usr/local/bin/telvyn-agent
COPY --from=build /out/integrations /opt/telvyn/integrations
# Agentes de linguagem (Java e Node) que o entrypoint publica em /opt/telvyn-shared quando
# TELVYN_LANGUAGE_AGENTS está definida. O jar do OpenTelemetry baixado acima acompanha o do Java.
COPY --from=ghcr.io/telvynmonitoring/telvyn-runtime-agents:0.5.5 /opt/telvyn/java /opt/telvyn/java
COPY --from=ghcr.io/telvynmonitoring/telvyn-runtime-agents:0.5.5 /opt/telvyn/node /opt/telvyn/node
RUN cp /opt/otel/javaagent.jar /opt/telvyn/java/opentelemetry-javaagent.jar
ENV TELVYN_EXTERNAL_PACKAGE_DIR=/opt/telvyn/integrations/packages \
    TELVYN_EXTERNAL_TRUST_DIR=/opt/telvyn/integrations/trust \
    TELVYN_EXTERNAL_PYTHON=/usr/bin/python3
COPY --chmod=755 docker/entrypoint.sh /usr/local/bin/entrypoint.sh
# O repositório pode ser checkoutado com CRLF no Windows; o shebang precisa
# terminar em LF para o tini executar o script dentro do Alpine.
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh

# O check icmp.ping abre socket ICMP cru (pinger.SetPrivileged(true)) e exige
# CAP_NET_RAW EFETIVO. Como a imagem roda com usuário não-root, a capability
# concedida pelo runtime (`--cap-add NET_RAW` / `capabilities.add`) entra só no
# bounding set e NÃO chega ao processo — medido: CapPrm/CapEff = 0. Marcar o
# binário faz o kernel entregá-la no exec. Sem isso o check falha em loop com
# "listen ip4:icmp: socket: operation not permitted". No systemd o equivalente
# já existe (AmbientCapabilities no unit) — isto alinha o Docker/k8s.
RUN apk add --no-cache --virtual .cap-build libcap \
 && setcap cap_net_raw+eip /usr/local/bin/telvyn-agent \
 && apk del .cap-build

# install-collector.sh mounts certs read-only at this path. The state volume is
# explicit so the certless outbox survives replacement of a Docker container.
RUN mkdir -p /var/lib/telvyn /opt/telvyn-shared \
 && chown -R telvyn:telvyn /var/lib/telvyn /opt/telvyn-shared
VOLUME ["/etc/telvyn/certs", "/var/lib/telvyn", "/opt/telvyn-shared"]

USER telvyn:telvyn

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]
