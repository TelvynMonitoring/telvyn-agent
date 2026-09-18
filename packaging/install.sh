#!/usr/bin/env bash
# Telvyn / IspWatch Agent — script canônico de instalação Linux (systemd).
# Atribuições de terceiros: ../THIRD_PARTY_NOTICES.md.
#
# Modelo CERTLESS/INGEST: o agent autentica no gateway
# /api/ingest/v1 com Bearer token (iwI_) sobre HTTPS — sem enrollment, sem
# mTLS, sem cert por máquina. O antigo caminho mTLS ("Plan 09") foi removido.
#
# Uso (o portal gera o comando pronto na tela "Instalar agent"):
#   curl -fsSL <este script> | \
#     ISPWATCH_INGEST_URL='https://telvyn.suaempresa.com' \
#     ISPWATCH_INGEST_TOKEN='iwI_...' \
#     ISPWATCH_AGENT_KIND=linux \
#     sudo -E bash

set -euo pipefail

# === Config ============================================================
# Obrigatórios (Bearer certless):
#   ISPWATCH_INGEST_URL    base do portal (https://...); o agent normaliza o
#                          sufixo /api/ingest/v1 sozinho.
#   ISPWATCH_INGEST_TOKEN  token iwI_ (Bearer).
# Opcionais:
#   ISPWATCH_AGENT_KIND    linux (default) — registra a máquina como host de app.
#   ISPWATCH_AGENT_PROFILE database — Agent dedicado a uma instância PostgreSQL.
#   ISPWATCH_DATABASE_ENGINE postgres — motor do Agent de Banco.
#   ISPWATCH_DATABASE_INSTALLATION_ID — legado; aceito só para instalações
#                                     antigas. Instalações novas se vinculam
#                                     automaticamente pelo UUID da máquina.
#   ISPWATCH_HOSTNAME      nome reportado (default: FQDN da máquina).
#   qualquer ISPWATCH_*/COLLECTOR_LOG_LEVEL extra é repassado ao agente (toggles).
ISPWATCH_AGENT_VERSION="${ISPWATCH_AGENT_VERSION:-latest}"
ISPWATCH_AGENT_KIND="${ISPWATCH_AGENT_KIND:-linux}"
ISPWATCH_AGENT_PROFILE="${ISPWATCH_AGENT_PROFILE:-}"
ISPWATCH_DATABASE_INSTALLATION_ID="${ISPWATCH_DATABASE_INSTALLATION_ID:-}"
ISPWATCH_DATABASE_ENROLLMENT_ID="${ISPWATCH_DATABASE_ENROLLMENT_ID:-}"
ISPWATCH_DATABASE_ENGINE="${ISPWATCH_DATABASE_ENGINE:-postgres}"
# ISPWATCH_UPGRADE=true → atualiza uma instalação existente sem reescrever seu
# EnvironmentFile. Para o profile database o instalador encontra o serviço
# local; o operador nunca precisa informar um identificador.
ISPWATCH_UPGRADE="${ISPWATCH_UPGRADE:-false}"
GITHUB_REPO="${ISPWATCH_GITHUB_REPO:-TelvynMonitoring/telvyn-agent}"
# ISPWATCH_DOWNLOAD_BASE permite redirecionar para mirror/dev local sem
# editar o script (usado pelos smoke tests e por VMs de dev).
ISPWATCH_DOWNLOAD_BASE="${ISPWATCH_DOWNLOAD_BASE:-https://github.com/${GITHUB_REPO}/releases/download}"

INSTALL_DIR="/usr/local/bin"
ETC_DIR="/etc/ispwatch"
BASE_LIB_DIR="/var/lib/ispwatch"
BASE_LOG_DIR="/var/log/ispwatch"
GENERIC_BINARY_PATH="${INSTALL_DIR}/ispwatch-agent"
GENERIC_UNIT_NAME="ispwatch-agent.service"
GENERIC_UNIT_PATH="/etc/systemd/system/${GENERIC_UNIT_NAME}"
DATABASE_UNIT_NAME="telvyn-agent.service"
DATABASE_UNIT_PATH="/etc/systemd/system/${DATABASE_UNIT_NAME}"
DATABASE_UPDATE_UNIT_NAME="telvyn-agent-update.service"
DATABASE_UPDATE_UNIT_PATH="/etc/systemd/system/${DATABASE_UPDATE_UNIT_NAME}"
DATABASE_UPDATE_SCRIPT="/usr/local/lib/telvyn-agent/update"
DATABASE_UPDATE_INSTALLER="/usr/local/lib/telvyn-agent/install"
DATABASE_CONFIG_DIR="/etc/telvyn"
DATABASE_ENV_FILE="${DATABASE_CONFIG_DIR}/agent.env"
DATABASE_BINARY_PATH="/usr/local/bin/telvyn-agent"
DATABASE_LIB_DIR="/var/lib/telvyn-agent"
DATABASE_LOG_DIR="/var/log/telvyn-agent"
DATABASE_SERVICE_USER="telvyn"
DATABASE_SERVICE_GROUP="telvyn"
LEGACY_DATABASE_ENV_FILE=""
LEGACY_DATABASE_UNIT_NAME=""

# === Validação =========================================================
# No modelo certless, INGEST_URL + INGEST_TOKEN são obrigatórios (substituem
# o antigo ISPWATCH_ENROLL_TOKEN do fluxo mTLS).
# No modo upgrade, INGEST_URL/TOKEN vêm do agent.env existente — não exigir.
if [[ "$ISPWATCH_UPGRADE" != "true" ]]; then
    missing=""
    [[ -z "${ISPWATCH_INGEST_URL:-}" ]]   && missing="${missing} ISPWATCH_INGEST_URL"
    [[ -z "${ISPWATCH_INGEST_TOKEN:-}" ]] && missing="${missing} ISPWATCH_INGEST_TOKEN"
    if [[ -n "$missing" ]]; then
        echo "ERROR: variável(is) de ambiente obrigatória(s) ausente(s):${missing}" >&2
        echo "" >&2
        # Sem -E, sudo limpa o environment e perde as vars mesmo que o operador
        # as tenha exportado.
        echo "Dica: esqueceu o 'sudo -E'? Sem -E, o sudo descarta as env vars." >&2
        echo "" >&2
        echo "  curl -fsSL <URL> | \\" >&2
        echo "    ISPWATCH_INGEST_URL='https://telvyn.suaempresa.com' \\" >&2
        echo "    ISPWATCH_INGEST_TOKEN='iwI_...' \\" >&2
        echo "    sudo -E bash" >&2
        exit 1
    fi
fi

AGENT_PROFILE_NORMALIZED=$(printf '%s' "$ISPWATCH_AGENT_PROFILE" | tr '[:upper:]' '[:lower:]')
if [[ "$AGENT_PROFILE_NORMALIZED" == "database" ]]; then
    ISPWATCH_AGENT_PROFILE="database"
fi

if [[ "$ISPWATCH_AGENT_PROFILE" == "database" && "$ISPWATCH_DATABASE_ENGINE" != "postgres" ]]; then
    echo "ERROR: ISPWATCH_DATABASE_ENGINE deve ser postgres para este release." >&2
    exit 1
fi

if [[ "$ISPWATCH_AGENT_PROFILE" == "database" ]]; then
    AGENT_KIND_NORMALIZED=$(printf '%s' "$ISPWATCH_AGENT_KIND" | tr '[:upper:]' '[:lower:]')
    if [[ "$AGENT_KIND_NORMALIZED" != "linux" && "$AGENT_KIND_NORMALIZED" != "docker" ]]; then
        echo "ERROR: Agent de Banco requer ISPWATCH_AGENT_KIND=linux ou docker; não use kind database." >&2
        exit 1
    fi
fi

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: precisa rodar como root (use 'sudo -E')." >&2
    exit 1
fi

# Um host PostgreSQL tem um único Agent de Banco. O agente gera sua própria
# identidade local e envia também a identidade estável da máquina; o backend
# preserva a instância existente sem pedir UUIDs ao operador.
if [[ "$ISPWATCH_AGENT_PROFILE" == "database" ]]; then
    UNIT_NAME="$DATABASE_UNIT_NAME"
    UNIT_PATH="$DATABASE_UNIT_PATH"
    CONFIG_DIR="$DATABASE_CONFIG_DIR"
    ENV_FILE="$DATABASE_ENV_FILE"
    LIB_DIR="$DATABASE_LIB_DIR"
    LOG_DIR="$DATABASE_LOG_DIR"
    BINARY_DIR="$(dirname "$DATABASE_BINARY_PATH")"
    BINARY_PATH="$DATABASE_BINARY_PATH"
    SERVICE_USER="$DATABASE_SERVICE_USER"
    SERVICE_GROUP="$DATABASE_SERVICE_GROUP"

    # Migração sem intervenção: releases anteriores usavam uma unit derivada
    # do UUID. Há somente um Agent de Banco por host; se houver uma única
    # instalação legada, preservamos o segredo e migramos para a unit estável.
    if [[ "$ISPWATCH_UPGRADE" == "true" && ! -f "$ENV_FILE" ]]; then
        if [[ -f "/etc/telvyn/database-agent.env" ]]; then
            # v0.4.21 usava nomes de serviço derivados do perfil. Migra sem
            # expor a identidade ou exigir qualquer parâmetro do operador.
            LEGACY_DATABASE_ENV_FILE="/etc/telvyn/database-agent.env"
            LEGACY_DATABASE_UNIT_NAME="telvyn-agent-database.service"
        else
            mapfile -t legacy_env_files < <(find /etc -maxdepth 2 -type f -path '/etc/ispwatch-database-*/agent.env' 2>/dev/null | sort)
            if [[ ${#legacy_env_files[@]} -eq 1 ]]; then
                LEGACY_DATABASE_ENV_FILE="${legacy_env_files[0]}"
                legacy_dir=$(basename "$(dirname "$LEGACY_DATABASE_ENV_FILE")")
                LEGACY_DATABASE_UNIT_NAME="ispwatch-agent-database@${legacy_dir#ispwatch-database-}.service"
            elif [[ ${#legacy_env_files[@]} -gt 1 ]]; then
                echo "ERROR: foram encontrados vários Agents de Banco legados neste host." >&2
                echo "       Mantenha apenas um Agent de Banco por servidor antes de atualizar." >&2
                exit 1
            fi
        fi
    fi
else
    UNIT_NAME="$GENERIC_UNIT_NAME"
    UNIT_PATH="$GENERIC_UNIT_PATH"
    CONFIG_DIR="$ETC_DIR"
    ENV_FILE="${ETC_DIR}/agent.env"
    LIB_DIR="$BASE_LIB_DIR"
    LOG_DIR="$BASE_LOG_DIR"
    BINARY_DIR="$INSTALL_DIR"
    BINARY_PATH="$GENERIC_BINARY_PATH"
    SERVICE_USER="telvyn"
    SERVICE_GROUP="telvyn"
fi

# === Traps =============================================================
on_error() {
    local lineno=$1
    echo "FATAL: install falhou na linha ${lineno}" >&2
    # Sem cleanup parcial — deixa o estado pro operador inspecionar.
    exit 1
}
on_exit() {
    rm -f /tmp/ispwatch-install-*.tar.gz /tmp/ispwatch-install-*.sha256 2>/dev/null || true
}
trap 'on_error $LINENO' ERR
trap on_exit EXIT

# === Detecção de distro em cascata =====================================
detect_distro() {
    if command -v lsb_release >/dev/null 2>&1; then
        lsb_release -si | tr '[:upper:]' '[:lower:]'
    elif [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release && echo "$ID"
    else
        uname -s | tr '[:upper:]' '[:lower:]'
    fi
}
DISTRO=$(detect_distro)
echo "Distro detectada: $DISTRO"

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)         GO_ARCH=amd64 ;;
    aarch64|arm64)  GO_ARCH=arm64 ;;
    *)              echo "ERROR: arquitetura não suportada: $ARCH (só amd64/arm64)" >&2; exit 1 ;;
esac
echo "Arquitetura detectada: $GO_ARCH"

# === Sanidade systemd ==================================================
# systemd < 247 não suporta algumas directives modernas (ProcSubset=pid,
# RestrictNamespaces granular). Não falha o install — apenas avisa; o kernel
# ignora directives desconhecidas com warning.
if command -v systemctl >/dev/null 2>&1; then
    SD_VER=$(systemctl --version | head -1 | awk '{print $2}')
    if [[ "$SD_VER" =~ ^[0-9]+$ ]] && [[ "$SD_VER" -lt 247 ]]; then
        echo "WARN: systemd $SD_VER detectado; algumas directives de hardening exigem >= 247." >&2
        echo "      O agent instala e roda mesmo assim, com sandbox reduzido." >&2
    fi
else
    echo "ERROR: systemctl não encontrado — o agent IspWatch requer systemd." >&2
    exit 1
fi

# === Idempotência / upgrade ============================================
# A instalação Linux genérica segue singleton. O profile database também é
# singleton por host: ele descobre todos os bancos visíveis para o usuário de
# leitura configurado no PostgreSQL.
INSTALLED=false
if [[ "$ISPWATCH_AGENT_PROFILE" == "database" ]]; then
    if [[ -f "$ENV_FILE" ]] || [[ -f "$BINARY_PATH" ]] || [[ -n "$LEGACY_DATABASE_ENV_FILE" ]]; then
        INSTALLED=true
    fi
elif [[ -f "$GENERIC_BINARY_PATH" ]] || [[ -f "$GENERIC_UNIT_PATH" ]]; then
    INSTALLED=true
fi
if [[ "$ISPWATCH_UPGRADE" == "true" ]]; then
    if [[ "$INSTALLED" != "true" ]]; then
        echo "ERROR: ISPWATCH_UPGRADE=true, mas não há a instalação selecionada do agent aqui para atualizar." >&2
        echo "       Rode o instalador normal (sem ISPWATCH_UPGRADE) primeiro." >&2
        exit 1
    fi
    echo "Modo upgrade: ${UNIT_NAME} detectado — troco apenas seu binário e reinicio (config preservada)."
elif [[ "$INSTALLED" == "true" ]]; then
    echo "WARN: instalação existente do agent IspWatch detectada para ${UNIT_NAME}." >&2
    echo "      Para ATUALIZAR no lugar (preserva token/config), rode com ISPWATCH_UPGRADE=true:" >&2
    if [[ "$ISPWATCH_AGENT_PROFILE" == "database" ]]; then
        echo "        sudo systemctl start ${DATABASE_UPDATE_UNIT_NAME}" >&2
    else
        echo "        curl -fsSL <URL> | ISPWATCH_UPGRADE=true sudo -E bash" >&2
    fi
    exit 1
fi

# === Resolução de versão ===============================================
if [[ "$ISPWATCH_AGENT_VERSION" == "latest" ]]; then
    VERSION=$(curl --proto '=https' --retry 5 --retry-delay 5 -sSL \
        "https://api.github.com/repos/$GITHUB_REPO/releases/latest" \
        | grep '"tag_name"' | head -1 | cut -d'"' -f4)
    if [[ -z "$VERSION" ]]; then
        echo "ERROR: não consegui resolver a última versão via GitHub Releases." >&2
        exit 1
    fi
else
    VERSION="$ISPWATCH_AGENT_VERSION"
fi
if [[ "$ISPWATCH_AGENT_PROFILE" == "database" ]]; then
    echo "Instalando o Agent de Banco Telvyn ${VERSION} para linux-${GO_ARCH}"
else
    echo "Instalando o agent IspWatch ${VERSION} para linux-${GO_ARCH}"
fi

TARBALL="ispwatch-agent-${VERSION}-linux-${GO_ARCH}.tar.gz"
URL="${ISPWATCH_DOWNLOAD_BASE}/${VERSION}/${TARBALL}"

# === Download + verify =================================================
TMP_TARBALL="/tmp/ispwatch-install-${VERSION}-${GO_ARCH}.tar.gz"
TMP_SHA="/tmp/ispwatch-install-${VERSION}-${GO_ARCH}.sha256"

curl --proto '=https' --retry 5 --retry-delay 5 -fsSL -o "$TMP_TARBALL" "$URL"
curl --proto '=https' --retry 5 --retry-delay 5 -fsSL -o "$TMP_SHA" "${URL}.sha256"

# sha256sum -c espera o arquivo no diretório corrente. Mover o sidecar pra um
# working dir temporário evita conflito com nomes absolutos.
WORK_DIR=$(mktemp -d /tmp/ispwatch-install-XXXXXX)
cp "$TMP_TARBALL" "${WORK_DIR}/${TARBALL}"
# O .sha256 publicado pelo release pipeline contém apenas o basename do tarball.
cp "$TMP_SHA" "${WORK_DIR}/${TARBALL}.sha256"
(cd "$WORK_DIR" && sha256sum -c "${TARBALL}.sha256")

# === User + dirs =======================================================
# Usuário de sistema sem shell e sem home — superfície de ataque mínima. O
# profile database recebe usuário/grupo próprios para não expor o token de uma
# instância às outras unidades que estejam no mesmo host.
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi
mkdir -p "$CONFIG_DIR" "$LIB_DIR" "$LOG_DIR" "$BINARY_DIR"

# === Extract + install =================================================
tar -xzf "${WORK_DIR}/${TARBALL}" -C "$WORK_DIR"
EXTRACTED_DIR=$(find "$WORK_DIR" -maxdepth 1 -type d -name "ispwatch-agent-${VERSION}-*" | head -1)
if [[ -z "$EXTRACTED_DIR" ]]; then
    echo "ERROR: diretório extraído não encontrado em $WORK_DIR." >&2
    exit 1
fi

if [[ "$ISPWATCH_AGENT_PROFILE" == "database" && ! -f "$EXTRACTED_DIR/telvyn-agent.service" ]]; then
    echo "ERROR: o release ${VERSION} não contém a unit do Agent de Banco; escolha uma release compatível." >&2
    exit 1
fi
install -m 0755 -o root -g root "$EXTRACTED_DIR/ispwatch-agent" "$BINARY_PATH"
if [[ "$ISPWATCH_AGENT_PROFILE" == "database" ]]; then
    install -m 0644 -o root -g root "$EXTRACTED_DIR/telvyn-agent.service" "$UNIT_PATH"
    install -m 0644 -o root -g root "$EXTRACTED_DIR/telvyn-agent-update.service" "$DATABASE_UPDATE_UNIT_PATH"
    install -d -m 0755 -o root -g root "$(dirname "$DATABASE_UPDATE_INSTALLER")"
    install -m 0755 -o root -g root "$EXTRACTED_DIR/install.sh" "$DATABASE_UPDATE_INSTALLER"
else
    install -m 0644 "$EXTRACTED_DIR/ispwatch-agent.service" "$UNIT_PATH"
fi

# === F2b: helper de atualização remota (privilegiado) ==================
# O agente roda SEM privilégio (User=telvyn) e não pode trocar o próprio
# binário nem se reiniciar. A atualização é delegada ao gerenciador de pacotes;
# quem APLICA o upgrade é um componente ROOT à parte — este helper. Fluxo:
#   config-pull manda should_update → agente escreve /var/lib/ispwatch/update-requested
#   → o .path (root) observa → dispara o .service (root) → roda o upgrade oficial.
# O marcador NÃO carrega payload (sem versão/URL vindo do servidor): um agente
# comprometido não faz o root rodar comando arbitrário — o helper roda SEMPRE o
# mesmo install.sh pinado, com o binário SHA256-verificado. Instalado/atualizado
# tanto no install novo quanto no upgrade (idempotente). O profile database
# tem seu próprio helper: o serviço e seu EnvironmentFile são únicos no host,
# então não há UUID para o operador informar.
if [[ "$ISPWATCH_AGENT_PROFILE" == "database" ]]; then
mkdir -p "$(dirname "$DATABASE_UPDATE_SCRIPT")"
cat > "$DATABASE_UPDATE_SCRIPT" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec env ISPWATCH_UPGRADE=true ISPWATCH_AGENT_PROFILE=database \\
  "${DATABASE_UPDATE_INSTALLER}"
EOF
chmod 0755 "$DATABASE_UPDATE_SCRIPT"
chown root:root "$DATABASE_UPDATE_SCRIPT"
elif [[ "$ISPWATCH_AGENT_PROFILE" != "database" ]]; then
UPGRADE_SCRIPT_URL="${ISPWATCH_INSTALL_SCRIPT_URL:-https://raw.githubusercontent.com/${GITHUB_REPO}/main/packaging/install.sh}"
cat > "$INSTALL_DIR/ispwatch-agent-upgrade" <<EOF
#!/usr/bin/env bash
# Gerado por install.sh (F2b). Roda como ROOT via ispwatch-agent-update.service.
set -euo pipefail
# Apaga o marcador ANTES do upgrade: o install.sh (chamado abaixo) re-liga o
# .path, e se o marcador ainda existisse o .path re-dispararia este .service →
# loop. Removendo primeiro, o re-enable não re-dispara. O ExecStopPost do
# .service é rede de segurança pro caso de falha antes daqui.
rm -f /var/lib/ispwatch/update-requested
logger -t ispwatch-agent-upgrade "atualização disparada — rodando upgrade oficial"
curl --proto '=https' --retry 5 --retry-delay 5 -fsSL "${UPGRADE_SCRIPT_URL}" | ISPWATCH_UPGRADE=true bash
logger -t ispwatch-agent-upgrade "upgrade concluído"
EOF
chmod 0755 "$INSTALL_DIR/ispwatch-agent-upgrade"
chown root:root "$INSTALL_DIR/ispwatch-agent-upgrade"

cat > /etc/systemd/system/ispwatch-agent-update.service <<'EOF'
[Unit]
Description=IspWatch Agent — helper de atualização (root, F2b)
Documentation=https://docs.ispwatch.com/agent
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/ispwatch-agent-upgrade
# Remove o marcador ao fim (sucesso OU falha) pra rearmar o .path e não repetir.
ExecStopPost=-/bin/rm -f /var/lib/ispwatch/update-requested
TimeoutStartSec=300
EOF

cat > /etc/systemd/system/ispwatch-agent-update.path <<'EOF'
[Unit]
Description=IspWatch Agent — observa pedido de atualização remota (F2b)

[Path]
# O agente (sem privilégio) escreve este arquivo quando o config-pull manda
# should_update. A EXISTÊNCIA dispara o .service root (o gatilho não tem payload).
PathExists=/var/lib/ispwatch/update-requested
Unit=ispwatch-agent-update.service

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ispwatch-agent-update.path
fi

# === Upgrade: binário+unit trocados → reinicia e sai ===================
# Preserva o EnvironmentFile (token/config/toggles) — não passa pela reescrita
# abaixo. Na migração da unit antiga, copia o segredo sem o exibir e troca
# apenas o serviço do Agent de Banco.
if [[ "$ISPWATCH_UPGRADE" == "true" ]]; then
    if [[ -n "$LEGACY_DATABASE_ENV_FILE" ]]; then
        grep -Ev '^(ISPWATCH_STATE_DIR|ISPWATCH_LOGS_CURSOR_PATH|ISPWATCH_DATABASE_REVOKED_MARKER_PATH)=' \
            "$LEGACY_DATABASE_ENV_FILE" > "$ENV_FILE"
        {
            echo "ISPWATCH_STATE_DIR=${LIB_DIR}"
            echo "ISPWATCH_LOGS_CURSOR_PATH=${LIB_DIR}/log_cursors.json"
            echo "ISPWATCH_DATABASE_REVOKED_MARKER_PATH=${LIB_DIR}/database-agent-revoked"
        } >> "$ENV_FILE"
        chown "root:${SERVICE_GROUP}" "$ENV_FILE"
        chmod 0640 "$ENV_FILE"
    fi
    # A unit pode ter mudado de usuário entre versões. Ajusta ownership antes
    # do restart para que o novo usuário consiga ler a configuração e usar o
    # WAL/arquivos de estado sem tornar o processo privilegiado.
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$LIB_DIR" "$LOG_DIR"
    chown "root:$SERVICE_GROUP" "$CONFIG_DIR" "$ENV_FILE" 2>/dev/null || true
    systemctl daemon-reload
    if [[ -n "$LEGACY_DATABASE_UNIT_NAME" ]]; then
        systemctl disable --now "$LEGACY_DATABASE_UNIT_NAME" || true
        systemctl enable --now "$UNIT_NAME"
    else
        systemctl restart "$UNIT_NAME"
    fi
    rm -rf "$WORK_DIR"
    echo ""
    if [[ "$ISPWATCH_AGENT_PROFILE" == "database" ]]; then
        echo "OK — Agent atualizado para ${VERSION} (config preservada)."
        echo "Status:     sudo systemctl status ${UNIT_NAME}"
        echo "Atualizar:  sudo systemctl start ${DATABASE_UPDATE_UNIT_NAME}"
        echo "Logs:       sudo journalctl -u ${UNIT_NAME} -f"
    else
        echo "OK — ${UNIT_NAME} atualizado para ${VERSION} e reiniciado (config preservada)."
        echo "Status: systemctl status ${UNIT_NAME}"
    fi
    exit 0
fi

# Permissões finais dos diretórios.
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$LIB_DIR" "$LOG_DIR"
chmod 0700 "$LIB_DIR"
chmod 0750 "$LOG_DIR"
chown "root:$SERVICE_GROUP" "$CONFIG_DIR"
chmod 0750 "$CONFIG_DIR"

# Cleanup do work dir (o trap on_exit cobre os /tmp/ispwatch-install-*.*).
rm -rf "$WORK_DIR"

# === EnvironmentFile do agent (certless) ===============================
# O systemd lê este arquivo (EnvironmentFile) e injeta as vars no processo do
# agent. Modo 0640 root:<grupo-da-unit>: contém o token iwI_ (segredo),
# legível só pelo root e pelo usuário daquela unit.
HOSTNAME_VALUE="${ISPWATCH_HOSTNAME:-$(hostname -f 2>/dev/null || hostname)}"
DATABASE_REVOKED_MARKER_PATH=""
if [[ "$ISPWATCH_AGENT_PROFILE" == "database" ]]; then
    if [[ -n "${ISPWATCH_DATABASE_REVOKED_MARKER_PATH:-}" && "${ISPWATCH_DATABASE_REVOKED_MARKER_PATH:-}" != "${LIB_DIR}/database-agent-revoked" ]]; then
        echo "WARN: ISPWATCH_DATABASE_REVOKED_MARKER_PATH é ignorado no instalador de banco; o marcador fica isolado no estado da instância." >&2
    fi
    DATABASE_REVOKED_MARKER_PATH="${LIB_DIR}/database-agent-revoked"
fi

umask 077
{
    echo "# Gerado por install.sh — modelo certless (Bearer iwI_)."
    echo "# Edite à vontade e rode: sudo systemctl restart ${UNIT_NAME}"
    echo "ISPWATCH_INGEST_URL=${ISPWATCH_INGEST_URL}"
    echo "ISPWATCH_INGEST_TOKEN=${ISPWATCH_INGEST_TOKEN}"
    echo "ISPWATCH_AGENT_KIND=${ISPWATCH_AGENT_KIND}"
    if [[ -n "$ISPWATCH_AGENT_PROFILE" ]]; then
        echo "ISPWATCH_AGENT_PROFILE=${ISPWATCH_AGENT_PROFILE}"
    fi
    if [[ -n "$ISPWATCH_DATABASE_INSTALLATION_ID" ]]; then
        echo "ISPWATCH_DATABASE_INSTALLATION_ID=${ISPWATCH_DATABASE_INSTALLATION_ID}"
    fi
    if [[ -n "$ISPWATCH_DATABASE_ENROLLMENT_ID" ]]; then
        echo "ISPWATCH_DATABASE_ENROLLMENT_ID=${ISPWATCH_DATABASE_ENROLLMENT_ID}"
    fi
    if [[ "$ISPWATCH_AGENT_PROFILE" == "database" ]]; then
        echo "ISPWATCH_DATABASE_ENGINE=${ISPWATCH_DATABASE_ENGINE}"
    fi
    if [[ -n "$DATABASE_REVOKED_MARKER_PATH" ]]; then
        echo "ISPWATCH_DATABASE_REVOKED_MARKER_PATH=${DATABASE_REVOKED_MARKER_PATH}"
    fi
    if [[ "$ISPWATCH_AGENT_PROFILE" == "database" ]]; then
        echo "ISPWATCH_DATABASE_AGENT_ID_PATH=${LIB_DIR}/agent-id"
    fi
    echo "ISPWATCH_INSTALL_MODE=linux"
    echo "ISPWATCH_NODE_NAME=${HOSTNAME_VALUE}"
    # Fila durável de métricas/APM: payloads não confirmados sobrevivem ao
    # restart do serviço e ficam no mesmo diretório persistente do agent.
    echo "ISPWATCH_STATE_DIR=${LIB_DIR}"
    # Cursor dos logs (se ligados) fica sob o dir gravável do serviço.
    echo "ISPWATCH_LOGS_CURSOR_PATH=${LIB_DIR}/log_cursors.json"
} > "$ENV_FILE"

# Repasse dos toggles: qualquer ISPWATCH_*/COLLECTOR_LOG_LEVEL que o operador
# passou (via sudo -E) vai pro agent.env, MENOS as vars de controle do próprio
# instalador (já consumidas acima). Mantém o contrato "1 agente, toggles" sem
# este script precisar conhecer cada capability — evita a defasagem que
# quebrava a instalação quando o front ganhava um toggle novo.
INSTALLER_VARS=" ISPWATCH_AGENT_VERSION ISPWATCH_GITHUB_REPO ISPWATCH_DOWNLOAD_BASE ISPWATCH_INSTALL_ONLY ISPWATCH_HOSTNAME ISPWATCH_ENROLL_TOKEN ISPWATCH_SITE ISPWATCH_DOCKER_INTEGRATION ISPWATCH_INGEST_URL ISPWATCH_INGEST_TOKEN ISPWATCH_AGENT_KIND ISPWATCH_AGENT_PROFILE ISPWATCH_DATABASE_INSTALLATION_ID ISPWATCH_DATABASE_ENROLLMENT_ID ISPWATCH_DATABASE_ENGINE ISPWATCH_DATABASE_REVOKED_MARKER_PATH ISPWATCH_UPGRADE ISPWATCH_INSTALL_SCRIPT_URL ISPWATCH_NODE_NAME ISPWATCH_STATE_DIR ISPWATCH_LOGS_CURSOR_PATH "
for name in $(compgen -v); do
    case "$name" in
        ISPWATCH_*|COLLECTOR_LOG_LEVEL) ;;
        *) continue ;;
    esac
    case "$INSTALLER_VARS" in *" $name "*) continue ;; esac
    printf '%s=%s\n' "$name" "${!name}" >> "$ENV_FILE"
done
umask 022

# Uma nova instalação de banco recebe token/installation_id novos e deve poder
# iniciar mesmo se uma instalação REMOVIDA tinha deixado o marcador local. O
# marcador nunca é limpo pelo binário após um HTTP 410; só uma instalação nova
# explícita do portal pode reativar a coleta.
if [[ "$ISPWATCH_AGENT_PROFILE" == "database" ]]; then
    rm -f -- "$DATABASE_REVOKED_MARKER_PATH"
    # A fresh database installation is a new Agent identity. The machine UUID
    # comes from the OS and remains unchanged, so Telvyn can transfer the
    # existing database instance automatically. Upgrades never execute this.
    rm -f -- "${LIB_DIR}/agent-id"
fi

chown "root:$SERVICE_GROUP" "$ENV_FILE"
chmod 0640 "$ENV_FILE"

# === Docker integration (opt-in) =======================================
# ISPWATCH_DOCKER_INTEGRATION=true dá ao usuário do serviço acesso ao socket
# do Docker (/var/run/docker.sock) via grupo `docker`. Esse grupo é
# root-equivalente no host (membros podem montar / como root via container);
# por isso é opt-in explícito. Default OFF.
if [[ "$ISPWATCH_AGENT_PROFILE" == "database" && "${ISPWATCH_DOCKER_INTEGRATION:-false}" == "true" ]]; then
    echo "WARN: integração Docker ignorada para o profile database; ele não coleta containers nem acessa docker.sock." >&2
elif [[ "${ISPWATCH_DOCKER_INTEGRATION:-false}" == "true" ]]; then
    # groupadd -f cria o grupo se ainda não existir (hosts sem Docker). Quando
    # o operador instalar Docker depois, o grupo é o mesmo (gid pode mudar, mas
    # a pertinência permanece pelo nome).
    groupadd -f docker >/dev/null 2>&1 || true
    usermod -aG docker "$SERVICE_USER"
    echo "Integração Docker habilitada: usuário '${SERVICE_USER}' adicionado ao grupo 'docker'."
    echo "AVISO de segurança: membros do grupo 'docker' têm acesso root-equivalente"
    echo "                    ao daemon Docker. Audite quem mais está no grupo."
fi

# === Start =============================================================
systemctl daemon-reload
if [[ "${ISPWATCH_INSTALL_ONLY:-}" != "true" ]]; then
    systemctl enable --now "$UNIT_NAME"
    echo ""
    if [[ "$ISPWATCH_AGENT_PROFILE" == "database" ]]; then
        echo "OK — Agent instalado e iniciado."
        echo "Status:     sudo systemctl status ${UNIT_NAME}"
        echo "Reiniciar:  sudo systemctl restart ${UNIT_NAME}"
        echo "Atualizar:  sudo systemctl start ${DATABASE_UPDATE_UNIT_NAME}"
        echo "Logs:       sudo journalctl -u ${UNIT_NAME} -f"
    else
        echo "OK — ${UNIT_NAME} instalado e iniciado (kind=${ISPWATCH_AGENT_KIND})."
        echo "Status: systemctl status ${UNIT_NAME}"
        echo "Logs:   journalctl -u ${UNIT_NAME} -f"
    fi
else
    echo ""
    echo "OK — ${UNIT_NAME} instalado (ISPWATCH_INSTALL_ONLY=true; não iniciado)."
    echo "Iniciar: sudo systemctl enable --now ${UNIT_NAME}"
fi
