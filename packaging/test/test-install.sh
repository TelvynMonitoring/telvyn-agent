#!/usr/bin/env bash
# Smoke test: install.sh syntactically valid + shellcheck clean across
# 3 distros (Ubuntu 22.04, Debian 11, Rocky 9). Full e2e install requires
# GH Releases (Plan 09) — deferido.

set -euo pipefail

cd "$(dirname "$0")"

# O Agent de Banco é único por host e usa comandos systemctl estáveis. A
# identidade da instalação permanece no EnvironmentFile, fora das instruções
# operacionais do usuário.
test -f ../telvyn-agent-database.service
test -f ../telvyn-agent-database-update.service
grep -Fq 'User=telvyn-database' ../telvyn-agent-database.service
grep -Fq 'Group=telvyn-database' ../telvyn-agent-database.service
grep -Fq 'EnvironmentFile=-/etc/telvyn/database-agent.env' ../telvyn-agent-database.service
grep -Fq 'ReadWritePaths=/var/lib/telvyn-agent/database /var/log/telvyn-agent/database' ../telvyn-agent-database.service
grep -Fq 'DATABASE_UNIT_NAME="telvyn-agent-database.service"' ../install.sh
grep -Fq 'DATABASE_UPDATE_UNIT_NAME="telvyn-agent-database-update.service"' ../install.sh
grep -Fq 'sudo systemctl start ${DATABASE_UPDATE_UNIT_NAME}' ../install.sh
grep -Fq 'foram encontrados vários Agents de Banco legados neste host' ../install.sh

# Copia o install.sh pro contexto de build pra cada Dockerfile poder
# fazer COPY (build context é este diretório).
cp ../install.sh ./install.sh
trap 'rm -f ./install.sh' EXIT

for distro in ubuntu-22.04 debian-11 rocky-9; do
    echo "=== Testing $distro ==="
    docker build -f "Dockerfile.${distro}" -t "ispwatch-install-test:${distro}" .
    docker run --rm "ispwatch-install-test:${distro}"
    echo "OK: $distro"
done

echo ""
echo "All distros passed syntax + shellcheck."
