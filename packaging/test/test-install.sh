#!/usr/bin/env bash
# Smoke test: install.sh syntactically valid + shellcheck clean across
# 3 distros (Ubuntu 22.04, Debian 11, Rocky 9). Full e2e install requires
# GH Releases (Plan 09) — deferido.

set -euo pipefail

cd "$(dirname "$0")"

# O profile database usa um modelo distribuído no release, mas o instalador
# materializa uma unit concreta por installation_id. Sem isso, instalar B
# poderia atualizar a unit compartilhada do banco A.
test -f ../ispwatch-agent-database@.service
grep -Fq 'User=tvdb-%i' ../ispwatch-agent-database@.service
grep -Fq 'Group=tvdb-%i' ../ispwatch-agent-database@.service
grep -Fq 'EnvironmentFile=-/etc/ispwatch-database-%i/agent.env' ../ispwatch-agent-database@.service
grep -Fq 'ReadWritePaths=/var/lib/ispwatch/database-%i /var/log/ispwatch/database-%i' ../ispwatch-agent-database@.service
grep -Fq 'UNIT_PATH="/etc/systemd/system/${UNIT_NAME}"' ../install.sh
grep -Fq 'sed "s/%i/${DATABASE_SERVICE_ID}/g"' ../install.sh
rendered_db_unit=$(sed 's/%i/example-db-0123456789abcdef/g' ../ispwatch-agent-database@.service)
grep -Fq 'User=tvdb-example-db-0123456789abcdef' <<<"$rendered_db_unit"
grep -Fq 'EnvironmentFile=-/etc/ispwatch-database-example-db-0123456789abcdef/agent.env' <<<"$rendered_db_unit"

database_service_id() {
    local installation_id=$1 base hash
    base=$(printf '%s' "$installation_id" | LC_ALL=C tr '[:upper:]' '[:lower:]' | LC_ALL=C tr -cs '[:alnum:]' '-' | sed 's/^-*//; s/-*$//')
    hash=$(printf '%s' "$installation_id" | sha256sum | awk '{print substr($1, 1, 16)}')
    printf '%s-%s\n' "${base:0:8}" "$hash"
}
first_db_service_id=$(database_service_id 'b7227b6a-c344-4254-953f-7417a214ea49')
second_db_service_id=$(database_service_id 'c8338c7b-d455-5365-a64f-8528b325fb5a')
[[ "$first_db_service_id" != "$second_db_service_id" ]]
[[ "/etc/ispwatch-database-${first_db_service_id}/agent.env" != "/etc/ispwatch-database-${second_db_service_id}/agent.env" ]]
[[ "/usr/local/lib/ispwatch/database-${first_db_service_id}/ispwatch-agent" != "/usr/local/lib/ispwatch/database-${second_db_service_id}/ispwatch-agent" ]]
[[ "ispwatch-agent-database@${first_db_service_id}.service" != "ispwatch-agent-database@${second_db_service_id}.service" ]]

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
