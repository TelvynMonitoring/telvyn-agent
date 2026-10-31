# Telvyn Agent

Agente de monitoramento do [Telvyn](https://telvyn.com) — coleta métricas,
logs e traces L7 (eBPF) do host/cluster e envia via HTTP/OTLP com um ingest
token Bearer (certless) para o servidor Telvyn. Um agent por host.

Para instalar os pacotes de aplicação pelo admission controller, consulte
[Injeção dos agentes de runtime](docs/RUNTIME-INJECTION.md). A seleção é explícita
por container; Go usa instrumentação durante a compilação.

## Kubernetes (DaemonSet)

Instala um pod por nó. O comando exato (com seu token e a URL do seu portal)
é gerado no painel Telvyn em **Monitores → Kubernetes**. Forma geral:

```bash
# Instala o chart direto do GHCR (OCI) — sem --version instala a mais recente.
# Autenticação certless: só a URL do portal + o ingest token (iwI_..., gerado
# no painel em Monitores → Kubernetes). Sem cert, sem enrollment.
helm install telvyn-agent \
  oci://ghcr.io/telvynmonitoring/charts/telvyn-agent \
  --namespace telvyn --create-namespace \
  --set ingest.url='https://<SEU_PORTAL>' \
  --set ingest.token='<SEU_INGEST_TOKEN>' \
  --set clusterName=<NOME_DO_CLUSTER>
```

Toggles opcionais (`--set`): `logs.enabled=true` (logs de pod),
`ebpfTracing.enabled=true` (traces L7 zero-código), `profiling.enabled=true`
(flame graph de CPU), `clusterAgent.enabled=true` (eventos do cluster),
`sbomScan.enabled=true` (vulnerabilidades de aplicação). Com eBPF/profiler
ligados o chart aplica automaticamente `resourcesEbpf` (limite 2Gi) e os
privilégios necessários.

Os nós aparecem no painel ~30s depois com o badge **Kubernetes**.

## Docker / Portainer (modo ingest, certless)

Um container do agente por máquina Docker, autenticado só com o ingest token
(`iwI_...`, gerado no painel). Ele registra a máquina no inventário, mede os
containers via `/var/run/docker.sock` (CPU/mem/rede/restarts por container) e
recebe OTLP das suas apps na porta 4318:

```bash
docker run -d --name telvyn-agent --restart unless-stopped \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -p 4318:4318 \
  -e TELVYN_INGEST_URL='https://<SEU_PORTAL>' \
  -e TELVYN_INGEST_TOKEN='<SEU_INGEST_TOKEN>' \
  -e TELVYN_AGENT_KIND=docker \
  -e TELVYN_NODE_NAME="$(hostname)" \
  ghcr.io/telvynmonitoring/telvyn-agent:latest
```

Aponte as apps para `OTEL_EXPORTER_OTLP_ENDPOINT=http://<host>:4318`
(`OTEL_EXPORTER_OTLP_PROTOCOL=http/json`). A máquina aparece em
**Aplicações**; cada app instrumentada aparece no catálogo de serviços com as
métricas do próprio container.

## Linux (Docker / systemd)

```bash
curl -fsSL https://raw.githubusercontent.com/TelvynMonitoring/telvyn-agent-releases/main/packaging/install.sh \
  | TELVYN_INGEST_URL='https://<SEU_PORTAL>' TELVYN_INGEST_TOKEN='<SEU_INGEST_TOKEN>' sudo -E bash
```

## Banco de dados por instância (Linux)

O portal cria a instalação e entrega um token e `installation_id` próprios. Use
um agente para cada instância de banco; ele descobre todos os bancos lógicos
aos quais as credenciais somente-leitura conseguem conectar. `database` é um
perfil, não um `TELVYN_AGENT_KIND`:

```bash
curl -fsSL https://raw.githubusercontent.com/TelvynMonitoring/telvyn-agent-releases/main/packaging/install.sh \
  | TELVYN_INGEST_URL='https://<SEU_PORTAL>' \
    TELVYN_INGEST_TOKEN='<TOKEN_DA_INSTALACAO>' \
    TELVYN_AGENT_KIND=linux \
    TELVYN_AGENT_PROFILE=database \
    TELVYN_DATABASE_INSTALLATION_ID='<INSTALLATION_ID>' \
    sudo -E bash
```

No mesmo host, cada instalação recebe uma unit
`telvyn-agent-database@…`, usuário de sistema, EnvironmentFile, binário,
fila e marcador de revogação próprios. Ela não substitui nem reinicia o
`telvyn-agent.service` genérico. Uma resposta terminal `410 Gone` interrompe
essa instância até uma nova instalação explícita do portal.

## Imagens / artefatos

| Artefato | Local |
|----------|-------|
| Imagem   | `ghcr.io/telvynmonitoring/telvyn-agent:<versão>` (multi-arch amd64/arm64) |
| Chart    | `oci://ghcr.io/telvynmonitoring/charts/telvyn-agent` |
| Install  | `https://raw.githubusercontent.com/TelvynMonitoring/telvyn-agent-releases/main/packaging/install.sh` |

Publicados pelo workflow [`publish.yml`](.github/workflows/publish.yml) a cada tag `v*`.

## Build local

```bash
make build          # binário em ./collector
make proto          # regenera stubs gRPC
docker build -t telvyn-agent:dev .
```

Ver [HARDENING-NOTES.md](HARDENING-NOTES.md) e [TUNING.md](TUNING.md) para
endurecimento e ajuste fino. Licença Apache-2.0 (ver [NOTICE](NOTICE)).
