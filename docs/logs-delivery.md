# Entrega durável de logs

O coletor usa a fila bbolt existente (`internal/sendbuf`) para CRI, syslog e OTLP/HTTP.
Os registros ficam em `sendbuf/logs.bolt`, abaixo de `TELVYN_STATE_DIR`, no volume
persistente já instalado pelo chart/systemd. Não é necessário um serviço novo.

- CRI/syslog gravam antes de liberar o leitor; o cursor não avança antes da gravação.
- OTLP recebe confirmação apenas depois da persistência. Corpo inválido é recusado
  antes da fila; fila indisponível/cheia devolve erro ao SDK.
- Envio em lotes de até 100 entradas ou a cada 2 segundos. Falhas preservam o WAL;
  o intervalo de retry cresce de 2 até 30 segundos. O startup retoma a fila mesmo
  sem novas linhas na origem.
- A exclusão do WAL ocorre somente após sucesso HTTP. Rejeições e falhas de disco
  são registradas; a coleta não cai silenciosamente para memória se o WAL não abrir.
- O limite é 64 MiB de payloads, além do overhead bbolt. Ao atingir o limite, os
  leitores aguardam espaço em vez de remover registros pendentes. OTLP devolve erro
  para permitir retry do SDK. Os arquivos de origem também têm retenção finita.

## Limites

A entrega é pelo menos uma vez: perda da resposta HTTP ou queda entre confirmação
remota e exclusão local pode duplicar registros. A gravação do cursor CRI não é uma
transação com o WAL; retomadas também podem reler linhas. Não há deduplicação no intake.
O WAL protege dados já aceitos; não recupera datagramas syslog perdidos antes da
persistência, arquivos rotacionados antes de serem lidos, nem volume removido/corrompido.
Um payload recusado permanece pendente e exige corrigir a causa; não é descartado
para aparentar sucesso. Corrigir credenciais/política quando o log indicar recusa.

Não reutilizar o volume entre instalações/tenants distintos. Preservar o diretório
na atualização do agente. A release pública só contém a mudança depois do merge e
publicação; uma imagem candidata de homologação não atualiza instalações existentes.

## Logs de host Linux (journald e arquivos)

Sem Kubernetes, `TELVYN_LOGS_ENABLED=1` liga também a coleta do próprio host (no Kubernetes quem coleta é o leitor CRI):

- **journald:** subprocesso `journalctl -f -o json`; a unidade vira o serviço (`nginx.service` → `nginx`). Só lê o que chega
  depois do início do agente (`-n 0`): o que o journal gravou com o agente parado não é recuperado.
- **Arquivos:** `/var/log/*.log` e `/var/log/*/*.log` (serviço = pasta, como `nginx`, ou o nome do arquivo). Na primeira
  varredura começa do fim; arquivos que aparecem depois são lidos do começo. Cursor (inode + offset) em
  `host_file_cursors.json`, ao lado do cursor CRI; sobrevive a reinício, rotação e truncamento. Quando há journald, os arquivos que
  o journal já entrega (auth.log, kern.log, dpkg.log, cloud-init…) são ignorados; `/var/log/telvyn*`, `pods`, `containers` e
  `journal` também.
- **Severidade nos arquivos:** campo `level` quando a linha é JSON; senão palavra-chave (error/warn/debug); padrão INFO.
- **Permissões:** o usuário `telvyn` precisa dos grupos `systemd-journal` (journal) e `adm` (arquivos); o `install.sh` os adiciona
  quando `TELVYN_LOGS_ENABLED=1`. Arquivo sem permissão é pulado em silêncio.
- **Variáveis:** `TELVYN_HOST_LOGS=0` desliga tudo; `TELVYN_HOST_LOGS_JOURNALD=0` só o journal; `TELVYN_HOST_LOGS_FILES`
  troca os globs (separados por vírgula; `off` desliga os arquivos); `TELVYN_HOST_LOGS_EXCLUDE` lista globs a ignorar.
- **Limites:** não junta linhas multilinha (stack trace vira várias entradas); linha acima de 16 KiB é cortada; no máximo 200
  arquivos acompanhados.
