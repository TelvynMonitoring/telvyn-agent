# Entrega durável de logs

O coletor usa a fila bbolt existente (`internal/sendbuf`) para CRI, syslog e OTLP/HTTP.
Os registros ficam em `sendbuf/logs.bolt`, abaixo de `ISPWATCH_STATE_DIR`, no volume
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
