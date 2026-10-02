# Laboratório local de persistência do agent

Este laboratório usa o agent real, construído pelo `Dockerfile` de produção, e
o backend Quarkus real do `compose.yml` principal. Não existe mock e nenhum
serviço do backend é iniciado ou parado por este compose.

## Pré-requisitos

1. Suba o backend principal normalmente:

   ```powershell
   cd C:\Users\David\Documents\workspace\ispwacthinfra
   docker compose up -d quarkus
   ```

2. Crie ou tenha um token de ingestão do tenant com:

   - `kind=agent`
   - capability `metrics`

3. Exporte o token apenas na sessão local:

   ```powershell
   $env:ISPWATCH_INGEST_TOKEN = "iwI_..."
   ```

## Subir o agent real

```powershell
cd C:\Users\David\Documents\workspace\telvyn-agent\lab\persistence
docker compose up --build -d
docker compose logs -f agent
```

O outbox fica no volume Docker `telvyn-agent-persistence-lab-state` e é
montado em `/var/lib/ispwatch`. Não use `docker compose down -v` durante o
teste, porque isso apaga o estado persistido do laboratório.

## Validar o restart sem perder métricas

O comando abaixo desconecta somente o agent da rede do backend. O Quarkus
continua rodando:

```powershell
docker network disconnect ispwatch-dev_ispwatch-net telvyn-agent-persistence-lab-agent-1
```

Aguarde um ciclo de coleta e reinicie somente o agent:

```powershell
docker compose restart agent
```

Depois reconecte o agent ao backend:

```powershell
docker network connect ispwatch-dev_ispwatch-net telvyn-agent-persistence-lab-agent-1
docker compose logs -f agent
```

Nos logs deve aparecer a fila durável sendo reaberta e os payloads retidos
sendo reenviados. O container do agent também pode ser recriado sem perder o
estado:

```powershell
docker compose up -d --force-recreate agent
```

## Limpar somente o laboratório

```powershell
docker compose down
docker volume rm telvyn-agent-persistence-lab-state
```
