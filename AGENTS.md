# AGENTS.md — Telvyn Agent

Leia `CONTEXT.md` antes de alterar este repositório. O produto se chama Telvyn; variáveis,
caminhos e binários usam o prefixo `telvyn`/`TELVYN_` e não há compatibilidade com
nomes antigos.

Regras essenciais:

- um agente por host, com token próprio;
- ingest canônico por HTTP/OTLP certless e Bearer token `iwI_...`;
- faça mudanças cirúrgicas e rode `go test ./...` antes de publicar;
- não versione tokens, chaves, credenciais ou artefatos de build.
