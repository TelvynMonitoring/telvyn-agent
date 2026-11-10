# Orçamento de cardinalidade

O agent limita quantas séries distintas (métrica + tags) cada **equipamento** pode enviar. Cada equipamento SNMP tem o
seu orçamento, mesmo que vários compartilhem o mesmo `host_id` do coletor.

- Padrão: **50000** séries por equipamento. Variável `TELVYN_TAGGER_BUDGET_PER_HOST` (1 a 100000; inválido volta ao padrão).
- Séries que somem por mais de 6 horas liberam espaço; ao remover o equipamento da configuração o orçamento é liberado na hora.
- Métricas de saúde (`snmp.collector.*`, `snmp.device.*`, `telvyn.*`) nunca entram no orçamento.
- Ao estourar, o agent emite `telvyn.tagger.over_budget` por equipamento (valor = séries ignoradas no lote; tags `device`,
  `budget`, `top_metrics`) e `telvyn.tagger.dropped` por métrica, além de um aviso de log a cada 5 minutos.

## Reduzir a cardinalidade de um equipamento

- `disabled_metrics` (params do check, JSON): desativa métricas/tabelas inteiras, ex.: `["snmp.storage.used"]`.
- `drop_tags` (params do check, JSON): remove tags antes do cálculo, por métrica; `"*"` vale para todas. Séries que
  ficam iguais são somadas. Ex.: `{"snmp.storage.used":["row_index","storage_descr"]}`.
