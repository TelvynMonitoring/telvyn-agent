# Arquitetura de integrações atualizáveis do agente Telvyn

Status: protótipo inicial em 01/10/2026. O usuário ampliou o critério para paridade do fluxo de checks Python do Datadog; o runner por coleta abaixo NÃO atende esse critério sozinho. O de-para oficial passa a orientar a revisão. Validação de laboratório e distribuição ainda pendentes.

## Limites do incremento atual

A implementação inicial não equivale ao desenho completo abaixo: o pacote é instalado localmente por um administrador, o Python/runtime também. O executor verifica assinatura e hashes antes de rodar, mas não baixa pacotes nem faz ativação/rollback automático. Sem a aprovação local explícita da execução sem sandbox, não executa. Essa aprovação não transforma o processo em sandbox; ambientes que exigem isolamento de sistema operacional ainda não podem habilitar este incremento.

Métricas validadas reaproveitam a ingestão existente. O inventário permanece como snapshot local: criar e relacionar hosts no backend/portal é uma entrega posterior. Contadores cumulativos não devem ser enviados como gauges; enquanto a ingestão não suportar sua semântica, sua ausência precisa constar na cobertura. Os testes Python passaram com respostas simuladas e execução real do runner; isso não certifica compatibilidade com um hypervisor real.

## Objetivo e decisão de produto

Permitir entregar novas integrações de coleta sem substituir o binário do agente a cada alteração. O núcleo continua em Go; checks existentes continuam funcionando. Novas integrações podem ser distribuídas como pacotes versionados executados por um runtime separado. Python é o primeiro candidato, não uma decisão de suporte a várias linguagens.

O usuário aprovou estudar a arquitetura pública do Datadog e escrever código próprio, sem copiar sua implementação. A referência não obriga reproduzir seus detalhes internos. Contrato, isolamento e distribuição abaixo são propostas Telvyn ainda sujeitas à revisão.

## O que a referência estabelece

O Datadog explica que incorporar Python permite alterar checks sem recompilar o agente. Seu artigo também descreve custos de integração entre linguagens e build. Isso justifica extensibilidade, não prova que o mesmo mecanismo embutido seja a melhor escolha para nós. [Engenharia Datadog](https://www.datadoghq.com/blog/engineering/cgo-and-python/).

A integração Proxmox consulta a API do cluster para descobrir recursos e coletar métricas; seu código é um check Python. [Integração](https://docs.datadoghq.com/integrations/proxmox/) e [implementação de referência](https://github.com/DataDog/integrations-core/blob/master/proxmox/datadog_checks/proxmox/check.py).

No vSphere, um agente consulta um endpoint vCenter; os detalhes de autenticação, inventário, métricas e dependências são específicos dessa integração. É a mesma categoria de coleta, não o mesmo código Proxmox com outra URL. [Arquitetura vSphere](https://datadoghq.dev/integrations-core/architecture/vsphere/).

Traces são produzidos por instrumentação e enviados ao coletor. O Datadog documenta recebimento OTLP de aplicações instrumentadas; não se trata de um check periódico que consulta uma API. [OTLP no Datadog](https://docs.datadoghq.com/opentelemetry/setup/otlp_ingest_in_the_agent/) e [conceito de traces](https://opentelemetry.io/docs/concepts/signals/traces/).

## Formas de coleta

| Caso | Mecanismo | Papel do agente |
|---|---|---|
| Proxmox | Check periódico consulta API | Descobrir cluster, nós, VMs/LXC e coletar recursos disponíveis |
| VMware vSphere | Outro check consulta vCenter | Descobrir ESXi/VMs/datastores e converter métricas próprias |
| Disponibilidade de API | Check HTTP periódico | Medir status, latência e conteúdo esperado; não gera tracing interno |
| Banco de dados | Check com protocolo/driver do banco | Consultar métricas com credencial específica; não necessariamente HTTP |
| APM e tracing | SDK ou instrumentação envia spans por OTLP | Receber, processar, amostrar e encaminhar traces |
| Logs | Tailer ou receptor contínuo | Ler/receber registros, filtrar e encaminhar; não usar o polling de checks para todo streaming |
| Processos e métricas locais | Coleta na máquina observada | Mostrar detalhes internos não disponíveis na API do hypervisor |

O cliente que quer somente a visão Proxmox não precisa instalar Telvyn em cada VM. Para processos e leitura local de logs, pode ativar um agente na VM. Integrações remotas e encaminhamento de logs são alternativas quando adequadas. QEMU Guest Agent e VMware Tools são componentes distintos do agente Telvyn; podem enriquecer dados sem entregar automaticamente APM.

## Fluxos propostos

```text
Proxmox/vCenter/API → check externo → validação no núcleo Go → ingestão Telvyn
Aplicação instrumentada → receptor OTLP do agente → pipeline APM → ingestão Telvyn
Arquivo/journal/forwarder → pipeline de logs → ingestão Telvyn
```

O núcleo controla identidade, tenant, envio, limites e diagnóstico. O check conhece apenas a integração e devolve resultados. Ele não recebe o token de ingestão do agente nem escolhe o tenant.

## Runtime e contrato mínimo propostos

Primeiro avaliar um executor Python em processo separado, gerenciado pelo núcleo Go, em vez de incorporar CPython por cgo. Essa opção facilita encerrar um check travado, mas um processo separado NÃO é uma sandbox nem uma garantia de restrição de rede/arquivos. A comparação precisa considerar empacotamento, desempenho e controles reais do sistema operacional.

Não executar um shell com parâmetros concatenados. Usar protocolo local versionado e tamanho máximo de mensagens. A primeira implementação executa um processo por coleta, aproveitando o scheduler existente. Reutilização de processos só será considerada se o custo medido justificar.

| Contrato | Informação necessária |
|---|---|
| Manifesto do pacote | Nome, versão, API do runner, runtime/arquiteturas suportadas, dependências e digest assinado |
| Configuração da instância | UUID da instância, alvo autorizado, parâmetros validados, filtros, intervalo e deadline |
| Credenciais | Somente segredos necessários à integração, entregues por canal local protegido; nunca argv, logs ou token de ingestão |
| Resultado de métricas | Nome, tipo, unidade, valor finito, timestamp de origem e referência do recurso; labels permitidas e limitadas |
| Resultado de inventário | Referência nativa, tipo, nome, relação com pai e completude da descoberta |
| Diagnóstico | Sucesso, parcial ou erro; duração, última coleta válida e código de erro sanitizado |
| Estado persistente | Esquema versionado para cursores quando necessários; sem depender apenas de RAM |

O backend atribui UUIDs públicos e preserva a referência externa. Para Proxmox, a identidade deve sobreviver à migração entre nós e distinguir exclusão/recriação com o mesmo VMID. Um scan parcial não autoriza marcar todos os recursos ausentes como removidos. VM desligada continua no inventário.

O núcleo valida os resultados antes da ingestão, não aceita NaN/infinito, impede cardinalidade descontrolada e separa unidade/taxa/contador. Horário de coleta e recebimento são distintos; não renovar artificialmente uma amostra antiga.

## Distribuição e segurança propostas

1. Publicar somente pacotes aprovados Telvyn, com versão imutável, assinatura e dependências fixadas. Não instalar dependências da internet durante cada execução.
2. Configuração autenticada indica a versão desejada. Baixar em staging, verificar integridade, assinatura, compatibilidade e extração segura antes de ativar.
3. Fazer troca atômica entre versões e manter versão anterior. Em falha de verificação ou ativação, conservar a versão válida; rollback de estado precisa ser compatível, não somente trocar arquivos.
4. Aplicar deadlines, limite de saída, orçamento de memória/CPU onde suportado e backoff de reinício. Não impedir checks Go nem OTLP de funcionar por erro de um pacote.
5. Definir usuário sem privilégios, diretórios permitidos e restrições de rede/arquivos aplicáveis à plataforma. Se os controles mínimos exigidos não estiverem disponíveis, rejeitar a execução do pacote; reportar a limitação e não chamar um processo irrestrito de isolado.
6. Redigir logs sem segredos. Restringir alvos configuráveis, redirects e acesso a serviços locais sensíveis; proteger chamadas HTTP contra abuso do coletor.

Assinatura comprova origem/integridade, não comportamento seguro. Python arbitrário de clientes fica fora da primeira entrega. O catálogo começa com integrações escritas e aprovadas por nós.

Pacotes compatíveis podem mudar sem atualizar o binário. Mudanças no protocolo, recursos do núcleo, segurança do runtime ou bibliotecas nativas podem exigir atualização do agente/runtime. Portanto, a promessa é reduzir atualizações, não eliminá-las.

## Reuso e mudanças no Telvyn

### De-para da primeira implementação

| Referência Datadog | Telvyn | Limite desta entrega |
|---|---|---|
| Agent Go executa checks Python com CPython embutido | Check Go chama runner Python em processo separado | Não reproduz cgo; Python precisa estar instalado/configurado localmente |
| Integração Proxmox consulta API do cluster | Pacote Proxmox consulta HTTPS e devolve métricas e inventário | Cobertura inicial explícita por endpoint, não paridade completa |
| vSphere usa SDK e PerformanceManager | Pacote vSphere usa pyVmomi para inventário e contadores selecionados | Dependência deve integrar o runtime; testes simulados não certificam vCenter |
| Scheduler e submissão centralizados no agente | Registry/Check e ingestão existentes no núcleo Go | Sem segundo scheduler nem token de ingestão entregue ao check |
| Integrações distribuídas separadamente | Pacotes verificados por assinatura e hashes | Catálogo remoto, download e ativação automática ficam fora deste incremento |
| Recursos associados a métricas | Referência externa no resultado, identidade do host controlada pelo Go | Inventário coletado não implica hosts criados no portal; persistência depende de contrato backend |

As referências de implementação são [Proxmox](https://github.com/DataDog/integrations-core/blob/master/proxmox/datadog_checks/proxmox/check.py) e [vSphere](https://github.com/DataDog/integrations-core/blob/master/vsphere/datadog_checks/vsphere/vsphere.py). O check vSphere não é somente uma chamada REST de disponibilidade: utiliza o SDK de vCenter e metadados dos contadores. A normalização deve seguir também as [unidades oficiais dos contadores VMware](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/network_counters.html).

O framework `internal/checks/check.go` já define Check, Registry e Factory. O executor externo deve se encaixar nesse agendamento, sem duplicá-lo. `internal/configpull` é o ponto candidato para a configuração desejada. A ingestão, fila e diagnóstico existentes devem ser reutilizados após revisão das interfaces reais.

O receptor e pipeline APM já têm desenho próprio em [AGENT-OTLP-RECEIVER-DESIGN.md](AGENT-OTLP-RECEIVER-DESIGN.md). Não reconstruir APM como check Python. Confirmar comportamento no código antes de usar detalhes históricos desse documento como contrato atual.

Os perfis/capabilities permanecem uma configuração do mesmo agente, conforme [AGENT-PROFILES-DESIGN.md](AGENT-PROFILES-DESIGN.md). Java continua no backend, React no portal e Go no núcleo. O novo componente é o runner, não outro produto ou agente por integração.

Frontend: configurar integração e versão em drawer, mostrar estado, cobertura e diagnóstico. Backend: autorização, credenciais e distribuição por tenant; qualquer nova tabela deve ter RLS. Agent: baixar/validar/ativar pacote, executar e encaminhar resultados. Migrações e endpoints exatos dependem do contrato aprovado, não são definidos especulativamente aqui.

## Organização das entregas

| Ordem | Responsabilidade | Evidência para concluir |
|---|---|---|
| 1 | Supervisor consolida contrato e revisões Edward/Alphonse | Decisões de runtime, segurança e limites registradas |
| 2 | Agente responsável pelo runner | Check de teste trava/falha/excede saída sem derrubar coleta existente |
| 3 | Agente responsável pelos pacotes/configuração | Assinatura inválida rejeitada; atualização e rollback preservam configuração e estado |
| 4 | Agente responsável por Proxmox | Inventário e métricas reais; desligamento, migração e falhas parciais sem duplicação |
| 5 | Agente responsável pelo portal/backend | Drawer, UUID, permissões e isolamento; sem segredos expostos |
| 6 | Revisor independente e supervisor | Fluxo integrado, compatibilidade e carga; relatório distingue mock de laboratório |

O usuário autorizou o executor e os dois checks. Edward implementa o executor Go e a verificação de pacotes; Alphonse implementa o runner Python, Proxmox, vSphere e o de-para. Ambos trabalham em uma cópia de desenvolvimento para preservar alterações existentes no repositório do agente. Portal, catálogo remoto e novo APM não fazem parte desta implementação inicial. Código e testes locais não substituem validação em hypervisors reais.

Antes do piloto, decidir plataformas/arquiteturas suportadas, política de publicação e rotação das chaves, runtime embutido no instalador versus pré-requisito gerenciado e regras de acesso de rede por integração. Não prometer qualquer linguagem nem compatibilidade Windows/Linux indistinta. A revisão Alphonse reforçou esses pontos e os critérios de atualização sem índice externo; não verificou o estado do agente Go.

## Critérios de aceite do piloto

- Trocar versão do check Proxmox sem trocar binário Go e comprovar por diagnóstico.
- Rejeitar pacote adulterado/incompatível e manter coleta anterior; validar rollback.
- Encerrar processo travado e limitar saída, memória/CPU onde suportado; demonstrar restrições de execução.
- Descobrir VM ligada/desligada, criar/excluir/migrar sem duplicação; falha parcial não remove inventário.
- Comparar métricas e timestamps com Proxmox; validar uma segunda versão suportada antes de prometer compatibilidade ampla.
- Testar credencial revogada, TLS inválido e indisponibilidade sem vazamento de segredos.
- Manter SNMP, checks Go e OTLP funcionando; medir impacto em máquina de poucos recursos.
- Validar isolamento por tenant e documentar limites, incluindo atualização do runtime quando necessária.

## Referências para estudo

- [Agente Datadog](https://github.com/DataDog/datadog-agent) e [integrações oficiais](https://github.com/DataDog/integrations-core).
- [Configuração Proxmox](https://github.com/DataDog/integrations-core/blob/master/proxmox/datadog_checks/proxmox/data/conf.yaml.example).
- [Zabbix Proxmox HTTP](https://www.zabbix.com/integrations/proxmox), como referência adicional de descoberta e permissões.

Nenhum código Datadog foi copiado. Se surgir proposta de incorporar um trecho ou dependência, revisar licença e avisos antes. Este documento não implica aprovação de execução de código remoto arbitrário.
