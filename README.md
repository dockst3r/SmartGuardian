# SmartGuardian

Guardião do PC para Windows 11. Monitora processos, conexões, a rede local e tudo que abre com o
Windows; dá a cada processo uma **pontuação de risco explicada** (você vê o motivo de cada ponto) e
avisa quando algo foge do normal. Tem um assistente opcional que roda **no seu PC** pelo
[LM Studio](https://lmstudio.ai): nada vai para a nuvem.

Fica como um ícone de escudo na bandeja, com janela no estilo do Windows 11. Mesma base do
[SmartDevices](https://github.com/dockst3r/SmartDevices).

## O que ele faz

| Tela | O que mostra |
|---|---|
| Visão geral | situação geral, CPU, memória, disco e rede (últimos 2 min), alertas recentes, aparelhos na rede |
| Rede local | conexão, roteador, DNS, latência da internet; aparelhos da rede com IP, MAC, fabricante e quando apareceram; clique no nome para renomear |
| Conexões | cada conexão de cada programa, com nome DNS; portas abertas neste PC; exportar CSV |
| Processos | assinatura digital, quem abriu, linha de comando, rede e **por que a pontuação**; Analisar com IA, Abrir local, VirusTotal, Encerrar, Quarentena, Isso é normal |
| Inicialização | chaves Run, pasta Inicializar, serviços automáticos e tarefas agendadas; ligar e desligar sem apagar nada |
| Alertas | histórico por dia; Ciente, Isso é normal, Pausar 1 hora, Resumir com IA |
| Assistente IA | conversa sobre o estado atual do PC; conversas salvas; relatório do dia em HTML |
| Configurações | intervalos, período de aprendizado, limite de aviso, tipos de aviso, LM Studio, VirusTotal, lista de confiança e quantos alarmes falsos cada regra já deu |

O ícone muda de estado: escudo normal = tudo certo, ponto amarelo = atenção, ponto vermelho = risco
alto, apagado = avisos pausados. Notificações do Windows avisam de processo suspeito, aparelho novo
na rede, mudança na inicialização e detecções do Windows Defender.

## Requisitos

- Windows 11 (funciona no 10, mas o visual é pensado para o 11)
- Python 3.12 ([python.org](https://www.python.org/downloads/))
- Permissão de administrador (o app pede ao abrir)
- Opcional: LM Studio para o assistente; chave gratuita do VirusTotal

## Instalar e usar

```
git clone https://github.com/dockst3r/SmartGuardian.git
cd SmartGuardian
"SmartGuardian (terminal).bat"
```

O `.bat` cria o ambiente (`.venv`) na primeira vez e lista no terminal os processos sem assinatura
confiável. Depois disso:

- **`SmartGuardian.vbs`** abre o app na bandeja (o Windows pede permissão de administrador).
- Fechar ou minimizar a janela só esconde; o monitoramento continua. Para encerrar: botão direito no
  escudo → **Sair**.
- **Configurações → Iniciar com o Windows** cria uma tarefa agendada que abre o app como
  administrador sem pedir permissão a cada login.

Por que administrador: sem isso o Windows esconde o caminho de boa parte dos processos e não deixa
encerrar processos nem mexer na inicialização.

## Pontuação de risco

Cada processo começa em 0 e cada sinal soma pontos. Aviso a partir de 30 (ajustável), risco alto a
partir de 60. Pesos e listas ficam em `rules.json`, criado na primeira execução.

| Sinal | Pontos |
|---|---|
| Nome de processo do Windows fora da pasta do Windows (**forte**) | 40 |
| Conexão ou porta aberta em porta usada por invasão: 4444, 1337, 31337… (**forte**) | 30 |
| Pasta temporária ou gravável por qualquer usuário · assinatura quebrada · comando codificado · Office abrindo terminal | 25 |
| Sem assinatura digital | 20 |
| Pasta do usuário (AppData, ProgramData) · Downloads | 15 |
| Processo pai errado · sem assinatura e na internet · porta aberta para a rede | 10 |
| Programa novo depois do aprendizado · sem assinatura em pasta protegida | 5 |

### Contra falso positivo

- **Nenhum sinal comum avisa sozinho.** O máximo é 25 (mesmo editando o `rules.json`) e o aviso
  começa em 30. Só as duas regras fortes avisam sozinhas, porque quase não acontecem com programa legítimo.
- **Assinatura válida anula as regras de local.** Discord em AppData e Defender em ProgramData ficam em 0.
  Não vale para nome do Windows fora do lugar: uma cópia do `svchost.exe` continua com assinatura
  válida da Microsoft.
- **Sem assinatura em Program Files ou Windows pesa só 5** (ferramentas do Git, por exemplo).
- **Período de aprendizado de 7 dias.** O que roda nesse período vira o normal. Se algo depois piorar
  (por exemplo, passar a usar uma porta de invasão), o aviso sobe de nível do mesmo jeito.
- **Isso é normal.** Programa assinado ganha confiança pela editora (continua confiável ao atualizar);
  sem assinatura, pelo hash (perde a confiança se o arquivo mudar). Cada clique conta como alarme falso
  da regra, e as Configurações mostram quais regras erram mais.
- **Inicialização:** só avisa de itens novos depois da primeira lista. Itens da Microsoft só ficam
  registrados, exceto quando chamam powershell, cmd, mshta e similares.

### Assinatura digital

Conferida como o Windows confere, sem internet (WinVerifyTrust): assinatura no próprio arquivo,
catálogo do Windows (System32) ou pacote da Microsoft Store/MSIX. Certificado vencido sem carimbo de
tempo conta como assinado, com observação.

## Ações com proteção

- **Encerrar** recusa processos essenciais do Windows (csrss, wininit, lsass, svchost do sistema…),
  que derrubariam o sistema, e o próprio SmartGuardian.
- **Quarentena** encerra o processo e move o arquivo para `quarentena/`, com um `.json` dizendo de
  onde veio. Recusa arquivos do Windows, arquivos assinados pela Microsoft e programas assinados
  instalados em Program Files (para esses, desinstale ou use o Defender).
- **Desligar da inicialização** nunca apaga: a entrada original fica guardada e volta igual ao religar.

## Assistente de IA (LM Studio)

1. Instale o [LM Studio](https://lmstudio.ai) e baixe um modelo (veja a tabela abaixo).
2. No LM Studio: carregue o modelo e ligue o servidor local (Developer → Start Server).
3. No SmartGuardian: Assistente IA → Ativar.

A cada pergunta vai junto um resumo em texto do estado do PC: processos com pontuação e motivos,
alertas, portas abertas, aparelhos da rede e itens novos da inicialização. O modelo é instruído a
tratar esses textos só como dados (um programa malicioso pode escrever instruções na própria linha
de comando). As conversas ficam salvas no banco local.

### Qual modelo usar com 12 GB de vídeo (ex.: RTX 5070)

| Modelo | Arquivo | Cabe nos 12 GB? | Indicação |
|---|---|---|---|
| **Gemma 4 12B QAT** (Q4_0) | ~7 GB | Sim, com folga para contexto | **Padrão recomendado.** Medido numa RTX 5070: ~68 tokens/s, respostas em 15–20 s, bom português. |
| Gemma 4 26B A4B QAT (Q4) | ~14 GB | Não inteiro; é MoE com 4B ativos, parte fica na RAM | Melhor qualidade (MMLU-Pro 82,6 vs 77,2; multilíngue 86,3 vs 83,4). Relatos de ~69 tokens/s numa RTX 4070 de 12 GB. Precisa de uns 4 GB de RAM livre. |
| Qwen3.5 9B (Q6/Q8) | 7–9 GB | Sim | Alternativa rápida e leve. |
| Qwen3.8 27B | 14–17 GB em Q4; 9,4 GB em 3 bits | Só em 3 bits | Não recomendado aqui: denso, mais lento e pensa muito antes de responder. |

Números de terceiros são aproximados; os da Gemma 4 12B foram medidos com este app. Modelos que
"pensam" antes de responder (Gemma 4, Qwen 3.x) funcionam: o app reserva espaço para o raciocínio.

## Privacidade: o que sai do PC

Só o que você ligar:

- **IP público:** consulta `api.ipify.org` a cada 30 min (desligado por padrão).
- **VirusTotal:** envia só o SHA-256 do arquivo, quando você clica (precisa de chave).
- **Lista de fabricantes do IEEE:** baixada uma vez para `data/oui.csv`.

A varredura da rede só manda ping e lê a tabela ARP do Windows; não abre portas nos aparelhos.
Banco, configurações, log, relatórios e quarentena ficam na pasta do programa e estão no `.gitignore`.

## Testes

```
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

24 casos. Programas comuns que **não** podem avisar (Discord, Git, Store, Defender, svchost
verdadeiro, instalador assinado em Temp, certificado vencido); ataques que **precisam** avisar
(svchost falso em Temp e em `C:\Windows\Tasks`, porta 4444, AppData sem assinatura na internet,
Word abrindo PowerShell codificado, assinatura adulterada); e as proteções de Encerrar e Quarentena
(testadas sem encerrar nem mover nada).

## Arquitetura

```
 Interfaces     tray.py + ui/ (bandeja e janela pywebview)          sg.py (terminal)
                         |
 Núcleo         core/guard.py   laços de coleta, pontuação, alertas, ações, contexto da IA, relatório
                /        |          |            |              \
 Coletores   system.py  procs.py  conns.py   lan.py         startup.py
             CPU/mem    processos conexões   ping, ARP,     Run, pasta, serviços,
             disco/rede (psutil)  DNS rev.   fabricante     tarefas agendadas
                         |
 Análise        signature.py (WinVerifyTrust)   rules.py (pontuação)   ai.py (LM Studio)   vt.py
                         |
 Dados          store.py → settings.json, smartguardian.db (SQLite), rules.json
```

| Arquivo | Papel |
|---|---|
| `tray.py` | app da bandeja: janela, ícone, administrador, instância única |
| `ui/index.html` | janela; tudo desenhado a partir de `api.state(view)` |
| `ui/api.py` | funções que a janela chama no Python (perguntas à IA rodam em segundo plano) |
| `ui/win.py` | detalhes do Windows: ícone, iniciar com o Windows, tema, cor de destaque |
| `docs/prototipo.html` | protótipo navegável da interface, com dados de exemplo |

## Limitações conhecidas

- A varredura cobre até um /24 (254 endereços) da rede do PC.
- Sem país de destino nas conexões (precisaria de uma base de dados externa).
- Reativar um serviço desligado pelo app volta para "Automático", mesmo que antes fosse "Automático (atraso)".

## Licença

[MIT](LICENSE)
