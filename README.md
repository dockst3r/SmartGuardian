# SmartGuardian

Guardião do PC para Windows 11. Monitora processos, conexões, a rede local, a GPU e tudo que abre
com o Windows; dá a cada processo uma **pontuação de risco explicada** (você vê o motivo de cada ponto)
e avisa quando algo foge do normal. Tem um assistente opcional que roda **no seu PC** pelo
[LM Studio](https://lmstudio.ai): nada vai para a nuvem.

Fica como um ícone de escudo na bandeja, com janela no estilo do Windows 11. Mesma base do
[SmartDevices](https://github.com/dockst3r/SmartDevices).

## O que ele faz

| Tela | O que mostra |
|---|---|
| Visão geral | situação geral, CPU, memória, disco e rede da placa física (últimos 2 min); GPU com uso, VRAM, temperatura e folga até o limite térmico, potência, driver e quem está usando a placa; alertas recentes, aparelhos na rede |
| Rede local | conexão, roteador, DNS, latência da internet; aparelhos da rede com IP, MAC, fabricante e quando apareceram; clique no nome para renomear |
| Conexões | cada conexão de cada programa, com nome DNS; portas abertas neste PC; exportar CSV |
| Processos | assinatura digital, quem abriu, linha de comando, rede, uso de GPU e VRAM e **por que a pontuação**; Analisar com IA, Abrir local, VirusTotal, Encerrar, Quarentena, Isso é normal |
| Inicialização | chaves Run, pasta Inicializar, serviços automáticos e tarefas agendadas; ligar e desligar sem apagar nada |
| Alertas | histórico por dia; Ciente, Isso é normal, Pausar 1 hora, Resumir com IA |
| Assistente IA | conversa sobre o estado atual do PC; conversas salvas, com o modelo e o tempo de cada resposta; relatório do dia em HTML |
| Configurações | intervalos, período de aprendizado, limite de aviso, tipos de aviso, modelo da IA (lista lida do LM Studio), VirusTotal, lista de confiança e quantos alarmes falsos cada regra já deu |

O ícone muda de estado: escudo normal = tudo certo, ponto amarelo = atenção, ponto vermelho = risco
alto, apagado = avisos pausados. Notificações do Windows avisam de processo suspeito, aparelho novo
na rede, mudança na inicialização, detecções do Windows Defender e GPU perto do limite de temperatura.

## Requisitos

- Windows 11 (funciona no 10, mas o visual é pensado para o 11)
- Python 3.12 ([python.org](https://www.python.org/downloads/))
- Permissão de administrador (o app pede ao abrir)
- Opcional: placa NVIDIA para o card completo da GPU (o uso por programa funciona com qualquer placa);
  LM Studio para o assistente; chave gratuita do VirusTotal

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
| Pasta temporária ou gravável por qualquer usuário · assinatura quebrada · comando codificado · Office abrindo terminal · GPU acima de 50 % por ~15 s sem assinatura válida (perfil de minerador) | 25 |
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

## GPU

Placas NVIDIA: uso, VRAM, temperatura, folga até a placa reduzir o desempenho, potência, ventoinha,
clock e versão do driver, pela biblioteca oficial da NVIDIA (`nvidia-ml-py`, que usa o `nvml.dll` do
driver). Uso de GPU e VRAM **por programa** vem dos contadores do próprio Windows, e vale para
qualquer fabricante. Avisos opcionais: GPU perto do limite térmico e VRAM cheia por 30 s.
Minerador escondido aparece como uso alto e contínuo de GPU por um programa estranho, por isso a
regra do minerador (jogos, navegadores e o LM Studio são assinados e não disparam).
Hotspot e temperatura da memória não existem na API oficial para placas GeForce.

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
programas sem assinatura, os que mais usam CPU e memória, GPU e quem a usa, conexões com a internet,
portas abertas, aparelhos da rede (inclusive os que saíram), inicialização, alertas e a sua lista de
confiança. O modelo é instruído a tratar esses textos só como dados (um programa malicioso pode
escrever instruções na própria linha de comando). A parte da conversa enviada junto se ajusta ao
contexto com que o LM Studio carregou o modelo: 4.000 caracteres em modelos de 8K, até 60.000 nos de 100K+. As conversas ficam salvas no banco local, e cada resposta mostra qual modelo respondeu e
em quanto tempo, o que ajuda a comparar modelos. Em Configurações, o modelo é escolhido numa lista
lida do próprio LM Studio (carregados primeiro); se o escolhido não estiver carregado, o app avisa.

### Qual modelo usar com 12 GB de vídeo

Medido com este app numa **RTX 5070 de 12 GB** (Ryzen 7 9800X3D, 32 GB de RAM), com o resumo do PC de
~2.000 tokens em cada pergunta:

| Modelo | Tamanho | Geração | Resposta típica | Avaliação |
|---|---|---|---|---|
| **Qwen3.5 9B** | 6,6 GB | **92–95 tokens/s** | **9–14 s** | **Recomendado.** O mais rápido, cabe inteiro na placa com contexto de 118K, respostas boas e fiéis aos dados. |
| Gemma 4 12B QAT (Q4_0) | ~7 GB | 67–71 tokens/s | 9–17 s | Bom e leve; português bom. |
| gpt-oss 20B (MXFP4) | ~11 GB | 41–59 tokens/s | 5–10 s | Pensa pouco, então responde rápido; ocupa quase toda a VRAM. |
| Gemma 4 26B A4B QAT (Q4_0) | 14,4 GB | 35–43 tokens/s | 10–26 s | Melhor qualidade, mas não cabe inteiro: parte vai para a RAM (o processo chegou a 18,6 GB de RAM). |
| Qwen3.8 27B (Q4_K_M) | 17,7 GB | — | — | Não cabe; as tentativas não terminaram. |

Modelos que "pensam" antes de responder (Gemma 4, Qwen 3.x) funcionam: o app reserva espaço para o
raciocínio. Cada resposta mostra o modelo e o tempo, então dá para comparar no seu próprio PC.

## Privacidade: o que sai do PC

Só o que você ligar:

- **IP público:** consulta `api.ipify.org` a cada 30 min (desligado por padrão).
- **VirusTotal:** envia só o SHA-256 do arquivo, quando você clica (precisa de chave).
- **Lista de fabricantes do IEEE:** baixada uma vez para `data/oui.csv`.

A varredura da rede só manda ping e lê a tabela ARP do Windows; não abre portas nos aparelhos.
O card de rede conta só as placas físicas ligadas (VPN e adaptadores virtuais ficam de fora, para não
contar o mesmo tráfego duas vezes) e bate com o contador do Windows dentro de 1 a 3%.
Banco, configurações, log, relatórios e quarentena ficam na pasta do programa e estão no `.gitignore`.

## Testes

```
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

30 casos. Programas comuns que **não** podem avisar (Discord, Git, Store, Defender, svchost
verdadeiro, instalador assinado em Temp, certificado vencido, jogo e LM Studio com GPU a 100 %);
ataques que **precisam** avisar (svchost falso em Temp e em `C:\Windows\Tasks`, porta 4444, AppData
sem assinatura na internet, Word abrindo PowerShell codificado, assinatura adulterada, minerador em
AppData); as proteções de Encerrar e Quarentena (testadas sem encerrar nem mover nada); e o tamanho
do histórico enviado à IA.

## Arquitetura

```
 Interfaces     tray.py + ui/ (bandeja e janela pywebview)          sg.py (terminal)
                         |
 Núcleo         core/guard.py   laços de coleta, pontuação, alertas, ações, contexto da IA, relatório
                /        |          |            |              \
 Coletores   system.py  gpu.py      procs.py  conns.py   lan.py       startup.py
             CPU/mem    NVML + uso  processos conexões   ping, ARP,   Run, pasta, serviços,
             disco/rede por programa (psutil)  DNS rev.   fabricante   tarefas agendadas
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
