"""Ferramentas da IA: cada uma lê um sensor do SmartGuardian e devolve texto compacto.

A IA recebe sempre a visão geral (guard.ai_overview) e chama estas ferramentas para aprofundar só o que
a pergunta pede: o funil. Nenhuma ferramenta muda nada no PC; limpar, encerrar e desligar continuam
sendo botões que o usuário aperta.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime

import psutil

from . import optimize

# esquema no formato da OpenAI (o LM Studio aceita igual)
def _fn(name: str, desc: str, props: dict | None = None, required: list | None = None) -> dict:
    return {"type": "function", "function": {"name": name, "description": desc,
            "parameters": {"type": "object", "properties": props or {}, "required": required or []}}}


TOOLS = [
    _fn("processos", "Lista processos com assinatura, pontuação de risco e motivos, uso de CPU, memória e GPU. Use para "
        "achar o que pesa ou o que é suspeito.",
        {"filtro": {"type": "string", "enum": ["risco", "sem_assinatura", "cpu", "memoria", "gpu", "todos"],
                    "description": "risco = pontuação > 0; cpu/memoria/gpu = ordena pelo uso"},
         "busca": {"type": "string", "description": "parte do nome ou do caminho do executável"},
         "limite": {"type": "integer", "description": "máximo de linhas (padrão 15, até 60)"}}),
    _fn("processo", "Tudo sobre um processo: caminho, linha de comando, quem abriu, filhos, assinatura, motivos da "
        "pontuação, conexões, portas e se o firewall as libera, itens de inicialização e alertas ligados a ele.",
        {"pid": {"type": "integer"}, "nome": {"type": "string", "description": "nome do executável, ex.: steam.exe"}}),
    _fn("conexoes", "Conexões de rede por programa, com destino (IP, nome DNS, porta), estado e tipo.",
        {"programa": {"type": "string", "description": "nome do executável ou PID; vazio = todos"},
         "tipo": {"type": "string", "enum": ["internet", "local", "todas"]},
         "limite": {"type": "integer"}}),
    _fn("portas", "Portas abertas neste PC, quem escuta, e se o firewall deixa alguém de fora alcançá-las, com a regra "
        "que libera.",
        {"exposicao": {"type": "string", "enum": ["alcancaveis", "bloqueadas", "todas"]}}),
    _fn("rede_local", "Conexão (adaptador, IP, roteador, DNS, Wi-Fi, latência) e aparelhos da rede local com IP, MAC, "
        "fabricante e quando foram vistos.",
        {"busca": {"type": "string", "description": "parte do nome, IP, MAC ou fabricante"}}),
    _fn("inicializacao", "Programas, serviços e tarefas que iniciam com o Windows, com assinatura e se estão ativos.",
        {"filtro": {"type": "string", "enum": ["terceiros", "novos", "desativados", "todos"]}}),
    _fn("alertas", "Histórico de alertas do banco (não só os recentes).",
        {"dias": {"type": "integer", "description": "quantos dias para trás (padrão 7)"},
         "busca": {"type": "string", "description": "texto no título ou detalhe"}}),
    _fn("sistema", "CPU, memória, discos, rede e tempo ligado, com mínimo, média e máximo dos últimos 2 minutos e a "
        "memória por categoria."),
    _fn("gpu", "Placa de vídeo: uso, VRAM, temperatura e folga térmica, potência, clocks, driver e quem usa a GPU."),
    _fn("otimizacao", "Mede o que dá para limpar (temporários, Windows Update, caches, despejos, Lixeira) e lista "
        "sugestões de desempenho a partir dos sensores. Não apaga nada: a limpeza é um botão na tela Otimização."),
]
LABELS = {"processos": "processos", "processo": "processo", "conexoes": "conexões", "portas": "portas",
          "rede_local": "rede local", "inicializacao": "inicialização", "alertas": "alertas", "sistema": "sistema",
          "gpu": "GPU", "otimizacao": "otimização"}


def label(name: str, args: dict) -> str:
    """Texto curto para a tela: "processo steam.exe", "portas alcançáveis"."""
    extra = args.get("nome") or args.get("pid") or args.get("programa") or args.get("busca") or args.get("filtro") or \
        args.get("exposicao") or args.get("tipo") or ""
    return f"{LABELS.get(name, name)} {extra}".strip()


def run(guard, name: str, args: dict, limit: int = 8000) -> str:
    fn = globals().get(f"_t_{name}")
    if not fn:
        return f"ferramenta desconhecida: {name}"
    try:
        text = fn(guard, **{k: v for k, v in (args or {}).items() if v not in (None, "")})
    except TypeError as e:
        return f"argumentos inválidos para {name}: {e}"
    except Exception as e:  # um sensor que falha não derruba a conversa
        return f"erro ao ler {name}: {e}"
    if len(text) > limit:
        text = text[:limit] + f"\n(cortado: {len(text) - limit} caracteres a mais; refine com busca/filtro/limite)"
    return text


# ---------- utilidades ----------
def _mb(b) -> str:
    return f"{b / 2**30:.1f} GB" if b >= 2**30 else f"{b / 2**20:.0f} MB"


def _when(ts) -> str:
    return datetime.fromtimestamp(ts).strftime("%d/%m %H:%M") if ts else "?"


def _sig(p: dict) -> str:
    from .guard import _sig_short
    return _sig_short(p)


def _find(guard, pid=None, nome=None) -> list[dict]:
    with guard.lock:
        procs = list(guard.procs)
    if pid:
        return [p for p in procs if p["pid"] == int(pid)]
    n = (nome or "").lower()
    return [p for p in procs if p["name"].lower() == n] or [p for p in procs if n and n in (p["name"] + p["exe"]).lower()]


def _pline(p: dict) -> str:
    why = "; ".join(f"{t} ({pts:+d})" for t, pts in p["reasons"] if pts) or "nenhum"
    gpu = f" · GPU {p['gpu']:.0f} % VRAM {_mb(p['vram'])}" if p.get("vram") or p.get("gpu", 0) >= 1 else ""
    return (f"{p['name']} PID {p['pid']} · pontuação {p['score']} ({p['sev']}) · {_sig(p)} · CPU {p['cpu']} % · "
            f"RAM {_mb(p['rss'])}{gpu} · {p['exe'] or '(caminho oculto)'} · pai {p['parent'] or '?'} · motivos: {why}")


# ---------- ferramentas ----------
def _t_processos(g, filtro="risco", busca="", limite=15):
    with g.lock:
        procs = list(g.procs)
    limite = max(1, min(int(limite), 60))
    b = busca.lower()
    rows = [p for p in procs if not b or b in (p["name"] + " " + p["exe"]).lower()]
    if filtro == "risco":
        rows = sorted([p for p in rows if p["score"] > 0], key=lambda p: -p["score"])
    elif filtro == "sem_assinatura":
        rows = sorted([p for p in rows if p["sig"] in ("none", "invalid")], key=lambda p: -p["score"])
    elif filtro == "cpu":
        rows = sorted(rows, key=lambda p: -p["cpu"])
    elif filtro == "memoria":
        rows = sorted(rows, key=lambda p: -p["rss"])
    elif filtro == "gpu":
        rows = sorted([p for p in rows if p.get("vram") or p.get("gpu", 0) >= 1], key=lambda p: -(p["vram"] + p["gpu"] * 2**24))
    else:
        rows = sorted(rows, key=lambda p: p["name"].lower())
    head = f"{len(rows)} processos no filtro '{filtro}'{f' com {busca!r}' if busca else ''} (de {len(procs)} no total)"
    return "\n".join([head] + [_pline(p) for p in rows[:limite]] or ["nenhum"])


def _t_processo(g, pid=None, nome=None):
    found = _find(g, pid, nome)
    if not found:
        return f"nenhum processo com {'PID ' + str(pid) if pid else repr(nome)} agora"
    with g.lock:
        procs, conns, listens, startup = list(g.procs), list(g.conns), list(g.listens), list(g.startup)
    out = []
    if len(found) > 1:
        out.append(f"{len(found)} processos com esse nome; detalhes dos 3 primeiros, PIDs: "
                   + ", ".join(str(p["pid"]) for p in found[:20]))
    for p in found[:3]:
        kids = [c for c in procs if c["ppid"] == p["pid"]]
        out += [f"\n== {p['name']} PID {p['pid']} ==", _pline(p),
                f"aberto em {_when(p['started'])} por PID {p['ppid']} ({p['parent'] or '?'}) · usuário {p['user'] or '?'}",
                f"assinatura: {p['sig']} {p['signer']} {p['sig_detail']}".rstrip(),
                f"linha de comando: {p['cmdline'][:500] or '(vazia ou oculta)'}"]
        if kids:
            out.append("filhos: " + ", ".join(f"{c['name']} {c['pid']}" for c in kids[:15]))
        pc = [c for c in conns if c["pid"] == p["pid"]]
        if pc:
            out.append(f"conexões ({len(pc)}):")
            out += [f"  {c['proto']} {c['raddr']}:{c['rport']} {c['host'] or ''} · {c['state']} · {c['scope']}"
                    + (" · PORTA SUSPEITA" if c["bad_port"] else "") for c in pc[:20]]
        pl = [l for l in listens if l["pid"] == p["pid"]]
        if pl:
            out.append("portas abertas:")
            for l in pl[:15]:
                why = g.firewall.why(proto=l["proto"], port=l["port"], exe=p["exe"], pid=p["pid"], laddr=l["addr"])
                out.append(f"  {l['proto']} {l['addr']}:{l['port']} · {_EXP.get(l.get('exposure', ''), '?')} · {why}{_port_use(l['port'])}")
        exe = os.path.normcase(p["exe"] or "-")
        su = [i for i in startup if exe != "-" and os.path.normcase(i.get("exe") or "") == exe]
        if su:
            out.append("inicia com o Windows: " + "; ".join(f"{i['name']} ({i['kind_label']}, {'ativo' if i['enabled'] else 'desativado'})" for i in su))
        al = g.db.q("select ts, sev, status, title from alerts where detail like ? order by ts desc limit 5", (f"%{p['exe'] or p['name']}%",))
        if al:
            out.append("alertas: " + "; ".join(f"{_when(a['ts'])} {a['sev']} {a['status']}: {a['title']}" for a in al))
        if p.get("trusted"):
            out.append("o usuário marcou como normal (lista de confiança)")
    return "\n".join(out)


_EXP = {"open": "LIBERADA para qualquer endereço", "lan": "liberada só para a rede local", "blocked": "bloqueada pelo firewall",
        "pc": "só este PC", "": "firewall não lido"}

# Para que serve cada porta comum: modelos pequenos erram isso de memória (ex.: 27036 do Steam como "amigos").
KNOWN_PORTS = {
    22: "SSH (terminal remoto)", 53: "DNS", 80: "HTTP", 135: "RPC Endpoint Mapper do Windows",
    137: "NetBIOS nomes (rede local)", 138: "NetBIOS datagramas (rede local)", 139: "NetBIOS sessão / SMB antigo",
    443: "HTTPS", 445: "SMB, compartilhamento de arquivos e impressoras do Windows", 1900: "SSDP/UPnP, descoberta na rede local (multicast)",
    3389: "Área de Trabalho Remota (RDP)", 5040: "CDPSvc, Plataforma de Dispositivos Conectados do Windows",
    5050: "serviço de mídia/descoberta do Windows (multicast local)", 5353: "mDNS, descoberta de aparelhos na rede local (multicast)",
    5355: "LLMNR, resolução de nomes na rede local (multicast)", 5357: "WSD, descoberta de impressoras/dispositivos",
    5900: "VNC (controle remoto)", 7680: "Otimização de Entrega do Windows (DoSvc): troca pedaços de atualizações com outros PCs",
    27036: "Steam Remote Play / Transmissão local: descoberta e streaming entre PCs da mesma rede",
    27015: "servidor de jogo Source/Steam", 3074: "Xbox Live / jogos", 1234: "LM Studio (servidor local de IA)",
}


def _port_use(port: int) -> str:
    if port in KNOWN_PORTS:
        return f" · uso conhecido: {KNOWN_PORTS[port]}"
    return " · faixa dinâmica do Windows (RPC e serviços internos)" if 49664 <= port <= 49700 else ""


def _t_conexoes(g, programa="", tipo="internet", limite=40):
    with g.lock:
        conns = list(g.conns)
    limite = max(1, min(int(limite), 120))
    if programa:
        pr = str(programa).lower()
        conns = [c for c in conns if pr == str(c["pid"]) or pr in c["proc"].lower()]
    if tipo != "todas":
        conns = [c for c in conns if c["scope"] == tipo]
    conns.sort(key=lambda c: (-c["score"], c["proc"].lower()))
    head = f"{len(conns)} conexões ({tipo}{', ' + programa if programa else ''})"
    return "\n".join([head] + [f"{c['proc']} {c['pid']} · {c['proto']} {c['laddr']}:{c['lport']} → {c['raddr']}:{c['rport']} "
                               f"{c['host'] or ''} · {c['state']} · {c['scope']}" + (" · PORTA SUSPEITA" if c["bad_port"] else "")
                               for c in conns[:limite]])


def _t_portas(g, exposicao="todas"):
    with g.lock:
        listens, procs = list(g.listens), {p["pid"]: p for p in g.procs}
    rows = [l for l in listens if l.get("exposure") != "pc" and l["scope"] != "pc"]
    if exposicao == "alcancaveis":
        rows = [l for l in rows if l.get("exposure") in ("open", "lan", "")]
    elif exposicao == "bloqueadas":
        rows = [l for l in rows if l.get("exposure") == "blocked"]
    seen, out = set(), [f"rede atual: {g.firewall.profile_name() or '?'} · {len(rows)} sockets"]
    for l in sorted(rows, key=lambda l: (not l["bad_port"], l["port"])):
        k = (l["proto"], l["port"], l["pid"])
        if k in seen:
            continue
        seen.add(k)
        p = procs.get(l["pid"], {})
        why = g.firewall.why(proto=l["proto"], port=l["port"], exe=p.get("exe", ""), pid=l["pid"], laddr=l["addr"])
        out.append(f"{l['proto']} {l['port']} · {l['proc']} PID {l['pid']} ({_sig(p) if p else '?'}) · escuta em {l['addr']} · "
                   f"{_EXP.get(l.get('exposure', ''), '?')} · {why}{_port_use(l['port'])}"
                   + (" · PORTA USADA POR INVASÃO" if l["bad_port"] else ""))
    return "\n".join(out)


def _t_rede_local(g, busca=""):
    n = g.netinfo or {}
    out = [f"conexão: {n.get('type', '?')} {n.get('ssid') or ''} · adaptador {n.get('iface', '?')} · IP {n.get('ip', '?')} · "
           f"roteador {n.get('gateway', '?')} ({n.get('gateway_ms', '?')} ms) · DNS {', '.join(n.get('dns') or []) or '?'} · "
           f"internet {n.get('internet_ms', '?')} ms" + (f" · IP público {n['public_ip']}" if n.get("public_ip") else "")]
    devs = g.devices()
    b = busca.lower()
    if b:
        devs = [d for d in devs if b in " ".join(str(d.get(k) or "") for k in ("ip", "mac", "name", "alias", "vendor")).lower()]
    out.append(f"{len(devs)} aparelhos ({sum(d['online'] for d in devs)} online):")
    for d in devs[:40]:
        who = "este PC" if d["self"] else "roteador" if d["gateway"] else ("conhecido" if d["known"] else "NOVO")
        out.append(f"  {d['ip']} · {d['alias'] or d['name'] or 'sem nome'} · {d['vendor'] or 'fabricante desconhecido'} · "
                   f"MAC {d['mac']} · {who} · {'online' if d['online'] else 'fora, visto ' + _when(d['last_seen'])} · "
                   f"primeira vez {_when(d['first_seen'])}")
    return "\n".join(out)


def _t_inicializacao(g, filtro="terceiros"):
    with g.lock:
        items = list(g.startup)
    if filtro == "terceiros":
        items = [i for i in items if not i["windows"]]
    elif filtro == "novos":
        items = [i for i in items if i.get("new")]
    elif filtro == "desativados":
        items = [i for i in items if not i["enabled"]]
    from .guard import _startup_line
    return "\n".join([f"{len(items)} itens ({filtro})"] + [("NOVO · " if i.get("new") else "") + _startup_line(i, full=True).strip()
                                                         for i in items[:40]])


def _t_alertas(g, dias=7, busca=""):
    since = time.time() - max(1, min(int(dias), 365)) * 86400
    rows = g.db.q("select ts, sev, status, kind, title, detail from alerts where ts >= ? and (title like ? or detail like ?) "
                  "order by ts desc limit 60", (since, f"%{busca}%", f"%{busca}%"))
    return "\n".join([f"{len(rows)} alertas em {dias} dias{f' com {busca!r}' if busca else ''}"] +
                     [f"{_when(a['ts'])} · {a['sev']} · {a['status']} · {a['kind']}: {a['title']} — {a['detail'][:220]}" for a in rows])


def _stats(xs, d: int = 0) -> str:
    xs = list(xs)
    return (f"agora {xs[-1]:.{d}f}, mín {min(xs):.{d}f}, média {sum(xs) / len(xs):.{d}f}, máx {max(xs):.{d}f}"
            if xs else "sem dados")


def _t_sistema(g):
    s = g.system.snapshot()
    h = s["hist"]
    vm, sw = psutil.virtual_memory(), psutil.swap_memory()
    out = [f"{s['host']} · {s['os']} · ligado há {s['uptime'] / 3600:.1f} h · CPU {s.get('cpu_name', '')} "
           f"({psutil.cpu_count(False)} núcleos / {psutil.cpu_count()} threads)",
           f"CPU %: {_stats(h['cpu'])}",
           f"memória: {vm.used / 2**30:.1f} de {vm.total / 2**30:.0f} GB ({vm.percent:.0f} %) · disponível {vm.available / 2**30:.1f} GB · "
           f"arquivo de paginação {sw.used / 2**30:.1f} de {sw.total / 2**30:.0f} GB · % uso: {_stats(h['mem'])}",
           f"rede Mb/s: download {_stats(h['down'], 1)} · upload {_stats(h['up'], 1)}"]
    try:
        freq = psutil.cpu_freq()
        out.append(f"clock da CPU: {freq.current:.0f} MHz (máx anunciado {freq.max:.0f})")
    except Exception:
        pass
    for part in psutil.disk_partitions():
        try:
            du = psutil.disk_usage(part.mountpoint)
        except OSError:
            continue
        out.append(f"disco {part.mountpoint} {part.fstype}: {du.used / 2**30:.0f} de {du.total / 2**30:.0f} GB ({du.percent:.0f} %), "
                   f"livre {du.free / 2**30:.0f} GB")
    plan = optimize.power_plan()
    if plan:
        out.append(f"plano de energia: {plan}")
    return "\n".join(out)


def _t_gpu(g):
    s = g.gpu.snapshot()
    with g.lock:
        procs = list(g.procs)
    users = sorted([p for p in procs if p.get("vram") or p.get("gpu", 0) >= 1], key=lambda p: -p["vram"])[:10]
    out = []
    if s.get("available"):
        h = s.get("hist", {})
        out.append(json.dumps({k: v for k, v in s.items() if k != "hist"}, ensure_ascii=False, default=str))
        for k, v in h.items():
            if v:
                out.append(f"histórico {k}: {_stats(v)}")
    else:
        out.append("sem dados detalhados da placa (não é NVIDIA ou o driver não respondeu); uso por programa abaixo")
    out.append("usando a GPU: " + (", ".join(f"{p['name']} PID {p['pid']} {p['gpu']:.0f} % VRAM {_mb(p['vram'])} ({_sig(p)})" for p in users) or "ninguém"))
    return "\n".join(out)


def _t_otimizacao(g):
    st = g.optimize_state(refresh=True)
    out = ["LIMPEZA POSSÍVEL (nada foi apagado; o usuário limpa pelo botão na tela Otimização):"]
    for it in st["items"]:
        size = _mb(it["size"]) if it["known"] else "tamanho só se sabe ao rodar"
        out.append(f"  {it['label']}: {size}, {it['count']} arquivos · {'marcado' if it['default'] else 'opcional'} · {it['desc']}")
    out.append("SUGESTÕES A PARTIR DOS SENSORES:")
    out += [f"  [{i['sev']}] {i['title']} — {i['detail']} Ação: {i['action']}" for i in st["insights"]] or ["  nenhuma"]
    out.append("O QUE O APP NÃO FAZ DE PROPÓSITO: " + "; ".join(f"{n}: {w}" for n, w in optimize.NOT_DONE))
    if st.get("history"):
        out.append("ÚLTIMAS LIMPEZAS: " + "; ".join(f"{_when(h['ts'])} {h['label']} {_mb(h['freed'])}" for h in st["history"][:6]))
    return "\n".join(out)
