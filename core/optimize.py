"""Otimização: mede e limpa o que o Windows acumula, e aponta o que mais pesa no PC.

Regras de segurança:
  - analisar nunca apaga nada; limpar só o que o usuário marcou e confirmou (a IA só sugere);
  - só arquivos mais velhos que o limite de cada item, e só dentro das pastas listadas aqui;
  - não segue junções nem atalhos de pasta (um link para outra pasta não leva a limpeza junto);
  - arquivo em uso é pulado, não forçado.

De propósito fica de fora:
  - Prefetch: o Windows usa para abrir os programas mais rápido; limpar deixa tudo mais lento por dias;
  - "limpar memória": RAM livre é desperdício; o Windows usa a sobra como cache e solta sozinho;
  - limpeza de registro: sem ganho medido e com risco de quebrar programas;
  - apagar SoftwareDistribution\\Download direto: com o Windows Update rodando, ele restaura e reorganiza a
    pasta (medido: 99 mil arquivos "apagados" voltaram); a limpeza das atualizações é pelo DISM (item winsxs).
"""
from __future__ import annotations

import ctypes
import logging
import os
import stat
import subprocess
import time
from ctypes import wintypes
from pathlib import Path

import psutil

log = logging.getLogger(__name__)
NO_WINDOW = 0x08000000
DAY = 86400

WIN = os.environ.get("SystemRoot", r"C:\Windows")
LOCAL = os.environ.get("LOCALAPPDATA", "")
PROGRAMDATA = os.environ.get("ProgramData", r"C:\ProgramData")

# id, nome, o que é, pastas (ou arquivos), idade mínima em dias, marcado por padrão, como limpa
ITEMS = [
    {"id": "temp_user", "label": "Arquivos temporários do usuário", "paths": [os.environ.get("TEMP", "")], "age": 1,
     "default": True, "how": "files",
     "desc": "Pasta %TEMP%: sobras de instaladores, atualizações e programas. Só arquivos com mais de 24 h e que não estejam em uso."},
    {"id": "temp_win", "label": "Arquivos temporários do Windows", "paths": [os.path.join(WIN, "Temp")], "age": 1,
     "default": True, "how": "files",
     "desc": r"C:\Windows\Temp: sobras de serviços e instaladores do sistema. Mais de 24 h e fora de uso."},
    {"id": "do_cache", "label": "Cache da Otimização de Entrega",
     "paths": [os.path.join(WIN, r"ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache")],
     "age": 0, "default": True, "how": "do",
     "desc": "Pedaços de atualizações guardados para compartilhar com outros PCs. Limpo pelo próprio Windows (Delete-DeliveryOptimizationCache)."},
    {"id": "dumps", "label": "Despejos de memória de travamentos",
     "paths": [os.path.join(WIN, "Minidump"), os.path.join(WIN, "MEMORY.DMP"), os.path.join(WIN, "LiveKernelReports"),
               os.path.join(LOCAL, "CrashDumps")], "age": 7, "default": True, "how": "files",
     "desc": "Arquivos gravados quando o Windows ou um programa trava (tela azul, travamento da GPU). Úteis para diagnóstico; só os com mais de 7 dias."},
    {"id": "wer", "label": "Relatórios de erro do Windows",
     "paths": [os.path.join(PROGRAMDATA, r"Microsoft\Windows\WER\ReportArchive"), os.path.join(PROGRAMDATA, r"Microsoft\Windows\WER\ReportQueue"),
               os.path.join(LOCAL, r"Microsoft\Windows\WER")], "age": 7, "default": True, "how": "files",
     "desc": "Relatórios de programas que travaram, já enviados ou na fila. Mais de 7 dias."},
    {"id": "shaders", "label": "Cache de shaders (NVIDIA, AMD, DirectX)",
     "paths": [os.path.join(LOCAL, r"NVIDIA\DXCache"), os.path.join(LOCAL, r"NVIDIA\GLCache"), os.path.join(LOCAL, "D3DSCache"),
               os.path.join(LOCAL, r"AMD\DxCache"), os.path.join(LOCAL, r"AMD\GLCache")], "age": 0, "default": False, "how": "files",
     "desc": "Shaders já compilados pelos jogos. Limpe só depois de trocar o driver de vídeo ou se um jogo travar ao carregar: na próxima vez o jogo recompila e demora um pouco mais."},
    {"id": "recycle", "label": "Lixeira", "paths": [], "age": 0, "default": False, "how": "recycle",
     "desc": "Esvazia a Lixeira de todos os discos. Não dá para desfazer."},
    {"id": "winsxs", "label": "Limpeza do Windows Update (WinSxS)", "paths": [], "age": 0, "default": False, "how": "dism",
     "desc": "Versões antigas de componentes substituídas por atualizações (DISM /StartComponentCleanup, a mesma \"Limpeza do Windows Update\" do Disk Cleanup). Pode levar de 5 a 20 min; o tamanho só se sabe ao terminar."},
]
BY_ID = {i["id"]: i for i in ITEMS}

NOT_DONE = [
    ("Prefetch", "o Windows usa essa pasta para abrir os programas mais rápido; limpar deixa tudo mais lento por dias, até ele reaprender."),
    ("Limpar a memória RAM", "memória livre é memória desperdiçada: o Windows usa a sobra como cache e solta na hora que um programa precisa. Forçar a limpeza faz os programas recarregarem do disco."),
    ("Limpeza de registro", "não tem ganho de desempenho medido e pode quebrar programas."),
]


def _is_link(st: os.stat_result) -> bool:
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _walk(root: str, min_age_days: float):
    """(caminho, tamanho) dos arquivos com idade mínima, sem seguir junções nem links."""
    if not root:
        return
    limit = time.time() - min_age_days * DAY
    try:
        st = os.lstat(root)
    except OSError:
        return
    if _is_link(st):
        return
    if not stat.S_ISDIR(st.st_mode):
        if st.st_mtime <= limit:
            yield root, st.st_size
        return
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            it = os.scandir(d)
        except OSError:
            continue
        with it:
            for e in it:
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                if _is_link(st):
                    continue
                if stat.S_ISDIR(st.st_mode):
                    stack.append(e.path)
                elif st.st_mtime <= limit:
                    yield e.path, st.st_size


class _SHQUERYRBINFO(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("i64Size", ctypes.c_longlong), ("i64NumItems", ctypes.c_longlong)]


def _recycle_size() -> tuple[int, int]:
    info = _SHQUERYRBINFO(ctypes.sizeof(_SHQUERYRBINFO), 0, 0)
    if ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(info)) != 0:
        return 0, 0
    return info.i64Size, info.i64NumItems


def analyze() -> list[dict]:
    """Mede cada item. Não apaga nada."""
    out = []
    for it in ITEMS:
        size = count = 0
        if it["how"] in ("files", "do"):
            for p in it["paths"]:
                for _, s in _walk(p, it["age"]):
                    size += s
                    count += 1
        elif it["how"] == "recycle":
            size, count = _recycle_size()
        out.append({k: it[k] for k in ("id", "label", "desc", "default", "how", "age")} |
                   {"size": size, "count": count, "known": it["how"] != "dism"})
    return out


def _delete_files(it: dict) -> tuple[int, int, int]:
    freed = files = skipped = 0
    for root in it["paths"]:
        if not root:
            continue
        for path, size in list(_walk(root, it["age"])):
            try:
                os.chmod(path, stat.S_IWRITE)  # somente leitura não impede (é sobra, não arquivo do usuário)
                os.remove(path)
                freed += size
                files += 1
            except OSError:
                skipped += 1  # em uso ou sem permissão: fica
        # pastas que ficaram vazias (de baixo para cima); a pasta raiz do item fica
        if os.path.isdir(root):
            for d, _, _ in sorted(os.walk(root, followlinks=False), key=lambda t: -len(t[0])):
                if d != root:
                    try:
                        if not _is_link(os.lstat(d)):
                            os.rmdir(d)
                    except OSError:
                        pass
    return freed, files, skipped


def _ps(cmd: str, timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd], capture_output=True,
                          creationflags=NO_WINDOW, timeout=timeout)


def clean(ids: list[str], progress=None) -> list[dict]:
    """Limpa só os itens pedidos. progress(texto) a cada item. Devolve o que foi feito em cada um."""
    results = []
    for i in ids:
        it = BY_ID.get(i)
        if not it:
            continue
        if progress:
            progress(it["label"])
        t = time.time()
        r = {"id": i, "label": it["label"], "freed": 0, "files": 0, "skipped": 0, "error": ""}
        try:
            if it["how"] == "files":
                r["freed"], r["files"], r["skipped"] = _delete_files(it)
            elif it["how"] == "do":
                before = sum(s for p in it["paths"] for _, s in _walk(p, 0))
                p = _ps("Delete-DeliveryOptimizationCache -Force", 300)
                if p.returncode:
                    raise RuntimeError(p.stderr.decode("cp850", "replace").strip()[-200:] or "o Windows recusou")
                r["freed"] = max(0, before - sum(s for p in it["paths"] for _, s in _walk(p, 0)))
            elif it["how"] == "recycle":
                size, n = _recycle_size()
                if n:
                    hr = ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 0x1 | 0x2 | 0x4)  # sem confirmação, progresso nem som
                    if hr not in (0, -2147418113):  # E_UNEXPECTED = lixeira já vazia
                        raise RuntimeError(f"Windows devolveu {hr:#x}")
                r["freed"], r["files"] = size, n
            elif it["how"] == "dism":
                before = psutil.disk_usage(WIN[:3]).free
                p = subprocess.run(["dism", "/Online", "/Cleanup-Image", "/StartComponentCleanup"], capture_output=True,
                                   creationflags=NO_WINDOW, timeout=3600)
                if p.returncode not in (0, 3010):
                    raise RuntimeError(p.stdout.decode("cp850", "replace").strip()[-200:] or f"DISM saiu com {p.returncode}")
                r["freed"] = max(0, psutil.disk_usage(WIN[:3]).free - before)
        except Exception as e:
            log.warning("limpeza %s falhou", i, exc_info=True)
            r["error"] = str(e) or type(e).__name__
        r["secs"] = round(time.time() - t, 1)
        results.append(r)
    return results


# ---------- sugestões: o que pesa no PC (não mexe em nada) ----------
def power_plan() -> str:
    try:
        p = subprocess.run(["powercfg", "/getactivescheme"], capture_output=True, creationflags=NO_WINDOW, timeout=10)
        text = p.stdout.decode("cp850", "replace")
        return text[text.find("(") + 1:text.rfind(")")] if "(" in text else text.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _folder_size(path: str, limit_files: int = 200_000) -> int:
    total = 0
    for n, (_, s) in enumerate(_walk(path, 0)):
        total += s
        if n >= limit_files:
            break
    return total


def insights(procs: list[dict], startup: list[dict], gpu: dict, system: dict, uptime_s: float) -> list[dict]:
    """Sugestões a partir dos sensores: [{"sev", "title", "detail", "action"}]. Só leitura."""
    out = []
    du = psutil.disk_usage(WIN[:3])
    pct = du.used / du.total * 100
    if pct >= 85:
        out.append({"sev": "bad" if pct >= 93 else "warn", "title": f"Disco {WIN[:2]} com {pct:.0f} % de uso",
                    "detail": f"Sobram {du.free / 2**30:.1f} GB. Abaixo de 10-15 % livre o Windows perde desempenho (arquivo de paginação, atualizações, desfragmentação do SSD).",
                    "action": "Rode a limpeza abaixo e veja a pasta Downloads e jogos instalados."})
    if uptime_s > 7 * DAY:
        out.append({"sev": "info", "title": f"PC ligado há {uptime_s / DAY:.0f} dias sem reiniciar",
                    "detail": "Atualizações do Windows e de drivers só terminam de instalar ao reiniciar; vazamentos de memória de programas também só somem assim.",
                    "action": "Reinicie quando puder (Reiniciar, não Desligar: com a Inicialização rápida, Desligar não zera o kernel)."})
    mem = psutil.virtual_memory()
    if mem.percent >= 85:
        top = sorted(procs, key=lambda p: -p["rss"])[:4]
        out.append({"sev": "warn", "title": f"Memória em {mem.percent:.0f} %",
                    "detail": "Os que mais usam: " + ", ".join(f"{p['name']} {p['rss'] / 2**30:.1f} GB" for p in top) + ".",
                    "action": "Feche o que não está usando. \"Limpar memória\" não resolve: o programa volta a ocupar o mesmo espaço."})
    third = [i for i in startup if i.get("enabled") and not i.get("windows")]
    if len(third) >= 8:
        out.append({"sev": "info", "title": f"{len(third)} programas de outros fabricantes iniciam com o Windows",
                    "detail": ", ".join(i["name"] for i in third[:12]) + ("…" if len(third) > 12 else ""),
                    "action": "Desligue em Inicialização os que você não usa todo dia (a entrada fica guardada e volta igual)."})
    if gpu.get("available") and gpu.get("vram_used") and gpu.get("mem_total"):
        vram_pct = gpu["vram_used"] / gpu["mem_total"] * 100
        holders = sorted([p for p in procs if p.get("vram", 0) >= 512 * 2**20], key=lambda p: -p["vram"])[:3]
        if vram_pct >= 50 and (gpu.get("util") or 0) < 10 and holders:
            out.append({"sev": "info", "title": f"VRAM {vram_pct:.0f} % ocupada com a GPU parada",
                        "detail": "Segurando memória de vídeo: " + ", ".join(f"{p['name']} {p['vram'] / 2**30:.1f} GB" for p in holders) + ".",
                        "action": "Se for jogar ou usar outro modelo de IA, descarregue o modelo no LM Studio ou feche o programa antes."})
    plan = power_plan()
    if plan and any(w in plan.lower() for w in ("economia", "power saver", "economizador")):
        out.append({"sev": "info", "title": f"Plano de energia: {plan}",
                    "detail": "O plano de economia reduz o clock da CPU para gastar menos.",
                    "action": "Em um desktop, use Equilibrado (o Windows já sobe o clock quando precisa)."})
    downloads = os.path.join(os.path.expanduser("~"), "Downloads")
    size = _folder_size(downloads)
    if size >= 10 * 2**30:
        out.append({"sev": "info", "title": f"Pasta Downloads com {size / 2**30:.0f} GB",
                    "detail": "Instaladores e arquivos baixados ficam aí. O SmartGuardian não apaga arquivos seus.",
                    "action": "Revise a pasta e apague o que não precisa mais."})
    hib = os.path.join(WIN[:3], "hiberfil.sys")
    try:
        hs = os.stat(hib).st_size
        if hs >= 4 * 2**30:
            out.append({"sev": "info", "title": f"Arquivo de hibernação com {hs / 2**30:.0f} GB",
                        "detail": "hiberfil.sys guarda a memória para hibernar e para a Inicialização rápida.",
                        "action": "Se nunca hiberna, `powercfg /h /type reduced` diminui o arquivo e mantém a Inicialização rápida."})
    except OSError:
        pass
    return out
