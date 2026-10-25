"""Processos em execução: quem é, de onde roda, quem abriu e se o executável é assinado."""
from __future__ import annotations

import ctypes
import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import psutil

from . import signature
from .signature import Signature

# Processos do próprio kernel: não têm executável, e é normal o caminho vir vazio.
KERNEL = {"Registry", "MemCompression", "Secure System", "vmmem", "vmmem.exe", "Memory Compression"}

ATTRS = ["pid", "name", "exe", "ppid", "username", "create_time", "cmdline", "memory_info"]


@dataclass
class Proc:
    pid: int
    name: str
    exe: str            # vazio quando o Windows não deixa ver (processo de outro usuário/sistema sem admin)
    ppid: int
    parent: str
    user: str
    started: float
    cmdline: str
    rss: int
    sig: Signature | None = field(default=None)


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot(with_signatures: bool = True) -> list[Proc]:
    procs = []
    for p in psutil.process_iter(ATTRS, ad_value=None):
        i = p.info
        if i["pid"] in (0, 4):  # System Idle Process e System: não têm executável
            continue
        exe = i["exe"] or ""
        if exe and not os.path.isabs(exe):
            exe = ""  # Registry, MemCompression, Secure System: processos do kernel, sem arquivo
        procs.append(Proc(
            pid=i["pid"], name=i["name"] or "", exe=exe, ppid=i["ppid"] or 0, parent="",
            user=(i["username"] or "").split("\\")[-1], started=i["create_time"] or 0.0,
            cmdline=" ".join(i["cmdline"] or []), rss=i["memory_info"].rss if i["memory_info"] else 0,
        ))
    names = {p.pid: p.name for p in procs}
    for p in procs:
        p.parent = names.get(p.ppid, "")
    if with_signatures:
        exes = sorted({p.exe for p in procs if p.exe})
        with ThreadPoolExecutor(8) as pool:
            sigs = dict(zip(exes, pool.map(signature.check, exes)))
        for p in procs:
            p.sig = sigs.get(p.exe)
    return procs
