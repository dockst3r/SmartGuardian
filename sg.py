"""SmartGuardian no terminal.

    python sg.py processos           resumo e lista do que não tem assinatura confiável
    python sg.py processos --todos   lista todos os executáveis, agrupados pela assinatura
    python sg.py processos --json    tudo em JSON (para testes e para a IA mais tarde)
"""
from __future__ import annotations

import json
import os
import sys
import time
from collections import defaultdict
from dataclasses import asdict

from core import procs as P
from core.signature import LABELS

os.system("")  # ativa cores ANSI no console do Windows
B, G, Y, R, D, X = "\033[1m", "\033[92m", "\033[93m", "\033[91m", "\033[2m", "\033[0m"
COLOR = {"file": G, "catalog": G, "package": G, "none": Y, "invalid": R, "unreadable": D}


def cmd_processos(args: list[str]) -> None:
    t = time.perf_counter()
    rows = P.snapshot()
    elapsed = time.perf_counter() - t

    if "--json" in args:
        print(json.dumps([asdict(p) for p in rows], ensure_ascii=False, indent=2))
        return

    by_exe: dict[str, list[P.Proc]] = defaultdict(list)
    hidden = [p for p in rows if not p.exe and p.name not in P.KERNEL]
    kernel = [p for p in rows if not p.exe and p.name in P.KERNEL]
    for p in rows:
        if p.exe:
            by_exe[p.exe].append(p)
    kinds: dict[str, list[str]] = defaultdict(list)
    for exe, ps in by_exe.items():
        kinds[ps[0].sig.kind].append(exe)

    admin = P.is_admin()
    print(f"\n{B}SmartGuardian · processos{X}  {D}({'administrador' if admin else 'usuário comum'}, {elapsed:.1f} s){X}")
    print(f"{len(rows)} processos, {len(by_exe)} executáveis diferentes")
    for kind in ("file", "catalog", "package", "none", "invalid", "unreadable"):
        if kinds.get(kind):
            print(f"  {COLOR[kind]}{LABELS[kind]:<20}{X} {len(kinds[kind]):>4}")
    if kernel:
        print(f"  {D}{'internos do Windows':<20} {len(kernel):>4}  ({', '.join(sorted({p.name for p in kernel}))}){X}")
    if hidden:
        print(f"  {D}{'caminho oculto':<20} {len(hidden):>4}  ", end="")
        print("(processos protegidos do sistema)" if admin else "(rode como administrador para ver)", X)

    show = ("file", "catalog", "package", "none", "invalid", "unreadable") if "--todos" in args else ("none", "invalid", "unreadable")
    for kind in show:
        exes = sorted(kinds.get(kind, []), key=str.lower)
        if not exes:
            continue
        print(f"\n{B}{COLOR[kind]}{LABELS[kind].capitalize()}{X}")
        for exe in exes:
            ps = by_exe[exe]
            sig = ps[0].sig
            who = f"{sig.signer}" + (f" · {sig.detail}" if sig.detail else "")
            pids = ", ".join(str(p.pid) for p in ps[:4]) + ("…" if len(ps) > 4 else "")
            print(f"  {ps[0].name:<34} {D}PID {pids:<22}{X} {who}")
            print(f"    {D}{exe}  ·  aberto por {ps[0].parent or '?'}{X}")
            if kind == "none":
                try:
                    print(f"    {D}SHA-256 {P.sha256(exe)}{X}")
                except OSError:
                    pass
    if not any(kinds.get(k) for k in ("none", "invalid")):
        print(f"\n{G}Todos os executáveis visíveis têm assinatura válida.{X}")


COMMANDS = {"processos": cmd_processos}


def main() -> None:
    args = sys.argv[1:]
    if not args or args[0] not in COMMANDS:
        print(__doc__)
        return
    COMMANDS[args[0]](args[1:])


if __name__ == "__main__":
    main()
