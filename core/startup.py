"""Tudo que abre sozinho com o Windows: chaves Run, pasta Inicializar, serviços automáticos e tarefas agendadas.

Desativar nunca apaga: a entrada original fica guardada no banco (startup_disabled) e volta igual
ao reativar. Atalhos da pasta Inicializar vão para C:\\SmartGuardian\\data\\startup_desativados.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import winreg
from pathlib import Path

import psutil

from . import signature
from .store import ROOT, Db

NO_WINDOW = subprocess.CREATE_NO_WINDOW
PARKED = ROOT / "data" / "startup_desativados"
HIVES = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
RUN_KEYS = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", "Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "Run"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Run"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "Run"),
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "Run32"),
]
APPROVED = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
FOLDERS = [
    Path(os.environ["APPDATA"]) / r"Microsoft\Windows\Start Menu\Programs\Startup",
    Path(os.environ.get("ProgramData", r"C:\ProgramData")) / r"Microsoft\Windows\Start Menu\Programs\StartUp",
]
EXT = r"\.(?:exe|com|bat|cmd|scr|ps1|vbs|js|msc)"


def exe_of(command: str) -> str:
    """Executável de uma linha de comando (Run, serviço, tarefa)."""
    cmd = os.path.expandvars(command.strip())
    cmd = re.sub(r"^\\\?\?\\", "", cmd)
    cmd = re.sub(r"^\\SystemRoot\\", os.environ.get("SystemRoot", r"C:\Windows").replace("\\", "\\\\") + r"\\", cmd, flags=re.I)
    if cmd.startswith('"'):
        exe = cmd[1:].split('"', 1)[0]
    else:
        m = re.match(rf"^(.*?{EXT})(?=\s|$)", cmd, re.I)
        exe = m.group(1) if m else cmd.split(" ", 1)[0]
    if exe and not os.path.isabs(exe):
        exe = shutil.which(exe) or os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", exe)
    return exe


def _approved(hive: str, sub: str) -> dict[str, bool]:
    """Itens desligados pelo Gerenciador de Tarefas (StartupApproved: primeiro byte ímpar = desligado)."""
    out = {}
    try:
        with winreg.OpenKey(HIVES[hive], f"{APPROVED}\\{sub}") as k:
            for i in range(winreg.QueryInfoKey(k)[1]):
                name, data, _ = winreg.EnumValue(k, i)
                if isinstance(data, bytes) and data:
                    out[name.lower()] = not (data[0] & 1)
    except OSError:
        pass
    return out


def _run_items() -> list[dict]:
    items = []
    for hive, path, approved_sub in RUN_KEYS:
        approved = _approved(hive, approved_sub)
        try:
            with winreg.OpenKey(HIVES[hive], path) as k:
                for i in range(winreg.QueryInfoKey(k)[1]):
                    name, data, _ = winreg.EnumValue(k, i)
                    if not isinstance(data, str) or not data.strip():
                        continue
                    items.append({"key": f"run:{hive}\\{path}\\{name}", "kind": "run", "kind_label": "Chave Run do registro",
                                  "name": name, "location": f"{hive}\\{path}", "command": data,
                                  "enabled": approved.get(name.lower(), True)})
        except OSError:
            continue
    return items


def _resolve_links(paths: list[Path]) -> dict[str, str]:
    if not paths:
        return {}
    ps = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8;$w=New-Object -ComObject WScript.Shell;"
          "$env:LNKS.Split('|') | % { $s=$w.CreateShortcut($_); [pscustomobject]@{p=$_;t=$s.TargetPath;a=$s.Arguments} } | ConvertTo-Json -Compress")
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], capture_output=True, timeout=30,
                           creationflags=NO_WINDOW, env=dict(os.environ, LNKS="|".join(map(str, paths))))
        data = json.loads(r.stdout.decode("utf-8", "replace") or "[]")
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return {}
    data = data if isinstance(data, list) else [data]
    return {d["p"]: f'"{d["t"]}" {d["a"] or ""}'.strip() for d in data if d.get("t")}


def _folder_items() -> list[dict]:
    files = [f for folder in FOLDERS if folder.exists() for f in folder.iterdir() if f.is_file() and f.name.lower() != "desktop.ini"]
    links = _resolve_links([f for f in files if f.suffix.lower() == ".lnk"])
    approved = _approved("HKCU", "StartupFolder") | _approved("HKLM", "StartupFolder")
    return [{"key": f"folder:{f}", "kind": "folder", "kind_label": "Pasta Inicializar", "name": f.stem,
             "location": str(f.parent), "command": links.get(str(f), f'"{f}"'),
             "enabled": approved.get(f.name.lower(), True)} for f in files]


def _service_items() -> list[dict]:
    items = []
    for s in psutil.win_service_iter():
        try:
            d = s.as_dict()
        except (psutil.Error, OSError):
            continue
        if d.get("start_type") != "automatic" or not d.get("binpath"):
            continue
        items.append({"key": f"service:{d['name']}", "kind": "service", "kind_label": "Serviço", "name": d["display_name"] or d["name"],
                      "location": d["name"], "command": d["binpath"], "enabled": True})
    return items


def _task_items() -> list[dict]:
    ps = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8;Get-ScheduledTask | % { $a=$_.Actions | ? { $_.Execute } | select -First 1;"
          "if ($a) { [pscustomobject]@{p=$_.TaskPath;n=$_.TaskName;s=\"$($_.State)\";e=$a.Execute;g=$a.Arguments} } } | ConvertTo-Json -Compress")
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], capture_output=True, timeout=60,
                           creationflags=NO_WINDOW)
        data = json.loads(r.stdout.decode("utf-8", "replace") or "[]")
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return []
    data = data if isinstance(data, list) else [data]
    return [{"key": f"task:{d['p']}{d['n']}", "kind": "task", "kind_label": "Tarefa agendada", "name": d["n"],
             "location": d["p"], "command": f'"{d["e"].strip(chr(34))}" {d.get("g") or ""}'.strip(),
             "enabled": d["s"] != "Disabled"} for d in data]


def enumerate_all(db: Db) -> list[dict]:
    items = _run_items() + _folder_items() + _service_items() + _task_items()
    keys = {i["key"] for i in items}
    for row in db.q("select key, data from startup_disabled"):
        if row["key"] not in keys:  # desativado por nós: some do Windows, mas continua na lista
            items.append(json.loads(row["data"]) | {"enabled": False, "parked": True})
    for it in items:
        it["exe"] = exe_of(it["command"])
        sig = signature.check(it["exe"]) if it["exe"] else signature.Signature("unreadable")
        it["sig"], it["signer"], it["sig_detail"] = sig.kind, sig.signer, sig.detail
        it["windows"] = sig.trusted and sig.signer.startswith("Microsoft") and (it["kind"] != "task" or it["location"].startswith("\\Microsoft\\"))
    return items


# ---------- ligar / desligar ----------
def _sc(*args: str) -> None:
    r = subprocess.run(["sc.exe", *args], capture_output=True, timeout=30, creationflags=NO_WINDOW)
    if r.returncode:
        raise RuntimeError(r.stdout.decode("cp850", "replace").strip().splitlines()[-1] if r.stdout else "sc falhou")


def set_enabled(db: Db, item: dict, enabled: bool) -> None:
    kind, key = item["kind"], item["key"]
    if kind == "run":
        hive, rest = item["location"].split("\\", 1)
        if enabled:
            saved = db.one("select data from startup_disabled where key=?", (key,))
            if not saved:
                raise RuntimeError("Este item foi desligado fora do SmartGuardian; religue pelo Gerenciador de Tarefas.")
            with winreg.CreateKeyEx(HIVES[hive], rest, 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, item["name"], 0, winreg.REG_SZ, json.loads(saved["data"])["command"])
        else:
            with winreg.OpenKey(HIVES[hive], rest, 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, item["name"])
    elif kind == "folder":
        src = Path(key.split(":", 1)[1])
        parked = PARKED / src.name
        if enabled:
            shutil.move(str(parked), str(src))
        else:
            PARKED.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(parked))
    elif kind == "service":
        _sc("config", item["location"], "start=", "auto" if enabled else "disabled")
    elif kind == "task":
        r = subprocess.run(["schtasks", "/change", "/tn", item["location"] + item["name"], "/enable" if enabled else "/disable"],
                           capture_output=True, timeout=30, creationflags=NO_WINDOW)
        if r.returncode:
            raise RuntimeError(r.stderr.decode("cp850", "replace").strip() or "schtasks falhou")
    if enabled:
        db.x("delete from startup_disabled where key=?", (key,))
    else:
        keep = {k: item[k] for k in ("key", "kind", "kind_label", "name", "location", "command")}
        db.x("insert or replace into startup_disabled(key, data) values(?, ?)", (key, json.dumps(keep, ensure_ascii=False)))
