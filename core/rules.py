"""Pontuação de risco dos processos. Pesos e listas ficam em rules.json (criado na primeira execução).

Garantias contra falso positivo, aplicadas aqui e não só no arquivo:
  - regra comum vale no máximo 25 pontos e o alerta começa em 30: nunca um sinal sozinho;
  - só as regras fortes (STRONG) alertam sozinhas, porque quase não acontecem com programa legítimo;
  - assinatura válida anula as regras de local (AppData, Downloads);
  - programa sem assinatura em pasta que só o administrador grava (Program Files, Windows) pesa pouco.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

from .store import ROOT, write_json

RULES_FILE = ROOT / "rules.json"
MAX_WEIGHT = 25
STRONG = {"fake_system_name", "bad_port"}

DEFAULT_RULES = {
    "weights": {
        "fake_system_name": 40,      # forte
        "bad_port": 30,              # forte
        "temp_dir": 25,
        "invalid_signature": 25,
        "encoded_command": 25,
        "office_spawns_shell": 25,
        "unsigned": 20,
        "user_dir": 15,
        "downloads_dir": 15,
        "wrong_parent": 10,
        "unsigned_internet": 10,
        "listen_all": 10,
        "new_exe": 5,
        "gpu_untrusted": 25,
        "unsigned_protected": 5,
    },
    "bad_ports": [4444, 1337, 31337, 6666, 6667, 12345, 54321],
    "system_names": ["svchost.exe", "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe", "services.exe",
                     "spoolsv.exe", "taskhostw.exe", "sihost.exe", "dllhost.exe", "conhost.exe", "ctfmon.exe", "dwm.exe",
                     "fontdrvhost.exe", "lsaiso.exe", "runtimebroker.exe", "searchindexer.exe", "wmiprvse.exe",
                     "rundll32.exe", "regsvr32.exe", "explorer.exe", "powershell.exe", "cmd.exe", "taskmgr.exe", "msiexec.exe"],
    "expected_parents": {"svchost.exe": ["services.exe", "MsMpEng.exe"], "lsass.exe": ["wininit.exe"], "services.exe": ["wininit.exe"]},
    "office_apps": ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "acrord32.exe", "acrobat.exe"],
    "shells": ["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"],
}

LABELS = {
    "fake_system_name": "Nome de processo do Windows fora da pasta do Windows",
    "bad_port": "Conexão em porta usada por ferramentas de invasão ({port})",
    "temp_dir": "Roda a partir de uma pasta temporária ou que qualquer usuário grava",
    "invalid_signature": "Assinatura quebrada: {detail}",
    "encoded_command": "Comando escondido (codificado) na linha de comando",
    "office_spawns_shell": "Aberto por {parent}, que não costuma abrir este tipo de programa",
    "unsigned": "Sem assinatura digital",
    "user_dir": "Executável numa pasta do usuário (AppData, ProgramData, Público)",
    "downloads_dir": "Roda direto da pasta Downloads",
    "wrong_parent": "Aberto por {parent} em vez de {expected}",
    "unsigned_internet": "Sem assinatura e conectado à internet",
    "listen_all": "Porta aberta para toda a rede ({port})",
    "new_exe": "Programa novo, visto depois do período de aprendizado",
    "unsigned_protected": "Sem assinatura, mas numa pasta que só o administrador grava",
    "trusted_location": "Assinatura válida anula a regra de local",
    "gpu_untrusted": "Uso alto e contínuo da GPU ({pct:.0f} %) por programa sem assinatura válida (perfil de minerador)",
}

WINDIR = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows"))
PROTECTED = [os.path.normcase(p) for p in (os.environ.get("ProgramFiles", r"C:\Program Files"),
                                           os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), WINDIR)]
TEMP_DIRS = [os.path.normcase(p) for p in (os.environ.get("TEMP", ""), os.path.join(WINDIR, "Temp")) if p]
# Pastas dentro do Windows onde qualquer usuário consegue gravar; vírus usam para parecer do sistema.
WRITABLE_IN_WINDOWS = [os.path.normcase(os.path.join(WINDIR, d)) for d in (
    "Tasks", "Tracing", r"System32\Tasks", r"System32\spool\drivers\color", r"Registration\CRMLog",
    r"System32\Microsoft\Crypto\RSA\MachineKeys", r"SysWOW64\Tasks", r"SysWOW64\com\dmp")]
ENCODED = re.compile(r"\s-(e|ec|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", re.I)


def load() -> dict:
    """Regras do arquivo, com os pesos comuns limitados a 25 (mesmo que alguém edite para mais)."""
    try:
        user = json.loads(RULES_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        write_json(RULES_FILE, DEFAULT_RULES)
        user = {}
    except json.JSONDecodeError:
        user = {}
    rules = {**DEFAULT_RULES, **{k: v for k, v in user.items() if k in DEFAULT_RULES}}
    rules["weights"] = {**DEFAULT_RULES["weights"], **user.get("weights", {})}
    for k, v in rules["weights"].items():
        if k not in STRONG:
            rules["weights"][k] = min(int(v), MAX_WEIGHT)
    rules["system_names"] = {n.lower() for n in rules["system_names"]}
    rules["office_apps"] = {n.lower() for n in rules["office_apps"]}
    rules["shells"] = {n.lower() for n in rules["shells"]}
    rules["bad_ports"] = set(int(p) for p in rules["bad_ports"])
    return rules


@dataclass
class Score:
    total: int = 0
    reasons: list = field(default_factory=list)   # [(rule, texto, pontos)]
    strong: bool = False

    def add(self, rules: dict, rule: str, **fmt) -> None:
        pts = rules["weights"].get(rule, 0)
        if not pts:
            return
        self.reasons.append((rule, LABELS[rule].format(**fmt), pts))
        self.total += pts
        self.strong |= rule in STRONG


def under(path: str, dirs: list[str]) -> bool:
    return any(d and (path == d or path.startswith(d + "\\")) for d in dirs)


def score(proc, rules: dict, *, conns=(), listens=(), new_exe: bool = False, gpu: float = 0.0) -> Score:
    """proc: core.procs.Proc com sig preenchida. conns/listens: core.conns.Conn deste processo.
    gpu: uso de GPU sustentado (%), o menor valor das últimas leituras."""
    s = Score()
    if not proc.exe or proc.sig is None:
        return s
    path = os.path.normcase(proc.exe)
    name = proc.name.lower()
    parent = (proc.parent or "").lower()
    sig = proc.sig
    trusted = sig.trusted
    writable = TEMP_DIRS + WRITABLE_IN_WINDOWS
    in_windows = under(path, [WINDIR]) and not under(path, writable)
    protected = under(path, PROTECTED) and not under(path, writable)
    home = os.path.normcase(os.path.expanduser("~"))

    if name in rules["system_names"] and not in_windows:
        s.add(rules, "fake_system_name")
    expected = rules["expected_parents"].get(name)
    if expected and parent and parent not in {e.lower() for e in expected}:
        s.add(rules, "wrong_parent", parent=proc.parent, expected=" ou ".join(expected))

    if under(path, writable):
        s.add(rules, "temp_dir")
    elif under(path, [os.path.join(home, "downloads")]):
        s.add(rules, "downloads_dir")
    elif not protected and under(path, [os.path.join(home, "appdata"), os.path.normcase(os.environ.get("ProgramData", "")),
                                         os.path.normcase(os.path.join(os.environ.get("PUBLIC", r"C:\Users\Public")))]):
        s.add(rules, "user_dir")
    if trusted and not s.strong:  # assinatura válida anula as regras de local (mas não legitima um nome do Windows fora do lugar)
        for i, (rule, _, pts) in enumerate(list(s.reasons)):
            if rule in ("temp_dir", "downloads_dir", "user_dir"):
                s.reasons.append(("trusted_location", LABELS["trusted_location"], -pts))
                s.total -= pts

    if sig.kind == "invalid":
        s.add(rules, "invalid_signature", detail=sig.detail)
    elif sig.kind == "none":
        s.add(rules, "unsigned_protected" if protected else "unsigned")
        if any(c.scope == "internet" and c.state == "Estabelecida" for c in conns):
            s.add(rules, "unsigned_internet")

    if ENCODED.search(" " + proc.cmdline):
        s.add(rules, "encoded_command")
    if name in rules["shells"] and parent in rules["office_apps"]:
        s.add(rules, "office_spawns_shell", parent=proc.parent)

    bad = next((c.rport for c in conns if c.rport in rules["bad_ports"]), None) or \
        next((c.lport for c in listens if c.lport in rules["bad_ports"]), None)
    if bad:
        s.add(rules, "bad_port", port=bad)
    if not trusted:
        open_all = next((c.lport for c in listens if c.laddr in ("0.0.0.0", "::")), None)
        if open_all:
            s.add(rules, "listen_all", port=open_all)
    if new_exe:
        s.add(rules, "new_exe")
    if gpu >= 50 and not trusted:  # jogos, LM Studio, navegadores são assinados; minerador costuma não ser
        s.add(rules, "gpu_untrusted", pct=gpu)
    s.total = max(0, s.total)
    return s


def severity(total: int, strong: bool, threshold: int) -> str:
    if strong or total >= 60:
        return "bad"
    if total >= threshold:
        return "warn"
    if total >= 15:
        return "info"
    return "ok"
