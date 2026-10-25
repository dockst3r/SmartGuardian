"""Firewall do Windows: diz se uma porta aberta neste PC pode mesmo ser alcançada de outro aparelho.

Porta "escutando" não é porta exposta: com o firewall ligado, entrada sem regra que libere é bloqueada.
As regras vêm direto do registro (o COM do firewall não mostra o PFN, e regras de app da Store, que só
valem para o próprio pacote, pareceriam liberar tudo). O perfil ativo (Público/Privado/Domínio), se o
firewall está ligado nele e a ação padrão de entrada vêm do COM, por PowerShell.

Resultado por porta: "pc" (só este PC), "blocked" (nenhuma regra libera), "lan" (liberada só para a
rede local), "open" (liberada para qualquer endereço) ou "" (não deu para ler o firewall: trate como antes).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import subprocess
import threading
import time
import winreg

import psutil

log = logging.getLogger(__name__)
NO_WINDOW = 0x08000000
TTL = 60  # s entre leituras: regras mudam raramente, e a leitura custa ~0,3 s
RULE_KEYS = (r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
             r"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules")   # local e política de grupo
PROFILE_NAMES = {1: "Domain", 2: "Private", 4: "Public"}
PROFILE_PT = {1: "Domínio", 2: "Privada", 4: "Pública"}
PROFILE_PS = ("$p = New-Object -ComObject HNetCfg.FwPolicy2; $c = $p.CurrentProfileTypes; "
              "@{cur=$c; prof=@(foreach ($t in 1,2,4) { if ($c -band $t) { @{t=$t; on=[bool]$p.FirewallEnabled($t); "
              "allow=[int]$p.DefaultInboundAction($t)} } })} | ConvertTo-Json -Depth 3 -Compress")
RPC_DYNAMIC = 49152  # "RPC" nas regras = portas dinâmicas do RPC (49152+ por padrão)


def parse_rule(text: str) -> dict:
    """'v2.33|Action=Allow|Dir=In|LPort=445|...' → {"Action": ["Allow"], "LPort": ["445"], ...}."""
    out: dict[str, list[str]] = {}
    for part in text.split("|")[1:]:
        k, sep, v = part.partition("=")
        if sep:
            out.setdefault(k, []).append(v)
    return out


def _one(rule: dict, key: str) -> str:
    return (rule.get(key) or [""])[0]


def inbound_allows(texts) -> list[dict]:
    """Só regras ligadas, de entrada, que liberam e que valem para o PC (não só para um app da Store).
    TTK* ("trust tuple keyword": Wi-Fi Direct, Play To/UPnP) só libera aparelho pareado, não a rede: fica de fora."""
    out = []
    for t in texts:
        r = parse_rule(t)
        if (_one(r, "Active").upper() == "TRUE" and _one(r, "Dir") == "In" and _one(r, "Action") == "Allow"
                and not r.get("PFN") and not r.get("AppPkgId") and not any(k.startswith("TTK") for k in r)):
            out.append(r)
    return out


def _port_matches(rule: dict, port: int) -> bool:
    ports = rule.get("LPort", []) + rule.get("LPort2_10", []) + rule.get("LPort2_20", [])
    if not ports:
        return True
    for p in ports:
        lo, dash, hi = p.partition("-")
        if p == "RPC" and port >= RPC_DYNAMIC or p == "RPC-EPMap" and port == 135:
            return True
        if lo.isdigit() and (int(lo) == port if not dash else hi.isdigit() and int(lo) <= port <= int(hi)):
            return True
    return False


def _remote_scope(rule: dict) -> str:
    addrs = sum((rule.get(k, []) for k in ("RA4", "RA6", "RA42", "RA62")), [])
    if not addrs:
        return "open"
    for a in addrs:
        if a in ("LocalSubnet", "Intranet", "PlayToDevice"):
            continue
        try:
            net = ipaddress.ip_network(a.split("-")[0].split("/")[0], strict=False)
        except ValueError:
            return "open"   # "*", DefaultGateway, Internet, faixa estranha: considere aberta
        if not (net.is_private or net.is_link_local or net.is_loopback):
            return "open"
    return "lan"


def exposure(rules: list[dict], profiles: list[dict], *, proto: str, port: int, exe: str, pid: int, laddr: str,
             services: dict[str, set[int]]) -> str:
    """profiles: os perfis ativos, [{"t": 4, "on": True, "allow": 0}]. services: serviço (minúsculo) → PIDs."""
    return match(rules, profiles, proto=proto, port=port, exe=exe, pid=pid, laddr=laddr, services=services)[0]


def describe(rule: dict | None) -> str:
    """Texto curto da regra que liberou a porta, para a IA explicar o porquê."""
    if not rule:
        return ""
    name = _one(rule, "Name")
    name = "regra do Windows" if name.startswith("@") else f"regra \"{name}\""
    parts = [f"programa {os.path.basename(os.path.expandvars(_one(rule, 'App')))}" if rule.get("App") else "qualquer programa",
             f"serviço {_one(rule, 'Svc')}" if rule.get("Svc") else "",
             "portas " + ",".join(rule.get("LPort", []) + rule.get("LPort2_10", [])) if rule.get("LPort") or rule.get("LPort2_10") else "qualquer porta",
             "remoto " + ",".join(sum((rule.get(k, []) for k in ("RA4", "RA6")), [])) if rule.get("RA4") or rule.get("RA6") else "qualquer origem",
             "perfis " + "/".join(rule["Profile"]) if rule.get("Profile") else "todos os perfis"]
    return f"{name} ({', '.join(p for p in parts if p)})"


def match(rules: list[dict], profiles: list[dict], *, proto: str, port: int, exe: str, pid: int, laddr: str,
          services: dict[str, set[int]]) -> tuple[str, dict | None]:
    """(exposição, regra que liberou ou None)."""
    try:
        if ipaddress.ip_address(laddr.split("%")[0]).is_loopback:
            return "pc", None
    except ValueError:
        pass
    if not profiles:
        return "", None
    if any(not p["on"] or p["allow"] for p in profiles):
        return "open", None   # firewall desligado (ou liberando tudo) num perfil ativo
    active = {PROFILE_NAMES[p["t"]] for p in profiles}
    proto_n = "6" if proto == "TCP" else "17"
    exe_n = os.path.normcase(exe) if exe else ("system" if pid == 4 else "")
    best, why = "blocked", None
    for r in rules:
        prof = r.get("Profile")
        if prof and not active & set(prof):
            continue
        p = _one(r, "Protocol")
        if p and p != proto_n:
            continue
        if not _port_matches(r, port):
            continue
        app = _one(r, "App")
        if app and os.path.normcase(os.path.expandvars(app)) != exe_n:
            continue
        svc = _one(r, "Svc").lower()
        if svc and svc != "*" and pid not in services.get(svc, ()):
            continue
        best, why = _remote_scope(r), r
        if best == "open":
            return best, why
    return best, why


class Firewall:
    """Lê regras e perfis no máximo a cada TTL segundos; se falhar, devolve "" (desconhecido)."""

    def __init__(self):
        self.rules: list[dict] = []
        self.profiles: list[dict] = []
        self.services: dict[str, set[int]] = {}
        self.ok = False
        self._at = 0.0
        self._lock = threading.Lock()

    def refresh(self, force: bool = False) -> None:
        with self._lock:
            if not force and time.time() - self._at < TTL:
                return
            self._at = time.time()
            try:
                self.rules = inbound_allows(_registry_rules())
                self.profiles = _profiles()
                self.services = _service_pids()
                self.ok = True
            except Exception:
                log.warning("não deu para ler o firewall; portas ficam sem essa informação", exc_info=True)
                self.ok = False

    def profile_name(self) -> str:
        return " + ".join(PROFILE_PT[p["t"]] for p in self.profiles) if self.ok else ""

    def exposure(self, *, proto: str, port: int, exe: str, pid: int, laddr: str) -> str:
        if not self.ok:
            return ""
        return exposure(self.rules, self.profiles, proto=proto, port=port, exe=exe, pid=pid, laddr=laddr,
                        services=self.services)

    def why(self, *, proto: str, port: int, exe: str, pid: int, laddr: str) -> str:
        """Qual regra libera a porta (texto), ou por que está bloqueada/aberta."""
        if not self.ok:
            return "firewall não lido"
        scope, rule = match(self.rules, self.profiles, proto=proto, port=port, exe=exe, pid=pid, laddr=laddr,
                            services=self.services)
        if scope == "open" and rule is None:
            return "firewall desligado ou liberando toda entrada no perfil ativo"
        if scope == "blocked":
            return f"nenhuma regra de entrada libera esta porta no perfil {self.profile_name()}"
        return describe(rule) if rule else ""


def _registry_rules() -> list[str]:
    out = []
    for path in RULE_KEYS:
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
        except OSError:
            continue
        with k:
            i = 0
            while True:
                try:
                    _, value, kind = winreg.EnumValue(k, i)
                except OSError:
                    break
                if kind == winreg.REG_SZ:
                    out.append(value)
                i += 1
    return out


def _profiles() -> list[dict]:
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", PROFILE_PS], capture_output=True,
                       creationflags=NO_WINDOW, timeout=20)
    data = json.loads(r.stdout.decode("utf-8", "replace") or "null")
    if not data:
        raise RuntimeError(r.stderr.decode("cp850", "replace").strip()[-200:] or "perfil do firewall vazio")
    prof = data.get("prof") or []
    return [prof] if isinstance(prof, dict) else prof


def _service_pids() -> dict[str, set[int]]:
    out: dict[str, set[int]] = {}
    for s in psutil.win_service_iter():
        try:
            pid = s.pid()
        except psutil.Error:
            continue
        if pid:
            out.setdefault(s.name().lower(), set()).add(pid)
    return out
