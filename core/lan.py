"""Rede local: dados da conexão e varredura dos aparelhos (ping + tabela ARP).

Não abre portas nos aparelhos: só manda um ping para cada endereço da faixa e lê a tabela ARP do
Windows, que registra quem respondeu (mesmo aparelhos que bloqueiam ping aparecem nela).
"""
from __future__ import annotations

import csv
import ctypes
import ipaddress
import logging
import re
import socket
import struct
import subprocess
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from ctypes import wintypes
from pathlib import Path

import psutil

log = logging.getLogger("smartguardian.lan")
ROOT = Path(__file__).resolve().parent.parent
OUI_FILE = ROOT / "data" / "oui.csv"
OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
NO_WINDOW = subprocess.CREATE_NO_WINDOW

iphlpapi = ctypes.WinDLL("iphlpapi")
iphlpapi.IcmpCreateFile.restype = wintypes.HANDLE
iphlpapi.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
iphlpapi.IcmpSendEcho.argtypes = [wintypes.HANDLE, ctypes.c_ulong, ctypes.c_void_p, wintypes.WORD, ctypes.c_void_p,
                                  ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
iphlpapi.IcmpSendEcho.restype = wintypes.DWORD


class ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [("Address", ctypes.c_ulong), ("Status", ctypes.c_ulong), ("RoundTripTime", ctypes.c_ulong),
                ("DataSize", ctypes.c_ushort), ("Reserved", ctypes.c_ushort), ("Data", ctypes.c_void_p),
                ("Options", ctypes.c_ubyte * 16)]


def ping(ip: str, timeout_ms: int = 700) -> int | None:
    """Tempo de resposta em ms, ou None. Usa a API do Windows (sem abrir ping.exe)."""
    h = iphlpapi.IcmpCreateFile()
    if not h or h == wintypes.HANDLE(-1).value:
        return None
    try:
        data = b"smartguardian"
        buf = ctypes.create_string_buffer(ctypes.sizeof(ICMP_ECHO_REPLY) + len(data) + 64)
        addr = struct.unpack("<L", socket.inet_aton(ip))[0]
        if iphlpapi.IcmpSendEcho(h, addr, data, len(data), None, buf, len(buf), timeout_ms):
            reply = ICMP_ECHO_REPLY.from_buffer(buf)
            if reply.Status == 0:
                return int(reply.RoundTripTime)
        return None
    finally:
        iphlpapi.IcmpCloseHandle(h)


def _out(cmd: list[str], timeout: int = 15) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, creationflags=NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    for enc in ("utf-8", "cp850", "cp1252"):
        try:
            return r.stdout.decode(enc)
        except UnicodeDecodeError:
            continue
    return r.stdout.decode("latin-1")


def default_route() -> tuple[str, str]:
    """(gateway, IP deste PC) da rota padrão."""
    m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)",
                  _out(["route", "print", "-4", "0.0.0.0"]), re.M)
    if m:
        return m.group(1), m.group(2)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("1.1.1.1", 53))  # UDP não envia nada; só escolhe a interface
        return "", s.getsockname()[0]
    finally:
        s.close()


def interface_of(ip: str) -> tuple[str, str, str]:
    """(nome da interface, máscara, MAC) da interface com esse IP."""
    for name, addrs in psutil.net_if_addrs().items():
        if any(a.family == socket.AF_INET and a.address == ip for a in addrs):
            mask = next(a.netmask for a in addrs if a.family == socket.AF_INET and a.address == ip)
            mac = next((a.address for a in addrs if a.family == psutil.AF_LINK), "")
            return name, mask, mac.replace("-", ":").upper()
    return "", "255.255.255.0", ""


def wifi_ssid() -> str:
    for line in _out(["netsh", "wlan", "show", "interfaces"]).splitlines():
        m = re.match(r"\s*SSID\s*:\s*(.+)$", line)
        if m:
            return m.group(1).strip()
    return ""


def dns_servers() -> list[str]:
    ps = "(Get-NetIPConfiguration | ? IPv4DefaultGateway | % { $_.DNSServer.ServerAddresses }) -join ','"
    out = _out(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], 20).strip()
    return [s for s in out.split(",") if re.match(r"^\d+\.\d+\.\d+\.\d+$", s)]


def public_ip() -> str:
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
            return r.read().decode().strip()
    except OSError:
        return ""


def scan_range(ip: str, mask: str) -> ipaddress.IPv4Network:
    net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
    if net.prefixlen < 24:  # redes grandes: varre só o /24 deste PC
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
    return net


def arp_table() -> dict[str, str]:
    out = {}
    for ip, mac in re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})", _out(["arp", "-a"])):
        mac = mac.replace("-", ":").upper()
        if mac == "FF:FF:FF:FF:FF:FF" or mac.startswith("01:00:5E") or mac.startswith("33:33"):
            continue
        out[ip] = mac
    return out


# ---------- fabricante pelo MAC ----------
_oui: dict[str, str] | None = None


def _load_oui() -> dict[str, str]:
    global _oui
    if _oui is not None:
        return _oui
    _oui = {}
    if not OUI_FILE.exists():
        try:  # baixa uma vez a lista oficial do IEEE (~3 MB) e guarda em data/
            OUI_FILE.parent.mkdir(exist_ok=True)
            req = urllib.request.Request(OUI_URL, headers={"User-Agent": "Mozilla/5.0 SmartGuardian"})  # sem isso o IEEE responde 418
            with urllib.request.urlopen(req, timeout=60) as r:
                OUI_FILE.write_bytes(r.read())
        except OSError:
            log.warning("não foi possível baixar a lista de fabricantes", exc_info=True)
            return _oui
    try:
        with OUI_FILE.open(encoding="utf-8", errors="replace", newline="") as f:
            for row in csv.reader(f):
                if len(row) >= 3 and len(row[1]) == 6:
                    _oui[row[1].upper()] = row[2].strip()
    except OSError:
        pass
    return _oui


def random_mac(mac: str) -> bool:
    """MAC "localmente administrado": celulares e notebooks usam um aleatório por rede."""
    try:
        return bool(int(mac[1], 16) & 0x2)
    except (ValueError, IndexError):
        return False


def vendor(mac: str) -> str:
    if random_mac(mac):
        return "MAC aleatório"
    return _load_oui().get(mac.replace(":", "")[:6], "")


KINDS = [
    ("router", r"d-link|tp-link|mitrastar|intelbras|tenda|mercusys|ubiquiti|mikrotik|netgear|zyxel|arcadyan|sagemcom|askey|technicolor"),
    ("printer", r"epson|canon|brother|hewlett|\bhp\b|xerox|lexmark|kyocera|ricoh"),
    ("speaker", r"amazon|sonos|google|bose"),
    ("tv", r"lg electronics|samsung electronics|tcl|hisense|roku|philips|sony|vizio"),
    ("chip", r"espressif|tuya|shenzhen|raspberry|arduino|sonoff|itead|hui zhou|beken"),
    ("phone", r"apple|xiaomi|motorola|huawei|oneplus|oppo|realme|vivo|zte|nokia|mac aleatório"),
]


def kind_of(vendor_name: str, name: str, is_gateway: bool, is_self: bool) -> str:
    if is_gateway:
        return "router"
    if is_self:
        return "pc"
    text = f"{vendor_name} {name}".lower()
    if re.search(r"android|iphone|galaxy|redmi|moto", text):
        return "phone"
    for kind, pat in KINDS:
        if re.search(pat, text):
            return kind
    return "pc"


def hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0].split(".")[0]
    except (OSError, UnicodeError):
        return ""


def scan(progress=None) -> dict:
    """Varre a faixa do PC. Devolve {"info": {...}, "devices": [...]}"""
    gateway, my_ip = default_route()
    iface, mask, my_mac = interface_of(my_ip)
    net = scan_range(my_ip, mask)
    hosts = [str(h) for h in net.hosts()]
    rtt: dict[str, int | None] = {}
    done = 0
    with ThreadPoolExecutor(64, thread_name_prefix="ping") as pool:
        for ip, ms in zip(hosts, pool.map(ping, hosts)):
            rtt[ip] = ms
            done += 1
            if progress and done % 16 == 0:
                progress(done / len(hosts))
    arp = {ip: mac for ip, mac in arp_table().items() if ipaddress.ip_address(ip) in net}
    alive = set(arp) | {ip for ip, ms in rtt.items() if ms is not None}
    alive.add(my_ip)
    with ThreadPoolExecutor(16, thread_name_prefix="rdns") as pool:
        names = dict(zip(sorted(alive), pool.map(hostname, sorted(alive))))
    devices = []
    for ip in sorted(alive, key=lambda s: tuple(int(x) for x in s.split("."))):
        mac = my_mac if ip == my_ip else arp.get(ip, "")
        if not mac:
            continue  # respondeu ao ping mas sem MAC (outra sub-rede): ignora
        v = vendor(mac)
        devices.append({"ip": ip, "mac": mac, "name": names.get(ip, ""), "vendor": v, "rtt": 0 if ip == my_ip else rtt.get(ip),
                        "self": ip == my_ip, "gateway": ip == gateway,
                        "kind": kind_of(v, names.get(ip, ""), ip == gateway, ip == my_ip)})
    if progress:
        progress(1.0)
    return {"info": {"ip": my_ip, "gateway": gateway, "iface": iface, "range": str(net), "mac": my_mac}, "devices": devices}


def connection_info(want_public_ip: bool, previous: dict | None = None) -> dict:
    """Roda a cada minuto. DNS (abre o PowerShell) só a cada 10 min e IP público (site de fora) a cada 30 min."""
    prev = previous or {}
    now = time.time()
    gateway, my_ip = default_route()
    iface, _, _ = interface_of(my_ip)
    ssid = wifi_ssid()
    fresh_dns = now - prev.get("dns_ts", 0) > 600 or prev.get("ip") != my_ip
    fresh_pub = want_public_ip and (now - prev.get("public_ts", 0) > 1800 or prev.get("ip") != my_ip or not prev.get("public_ip"))
    return {
        "ip": my_ip, "gateway": gateway, "iface": iface, "ssid": ssid,
        "type": "Wi-Fi" if ssid else "Cabo",
        "gateway_ms": ping(gateway) if gateway else None,
        "internet_ms": ping("1.1.1.1", 1500),
        "dns": dns_servers() if fresh_dns else prev.get("dns", []),
        "dns_ts": now if fresh_dns else prev.get("dns_ts", 0),
        "public_ip": (public_ip() if fresh_pub else prev.get("public_ip", "")) if want_public_ip else "",
        "public_ts": now if fresh_pub else prev.get("public_ts", 0),
        "ts": now,
    }
