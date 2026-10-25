"""Conexões de rede por processo e portas abertas neste PC."""
from __future__ import annotations

import ipaddress
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import psutil

STATES = {"ESTABLISHED": "Estabelecida", "LISTEN": "Escutando", "TIME_WAIT": "Encerrando", "CLOSE_WAIT": "Encerrando",
          "SYN_SENT": "Conectando", "SYN_RECV": "Conectando", "FIN_WAIT1": "Encerrando", "FIN_WAIT2": "Encerrando",
          "LAST_ACK": "Encerrando", "CLOSING": "Encerrando", "NONE": "UDP"}


@dataclass
class Conn:
    pid: int
    proto: str
    laddr: str
    lport: int
    raddr: str
    rport: int
    state: str
    scope: str   # internet, local, pc


def scope(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return "internet"
    if a.is_loopback:
        return "pc"
    if a.is_private or a.is_link_local or a.is_multicast:
        return "local"
    return "internet"


def snapshot() -> tuple[list[Conn], list[Conn]]:
    """(conexões com outro endereço, portas TCP escutando)."""
    out, listen = [], []
    try:
        items = psutil.net_connections("inet")
    except psutil.AccessDenied:
        return out, listen
    for c in items:
        proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
        la, lp = (c.laddr.ip, c.laddr.port) if c.laddr else ("", 0)
        if c.raddr:
            out.append(Conn(c.pid or 0, proto, la, lp, c.raddr.ip, c.raddr.port, STATES.get(c.status, c.status), scope(c.raddr.ip)))
        elif c.status == "LISTEN" or (proto == "UDP" and 0 < lp < 49152):
            # UDP não tem "escutando": socket sem destino numa porta fixa é porta aberta. Portas 49152+ são as
            # temporárias que o Windows sorteia para conexões de saída (QUIC, DNS…), não serviço aberto.
            listen.append(Conn(c.pid or 0, proto, la, lp, "", 0, "Escutando" if proto == "TCP" else "Aberta (UDP)",
                               "pc" if scope(la) == "pc" else "local"))
    return out, listen


class Resolver:
    """Nome DNS reverso dos IPs, em segundo plano (pode levar segundos) e guardado."""

    def __init__(self):
        self.names: dict[str, str] = {}
        self._pending: set[str] = set()
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(6, thread_name_prefix="dns")

    def get(self, ip: str) -> str | None:
        with self._lock:
            if ip in self.names:
                return self.names[ip]
            if ip not in self._pending:
                self._pending.add(ip)
                self._pool.submit(self._resolve, ip)
        return None

    def _resolve(self, ip: str) -> None:
        try:
            name = socket.gethostbyaddr(ip)[0]
        except (OSError, UnicodeError):
            name = ""
        with self._lock:
            self.names[ip] = name
            self._pending.discard(ip)
