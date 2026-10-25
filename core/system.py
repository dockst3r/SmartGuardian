"""CPU, memória, disco e rede do PC, com os últimos 2 minutos de histórico."""
from __future__ import annotations

import os
import platform
import re
import socket
import threading
import time
from collections import deque

import psutil

SAMPLES = 60  # uma amostra a cada 2 s
# Interfaces que não são placa de rede física: somadas, contariam o mesmo tráfego duas vezes (túnel + placa).
VIRTUAL = re.compile(r"loopback|pseudo|vethernet|hyper-v|wsl|virtual|vmware|vbox|tunnel|teredo|isatap|"
                     r"vpn|tap-|tap\d|wireguard|wg\d|tailscale|zerotier|npcap|bluetooth", re.I)


def _net_bytes() -> dict[str, tuple[int, int]]:
    """{interface: (recebidos, enviados)} só das interfaces físicas ligadas."""
    stats = psutil.net_if_stats()
    return {name: (c.bytes_recv, c.bytes_sent) for name, c in psutil.net_io_counters(pernic=True).items()
            if not VIRTUAL.search(name) and stats.get(name) and stats[name].isup}


class System:
    def __init__(self):
        self.hist = {k: deque(maxlen=SAMPLES) for k in ("cpu", "mem", "disk", "down", "up")}
        self._lock = threading.Lock()  # sample() roda numa thread; snapshot() na da janela
        self._net = _net_bytes()
        self._t = time.monotonic()
        psutil.cpu_percent(None)  # a primeira leitura sempre volta 0
        self.cpu_name = _cpu_name()
        self.mem_total = psutil.virtual_memory().total
        self.drive = os.environ.get("SystemDrive", "C:") + "\\"

    def sample(self) -> None:
        now = time.monotonic()
        net = _net_bytes()
        dt = max(0.1, now - self._t)
        # só interfaces presentes nas duas leituras: uma placa que sumiu ou apareceu não vira taxa negativa ou pico
        both = net.keys() & self._net.keys()
        down = sum(max(0, net[n][0] - self._net[n][0]) for n in both) * 8 / dt / 1e6  # Mb/s (megabits, como o Windows)
        up = sum(max(0, net[n][1] - self._net[n][1]) for n in both) * 8 / dt / 1e6
        self._net, self._t = net, now
        cpu, mem, disk = psutil.cpu_percent(None), psutil.virtual_memory().percent, psutil.disk_usage(self.drive).percent
        with self._lock:
            self.hist["down"].append(down)
            self.hist["up"].append(up)
            self.hist["cpu"].append(cpu)
            self.hist["mem"].append(mem)
            self.hist["disk"].append(disk)

    def snapshot(self) -> dict:
        vm = psutil.virtual_memory()
        du = psutil.disk_usage(self.drive)
        return {
            "host": socket.gethostname(),
            "os": f"Windows {platform.release()} · build {platform.version().split('.')[-1]}",
            "uptime": time.time() - psutil.boot_time(),
            "cpu_name": self.cpu_name, "cores": psutil.cpu_count(),
            "mem_used": vm.used, "mem_total": vm.total,
            "disk_used": du.used, "disk_total": du.total, "drive": self.drive[:2],
            "hist": self._hist_copy(),
        }

    def _hist_copy(self) -> dict:
        with self._lock:
            return {k: [round(v, 2) for v in d] for k, d in self.hist.items()}


def _cpu_name() -> str:
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as k:
            return winreg.QueryValueEx(k, "ProcessorNameString")[0].strip()
    except OSError:
        return platform.processor()
