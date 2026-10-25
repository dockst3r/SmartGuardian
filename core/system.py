"""CPU, memória, disco e rede do PC, com os últimos 2 minutos de histórico."""
from __future__ import annotations

import os
import platform
import socket
import time
from collections import deque

import psutil

SAMPLES = 60  # uma amostra a cada 2 s


class System:
    def __init__(self):
        self.hist = {k: deque(maxlen=SAMPLES) for k in ("cpu", "mem", "disk", "down", "up")}
        self._net = psutil.net_io_counters()
        self._t = time.monotonic()
        psutil.cpu_percent(None)  # a primeira leitura sempre volta 0
        self.cpu_name = _cpu_name()
        self.mem_total = psutil.virtual_memory().total
        self.drive = os.environ.get("SystemDrive", "C:") + "\\"

    def sample(self) -> None:
        now = time.monotonic()
        net = psutil.net_io_counters()
        dt = max(0.1, now - self._t)
        self.hist["down"].append((net.bytes_recv - self._net.bytes_recv) * 8 / dt / 1e6)  # Mb/s
        self.hist["up"].append((net.bytes_sent - self._net.bytes_sent) * 8 / dt / 1e6)
        self._net, self._t = net, now
        self.hist["cpu"].append(psutil.cpu_percent(None))
        self.hist["mem"].append(psutil.virtual_memory().percent)
        self.hist["disk"].append(psutil.disk_usage(self.drive).percent)

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
            "hist": {k: [round(v, 2) for v in d] for k, d in self.hist.items()},
        }


def _cpu_name() -> str:
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as k:
            return winreg.QueryValueEx(k, "ProcessorNameString")[0].strip()
    except OSError:
        return platform.processor()
