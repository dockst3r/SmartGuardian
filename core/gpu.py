"""GPU: uso, VRAM, temperatura e potência (biblioteca da NVIDIA, NVML) e uso por programa
(contadores do próprio Windows, valem para qualquer fabricante).

Sem placa NVIDIA, `Gpu.available` fica False e só o uso por programa funciona.
Hotspot e temperatura da memória não existem na API oficial para placas GeForce.
"""
from __future__ import annotations

import ctypes
import logging
import re
import threading
from collections import defaultdict, deque
from ctypes import wintypes

log = logging.getLogger("smartguardian.gpu")
SAMPLES = 60  # uma amostra a cada 2 s

try:
    import pynvml as N
except ImportError:  # nvidia-ml-py não instalado
    N = None


class Gpu:
    def __init__(self):
        self.available = False
        self.name = self.driver = ""
        self.mem_total = 0
        self.slowdown = self.shutdown = 0
        self.hist = {k: deque(maxlen=SAMPLES) for k in ("util", "vram", "temp", "power")}
        self.now: dict = {}
        self._h = None
        self._lock = threading.Lock()  # sample() roda numa thread; snapshot() na da janela
        if N is None:
            return
        try:
            N.nvmlInit()
            if N.nvmlDeviceGetCount() < 1:
                return
            self._h = N.nvmlDeviceGetHandleByIndex(0)
            self.name = N.nvmlDeviceGetName(self._h)
            self.driver = N.nvmlSystemGetDriverVersion()
            self.mem_total = N.nvmlDeviceGetMemoryInfo(self._h).total
            self.slowdown = self._try(N.nvmlDeviceGetTemperatureThreshold, self._h, N.NVML_TEMPERATURE_THRESHOLD_SLOWDOWN)
            self.shutdown = self._try(N.nvmlDeviceGetTemperatureThreshold, self._h, N.NVML_TEMPERATURE_THRESHOLD_SHUTDOWN)
            self.available = True
        except Exception:
            log.info("sem GPU NVIDIA para monitorar", exc_info=True)

    @staticmethod
    def _try(fn, *args):
        try:
            return fn(*args)
        except Exception:  # cada placa/driver expõe um subconjunto
            return None

    def sample(self) -> None:
        if not self.available:
            return
        h = self._h
        util = self._try(N.nvmlDeviceGetUtilizationRates, h)
        mem = self._try(N.nvmlDeviceGetMemoryInfo, h)
        power = self._try(N.nvmlDeviceGetPowerUsage, h)
        self.now = {
            "util": util.gpu if util else None,
            "vram_used": mem.used if mem else None,
            "temp": self._try(N.nvmlDeviceGetTemperature, h, N.NVML_TEMPERATURE_GPU),
            "margin": self._try(N.nvmlDeviceGetMarginTemperature, h),  # graus até o limite térmico
            "power": power / 1000 if power is not None else None,
            "power_limit": (self._try(N.nvmlDeviceGetEnforcedPowerLimit, h) or 0) / 1000 or None,
            "fan": self._try(N.nvmlDeviceGetFanSpeed, h),
            "clock": self._try(N.nvmlDeviceGetClockInfo, h, N.NVML_CLOCK_GRAPHICS),
        }
        with self._lock:
            self.hist["util"].append(self.now["util"] or 0)
            self.hist["vram"].append(100 * (self.now["vram_used"] or 0) / self.mem_total if self.mem_total else 0)
            self.hist["temp"].append(self.now["temp"] or 0)
            self.hist["power"].append(self.now["power"] or 0)

    def snapshot(self) -> dict:
        with self._lock:
            hist = {k: [round(v, 1) for v in d] for k, d in self.hist.items()}
        return {"available": self.available, "name": self.name, "driver": self.driver, "mem_total": self.mem_total,
                "slowdown": self.slowdown, "shutdown": self.shutdown, **self.now, "hist": hist}


# ---------- uso de GPU por programa: contadores de desempenho do Windows (PDH) ----------
pdh = ctypes.WinDLL("pdh")
PDH_FMT_DOUBLE, PDH_FMT_LARGE, PDH_FMT_NOCAP100 = 0x200, 0x400, 0x8000
PDH_MORE_DATA = 0x800007D2


class _VALUE(ctypes.Structure):
    class _U(ctypes.Union):
        _fields_ = [("longValue", ctypes.c_long), ("doubleValue", ctypes.c_double), ("largeValue", ctypes.c_longlong)]
    _anonymous_ = ("u",)
    _fields_ = [("CStatus", wintypes.DWORD), ("u", _U)]


class _ITEM(ctypes.Structure):
    _fields_ = [("szName", wintypes.LPWSTR), ("FmtValue", _VALUE)]


pdh.PdhOpenQueryW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p, ctypes.POINTER(wintypes.HANDLE)]
pdh.PdhAddEnglishCounterW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, ctypes.c_void_p, ctypes.POINTER(wintypes.HANDLE)]
pdh.PdhCollectQueryData.argtypes = [wintypes.HANDLE]
pdh.PdhGetFormattedCounterArrayW.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                             ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
for _f in (pdh.PdhOpenQueryW, pdh.PdhAddEnglishCounterW, pdh.PdhCollectQueryData, pdh.PdhGetFormattedCounterArrayW):
    _f.restype = wintypes.DWORD

INSTANCE = re.compile(r"pid_(\d+)_.*engtype_(\w+)", re.I)
PID = re.compile(r"pid_(\d+)", re.I)


class GpuProcesses:
    """Uso de GPU (%) e VRAM dedicada por PID, como no Gerenciador de Tarefas.

    O uso de cada programa é o do motor mais ocupado (3D, Compute, Vídeo…), somando as filas de cada motor.
    A primeira leitura sempre volta vazia: o contador de uso precisa de duas coletas."""

    def __init__(self):
        self._lock = threading.Lock()
        self._q = wintypes.HANDLE()
        self._util = wintypes.HANDLE()
        self._mem = wintypes.HANDLE()
        self.ok = (pdh.PdhOpenQueryW(None, None, ctypes.byref(self._q)) == 0
                   and pdh.PdhAddEnglishCounterW(self._q, r"\GPU Engine(*)\Utilization Percentage", None, ctypes.byref(self._util)) == 0
                   and pdh.PdhAddEnglishCounterW(self._q, r"\GPU Process Memory(*)\Dedicated Usage", None, ctypes.byref(self._mem)) == 0)
        if self.ok:
            pdh.PdhCollectQueryData(self._q)

    def _array(self, counter, fmt) -> list[tuple[str, float]]:
        size, count = wintypes.DWORD(0), wintypes.DWORD(0)
        r = pdh.PdhGetFormattedCounterArrayW(counter, fmt, ctypes.byref(size), ctypes.byref(count), None)
        if r != PDH_MORE_DATA or not size.value:
            return []
        buf = ctypes.create_string_buffer(size.value)
        if pdh.PdhGetFormattedCounterArrayW(counter, fmt, ctypes.byref(size), ctypes.byref(count), buf) != 0:
            return []
        items = ctypes.cast(buf, ctypes.POINTER(_ITEM))
        out = []
        for i in range(count.value):
            it = items[i]
            if it.FmtValue.CStatus in (0, 1):  # PDH_CSTATUS_VALID_DATA / NEW_DATA
                v = it.FmtValue.doubleValue if fmt & PDH_FMT_DOUBLE else it.FmtValue.largeValue
                out.append((it.szName, v))
        return out

    def sample(self) -> dict[int, dict]:
        """{pid: {"gpu": %, "vram": bytes}}, só programas usando a GPU ou com VRAM alocada."""
        if not self.ok:
            return {}
        with self._lock:
            if pdh.PdhCollectQueryData(self._q) != 0:
                return {}
            engines: dict[tuple[int, str], float] = defaultdict(float)
            for name, v in self._array(self._util, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100):
                m = INSTANCE.search(name)
                if m and v > 0:
                    engines[(int(m.group(1)), m.group(2))] += v
            mem = {}
            for name, v in self._array(self._mem, PDH_FMT_LARGE):
                m = PID.search(name)
                if m and v > 0:
                    pid = int(m.group(1))
                    mem[pid] = mem.get(pid, 0) + v
        out: dict[int, dict] = {}
        for (pid, _), v in engines.items():
            d = out.setdefault(pid, {"gpu": 0.0, "vram": 0})
            d["gpu"] = round(min(100.0, max(d["gpu"], v)), 1)
        for pid, v in mem.items():
            out.setdefault(pid, {"gpu": 0.0, "vram": 0})["vram"] = int(v)
        return out
