"""Detalhes do Windows: administrador, instância única, tema, ícone e iniciar com o Windows."""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import winreg
from ctypes import wintypes
from pathlib import Path

from PIL import Image, ImageDraw

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32
shell32 = ctypes.windll.shell32
shell32.ShellExecuteW.restype = wintypes.HINSTANCE
user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
user32.FindWindowW.restype = wintypes.HWND
user32.SetForegroundWindow.argtypes = [wintypes.HWND]
user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]

ROOT = Path(__file__).resolve().parent.parent
ICON_ICO = ROOT / "ui" / "icon.ico"
TASK = "SmartGuardian"
NO_WINDOW = subprocess.CREATE_NO_WINDOW


def is_admin() -> bool:
    try:
        return bool(shell32.IsUserAnAdmin())
    except OSError:
        return False


def relaunch_as_admin() -> bool:
    """Abre de novo pedindo administrador (UAC). True se o Windows aceitou."""
    exe = Path(sys.executable).with_name("pythonw.exe")
    args = " ".join(f'"{a}"' for a in [str(ROOT / "tray.py"), *sys.argv[1:]])
    return shell32.ShellExecuteW(None, "runas", str(exe), args, str(ROOT), 1) > 32


def single_instance(name: str = "Local\\SmartGuardianTray") -> bool:
    global _mutex
    _mutex = kernel32.CreateMutexW(None, False, name)
    return kernel32.GetLastError() != 183  # ERROR_ALREADY_EXISTS


def message_box(text: str, title: str = "SmartGuardian") -> None:
    user32.MessageBoxW(None, text, title, 0x40)


def find_window(title: str) -> int | None:
    return user32.FindWindowW(None, title)


def set_app_id(app_id: str = "SmartGuardian.App") -> None:
    """Identidade própria na barra de tarefas: sem isso o Windows agrupa com outros pythonw (SmartDevices)
    e usa o ícone do Python."""
    try:
        shell32.SetCurrentProcessExplicitAppUserModelID(app_id)
    except (AttributeError, OSError):
        pass


def set_window_icon(hwnd: int) -> None:
    """Troca o ícone do Python pelo escudo na barra de título, na barra de tarefas e no Alt+Tab."""
    user32.LoadImageW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT, ctypes.c_int, ctypes.c_int, wintypes.UINT]
    user32.LoadImageW.restype = wintypes.HANDLE
    user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    IMAGE_ICON, LR_LOADFROMFILE, WM_SETICON = 1, 0x10, 0x80
    for which, metric in ((1, 11), (0, 49)):  # ICON_BIG/SM_CXICON, ICON_SMALL/SM_CXSMICON
        size = user32.GetSystemMetrics(metric)
        icon = user32.LoadImageW(None, str(ICON_ICO), IMAGE_ICON, size, size, LR_LOADFROMFILE)
        if icon:
            user32.SendMessageW(hwnd, WM_SETICON, which, icon)


def bring_to_front(hwnd: int) -> None:
    user32.ShowWindow(hwnd, 9)  # SW_RESTORE
    user32.SetForegroundWindow(hwnd)


def _personalize(name: str) -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as key:
            return bool(winreg.QueryValueEx(key, name)[0])
    except OSError:
        return True


def light_theme() -> bool:
    return _personalize("AppsUseLightTheme")


def light_taskbar() -> bool:
    return _personalize("SystemUsesLightTheme")


def accent_colors() -> dict | None:
    """Cor de destaque do Windows nas variações que o Windows 11 usa em cada tema."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Accent") as key:
            pal = winreg.QueryValueEx(key, "AccentPalette")[0]
    except OSError:
        return None
    if len(pal) < 32:
        return None
    color = lambda i: "#%02x%02x%02x" % tuple(pal[i * 4:i * 4 + 3])
    return {"light": color(4), "dark": color(1)}


def promote_tray_icon(tooltip_prefix: str) -> bool:
    """O Windows 11 esconde ícones novos na seta "^". Mostra o nosso, se o usuário ainda não escolheu."""
    changed = False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\NotifyIconSettings") as root:
            for i in range(winreg.QueryInfoKey(root)[0]):
                with winreg.OpenKey(root, winreg.EnumKey(root, i), 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
                    try:
                        tip = winreg.QueryValueEx(key, "InitialTooltip")[0]
                    except OSError:
                        continue
                    if not str(tip).startswith(tooltip_prefix):
                        continue
                    try:
                        winreg.QueryValueEx(key, "IsPromoted")
                    except FileNotFoundError:
                        winreg.SetValueEx(key, "IsPromoted", 0, winreg.REG_DWORD, 1)
                        changed = True
    except OSError:
        pass
    return changed


# ---------- iniciar com o Windows ----------
# Tarefa agendada "ao fazer logon" com privilégios mais altos: abre como administrador sem perguntar
# toda vez (o atalho da pasta Inicializar dispararia o UAC a cada login).
def startup_enabled() -> bool:
    r = subprocess.run(["schtasks", "/query", "/tn", TASK], capture_output=True, creationflags=NO_WINDOW)
    return r.returncode == 0


def set_startup(enabled: bool) -> None:
    if not enabled:
        subprocess.run(["schtasks", "/delete", "/tn", TASK, "/f"], capture_output=True, creationflags=NO_WINDOW, check=True)
        return
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    cmd = f'"{pythonw}" "{ROOT / "tray.py"}" --tray'
    r = subprocess.run(["schtasks", "/create", "/tn", TASK, "/tr", cmd, "/sc", "onlogon", "/rl", "highest", "/f",
                        "/delay", "0000:20"], capture_output=True, creationflags=NO_WINDOW)
    if r.returncode:
        raise RuntimeError(r.stderr.decode("cp850", "replace").strip() or "não foi possível criar a tarefa")


# ---------- ícone: escudo de uma cor, como os ícones do sistema ----------
STATE_COLORS = {"warn": (252, 185, 0), "bad": (232, 17, 35), "learning": (0, 120, 212)}


def make_icon(state: str = "ok", light_bar: bool | None = None, size: int = 64, stroke: tuple | None = None) -> Image.Image:
    """state: ok, warn (ponto amarelo), bad (ponto vermelho), paused (apagado)."""
    if light_bar is None:
        light_bar = light_taskbar()
    if stroke is None:
        stroke = (27, 27, 27) if light_bar else (255, 255, 255)
    k = 256 / 16
    big = Image.new("RGBA", (256, 256), (0, 0, 0, 0))
    d = ImageDraw.Draw(big)
    w = round(1.5 * k)
    shield = [(8, 1.3), (13.6, 3.3), (13.6, 7.6), (12.9, 10.3), (11.0, 12.7), (8, 14.7), (5.0, 12.7), (3.1, 10.3), (2.4, 7.6), (2.4, 3.3)]
    pts = [(x * k, y * k) for x, y in shield]
    d.line(pts + [pts[0], pts[1]], fill=stroke, width=w, joint="curve")
    check = [(5.4 * k, 8.0 * k), (7.3 * k, 9.9 * k), (10.8 * k, 6.2 * k)]
    d.line(check, fill=stroke, width=w, joint="curve")
    for x, y in (check[0], check[-1]):
        d.ellipse([x - w / 2, y - w / 2, x + w / 2, y + w / 2], fill=stroke)
    dot = STATE_COLORS.get(state)
    if dot:
        d.ellipse([9.9 * k, 9.9 * k, 16 * k, 16 * k], fill=(0, 0, 0, 0))
        d.ellipse([10.8 * k, 10.8 * k, 15.4 * k, 15.4 * k], fill=dot)
    if state == "paused":
        big.putalpha(big.getchannel("A").point(lambda a: a * 45 // 100))
    return big.resize((size, size), Image.LANCZOS)


def ensure_ico() -> None:
    if not ICON_ICO.exists():
        make_icon("ok", size=256, stroke=(0, 120, 212)).save(
            ICON_ICO, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (256, 256)])


def open_location(path: str) -> None:
    subprocess.Popen(["explorer", "/select,", path])


def open_file(path: str) -> None:
    os.startfile(path)
