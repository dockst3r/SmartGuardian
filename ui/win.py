"""Detalhes do Windows: administrador, instância única, tema, ícone e iniciar com o Windows."""
from __future__ import annotations

import ctypes
import os
import re
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


# ---------- instância única e "mostrar a janela" vindo de uma segunda cópia ----------
# A cópia aberta roda como administrador; o atalho do menu Iniciar abre outra como usuário comum. Os
# objetos abaixo levam um descritor que deixa qualquer nível de integridade abrir e sinalizar, senão o
# Windows negaria o acesso de baixo para cima e a segunda cópia não conseguiria avisar a primeira.
MUTEX_NAME = "Local\\SmartGuardianTray"
SHOW_EVENT = "Local\\SmartGuardianShow"
_SDDL = "D:(A;;GA;;;WD)S:(ML;;NW;;;LW)"  # todos com acesso; rótulo de integridade baixa


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p), ("bInheritHandle", wintypes.BOOL)]


advapi32 = ctypes.windll.advapi32
advapi32.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p,
                                           ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR), ctypes.c_void_p]
kernel32.LocalFree.argtypes = [ctypes.c_void_p]
advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.CreateMutexW.restype = wintypes.HANDLE
kernel32.OpenMutexW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.OpenMutexW.restype = wintypes.HANDLE
kernel32.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.CreateEventW.restype = wintypes.HANDLE
kernel32.OpenEventW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.OpenEventW.restype = wintypes.HANDLE
kernel32.SetEvent.argtypes = [wintypes.HANDLE]
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
SYNCHRONIZE, EVENT_MODIFY_STATE, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS = 0x00100000, 0x0002, 5, 183


def _open_to_all() -> SECURITY_ATTRIBUTES | None:
    sd = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(_SDDL, 1, ctypes.byref(sd), None):
        return None
    return SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), sd, False)


def another_instance_running() -> bool:
    """Funciona antes de pedir administrador: acesso negado também quer dizer que já existe."""
    h = kernel32.OpenMutexW(SYNCHRONIZE, False, MUTEX_NAME)
    if h:
        kernel32.CloseHandle(h)
        return True
    return ctypes.GetLastError() == ERROR_ACCESS_DENIED


def single_instance() -> bool:
    global _mutex, _sa
    _sa = _open_to_all()  # mantido vivo junto com o mutex
    _mutex = kernel32.CreateMutexW(ctypes.byref(_sa) if _sa else None, False, MUTEX_NAME)
    err = ctypes.GetLastError()
    return bool(_mutex) and err != ERROR_ALREADY_EXISTS


def kill_orphan_webviews(storage: Path) -> int:
    """WebView2 que sobrou de uma cópia que caiu ou foi encerrada à força segura o perfil, e a próxima abertura
    falha com 0x800700AA (janela preta ou nada). Só chame com o single_instance() na mão: aí nenhum outro
    SmartGuardian usa esse perfil. Encerra só os msedgewebview2 com --user-data-dir dentro de `storage`."""
    import psutil
    mark = str(storage).lower()
    n = 0
    for p in psutil.process_iter(["name", "cmdline"]):
        try:
            if (p.info["name"] or "").lower() == "msedgewebview2.exe" and mark in " ".join(p.info["cmdline"] or []).lower():
                p.kill()
                n += 1
        except psutil.Error:
            continue
    return n


def signal_show() -> bool:
    """Pede para a cópia aberta mostrar a janela. False se não deu (cópia antiga, sem o evento)."""
    h = kernel32.OpenEventW(EVENT_MODIFY_STATE, False, SHOW_EVENT)
    if not h:
        return False
    ok = bool(kernel32.SetEvent(h))
    kernel32.CloseHandle(h)
    return ok


def wait_show(callback, stopped) -> None:
    """Na cópia aberta: chama callback() sempre que outra cópia pedir para mostrar a janela."""
    sa = _open_to_all()
    h = kernel32.CreateEventW(ctypes.byref(sa) if sa else None, False, False, SHOW_EVENT)  # reinicia sozinho
    if not h:
        return
    while not stopped():
        if kernel32.WaitForSingleObject(h, 1000) == 0:
            callback()


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


# ---------- permissões da pasta do programa ----------
# O app roda como administrador (e pode iniciar sozinho no login). Se usuários comuns podem alterar os
# arquivos dele, qualquer programa sem administrador ganharia administrador editando um .py.
_GROUPS = {"AU", "BU", "WD", "IU", "S-1-5-11", "S-1-5-32-545", "S-1-1-0", "S-1-5-4"}
_WRITE_LETTERS = {"FA", "FW", "GA", "GW", "WD", "WO", "SD", "CC", "DC"}
_WRITE_BITS = 0x2 | 0x4 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000  # gravar, acrescentar, apagar, DACL, dono, GA, GW


def _sddl(path: Path) -> str:
    sd, out = ctypes.c_void_p(), wintypes.LPWSTR()
    if advapi32.GetNamedSecurityInfoW(str(path), 1, 0x4 | 0x1, None, None, None, None, ctypes.byref(sd)) != 0:  # DACL + dono
        return ""
    try:
        if not advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, 0x4 | 0x1, ctypes.byref(out), None):
            return ""
        return out.value
    finally:
        kernel32.LocalFree(sd)
        if out:
            kernel32.LocalFree(out)


def folder_open_to_users(path: Path = ROOT) -> bool:
    """True se usuários comuns (ou o dono sem administrador) podem alterar os arquivos da pasta."""
    sddl = _sddl(path)
    if not sddl:
        return False
    owner = re.search(r"O:([^:]+?)(?:G:|D:)", sddl)
    # dono seguro: Administradores, SYSTEM ou serviço do Windows (TrustedInstaller e cia., S-1-5-80-*)
    if owner and owner.group(1) not in ("BA", "SY", "S-1-5-32-544", "S-1-5-18") and not owner.group(1).startswith("S-1-5-80-"):
        return True  # o dono pode mudar as permissões, com ou sem administrador
    for rights, sid in re.findall(r"\(A;[^;]*;([^;]*);[^;]*;[^;]*;([^)]*)\)", sddl):
        if sid not in _GROUPS:
            continue
        if rights.lower().startswith("0x"):
            if int(rights, 16) & _WRITE_BITS:
                return True
        elif {rights[i:i + 2] for i in range(0, len(rights), 2)} & _WRITE_LETTERS:
            return True
    return False


def protect_folder(path: Path = ROOT) -> None:
    """Só Administradores e SYSTEM gravam; usuários leem e executam. Dono: Administradores.
    Depois disso, atualizar (git pull, Instalar.bat) precisa de administrador.
    As permissões ficam só na pasta raiz e o resto herda. Não use /inheritance:r com /T: em arquivo, (OI)(CI)
    não vale, o grant não entra e o arquivo fica sem nenhuma permissão (nem administrador abre)."""
    for target, args in ((path, ["/setowner", "*S-1-5-32-544", "/T", "/C", "/Q"]),
                         (path, ["/inheritance:r", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F",
                                 "*S-1-5-32-545:(OI)(CI)RX", "/Q"]),
                         (path / "*", ["/reset", "/T", "/C", "/Q"])):
        r = subprocess.run(["icacls", str(target), *args], capture_output=True, creationflags=NO_WINDOW, timeout=300)
        if r.returncode:
            raise RuntimeError((r.stdout + r.stderr).decode("cp850", "replace").strip()[-300:] or "icacls falhou")
    if "(A;" not in _sddl(path / "tray.py"):
        raise RuntimeError("os arquivos ficaram sem permissão; rode no terminal como administrador: "
                           f'icacls "{path}\\*" /reset /T /C')


# ---------- atalho no menu Iniciar ----------
# Aponta para o pythonw do ambiente com o tray.py; aberto sem administrador, o próprio app pede (UAC).
START_MENU_LNK = Path(os.environ["APPDATA"]) / r"Microsoft\Windows\Start Menu\Programs\SmartGuardian.lnk"


def start_menu_enabled() -> bool:
    return START_MENU_LNK.exists()


def set_start_menu(enabled: bool) -> None:
    if not enabled:
        START_MENU_LNK.unlink(missing_ok=True)
        return
    ensure_ico()
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    ps = ("$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:LNK);"
          "$s.TargetPath=$env:TARGET;$s.Arguments=$env:ARGS;$s.WorkingDirectory=$env:WD;"
          "$s.IconLocation=$env:ICON;$s.Description='SmartGuardian: guardião do PC';$s.Save()")
    env = dict(os.environ, LNK=str(START_MENU_LNK), TARGET=str(pythonw), ARGS=f'"{ROOT / "tray.py"}"',
               WD=str(ROOT), ICON=str(ICON_ICO))
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], env=env,
                       capture_output=True, creationflags=NO_WINDOW, timeout=30)
    if r.returncode or not START_MENU_LNK.exists():
        raise RuntimeError(r.stderr.decode("cp850", "replace").strip() or "não foi possível criar o atalho")


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
