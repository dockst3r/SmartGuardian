"""SmartGuardian na bandeja do Windows.

    pythonw tray.py          abre a janela ao iniciar
    pythonw tray.py --tray   começa só com o ícone (usado ao iniciar com o Windows)

Pede administrador ao abrir: sem isso o Windows esconde processos do sistema e não deixa
encerrar processos nem mexer na inicialização. Fechar ou minimizar a janela só a esconde;
o monitoramento continua até "Sair".
"""
from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

if sys.stderr is None:  # pythonw não tem console
    sys.stdout = sys.stderr = open(os.devnull, "w", encoding="utf-8")
logging.basicConfig(
    level=logging.DEBUG if os.environ.get("SG_DEBUG") else logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[RotatingFileHandler(ROOT / "smartguardian.log", maxBytes=1_000_000, backupCount=2, encoding="utf-8")],
)
log = logging.getLogger("smartguardian")

import pystray  # noqa: E402
import webview  # noqa: E402

from core.guard import Guard  # noqa: E402
from ui import win  # noqa: E402
from ui.api import Api  # noqa: E402

TITLE = "SmartGuardian"


class App:
    def __init__(self, start_hidden: bool):
        self.guard = Guard()
        self.api = Api(self.guard, self)
        self.visible = False
        self._start_hidden = start_hidden
        self._quitting = False
        self._hwnd = None
        self._icon_key = None

        win.ensure_ico()
        self.window = webview.create_window(
            TITLE, str(ROOT / "ui" / "index.html"), js_api=self.api, width=1180, height=780, min_size=(760, 560),
            hidden=True, background_color="#f3f3f3" if win.light_theme() else "#202020",
        )
        self.window.events.closing += self._on_closing
        self.window.events.minimized += self._on_minimized
        self.guard.listeners.append(self._notify)
        self.guard.on_change.append(self.refresh_icon)
        self.icon = pystray.Icon("SmartGuardian", win.make_icon("ok"), TITLE, menu=self._menu())

    # ---------- bandeja ----------
    def _menu(self) -> pystray.Menu:
        item = pystray.MenuItem
        return pystray.Menu(
            item("Abrir SmartGuardian", lambda: self.show(), default=True),
            item("Verificar agora", lambda: threading.Thread(target=self.guard.check_processes, daemon=True).start()),
            item("Escanear a rede", lambda: self.guard.request_scan()),
            pystray.Menu.SEPARATOR,
            item("Pausar alertas por 1 hora", lambda: self._toggle_pause(), checked=lambda _: self.guard.paused_until > time.time()),
            item("Iniciar com o Windows", lambda: self._toggle_startup(), checked=lambda _: self._startup_cached),
            pystray.Menu.SEPARATOR,
            item("Sair", lambda: self.quit()),
        )

    _startup_cached = False

    def _toggle_pause(self) -> None:
        self.guard.pause(0 if self.guard.paused_until > time.time() else 60)
        self.refresh_icon()

    def _toggle_startup(self) -> None:
        try:
            win.set_startup(not self._startup_cached)
            self._startup_cached = win.startup_enabled()
        except Exception as e:
            log.exception("startup")
            self.icon.notify(str(e), "Não foi possível alterar a inicialização")

    def _notify(self, title: str, text: str, sev: str) -> None:
        self.icon.notify(text, title)

    def refresh_icon(self) -> None:
        s = self.guard.summary()
        state = "paused" if s["paused_until"] else (s["worst"] or "ok")
        key = (state, win.light_taskbar())
        if key != self._icon_key:
            self._icon_key = key
            self.icon.icon = win.make_icon(*key)
        c = len(self.guard.lan_info.get("live", {}))
        parts = [f"{s['open']} aviso{'s' if s['open'] != 1 else ''}" if s["open"] else "tudo certo"]
        if c:
            parts.append(f"{c} na rede")
        if s["learning_left"]:
            parts.append(f"aprendendo ({s['learning_left']:.0f} d)")
        self.icon.title = f"{TITLE} · " + " · ".join(parts)

    # ---------- janela ----------
    def _started(self) -> None:
        for _ in range(50):
            self._hwnd = win.find_window(TITLE)
            if self._hwnd:
                break
            time.sleep(0.1)
        if self._hwnd:
            win.set_window_icon(self._hwnd)
        self._startup_cached = win.startup_enabled()
        self.guard.start()
        threading.Thread(target=self._promote_icon, daemon=True).start()
        threading.Thread(target=self._theme_watch, daemon=True).start()
        threading.Thread(target=win.wait_show, args=(self.show, lambda: self._quitting), name="mostrar", daemon=True).start()
        if not self._start_hidden:
            time.sleep(0.3)
            self.show(os.environ.get("SG_OPEN_VIEW"))

    def _promote_icon(self) -> None:
        if self.guard.settings.get("tray_promoted"):
            return
        for _ in range(20):
            time.sleep(1)
            if win.promote_tray_icon(TITLE):
                break
        self.guard.settings.update({"tray_promoted": True})

    def _theme_watch(self) -> None:
        while not self._quitting:
            time.sleep(3)
            self.refresh_icon()

    def show(self, view: str | None = None) -> None:
        self.window.show()
        self.window.restore()
        if self._hwnd:
            win.bring_to_front(self._hwnd)
        self.visible = True
        self._js(f"window.app && app.onShow({json.dumps(view)})")

    def hide(self) -> None:
        self.visible = False
        self.window.hide()
        self._js("window.app && app.onHide()")

    def _on_minimized(self) -> None:
        if self.guard.settings.get("close_to_tray", True):
            threading.Thread(target=self.hide, daemon=True).start()

    def _on_closing(self):
        if self._quitting or not self.guard.settings.get("close_to_tray", True):
            if not self._quitting:
                threading.Thread(target=self.quit, daemon=True).start()
                return False
            return True
        if not self.guard.settings.get("tray_hint_shown"):
            self.guard.settings.update({"tray_hint_shown": True})
            self.icon.notify("Para encerrar de vez, clique com o botão direito no ícone e escolha Sair.",
                             "O SmartGuardian continua na bandeja")
        threading.Thread(target=self.hide, daemon=True).start()
        return False

    def _js(self, code: str) -> None:
        def run():
            try:
                self.window.evaluate_js(code)
            except Exception:
                log.debug("evaluate_js falhou", exc_info=True)
        threading.Thread(target=run, daemon=True).start()

    # ---------- ciclo de vida ----------
    def run(self) -> None:
        self.icon.run_detached()
        self.refresh_icon()
        webview.start(self._started, private_mode=False, storage_path=str(ROOT / "data" / "webview"))

    def quit(self) -> None:
        if self._quitting:
            return
        self._quitting = True
        log.info("encerrando")
        self.guard.stop()
        self.icon.stop()
        self.window.destroy()


def _already_open() -> None:
    """Outra cópia já roda (atalho clicado com o app na bandeja): traz a janela dela para a frente."""
    if "--tray" in sys.argv:
        return  # início automático com o Windows: nada a mostrar
    if not win.signal_show():  # cópia de uma versão antiga, sem o evento
        win.message_box("O SmartGuardian já está aberto. Procure o ícone do escudo perto do relógio.")


def main() -> None:
    # antes de pedir administrador: se já está aberto, só mostra a janela (sem UAC à toa)
    if win.another_instance_running():
        _already_open()
        return
    if not win.is_admin() and "--sem-admin" not in sys.argv:
        if win.relaunch_as_admin():
            return
        # recusou o UAC: segue com o que der para ver
        log.warning("rodando sem administrador")
    if not win.single_instance():
        _already_open()
        return
    log.info("iniciando (admin=%s)", win.is_admin())
    win.set_app_id()
    try:
        App(start_hidden="--tray" in sys.argv).run()
    except Exception:
        log.exception("erro fatal")
        win.message_box(f"O SmartGuardian encontrou um erro. Detalhes em:\n{ROOT / 'smartguardian.log'}")
    os._exit(0)


if __name__ == "__main__":
    main()
