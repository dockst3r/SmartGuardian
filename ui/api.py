"""Funções que o painel HTML chama via pywebview (window.pywebview.api.*).

Todo método público vira uma função no JavaScript. Erros voltam como {"error": "..."} para o
painel mostrar, em vez de exceções que o JavaScript não entende.
"""
from __future__ import annotations

import functools
import logging
import threading
import time
import uuid

from core import ai
from core.guard import Guard

from . import win

log = logging.getLogger("smartguardian.api")


def _safe(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        t = time.perf_counter()
        try:
            result = fn(*args, **kwargs)
            return {"ok": True} if result is None else result
        except Exception as e:
            log.exception("api.%s falhou", fn.__name__)
            return {"error": str(e) or type(e).__name__}
        finally:
            if fn.__name__ != "state":  # state roda a cada 2 s; o resto vai para o log (sem valores de configurações: chave do VirusTotal)
                shown = "(...)" if fn.__name__ == "save_settings" or len(repr(args[1:])) > 160 else args[1:]
                log.info("api.%s%s %.2f s", fn.__name__, shown, time.perf_counter() - t)
    return wrapper


class Api:
    def __init__(self, guard: Guard, app):
        self._g = guard
        self._app = app  # tray.App: hide(), quit()
        self._jobs: dict[str, dict] = {}
        self._folder_check = (0.0, False)  # (quando, pasta gravável por todos E inicia com o Windows)

    # ---------- leitura ----------
    @_safe
    def state(self, view="overview"):
        g = self._g
        sysinfo = g.system.snapshot()
        if time.time() - self._folder_check[0] > 60:
            self._folder_check = (time.time(), win.folder_open_to_users() and win.startup_enabled())
        out = {"summary": g.summary(), "admin": win.is_admin(), "system": sysinfo, "now": time.time(), "gpu": g.gpu.snapshot(),
               "folder_risk": self._folder_check[1],
               "interval": g.settings.get("interval", 5)}
        with g.lock:
            procs = list(g.procs)
        devices = g.devices()
        out["counts"] = {"procs": len(procs), "devices": sum(d["online"] for d in devices),
                         "new_devices": sum(1 for d in devices if d["online"] and not d["known"]),
                         "conns": len(g.conns)}
        if view == "overview":
            out["alerts"] = g.alerts(6)
            out["devices"] = [d for d in devices if d["online"]][:8]
            out["top_mem"] = sorted(procs, key=lambda p: -p["rss"])[:5]
            out["gpu_users"] = sorted([p for p in procs if p["vram"] or p["gpu"] >= 1], key=lambda p: -p["vram"])[:5]
            thr = g.settings.get("alert_threshold", 30)
            out["risky"] = sorted([p for p in procs if p["score"] >= thr or p["strong"]], key=lambda p: -p["score"])[:5]
        elif view == "lan":
            out["devices"] = devices
            out["net"] = g.netinfo
            out["lan"] = {k: v for k, v in g.lan_info.items() if k != "live"}
            out["scan"] = g.scan_progress
            out["lan_interval"] = g.settings.get("lan_interval")
        elif view == "conns":
            with g.lock:
                out["conns"], out["listens"] = list(g.conns), list(g.listens)
        elif view == "procs":
            out["procs"] = procs
            out["threshold"] = g.settings.get("alert_threshold", 30)
        elif view == "startup":
            with g.lock:
                out["startup"] = list(g.startup)
        elif view == "alerts":
            out["alerts"] = g.alerts(300)
        elif view == "settings":
            out["settings"] = g.settings.data
            out["startup_enabled"] = win.startup_enabled()
            out["start_menu_enabled"] = win.start_menu_enabled()
            out["folder_open"] = win.folder_open_to_users()
            out["root"] = str(win.ROOT)
            out["trust"] = g.db.q("select key, ts, label from trust order by ts desc")
            out["stats"] = g.db.q("select * from rule_stats order by false_pos desc, alerts desc")
            out["weights"] = g.rules["weights"]
        elif view == "ai":
            out["ai"] = g.settings.get("ai")
        return out

    @_safe
    def accent(self):
        return {"accent": win.accent_colors()}

    # ---------- ações ----------
    @_safe
    def scan_lan(self):
        self._g.request_scan()

    @_safe
    def check_now(self):
        self._g.check_processes()
        return {"procs": len(self._g.procs), "conns": len(self._g.conns)}

    @_safe
    def refresh_startup(self):
        self._g.refresh_startup()

    @_safe
    def update_device(self, mac, alias=None, known=None):
        self._g.update_device(mac, alias, known)

    @_safe
    def trust_exe(self, exe):
        self._g.trust_exe(exe)

    @_safe
    def untrust(self, key):
        self._g.untrust(key)

    @_safe
    def resolve_alert(self, alert_id, normal=False):
        self._g.resolve_alert(int(alert_id), bool(normal))

    @_safe
    def resolve_all(self):
        for a in self._g.open_alerts():
            self._g.resolve_alert(a["id"], False)

    @_safe
    def kill(self, pid, started=None):
        return {"name": self._g.kill(int(pid), float(started) if started else None)}

    @_safe
    def quarantine(self, exe):
        return {"path": self._g.quarantine(exe)}

    @_safe
    def open_location(self, path):
        win.open_location(path)

    @_safe
    def open_folder(self, which):
        from core import guard
        folder = {"reports": guard.REPORTS, "exports": guard.EXPORTS, "quarantine": guard.QUARANTINE, "root": guard.ROOT}[which]
        folder.mkdir(exist_ok=True)
        win.open_file(str(folder))

    @_safe
    def vt_lookup(self, exe):
        return self._g.vt_lookup(exe)

    @_safe
    def set_startup_item(self, key, enabled):
        self._g.set_startup_item(key, bool(enabled))

    @_safe
    def pause(self, minutes):
        self._g.pause(int(minutes))
        self._app.refresh_icon()

    @_safe
    def export_conns(self):
        return {"path": str(self._g.export_conns())}

    @_safe
    def report(self, with_ai=False):
        """Gera em segundo plano (com a IA leva até um minuto) e abre o arquivo quando ficar pronto."""
        def run():
            try:
                win.open_file(str(self._g.report(bool(with_ai))))
            except Exception:
                log.exception("relatório")
        threading.Thread(target=run, name="relatorio", daemon=True).start()

    # ---------- IA ----------
    @_safe
    def ai_status(self):
        cfg = self._g.settings.get("ai")
        try:
            ml = ai.model_list(cfg["url"])
            return {"reachable": True, "models": [m["id"] for m in ml], "model_list": ml, **cfg}
        except OSError as e:
            return {"reachable": False, "models": [], "model_list": [], "reason": str(e), **cfg}

    @_safe
    def ai_ask(self, chat_id, question, pid=None):
        """Guarda a pergunta na conversa (nova se chat_id for vazio), pergunta em segundo plano e devolve
        na hora; o painel consulta ai_result. (Uma chamada que fica 20+ s pendurada entre o JavaScript
        e o Python pode não voltar.)"""
        db, now = self._g.db, time.time()
        question = question.strip()
        if not chat_id:
            chat_id = db.x("insert into chats(ts, title) values(?, ?)", (now, question[:80]))
        db.x("update chats set ts=? where id=?", (now, chat_id))
        db.x("insert into chat_msgs(chat_id, ts, role, content) values(?,?,?,?)", (chat_id, now, "user", question))
        rows = db.q("select role, content, err from chat_msgs where chat_id=? order by id", (chat_id,))
        # tira as perguntas que deram erro (e o erro): o modelo não deve ver duas perguntas seguidas sem resposta
        history = [r for k, r in enumerate(rows) if not r["err"]
                   and not (r["role"] == "user" and k + 1 < len(rows) and rows[k + 1]["err"])]
        job = uuid.uuid4().hex
        self._jobs[job] = {"done": False, "chat_id": chat_id}

        def run():
            model, secs = None, None
            try:
                r = self._g.ask(history, int(pid) if pid else None)
                answer, err, model, secs = r["text"], 0, r["model"], r["secs"]
                log.info("IA respondeu: %s em %.1f s", model, secs)
            except Exception as e:
                log.warning("IA: %s", e)
                answer, err = str(e) or type(e).__name__, 1
            db.x("insert into chat_msgs(chat_id, ts, role, content, err, model, secs) values(?,?,?,?,?,?,?)",
                 (chat_id, time.time(), "assistant", answer, err, model, secs))
            self._jobs[job] = {"done": True, "chat_id": chat_id}
        threading.Thread(target=run, name="ia", daemon=True).start()
        return {"job": job, "chat_id": chat_id}

    def ai_result(self, job):
        r = self._jobs.get(job, {"done": True})
        if r["done"]:
            self._jobs.pop(job, None)
        return r

    @_safe
    def chat_list(self):
        return {"chats": self._g.db.q(
            "select c.id, c.ts, c.title, count(m.id) n from chats c left join chat_msgs m on m.chat_id = c.id "
            "group by c.id order by c.ts desc limit 100")}

    @_safe
    def chat_get(self, chat_id):
        chat = self._g.db.one("select id, ts, title from chats where id=?", (chat_id,))
        if not chat:
            return {"chat": None, "msgs": []}
        msgs = self._g.db.q("select role, content, err, ts, model, secs from chat_msgs where chat_id=? order by id", (chat_id,))
        pending = any(j.get("chat_id") == chat_id and not j["done"] for j in self._jobs.values())
        return {"chat": chat, "msgs": msgs, "pending": pending}

    @_safe
    def chat_delete(self, chat_id):
        self._g.db.x("delete from chat_msgs where chat_id=?", (chat_id,))
        self._g.db.x("delete from chats where id=?", (chat_id,))

    # ---------- configurações ----------
    @_safe
    def save_settings(self, changes):
        allowed = {"interval", "lan_interval", "history_days", "learning_days", "alert_threshold", "notify",
                   "close_to_tray", "public_ip", "ai", "vt_key"}
        changes = {k: v for k, v in (changes or {}).items() if k in allowed}
        if changes.get("learning_days") and not self._g.settings.get("learning_days"):
            changes["learning_started"] = time.time()  # religou o aprendizado: conta do zero
        self._g.settings.update(changes)
        if "lan_interval" in changes:
            self._g._scan_now.set()  # varre agora e segue o novo intervalo

    @_safe
    def protect_folder(self):
        if not win.is_admin():
            raise RuntimeError("Precisa do SmartGuardian aberto como administrador.")
        win.protect_folder()
        return {"open": win.folder_open_to_users()}

    @_safe
    def set_start_menu(self, enabled):
        win.set_start_menu(bool(enabled))
        return {"start_menu": win.start_menu_enabled()}

    @_safe
    def set_startup(self, enabled):
        win.set_startup(bool(enabled))
        self._folder_check = (0.0, False)  # reavalia o aviso da pasta
        self._app._startup_cached = on = win.startup_enabled()  # o menu da bandeja mostra o mesmo estado
        return {"startup": on}

    def hide(self):
        self._app.hide()

    def quit(self):
        self._app.quit()
