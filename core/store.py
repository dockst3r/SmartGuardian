"""Persistência: preferências (settings.json) e histórico (smartguardian.db, SQLite)."""
from __future__ import annotations

import copy
import json
import sqlite3
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SETTINGS = ROOT / "settings.json"
DB = ROOT / "smartguardian.db"

DEFAULTS = {
    "interval": 5,               # processos e conexões, em segundos
    "lan_interval": 300,         # varredura da rede; 0 = só manualmente
    "history_days": 30,
    "learning_days": 7,
    "learning_started": 0,       # preenchido na primeira execução
    "alert_threshold": 30,
    "notify": {"new_device": True, "process": True, "startup": True, "defender": True, "high_cpu": False,
               "gpu_temp": True, "vram": False},
    "close_to_tray": True,
    "public_ip": False,          # consulta api.ipify.org; desligado para nada sair do PC sem você pedir
    "ai": {"enabled": False, "url": "http://localhost:1234/v1", "model": "", "auto": False},
    "vt_key": "",
    "tray_promoted": False,
}


def _read(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def write_json(path: Path, data) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)  # troca atômica: um travamento no meio não corrompe o arquivo


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in over.items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


class Settings:
    def __init__(self):
        self._lock = threading.Lock()
        self.data = _merge(DEFAULTS, _read(SETTINGS, {}))
        if not self.data["learning_started"]:
            self.data["learning_started"] = time.time()
            self.save()

    def get(self, key, default=None):
        return self.data.get(key, default)

    def update(self, changes: dict) -> None:
        with self._lock:
            self.data = _merge(self.data, changes)
            self.save()

    def save(self) -> None:
        write_json(SETTINGS, self.data)

    def learning_left(self) -> float:
        """Dias que faltam no período de aprendizado (0 = terminou ou desligado)."""
        days = self.data["learning_days"]
        if not days:
            return 0.0
        return max(0.0, days - (time.time() - self.data["learning_started"]) / 86400)


SCHEMA = """
create table if not exists alerts(id integer primary key, ts real, sev text, kind text, key text, title text,
    detail text, target text, data text, status text default 'open');
create index if not exists alerts_key on alerts(key);
create table if not exists seen_exe(path text primary key, first_seen real, last_seen real, kind text, signer text);
create table if not exists devices(mac text primary key, ip text, name text, vendor text, alias text default '',
    first_seen real, last_seen real, known integer default 0);
create table if not exists startup_seen(key text primary key, first_seen real);
create table if not exists startup_disabled(key text primary key, data text);
create table if not exists trust(key text primary key, ts real, label text);
create table if not exists rule_stats(rule text primary key, alerts integer default 0, false_pos integer default 0);
create table if not exists defender_seen(id text primary key);
create table if not exists meta(k text primary key, v text);
create table if not exists chats(id integer primary key, ts real, title text);
create table if not exists chat_msgs(id integer primary key, chat_id integer, ts real, role text, content text, err integer default 0);
create index if not exists chat_msgs_chat on chat_msgs(chat_id);
"""


class Db:
    def __init__(self, path: Path = DB):
        self._lock = threading.RLock()
        self.con = sqlite3.connect(path, check_same_thread=False)
        self.con.row_factory = sqlite3.Row
        self.con.executescript(SCHEMA)
        for col in ("model text", "secs real"):  # colunas acrescentadas depois; bancos antigos ganham aqui
            try:
                self.con.execute(f"alter table chat_msgs add column {col}")
            except sqlite3.OperationalError:
                pass

    def q(self, sql: str, args=()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self.con.execute(sql, args).fetchall()]

    def one(self, sql: str, args=()):
        rows = self.q(sql, args)
        return rows[0] if rows else None

    def x(self, sql: str, args=()) -> int:
        with self._lock:
            cur = self.con.execute(sql, args)
            self.con.commit()
            return cur.lastrowid

    def many(self, sql: str, rows) -> None:
        with self._lock:
            self.con.executemany(sql, rows)
            self.con.commit()

    def meta(self, k: str, default=None):
        r = self.one("select v from meta where k=?", (k,))
        return json.loads(r["v"]) if r else default

    def set_meta(self, k: str, v) -> None:
        self.x("insert or replace into meta(k, v) values(?, ?)", (k, json.dumps(v)))
