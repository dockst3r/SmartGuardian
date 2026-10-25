"""O núcleo: agenda os coletores, guarda o estado atual, pontua e dispara os alertas.

Laços em threads separadas, cada um no seu ritmo:
  sistema   2 s       CPU, memória, disco, rede
  processos 5 s       processos, conexões, pontuação, alertas (ajustável)
  rede      5 min     varredura da rede local (ajustável; 0 = só manual)
  conexão   1 min     Wi-Fi, gateway, DNS, latência
  lento     10 min    inicialização, Windows Defender, limpeza do histórico
"""
from __future__ import annotations

import csv
import hashlib
import html
import json
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

import psutil

from . import ai, conns as C, firewall, lan, procs as P, rules as R, startup, vt
from .gpu import Gpu, GpuProcesses
from .system import System

# Processos sem os quais o Windows cai (tela azul) ou trava a sessão.
CRITICAL = {"csrss.exe", "wininit.exe", "winlogon.exe", "smss.exe", "services.exe", "lsass.exe", "lsaiso.exe",
            "svchost.exe", "dwm.exe", "fontdrvhost.exe", "registry", "memcompression", "system", "secure system"}
SEV_RANK = {"ok": 0, "info": 1, "warn": 2, "bad": 3}
HASH_TTL = 600  # s: o hash de um arquivo é recalculado depois disso, mesmo com tamanho e data iguais


def _ancestors() -> list:
    try:
        return psutil.Process().parents()
    except psutil.Error:
        return []


def _own_executables() -> set[str]:
    """Executáveis que rodam o SmartGuardian: o pythonw do venv (lançador), o Python base e os processos pai."""
    paths = {sys.executable, getattr(sys, "_base_executable", ""), str(Path(sys.executable).with_name("pythonw.exe"))}
    for p in [psutil.Process(), *_ancestors()]:
        try:
            paths.add(p.exe())
        except psutil.Error:
            pass
    return {os.path.normcase(x) for x in paths if x}
from .store import ROOT, Db, Settings, write_json

log = logging.getLogger("smartguardian.guard")
QUARANTINE = ROOT / "quarentena"
REPORTS = ROOT / "relatorios"
EXPORTS = ROOT / "exports"
NO_WINDOW = subprocess.CREATE_NO_WINDOW


class Guard:
    def __init__(self):
        self.settings = Settings()
        self.db = Db()
        self.rules = R.load()
        self.system = System()
        self.gpu = Gpu()
        self.gpu_procs = GpuProcesses()
        self._gpu_hist: dict[int, deque] = {}   # PID → últimas leituras de uso de GPU (para "uso sustentado")
        self._check_lock = threading.Lock()   # "Verificar agora" e o laço de 5 s não rodam ao mesmo tempo
        self._alert_lock = threading.Lock()   # consulta + insert do alerta sem duplicar
        self.resolver = C.Resolver()
        self.firewall = firewall.Firewall()
        self.lock = threading.RLock()
        self.listeners: list = []          # fn(title, text, sev): notificações
        self.on_change: list = []          # fn(): algo mudou (ícone, painel)
        self.procs: list[dict] = []
        self.conns: list[dict] = []
        self.listens: list[dict] = []
        self.startup: list[dict] = []
        self.netinfo: dict = {}
        self.lan_info: dict = {}
        self.scan_progress: float | None = None
        self.last_check = 0.0
        self.paused_until = 0.0
        self._stop = threading.Event()
        self._scan_now = threading.Event()
        self._slow_now = threading.Event()
        self._pobj: dict[int, psutil.Process] = {}
        self._hot: dict[int, int] = defaultdict(int)
        self._hashes: dict[tuple, str] = {}
        self._first_seen = {r["path"]: r["first_seen"] for r in self.db.q("select path, first_seen from seen_exe")}
        self._trust = {r["key"] for r in self.db.q("select key from trust")}

    # ---------- ciclo de vida ----------
    def start(self) -> None:
        for name, fn in (("sistema", self._system_loop), ("processos", self._proc_loop), ("rede", self._lan_loop),
                         ("conexao", self._netinfo_loop), ("lento", self._slow_loop)):
            threading.Thread(target=self._guarded(fn), name=name, daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        self._scan_now.set()
        self._slow_now.set()

    def _guarded(self, fn):
        def run():
            while not self._stop.is_set():
                try:
                    fn()
                    return
                except Exception:
                    log.exception("laço %s caiu; reiniciando em 10 s", threading.current_thread().name)
                    self._stop.wait(10)
        return run

    def _changed(self) -> None:
        for fn in list(self.on_change):
            try:
                fn()
            except Exception:
                log.debug("on_change falhou", exc_info=True)

    # ---------- laços ----------
    def _system_loop(self) -> None:
        while not self._stop.is_set():
            self.system.sample()
            self.gpu.sample()
            self.check_gpu()
            self._stop.wait(2)

    def check_gpu(self) -> None:
        """Avisa de GPU perto do limite térmico (onde ela começa a perder desempenho) e de VRAM cheia."""
        g = self.gpu
        if not g.available or not g.now:
            return
        day = datetime.now().strftime("%Y-%m-%d")
        temp, margin = g.now.get("temp"), g.now.get("margin")
        hot = (margin is not None and margin <= 5) or (temp and g.slowdown and temp >= g.slowdown - 3)
        if hot and len(g.hist["temp"]) >= 3 and min(list(g.hist["temp"])[-3:]) >= (temp - 2):  # não é pico de 1 leitura
            self.alert("gpu", f"gpu:temp:{day}", "warn", f"GPU a {temp} °C, perto do limite",
                       f"{g.name} · reduz o desempenho a {g.slowdown} °C e desliga a {g.shutdown} °C · "
                       f"{margin} °C de folga · confira ventilação e poeira", {"view": "overview"}, category="gpu_temp")
        vram = list(g.hist["vram"])[-15:]  # ~30 s
        if len(vram) >= 15 and min(vram) >= 97:
            self.alert("gpu", f"gpu:vram:{day}", "warn", "VRAM da GPU quase cheia há 30 s",
                       f"{g.name} · {vram[-1]:.0f} % de {g.mem_total / 2**30:.0f} GB · programas e modelos de IA podem ficar lentos",
                       {"view": "procs"}, category="vram")

    def _proc_loop(self) -> None:
        while not self._stop.is_set():
            t = time.monotonic()
            self.check_processes()
            self._stop.wait(max(1.0, self.settings.get("interval", 5) - (time.monotonic() - t)))

    def _lan_loop(self) -> None:
        self._stop.wait(3)
        while not self._stop.is_set():
            try:
                self.scan_lan()
            except Exception:
                log.exception("varredura da rede falhou")
                self.scan_progress = None
                with self.lock:  # sem rede: nada de aparelhos "online" com dados velhos
                    self.lan_info = {k: v for k, v in self.lan_info.items() if k != "live"} | {"live": {}}
            interval = self.settings.get("lan_interval", 300)
            self._scan_now.wait(interval if interval > 0 else None)
            self._scan_now.clear()

    def _netinfo_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.netinfo = lan.connection_info(self.settings.get("public_ip", False), self.netinfo)
            except Exception:
                log.warning("sem conexão de rede", exc_info=True)
                self.netinfo = {"ip": "", "gateway": "", "iface": "", "ssid": "", "type": "Sem conexão", "gateway_ms": None,
                                "internet_ms": None, "dns": [], "public_ip": "", "ts": time.time()}
            self._stop.wait(60)

    def _slow_loop(self) -> None:
        self._stop.wait(5)
        while not self._stop.is_set():
            for step in (self.check_startup, self.check_defender, self.cleanup):
                try:
                    step()
                except Exception:
                    log.exception("%s falhou", step.__name__)
            self._slow_now.wait(600)
            self._slow_now.clear()

    # ---------- processos ----------
    def _sha(self, path: str) -> str:
        try:
            st = os.stat(path)
        except OSError:
            return ""
        key = (path, st.st_size, st.st_mtime_ns)
        cached = self._hashes.get(key)
        if cached is None or time.time() - cached[1] > HASH_TTL:
            try:
                cached = self._hashes[key] = (P.sha256(path), time.time())
            except OSError:
                return ""
        return cached[0]

    def trust_key(self, exe: str, sig) -> str:
        """Programa assinado: confia pela editora (continua confiável quando atualiza).
        Sem assinatura: confia por este conteúdo exato (hash); se o arquivo mudar, perde a confiança."""
        base = os.path.normcase(exe)
        return f"exe:{base}|{sig.signer}" if sig and sig.trusted else f"exe:{base}|{self._sha(exe)}"

    def check_processes(self) -> None:
        with self._check_lock:
            self._check_processes()

    def _check_processes(self) -> None:
        procs = P.snapshot()
        conns, listens = C.snapshot()
        self.firewall.refresh()
        exe_of = {p.pid: p.exe for p in procs}
        by_pid_c, by_pid_l = defaultdict(list), defaultdict(list)
        for c in conns:
            by_pid_c[c.pid].append(c)
        for c in listens:
            c.exposure = self.firewall.exposure(proto=c.proto, port=c.lport, exe=exe_of.get(c.pid, ""), pid=c.pid,
                                                laddr=c.laddr)
            by_pid_l[c.pid].append(c)

        cores = psutil.cpu_count() or 1
        alive = set()
        cpu = {}
        for p in procs:
            alive.add(p.pid)
            obj = self._pobj.get(p.pid)
            try:
                if obj is None:
                    obj = self._pobj[p.pid] = psutil.Process(p.pid)
                    obj.cpu_percent(None)
                    cpu[p.pid] = 0.0
                else:
                    cpu[p.pid] = obj.cpu_percent(None) / cores
            except psutil.Error:
                cpu[p.pid] = 0.0
        for pid in list(self._pobj):
            if pid not in alive:
                self._pobj.pop(pid, None)
                self._hot.pop(pid, None)
                self._gpu_hist.pop(pid, None)
        gpu_now = self.gpu_procs.sample()
        for pid, v in gpu_now.items():
            self._gpu_hist.setdefault(pid, deque(maxlen=3)).append(v["gpu"])
        for pid, hist in self._gpu_hist.items():
            if pid not in gpu_now:
                hist.append(0.0)

        now = time.time()
        learning = self.settings.learning_left() > 0
        learning_end = self.settings.get("learning_started") + self.settings.get("learning_days", 7) * 86400
        threshold = self.settings.get("alert_threshold", 30)
        new_rows = []
        for p in procs:
            if p.exe and p.exe not in self._first_seen:
                self._first_seen[p.exe] = now
                new_rows.append((p.exe, now, now, p.sig.kind if p.sig else "", p.sig.signer if p.sig else ""))
        if new_rows:
            self.db.many("insert or ignore into seen_exe(path, first_seen, last_seen, kind, signer) values(?,?,?,?,?)", new_rows)

        rows, per_exe = [], {}
        for p in procs:
            first = self._first_seen.get(p.exe, 0)
            is_new = bool(p.exe) and not learning and first > learning_end and now - first < 7 * 86400
            gh = self._gpu_hist.get(p.pid)
            gpu_sustained = min(gh) if gh and len(gh) == gh.maxlen else 0.0  # uso em 3 leituras seguidas (~15 s)
            sc = R.score(p, self.rules, conns=by_pid_c.get(p.pid, ()), listens=by_pid_l.get(p.pid, ()), new_exe=is_new,
                         gpu=gpu_sustained)
            user_trusted = bool(p.exe) and sc.total > 0 and self.trust_key(p.exe, p.sig) in self._trust
            if user_trusted:
                sc = R.Score(0, [("user_trust", "Na sua lista de confiança", 0)], False)
            sev = R.severity(sc.total, sc.strong, threshold)
            pc = by_pid_c.get(p.pid, [])
            net = [f"{c.raddr}:{c.rport}" for c in pc if c.scope == "internet" and c.state == "Estabelecida"]
            rows.append({
                "pid": p.pid, "name": p.name, "exe": p.exe, "parent": p.parent, "ppid": p.ppid, "user": p.user,
                "started": p.started, "cmdline": p.cmdline[:600], "cpu": round(cpu.get(p.pid, 0), 1), "rss": p.rss,
                "sig": p.sig.kind if p.sig else ("kernel" if p.name in P.KERNEL else "hidden"),
                "signer": p.sig.signer if p.sig else "", "sig_detail": p.sig.detail if p.sig else "",
                "score": sc.total, "sev": sev, "strong": sc.strong, "trusted": user_trusted,
                "reasons": [[t, pts] for _, t, pts in sc.reasons], "rules": [r for r, _, pts in sc.reasons if pts > 0],
                "net": net[:6], "net_count": len(pc), "listen": [f"{c.laddr}:{c.lport}" for c in by_pid_l.get(p.pid, [])],
                "gpu": gpu_now.get(p.pid, {}).get("gpu", 0.0), "vram": gpu_now.get(p.pid, {}).get("vram", 0),
            })
            if p.exe and (sc.strong or sc.total >= threshold):
                cur = per_exe.get(p.exe)
                if cur is None or sc.total > cur[1].total:
                    per_exe[p.exe] = (p, sc, sev)

        for exe, (p, sc, sev) in per_exe.items():
            why = "; ".join(t for _, t, pts in sc.reasons if pts > 0)
            self.alert("proc", f"proc:{os.path.normcase(exe)}", sev,
                       f"{p.name} pede atenção (pontuação {sc.total})", f"PID {p.pid} · {exe} · {why}",
                       {"view": "procs", "pid": p.pid, "exe": exe},
                       rules=[r for r, _, pts in sc.reasons if pts > 0], quiet=learning and not sc.strong, category="process")

        if self.settings.get("notify", {}).get("high_cpu"):
            ticks = max(1, int(120 / self.settings.get("interval", 5)))
            for r in rows:
                if r["cpu"] >= 90:
                    self._hot[r["pid"]] += 1
                    if self._hot[r["pid"]] == ticks:
                        self.alert("cpu", f"cpu:{r['pid']}", "warn", f"{r['name']} usando {r['cpu']:.0f} % da CPU há 2 min",
                                   f"PID {r['pid']} · {r['exe']}", {"view": "procs", "pid": r["pid"]}, category="high_cpu")
                else:
                    self._hot.pop(r["pid"], None)

        names = {p.pid: p.name for p in procs}
        score_of = {r["pid"]: (r["score"], r["sev"]) for r in rows}
        crow = []
        for c in conns:
            host = self.resolver.get(c.raddr) if c.scope != "pc" else "este PC"
            s, sv = score_of.get(c.pid, (0, "ok"))
            crow.append({"pid": c.pid, "proc": names.get(c.pid, "?"), "proto": c.proto, "laddr": c.laddr, "lport": c.lport,
                         "raddr": c.raddr, "rport": c.rport, "host": host, "state": c.state, "scope": c.scope,
                         "score": s, "sev": sv, "bad_port": c.rport in self.rules["bad_ports"]})
        lrow = [{"pid": c.pid, "proc": names.get(c.pid, "System" if c.pid == 4 else "?"), "addr": c.laddr, "port": c.lport, "proto": c.proto,
                 "scope": c.scope, "all": c.laddr in ("0.0.0.0", "::"), "bad_port": c.lport in self.rules["bad_ports"],
                 "exposure": c.exposure}
                for c in listens]
        with self.lock:
            self.procs, self.conns, self.listens = rows, crow, lrow
            self.last_check = now
        self._changed()

    # ---------- alertas ----------
    def alert(self, kind: str, key: str, sev: str, title: str, detail: str, target: dict, *, rules=(), quiet=False,
              category: str = "") -> int | None:
        with self._alert_lock:
            return self._alert(kind, key, sev, title, detail, target, rules=rules, quiet=quiet, category=category)

    def _alert(self, kind, key, sev, title, detail, target, *, rules, quiet, category) -> int | None:
        now = time.time()
        last = self.db.one("select id, ts, sev, status from alerts where key=? order by id desc limit 1", (key,))
        worse = last is not None and SEV_RANK.get(sev, 0) > SEV_RANK.get(last["sev"], 0)
        if last and not (worse and last["status"] != "normal") and (
                last["status"] in ("open", "learning", "normal") or (last["status"] == "dismissed" and now - last["ts"] < 7 * 86400)):
            return None
        status = "learning" if quiet else "open"
        aid = self.db.x("insert into alerts(ts, sev, kind, key, title, detail, target, data, status) values(?,?,?,?,?,?,?,?,?)",
                        (now, sev, kind, key, title, detail, json.dumps(target), json.dumps({"rules": list(rules)}), status))
        for r in rules:
            self.db.x("insert into rule_stats(rule, alerts) values(?, 1) on conflict(rule) do update set alerts = alerts + 1", (r,))
        log.info("alerta %s [%s/%s] %s", aid, sev, status, title)
        if not quiet and now >= self.paused_until and self.settings.get("notify", {}).get(category, True) and sev in ("bad", "warn"):
            for fn in list(self.listeners):
                try:
                    fn(title, detail[:220], sev)
                except Exception:
                    log.debug("notificação falhou", exc_info=True)
        self._changed()
        return aid

    def alerts(self, limit: int = 300) -> list[dict]:
        rows = self.db.q("select * from alerts order by ts desc limit ?", (limit,))
        for r in rows:
            r["target"] = json.loads(r["target"] or "{}")
            r["data"] = json.loads(r["data"] or "{}")
        return rows

    def resolve_alert(self, alert_id: int, normal: bool) -> None:
        """normal=True: "Isso é normal" (confia no item e conta falso positivo). False: só "ciente"."""
        a = self.db.one("select * from alerts where id=?", (alert_id,))
        if not a:
            raise RuntimeError("Alerta não encontrado.")
        self.db.x("update alerts set status=? where id=?", ("normal" if normal else "dismissed", alert_id))
        if normal:
            for r in json.loads(a["data"] or "{}").get("rules", []):
                self.db.x("insert into rule_stats(rule, false_pos) values(?, 1) on conflict(rule) do update set false_pos = false_pos + 1", (r,))
            target = json.loads(a["target"] or "{}")
            if a["kind"] == "proc" and target.get("exe"):
                self.trust_exe(target["exe"])
            elif a["kind"] == "lan" and target.get("mac"):
                self.update_device(target["mac"], known=True)
        self._changed()

    def open_alerts(self) -> list[dict]:
        return self.db.q("select id, sev, kind, title from alerts where status='open' order by ts desc")

    # ---------- confiança e ações ----------
    def trust_exe(self, exe: str) -> None:
        from .signature import check
        key = self.trust_key(exe, check(exe))
        self.db.x("insert or replace into trust(key, ts, label) values(?,?,?)", (key, time.time(), exe))
        self._trust.add(key)
        for a in self.db.q("select id from alerts where key=? and status in ('open','learning')", (f"proc:{os.path.normcase(exe)}",)):
            self.db.x("update alerts set status='normal' where id=?", (a["id"],))
        self._changed()

    def untrust(self, key: str) -> None:
        self.db.x("delete from trust where key=?", (key,))
        self._trust.discard(key)

    def _check_can_touch(self, p: psutil.Process) -> None:
        """Recusa encerrar processos essenciais do Windows (derrubaria o sistema) e o próprio SmartGuardian
        (inclusive o lançador do venv, que é processo pai deste)."""
        own = {os.getpid()} | {a.pid for a in _ancestors()}
        if p.pid in (0, 4) or p.pid in own:
            raise RuntimeError("Este processo não pode ser encerrado por aqui (é o próprio SmartGuardian ou o sistema).")
        try:
            exe = os.path.normcase(p.exe() or "")
        except psutil.Error:
            exe = ""
        if not os.path.isabs(exe):  # Registry, MemCompression: "exe" é só o nome
            exe = ""
        if p.name().lower() in CRITICAL and (not exe or R.under(exe, [R.WINDIR])):
            raise RuntimeError(f"{p.name()} é essencial para o Windows; encerrar derrubaria o sistema.")

    def kill(self, pid: int, started: float | None = None) -> str:
        """Encerra só este processo (como o Gerenciador de Tarefas), não os que ele abriu: matar a árvore do
        explorer, por exemplo, fecharia tudo que foi aberto pelo menu Iniciar."""
        try:
            p = psutil.Process(pid)
            if started and abs(p.create_time() - started) > 1:  # PID reaproveitado por outro programa
                raise psutil.NoSuchProcess(pid)
        except psutil.NoSuchProcess:
            raise RuntimeError("Esse processo já terminou; nada foi encerrado.") from None
        self._check_can_touch(p)
        name = p.name()
        p.kill()
        log.info("processo encerrado: %s (%s)", name, pid)
        return name

    def quarantine(self, exe: str) -> str:
        """Encerra todos os processos desse executável e move o arquivo para C:\\SmartGuardian\\quarentena."""
        from .signature import check
        target = os.path.normcase(exe)
        sig = check(exe)
        writable = R.TEMP_DIRS + R.WRITABLE_IN_WINDOWS
        if R.under(target, [R.WINDIR]) and not R.under(target, writable):
            raise RuntimeError("Arquivos do Windows não vão para a quarentena; use o Windows Defender.")
        # Programa assinado e instalado em pasta protegida (Chrome, Steam…) não é alvo de quarentena:
        # o risco de quebrar algo legítimo é maior que o benefício. Para esses, desinstale ou use o Defender.
        if sig.trusted and R.under(target, R.PROTECTED) and not R.under(target, writable):
            raise RuntimeError(f"Programa assinado por {sig.signer or 'editora válida'} e instalado em pasta protegida; "
                               "não vai para a quarentena. Se não quiser ele, desinstale pelo Windows.")
        if sig.trusted and sig.signer.startswith("Microsoft") and not R.under(target, writable):
            raise RuntimeError("Arquivo assinado pela Microsoft; não vai para a quarentena.")
        if target in _own_executables():
            raise RuntimeError("Este é o Python que roda o próprio SmartGuardian.")
        for p in psutil.process_iter(["exe"]):
            if p.info["exe"] and os.path.normcase(p.info["exe"]) == target:
                try:
                    p.kill()
                    p.wait(5)
                except psutil.Error:
                    pass
        QUARANTINE.mkdir(exist_ok=True)
        sha = self._sha(exe) or hashlib.sha256(exe.encode()).hexdigest()
        dest = QUARANTINE / f"{sha}.quarentena"
        shutil.move(exe, dest)
        write_json(dest.with_suffix(".json"), {"original": exe, "sha256": sha, "quando": datetime.now().isoformat(timespec="seconds")})
        log.info("quarentena: %s -> %s", exe, dest)
        return str(dest)

    def update_device(self, mac: str, alias: str | None = None, known: bool | None = None) -> None:
        """alias muda só o nome; known (Conheço / Isso é normal) é o que fecha o alerta de aparelho novo."""
        if alias is not None:
            self.db.x("update devices set alias=? where mac=?", (alias.strip(), mac))
        if known is not None:
            self.db.x("update devices set known=? where mac=?", (1 if known else 0, mac))
            if known:
                self.db.x("update alerts set status='normal' where key=? and status in ('open','learning')", (f"lan:{mac}",))
        self._changed()

    def set_startup_item(self, key: str, enabled: bool) -> None:
        item = next((i for i in self.startup if i["key"] == key), None)
        if not item:
            raise RuntimeError("Item não encontrado; atualize a lista.")
        if not enabled and item.get("windows") and os.path.basename(item.get("exe", "")).lower() not in self.rules["shells"]:
            # serviço/tarefa da Microsoft: desligar pode deixar o PC sem rede, firewall ou atualizações.
            # Exceção: os que chamam powershell, cmd, mshta… (jeito comum de vírus se instalar com cara de Windows).
            raise RuntimeError(f"{item['name']} faz parte do Windows; desligar por aqui pode quebrar o sistema.")
        startup.set_enabled(self.db, item, enabled)
        item["enabled"] = enabled
        log.info("inicialização: %s %s", "ativado" if enabled else "desativado", key)
        self._changed()

    def vt_lookup(self, exe: str) -> dict:
        sha = self._sha(exe)
        if not sha:
            raise RuntimeError("Não consegui ler o arquivo para calcular o hash.")
        return {"sha256": sha, **vt.lookup(sha, self.settings.get("vt_key", ""))}

    def pause(self, minutes: int) -> None:
        self.paused_until = time.time() + minutes * 60 if minutes else 0.0
        self._changed()

    # ---------- rede local ----------
    def scan_lan(self) -> None:
        def progress(f):
            self.scan_progress = f
            self._changed()
        self.scan_progress = 0.0
        result = lan.scan(progress)
        now = time.time()
        baseline = self.db.meta("lan_baseline", False)
        for d in result["devices"]:
            row = self.db.one("select * from devices where mac=?", (d["mac"],))
            if row:
                self.db.x("update devices set ip=?, last_seen=?, name=coalesce(nullif(?, ''), name), vendor=coalesce(nullif(?, ''), vendor) where mac=?",
                          (d["ip"], now, d["name"], d["vendor"], d["mac"]))
            else:
                known = 1 if (not baseline or d["self"] or d["gateway"]) else 0
                self.db.x("insert into devices(mac, ip, name, vendor, first_seen, last_seen, known) values(?,?,?,?,?,?,?)",
                          (d["mac"], d["ip"], d["name"], d["vendor"], now, now, known))
                if not known:
                    label = d["name"] or "sem nome"
                    self.alert("lan", f"lan:{d['mac']}", "warn", "Dispositivo novo na rede",
                               f"{d['ip']} · {label} · {d['vendor'] or 'fabricante desconhecido'} · MAC {d['mac']}",
                               {"view": "lan", "mac": d["mac"]}, category="new_device")
        if not baseline:
            self.db.set_meta("lan_baseline", True)
        with self.lock:
            self.lan_info = result["info"] | {"ts": now, "live": {d["mac"]: d for d in result["devices"]}}
            self.scan_progress = None
        self._changed()

    def devices(self) -> list[dict]:
        live = self.lan_info.get("live", {})
        rows = self.db.q("select * from devices order by last_seen desc")
        out = []
        for r in rows:
            d = live.get(r["mac"])
            out.append(r | {"online": d is not None, "rtt": d["rtt"] if d else None, "self": bool(d and d["self"]),
                            "gateway": bool(d and d["gateway"]),
                            "kind": d["kind"] if d else lan.kind_of(r["vendor"] or "", r["name"] or "", False, False)})
        out.sort(key=lambda r: (not r["online"], tuple(int(x) for x in r["ip"].split("."))))
        return out

    def request_scan(self) -> None:
        if self.scan_progress is None:
            self._scan_now.set()

    # ---------- inicialização, Defender, limpeza ----------
    def check_startup(self) -> None:
        items = startup.enumerate_all(self.db)
        now = time.time()
        baseline = self.db.meta("startup_baseline", False)
        seen = {r["key"] for r in self.db.q("select key from startup_seen")}
        fresh = [i for i in items if i["key"] not in seen]
        if fresh:
            self.db.many("insert or ignore into startup_seen(key, first_seen) values(?, ?)", [(i["key"], now) for i in fresh])
        first = {r["key"]: r["first_seen"] for r in self.db.q("select key, first_seen from startup_seen")}
        base_ts = baseline
        if base_ts is True:  # versões antigas guardavam só True: a referência é quando a primeira lista foi feita
            base_ts = min(first.values(), default=now)
            self.db.set_meta("startup_baseline", base_ts)
        for i in items:
            i["first_seen"] = first.get(i["key"], now)
            # novo = apareceu depois da primeira lista e há menos de 7 dias
            i["new"] = bool(base_ts) and i["first_seen"] > base_ts + 120 and now - i["first_seen"] < 7 * 86400
        if baseline:
            shells = self.rules["shells"]
            for i in fresh:
                # Item da Microsoft (serviço que o próprio Windows liga e desliga, tarefa do sistema): só registra.
                # Exceção: atalhos para powershell, cmd, mshta etc., o jeito comum de vírus se instalar.
                if i["windows"] and (i["kind"] == "service" or os.path.basename(i["exe"]).lower() not in shells):
                    continue
                bad = i["sig"] in ("none", "invalid") and any(t in os.path.normcase(i["exe"]) for t in ("\\temp\\", "\\appdata\\"))
                self.alert("startup", f"startup:{i['key']}", "bad" if bad else "warn", f"Novo item na inicialização: {i['name']}",
                           f"{i['kind_label']} · {i['command'][:200]} · {'sem assinatura' if i['sig'] == 'none' else i['signer'] or i['sig']}",
                           {"view": "startup", "key": i["key"]}, category="startup")
        else:
            self.db.set_meta("startup_baseline", now)
        with self.lock:
            self.startup = items
        self._changed()

    def refresh_startup(self) -> None:
        self._slow_now.set()

    def check_defender(self) -> None:
        ps = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8;$t=@{}; Get-MpThreat -EA SilentlyContinue | % { $t[[string]$_.ThreatID]=$_.ThreatName };"
              "Get-MpThreatDetection -EA SilentlyContinue | % { [pscustomobject]@{id=$_.DetectionID; name=$t[[string]$_.ThreatID];"
              "when=$_.InitialDetectionTime.ToString('s'); res=($_.Resources -join ' | '); ok=$_.ActionSuccess} } | ConvertTo-Json -Compress")
        try:
            r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], capture_output=True, timeout=60,
                               creationflags=NO_WINDOW)
            data = json.loads(r.stdout.decode("utf-8", "replace") or "[]")
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            return
        data = data if isinstance(data, list) else [data]
        baseline = self.db.meta("defender_baseline", False)
        for d in data:
            if not d.get("id") or self.db.one("select id from defender_seen where id=?", (d["id"],)):
                continue
            self.db.x("insert into defender_seen(id) values(?)", (d["id"],))
            self.alert("defender", f"defender:{d['id']}", "bad", f"Windows Defender detectou {d.get('name') or 'uma ameaça'}",
                       f"{d.get('when', '')} · {d.get('res', '')[:200]} · {'removida' if d.get('ok') else 'ação pendente'}",
                       {"view": "alerts"}, quiet=not baseline, category="defender")
        if not baseline:
            self.db.set_meta("defender_baseline", True)

    def cleanup(self) -> None:
        days = self.settings.get("history_days", 30)
        # "aprendizado" e "normal" ficam: são a memória de que aquilo já foi visto; apagar faria o alerta voltar
        self.db.x("delete from alerts where ts < ? and status = 'dismissed'", (time.time() - days * 86400,))

    # ---------- resumo, IA, relatório ----------
    def summary(self) -> dict:
        open_ = self.open_alerts()
        worst = "bad" if any(a["sev"] == "bad" for a in open_) else "warn" if open_ else None
        return {"open": len(open_), "worst": worst, "learning_left": self.settings.learning_left(),
                "paused_until": self.paused_until if self.paused_until > time.time() else 0, "last_check": self.last_check,
                "by_kind": {k: sum(1 for a in open_ if a["kind"] == k) for k in ("proc", "lan", "startup", "defender", "cpu", "gpu")}}

    def ai_context(self, pid: int | None = None) -> str:
        """Resumo em texto do estado do PC para o modelo. Compacto de propósito: o LM Studio costuma carregar
        o modelo com 8K tokens, que precisam caber este resumo, a conversa, o raciocínio e a resposta."""
        s = self.system.snapshot()
        h = s["hist"]
        left = self.settings.learning_left()
        with self.lock:
            procs, listens, conns = list(self.procs), list(self.listens), list(self.conns)
        by_pid = {p["pid"]: p for p in procs}
        lines = [f"PC {s['host']} · {s['os']} · ligado há {s['uptime'] / 3600:.1f} h",
                 f"CPU {h['cpu'][-1] if h['cpu'] else 0:.0f} % · memória {s['mem_used'] / 2**30:.1f} de {s['mem_total'] / 2**30:.0f} GB"
                 f" · disco {s['drive']} {s['disk_used'] / 2**30:.0f} de {s['disk_total'] / 2**30:.0f} GB",
                 f"Período de aprendizado: {'faltam %.1f dias (só regras fortes avisam)' % left if left else 'terminou'}",
                 "Pontuação de risco: 0 = normal, 30+ = atenção, 60+ = alto."]

        risky = sorted([p for p in procs if p["score"] >= 15], key=lambda p: -p["score"])[:12]
        lines.append(f"\nPROCESSOS ({len(procs)} no total) com pontuação 15 ou mais:")
        lines += [_proc_line(p) for p in risky] or ["  nenhum"]

        unsigned, seen = [], set()
        for p in sorted(procs, key=lambda p: -p["score"]):
            if p["sig"] in ("none", "invalid") and p["exe"] and p["exe"] not in seen:
                seen.add(p["exe"])
                unsigned.append(p)
        lines.append(f"\nPROCESSOS SEM ASSINATURA VÁLIDA ({len(unsigned)} programas):")
        lines += [_proc_line(p) for p in unsigned[:10]] or ["  nenhum: todos os programas visíveis têm assinatura válida"]

        top_cpu = [p for p in sorted(procs, key=lambda p: -p["cpu"]) if p["name"] and p["cpu"] >= 1][:5]
        top_mem = [p for p in sorted(procs, key=lambda p: -p["rss"]) if p["name"]][:5]
        g = self.gpu.snapshot()
        users = [p for p in sorted(procs, key=lambda p: -(p["vram"] + p["gpu"] * 2**24)) if p["vram"] or p["gpu"] >= 1][:6]
        if g["available"]:
            lines.append(f"\nGPU: {g['name']} · driver {g['driver']} · uso {g.get('util', 0)} % · VRAM "
                         f"{(g.get('vram_used') or 0) / 2**30:.1f} de {g['mem_total'] / 2**30:.1f} GB · {g.get('temp')} °C "
                         f"(reduz desempenho a {g['slowdown']} °C) · {g.get('power') or 0:.0f} W de {g.get('power_limit') or 0:.0f} W")
        if users:
            lines.append(("" if g["available"] else "\n") + "USANDO A GPU: " + ", ".join(
                f"{p['name']} ({p['gpu']:.0f} %, {p['vram'] / 2**20:.0f} MB VRAM, {_sig_short(p)})" for p in users))
        lines.append("\nMAIS CPU: " + (", ".join(f"{p['name']} {p['cpu']:.0f} %" for p in top_cpu) or "nenhum processo acima de 1 %"))
        lines.append("MAIS MEMÓRIA: " + ", ".join(f"{p['name']} {p['rss'] / 2**20:.0f} MB" for p in top_mem))

        if pid and pid in by_pid:
            lines.append("\nPROCESSO QUE O USUÁRIO PEDIU PARA ANALISAR:\n" + _proc_line(by_pid[pid], full=True))

        net = defaultdict(list)
        for c in conns:
            if c["scope"] == "internet" and c["pid"]:  # PID 0: conexões já encerradas, sem dono
                net[c["pid"]].append(c)
        lines.append(f"\nCONEXÕES COM A INTERNET ({sum(map(len, net.values()))} de {len(net)} programas):")
        for cpid, cs in sorted(net.items(), key=lambda kv: (-max(c["score"] for c in kv[1]), -len(kv[1])))[:12]:
            p = by_pid.get(cpid, {})
            dests = sorted({f"{c['host'] or c['raddr']}:{c['rport']}" + (" (PORTA SUSPEITA)" if c["bad_port"] else "") for c in cs})
            lines.append(f"  {p.get('name', '?')} PID {cpid} ({_sig_short(p)}) · {len(cs)} conexões · {', '.join(dests[:4])}"
                         + (f" e mais {len(dests) - 4}" if len(dests) > 4 else ""))
        if not net:
            lines.append("  nenhuma")

        # Escutando não é exposto: com o firewall ligado, só passa o que uma regra libera. Sem isso a IA
        # tratava 135/445/RPC do Windows, bloqueados no perfil Público, como portas abertas para a internet.
        rank = {"open": 3, "lan": 2, "": 1, "blocked": 0}
        ports = {}
        for l in listens:
            if l["scope"] == "pc" or l.get("exposure") == "pc":
                continue
            k = (l["proc"], f"{l['proto']} {l['port']}")
            v = ports.setdefault(k, {"bad": l["bad_port"], "pid": l["pid"], "exp": "blocked"})
            if rank[l.get("exposure", "")] > rank[v["exp"]]:
                v["exp"] = l.get("exposure", "")
        key = lambda kv: (not kv[1]["bad"], int(kv[0][1].split()[1]))
        reach = {"open": "liberada para qualquer endereço", "lan": "liberada só para a rede local",
                 "": "firewall não lido"}
        prof = self.firewall.profile_name()
        lines.append("\nPORTAS ABERTAS NESTE PC" + (f" (rede atual: {prof}; firewall ligado, entrada sem regra é bloqueada)"
                                                    if prof else "") + ":")
        lines.append("  Alcançáveis de outro aparelho:")
        reachable = [kv for kv in sorted(ports.items(), key=key) if kv[1]["exp"] != "blocked"]
        for (proc, port), v in reachable:
            lines.append(f"    porta {port} · {proc} ({_sig_short(by_pid.get(v['pid']) or {'pid': v['pid'], 'name': proc})}) · "
                         f"{reach[v['exp']]}{' · PORTA USADA POR INVASÃO' if v['bad'] else ''}")
        if not reachable:
            lines.append("    nenhuma")
        blocked = [f"{port} {proc}" + (" (PORTA USADA POR INVASÃO)" if v["bad"] else "")
                   for (proc, port), v in sorted(ports.items(), key=key) if v["exp"] == "blocked"]
        if blocked:
            lines.append("  Escutando, mas BLOQUEADAS pelo firewall (ninguém de fora alcança; não são risco de rede): "
                         + ", ".join(blocked))

        status_pt = {"open": "aberto", "learning": "registrado no aprendizado", "dismissed": "visto pelo usuário",
                     "normal": "usuário marcou como normal"}
        sev_pt = {"bad": "alto", "warn": "atenção", "info": "baixo", "ok": "normal"}
        lines.append("\nALERTAS RECENTES:")
        for a in self.db.q("select ts, sev, status, title, detail from alerts order by ts desc limit 12"):
            lines.append(f"  [{datetime.fromtimestamp(a['ts']):%d/%m %H:%M}] {sev_pt.get(a['sev'], a['sev'])}, "
                         f"{status_pt.get(a['status'], a['status'])}: {a['title']} — {a['detail'][:200]}")
        if len(lines) and lines[-1] == "\nALERTAS RECENTES:":
            lines.append("  nenhum")

        devs = self.devices()
        lines.append(f"\nREDE LOCAL ({sum(d['online'] for d in devs)} aparelhos online agora, {len(devs)} já vistos):")
        for d in devs[:20]:
            when = "online" if d["online"] else f"fora da rede, visto {datetime.fromtimestamp(d['last_seen']):%d/%m %H:%M}"
            who = "este PC" if d["self"] else "roteador" if d["gateway"] else ("conhecido" if d["known"] else "NOVO, não reconhecido")
            lines.append(f"  {d['ip']} {d['alias'] or d['name'] or 'sem nome'} · {d['vendor'] or 'fabricante desconhecido'} · {who} · {when}")

        with self.lock:
            items = list(self.startup)
        new = [i for i in items if i.get("new")]
        third = [i for i in items if not i["windows"] and not i.get("new")]
        lines.append(f"\nINICIALIZAÇÃO: {len(items)} itens; {len(new)} novos desde a primeira lista; {len(third)} de outros fabricantes (fora da Microsoft):")
        for i in new[:10]:
            lines.append(f"  NOVO · {_startup_line(i, full=True)}")
        for i in third[:15]:
            lines.append(f"  {_startup_line(i)}")

        trusted = self.db.q("select label from trust order by ts desc limit 10")
        if trusted:
            lines.append("\nO USUÁRIO MARCOU COMO NORMAL: " + ", ".join(os.path.basename(t["label"]) for t in trusted))
        return "\n".join(lines)

    def ask(self, history: list[dict], pid: int | None = None) -> str:
        cfg = self.settings.get("ai")
        # sem modelo escolhido: o primeiro carregado (a lista vem com os carregados na frente)
        try:
            listed = ai.model_list(cfg["url"])
        except OSError:
            listed = []
        model = cfg.get("model") or next((m["id"] for m in listed), "")
        if not model:
            raise RuntimeError("Nenhum modelo carregado no LM Studio. Carregue um modelo e tente de novo.")
        # contexto do modelo que vai responder (o escolhido se carregado; senão o carregado que o LM Studio usa)
        info = next((m for m in listed if m["id"] == model and m["loaded"]), None) or next((m for m in listed if m["loaded"]), {})
        return ai.chat(cfg["url"], model, self.ai_context(pid), history,
                       context_tokens=info.get("ctx") or 0)  # {"text", "model", "secs"}

    def report(self, with_ai: bool = False) -> Path:
        REPORTS.mkdir(exist_ok=True)
        today = datetime.now()
        since = today.replace(hour=0, minute=0, second=0).timestamp()
        alerts = self.db.q("select * from alerts where ts >= ? order by ts desc", (since,))
        with self.lock:
            procs = sorted([p for p in self.procs if p["score"] >= 15], key=lambda p: -p["score"])
        devs = self.devices()
        summary = ""
        if with_ai:
            try:
                summary = self.ask([{"role": "user", "content": "Escreva um resumo do dia de hoje para o relatório: o que está bem, o que pede atenção e o que fazer. Até 8 linhas."}])["text"]
            except Exception as e:
                summary = f"(IA indisponível: {e})"
        e = html.escape
        sev_pt = {"bad": "Alto", "warn": "Atenção", "info": "Baixo", "ok": "Normal"}
        body = [f"<h1>SmartGuardian · relatório de {today:%d/%m/%Y}</h1><p class=m>Gerado às {today:%H:%M} em {e(self.system.snapshot()['host'])}</p>"]
        if summary:
            body.append(f"<h2>Resumo da IA</h2><div class=card>{'<br>'.join(e(l) for l in summary.splitlines())}</div>")
        body.append(f"<h2>Alertas de hoje ({len(alerts)})</h2><table><tr><th>Hora</th><th>Nível</th><th>Situação</th><th>Alerta</th></tr>")
        body += [f"<tr><td>{datetime.fromtimestamp(a['ts']):%H:%M}</td><td class={a['sev']}>{sev_pt.get(a['sev'], a['sev'])}</td><td>{e(a['status'])}</td>"
                 f"<td><b>{e(a['title'])}</b><br><span class=m>{e(a['detail'])}</span></td></tr>" for a in alerts]
        body.append("</table>" if alerts else "</table><p class=m>Nenhum alerta hoje.</p>")
        body.append(f"<h2>Processos com pontuação ({len(procs)})</h2><table><tr><th>Processo</th><th>Pontos</th><th>Motivos</th></tr>")
        body += [f"<tr><td><b>{e(p['name'])}</b> {p['pid']}<br><span class=m>{e(p['exe'])}</span></td><td class={p['sev']}>{p['score']}</td>"
                 f"<td>{'<br>'.join(e(f'{t} ({pts:+d})') for t, pts in p['reasons'])}</td></tr>" for p in procs]
        body.append("</table>")
        body.append(f"<h2>Rede local ({sum(d['online'] for d in devs)} online)</h2><table><tr><th>IP</th><th>Nome</th><th>Fabricante</th><th>MAC</th><th>Situação</th></tr>")
        body += [f"<tr><td>{d['ip']}</td><td>{e(d['alias'] or d['name'] or 'sem nome')}</td><td>{e(d['vendor'] or '')}</td><td>{d['mac']}</td>"
                 f"<td>{'conhecido' if d['known'] else '<b class=warn>novo</b>'}{'' if d['online'] else ' · fora da rede'}</td></tr>" for d in devs]
        body.append("</table>")
        page = f"""<!doctype html><meta charset=utf-8><title>SmartGuardian {today:%d/%m/%Y}</title><style>
body{{font:14px/1.45 "Segoe UI",system-ui,sans-serif;max-width:1000px;margin:24px auto;padding:0 16px;color:#1b1b1b;background:#f3f3f3}}
h1{{font-size:24px;margin:0}} h2{{font-size:17px;margin:24px 0 8px}} .m{{color:#5f5f5f;font-size:12.5px}}
table{{border-collapse:collapse;width:100%;background:#fff;border:1px solid #ddd;border-radius:6px}} td,th{{padding:7px 10px;border-top:1px solid #eee;text-align:left;vertical-align:top}}
th{{font-size:12px;color:#5f5f5f}} .card{{background:#fff;border:1px solid #ddd;border-radius:6px;padding:12px 14px}}
.bad{{color:#c42b1c;font-weight:600}} .warn{{color:#9d5d00;font-weight:600}} .info{{color:#005fb8}} .ok{{color:#0f7b0f}}
@media (prefers-color-scheme:dark){{body{{background:#202020;color:#fff}} table,.card{{background:#2b2b2b;border-color:#3a3a3a}} td,th{{border-color:#3a3a3a}} .m,th{{color:#c5c5c5}} .bad{{color:#ff99a4}} .warn{{color:#fce100}} .info{{color:#4cc2ff}} .ok{{color:#6ccb5f}}}}
</style>{''.join(body)}"""
        path = REPORTS / f"{today:%Y-%m-%d}.html"
        path.write_text(page, encoding="utf-8")
        return path

    def export_conns(self) -> Path:
        EXPORTS.mkdir(exist_ok=True)
        path = EXPORTS / f"conexoes-{datetime.now():%Y-%m-%d-%H%M}.csv"
        with self.lock:
            rows = list(self.conns)
        with path.open("w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f, delimiter=";")
            w.writerow(["Programa", "PID", "Protocolo", "Local", "Remoto", "Nome", "Estado", "Tipo", "Pontuação"])
            for c in rows:
                w.writerow([c["proc"], c["pid"], c["proto"], f"{c['laddr']}:{c['lport']}", f"{c['raddr']}:{c['rport']}",
                            c["host"] or "", c["state"], c["scope"], c["score"]])
        return path


def _sig_short(p: dict) -> str:
    if p.get("pid") == 4 or p.get("name") == "System":
        return "kernel do Windows"
    if not p:
        return "?"
    if p.get("sig") in ("file", "catalog", "package"):
        return f"assinado por {p.get('signer') or 'editora válida'}"
    return {"none": "SEM assinatura", "invalid": "assinatura INVÁLIDA"}.get(p.get("sig"), "assinatura desconhecida")


def _startup_line(i: dict, full: bool = False) -> str:
    sig = (f"assinado por {i['signer']}" if i["sig"] in ("file", "catalog", "package")
           else "SEM assinatura" if i["sig"] == "none" else "assinatura INVÁLIDA" if i["sig"] == "invalid" else "arquivo não encontrado")
    what = i["command"][:180] if full else (os.path.basename(i["exe"]) or i["command"][:80])
    return f"{i['name']} ({i['kind_label']}) → {what} · {sig} · {'ativo' if i['enabled'] else 'desativado'}"


def _proc_line(p: dict, full: bool = False) -> str:
    sig = {"file": "assinado", "catalog": "assinado (catálogo do Windows)", "package": "pacote assinado", "none": "SEM assinatura",
           "invalid": "assinatura INVÁLIDA", "unreadable": "sem acesso"}.get(p["sig"], p["sig"])
    why = "; ".join(f"{t} ({pts:+d})" for t, pts in p["reasons"])
    line = (f"  {p['name']} PID {p['pid']} · pontuação {p['score']} · {sig}{' por ' + p['signer'] if p['signer'] else ''}"
            f" · {p['exe']} · aberto por {p['parent'] or '?'} · motivos: {why or 'nenhum'}")
    if p["net"]:
        line += f" · conectado a {', '.join(p['net'])}"
    if p["listen"]:
        line += f" · escutando em {', '.join(p['listen'][:4])}"
    if full:
        line += f"\n  linha de comando: {p['cmdline'][:400]}\n  usuário: {p['user']} · CPU {p['cpu']} % · memória {p['rss'] / 2**20:.0f} MB"
    return line
