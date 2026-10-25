"""Testes da pontuação: casos legítimos comuns não podem gerar aviso; casos de ataque, sim.

    .venv\\Scripts\\python.exe -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import rules as R  # noqa: E402
from core.conns import Conn  # noqa: E402
from core.procs import Proc  # noqa: E402
from core.signature import Signature  # noqa: E402

HOME = os.path.expanduser("~")
TEMP = os.environ["TEMP"]
SIGNED = Signature("file", "Discord Inc.")
MS_CATALOG = Signature("catalog", "Microsoft Windows")
UNSIGNED = Signature("none")


def proc(exe, sig, name=None, parent="explorer.exe", cmd=""):
    return Proc(pid=1000, name=name or os.path.basename(exe), exe=exe, ppid=1, parent=parent, user="usuario",
                started=0, cmdline=cmd, rss=0, sig=sig)


def internet(port=443):
    return Conn(1000, "TCP", "192.168.0.10", 50000, "185.220.101.47", port, "Estabelecida", "internet")


class Legitimate(unittest.TestCase):
    """Programas comuns: precisam ficar abaixo do limite de aviso (30)."""

    def setUp(self):
        self.rules = R.load()

    def check_quiet(self, p, **kw):
        s = R.score(p, self.rules, **kw)
        self.assertFalse(s.strong, s.reasons)
        self.assertLess(s.total, 30, s.reasons)
        return s

    def test_discord_signed_in_appdata(self):
        s = self.check_quiet(proc(rf"{HOME}\AppData\Local\Discord\app-1.0.9265\Discord.exe", SIGNED), conns=[internet()])
        self.assertEqual(s.total, 0)

    def test_git_tools_unsigned_in_program_files(self):
        s = self.check_quiet(proc(r"C:\Program Files\Git\usr\bin\bash.exe", UNSIGNED, parent="claude.exe"))
        self.assertEqual(s.total, 5)

    def test_store_app_package(self):
        exe = r"C:\Program Files\WindowsApps\Microsoft.WidgetsPlatformRuntime_1.6.19.0_x64__8wekyb3d8bbwe\WidgetService\WidgetService.exe"
        self.assertEqual(self.check_quiet(proc(exe, Signature("package", "Microsoft Corporation"))).total, 0)

    def test_real_svchost(self):
        self.check_quiet(proc(r"C:\Windows\System32\svchost.exe", MS_CATALOG, parent="services.exe"), conns=[internet()])

    def test_defender_in_programdata(self):
        exe = r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26090.9-0\MsMpEng.exe"
        self.assertEqual(self.check_quiet(proc(exe, Signature("file", "Microsoft Windows Publisher"), parent="services.exe")).total, 0)

    def test_signed_installer_in_temp(self):
        self.check_quiet(proc(rf"{TEMP}\setup_chrome\setup.exe", Signature("file", "Google LLC")))

    def test_python_in_venv_listening_locally(self):
        listen = [Conn(1000, "TCP", "127.0.0.1", 1234, "", 0, "Escutando", "pc")]
        self.check_quiet(proc(r"C:\SmartDevices\.venv\Scripts\pythonw.exe", Signature("file", "Python Software Foundation")), listens=listen)

    def test_old_program_expired_certificate(self):
        self.check_quiet(proc(r"C:\Program Files (x86)\Velho\app.exe", Signature("file", "Velho Ltda", "certificado vencido")))

    def test_unsigned_alone_never_alerts(self):
        """Nenhum sinal sozinho chega a 30, exceto as regras fortes."""
        self.check_quiet(proc(r"D:\Jogos\mod\launcher.exe", UNSIGNED))


class Suspicious(unittest.TestCase):
    def setUp(self):
        self.rules = R.load()

    def test_fake_svchost_in_temp_even_if_signed_copy(self):
        """Cópia idêntica do svchost (assinatura válida da Microsoft) rodando da pasta Temp."""
        s = R.score(proc(rf"{TEMP}\svchost.exe", MS_CATALOG, parent="powershell.exe"), self.rules)
        self.assertTrue(s.strong)
        self.assertEqual(R.severity(s.total, s.strong, 30), "bad")

    def test_bad_port(self):
        s = R.score(proc(r"C:\Tools\nc.exe", UNSIGNED), self.rules, conns=[internet(4444)])
        self.assertTrue(s.strong)

    def test_unsigned_in_appdata_on_internet(self):
        s = R.score(proc(rf"{HOME}\AppData\Roaming\FreeConvert\updater_x64.exe", UNSIGNED), self.rules, conns=[internet()])
        self.assertGreaterEqual(s.total, 30)
        self.assertFalse(s.strong)

    def test_word_spawning_encoded_powershell(self):
        p = proc(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", MS_CATALOG, parent="WINWORD.EXE",
                 cmd="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")
        s = R.score(p, self.rules)
        self.assertGreaterEqual(s.total, 30)

    def test_tampered_signature_in_downloads(self):
        s = R.score(proc(rf"{HOME}\Downloads\crack.exe", Signature("invalid", "Adobe Inc.", "arquivo alterado depois de assinado")), self.rules)
        self.assertGreaterEqual(s.total, 30)


    def test_unsigned_in_user_writable_windows_folder(self):
        """A pasta Tasks do Windows aceita gravação de qualquer usuário: não conta como pasta protegida."""
        s = R.score(proc(r"C:\Windows\Tasks\update.exe", UNSIGNED), self.rules, conns=[internet()])
        self.assertGreaterEqual(s.total, 30)

    def test_fake_svchost_in_windows_tasks(self):
        s = R.score(proc(r"C:\Windows\Tasks\svchost.exe", MS_CATALOG), self.rules)
        self.assertTrue(s.strong)


class Gpu(unittest.TestCase):
    """Regra do minerador: GPU alta e contínua por programa sem assinatura válida."""

    def setUp(self):
        self.rules = R.load()

    def test_signed_game_at_full_gpu_is_quiet(self):
        s = R.score(proc(r"C:\Program Files (x86)\Steam\steamapps\common\Jogo\jogo.exe", Signature("file", "Valve Corp.")), self.rules, gpu=99)
        self.assertEqual(s.total, 0)

    def test_lm_studio_signed_is_quiet(self):
        s = R.score(proc(rf"{HOME}\AppData\Local\Programs\LM Studio\resources\llama-server.exe", Signature("file", "Element Labs Inc.")), self.rules, gpu=95)
        self.assertLess(s.total, 30)

    def test_miner_in_appdata(self):
        s = R.score(proc(rf"{HOME}\AppData\Roaming\svc\xmr.exe", UNSIGNED), self.rules, gpu=90, conns=[internet(3333)])
        self.assertGreaterEqual(s.total, 60)

    def test_low_gpu_does_not_count(self):
        s = R.score(proc(rf"{HOME}\AppData\Roaming\tool\tool.exe", UNSIGNED), self.rules, gpu=30)
        self.assertNotIn("gpu_untrusted", [r for r, _, _ in s.reasons])


class HistorySize(unittest.TestCase):
    def test_small_or_unknown_context_keeps_4000(self):
        from core.ai import history_chars
        self.assertEqual(history_chars(0), 4000)
        self.assertEqual(history_chars(8192), 4000 if (8192 - 5500) * 2.5 < 4000 else int((8192 - 5500) * 2.5))

    def test_big_context_is_capped(self):
        from core.ai import history_chars
        self.assertEqual(history_chars(118016), 60000)


class Ports(unittest.TestCase):
    """Porta de invasão só conta em conexão que o programa abriu para fora, nunca no loopback."""

    def setUp(self):
        self.rules = R.load()

    def test_incoming_connection_from_bad_port_is_ignored(self):
        listen = [Conn(1000, "TCP", "0.0.0.0", 8080, "", 0, "Escutando", "local")]
        incoming = [Conn(1000, "TCP", "192.168.0.10", 8080, "192.168.0.50", 4444, "Estabelecida", "local")]
        s = R.score(proc(r"C:\Program Files\App\server.exe", SIGNED), self.rules, conns=incoming, listens=listen)
        self.assertFalse(s.strong, s.reasons)

    def test_loopback_is_ignored(self):
        loop = [Conn(1000, "TCP", "127.0.0.1", 50000, "127.0.0.1", 4444, "Estabelecida", "pc")]
        s = R.score(proc(r"C:\Program Files\App\app.exe", SIGNED), self.rules, conns=loop)
        self.assertFalse(s.strong, s.reasons)

    def test_ephemeral_ports_never_count_even_if_in_rules_file(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "rules.json"
            f.write_text(json.dumps({"bad_ports": [4444, 54321]}), encoding="utf-8")
            with mock.patch.object(R, "RULES_FILE", f):
                rules = R.load()
        self.assertEqual(rules["bad_ports"], {4444})


    def test_unsigned_listener_blocked_by_firewall_is_not_open_to_network(self):
        listen = [Conn(1000, "TCP", "0.0.0.0", 8080, "", 0, "Escutando", "local", "blocked")]
        s = R.score(proc(r"C:\Tools\server.exe", UNSIGNED), self.rules, listens=listen)
        self.assertNotIn("listen_all", [r for r, _, _ in s.reasons])

    def test_unsigned_listener_allowed_by_firewall_counts(self):
        for exp in ("open", "lan", ""):  # "" = firewall não lido: conta como antes
            listen = [Conn(1000, "TCP", "0.0.0.0", 8080, "", 0, "Escutando", "local", exp)]
            s = R.score(proc(r"C:\Tools\server.exe", UNSIGNED), self.rules, listens=listen)
            self.assertIn("listen_all", [r for r, _, _ in s.reasons], exp)

    def test_bad_port_listener_alerts_even_if_blocked(self):
        listen = [Conn(1000, "TCP", "0.0.0.0", 4444, "", 0, "Escutando", "local", "blocked")]
        self.assertTrue(R.score(proc(r"C:\Tools\x.exe", UNSIGNED), self.rules, listens=listen).strong)


class Firewall(unittest.TestCase):
    """Porta escutando só é exposta se uma regra do firewall liberar (perfil ativo, protocolo, porta, programa)."""
    PUBLIC = [{"t": 4, "on": True, "allow": 0}]
    SVCHOST = r"C:\WINDOWS\system32\svchost.exe"

    def exp(self, texts, proto="TCP", port=445, exe="", pid=4, laddr="0.0.0.0", profiles=PUBLIC, services=None):
        from core import firewall as F
        return F.exposure(F.inbound_allows(texts), profiles, proto=proto, port=port, exe=exe, pid=pid, laddr=laddr,
                          services=services or {})

    # legítimos: Windows padrão no perfil Público
    def test_smb_rule_for_private_only_is_blocked_on_public(self):
        rule = "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|LPort=445|RA4=LocalSubnet|App=System|"
        self.assertEqual(self.exp([rule]), "blocked")

    def test_disabled_rule_is_blocked(self):
        self.assertEqual(self.exp(["v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=6|LPort=445|App=System|"]), "blocked")

    def test_store_app_rule_does_not_open_the_pc(self):
        rule = "v2.33|Action=Allow|Active=TRUE|Dir=In|Name=Game Bar|PFN=Microsoft.XboxGamingOverlay_8wekyb3d8bbwe|Edge=TRUE|"
        self.assertEqual(self.exp([rule]), "blocked")

    def test_wifi_direct_and_playto_rules_do_not_open_the_pc(self):
        rules = ["v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App=System|TTK2_27=WFDKmDriver|",
                 "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Public|App=System|TTK2_27=UPnP|"]
        self.assertEqual(self.exp(rules), "blocked")

    def test_rpc_rule_for_domain_only(self):
        rule = f"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Domain|LPort=RPC|App={self.SVCHOST}|"
        self.assertEqual(self.exp([rule], port=49666, exe=self.SVCHOST, pid=900), "blocked")

    def test_loopback_is_pc(self):
        self.assertEqual(self.exp([], port=1234, laddr="127.0.0.1"), "pc")

    def test_mdns_service_rule_only_local(self):
        rule = (f"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=5353|RA4=LocalSubnet|RA6=LocalSubnet|"
                f"App=%SystemRoot%\\system32\\svchost.exe|Svc=dnscache|")
        self.assertEqual(self.exp([rule], "UDP", 5353, self.SVCHOST, 900, services={"dnscache": {900}}), "lan")
        self.assertEqual(self.exp([rule], "UDP", 5353, self.SVCHOST, 901, services={"dnscache": {900}}), "blocked")

    # ataque: programa que se libera no firewall, ou firewall desligado
    def test_program_with_allow_any_rule_is_open(self):
        exe = rf"{HOME}\AppData\Roaming\upd\svc.exe"
        rule = f"v2.33|Action=Allow|Active=TRUE|Dir=In|App={exe}|Name=Update|"
        self.assertEqual(self.exp([rule], port=8443, exe=exe, pid=1000), "open")

    def test_port_range_rule(self):
        rule = "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort2_10=4000-5000|"
        self.assertEqual(self.exp([rule], port=4444, exe=r"C:\x.exe", pid=1000), "open")
        self.assertEqual(self.exp([rule], port=5001, exe=r"C:\x.exe", pid=1000), "blocked")

    def test_firewall_off_exposes_everything(self):
        self.assertEqual(self.exp([], profiles=[{"t": 4, "on": False, "allow": 0}]), "open")

    def test_unknown_profile_is_unknown(self):
        self.assertEqual(self.exp([], profiles=[]), "")


class EncodedCommand(unittest.TestCase):
    B64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"

    def test_abbreviations_powershell_accepts(self):
        for flag in ("-e", "-ec", "-en", "-enc", "-EncodedCom", "-EncodedCommand", "/enc", "\u2013enc"):
            self.assertTrue(R.ENCODED.search(f" powershell {flag} {self.B64}"), flag)

    def test_other_flags_do_not_match(self):
        for cmd in ("powershell -ExecutionPolicy Bypass -File x.ps1", f"node --enable-source-maps {self.B64}"):
            self.assertFalse(R.ENCODED.search(" " + cmd), cmd)


class Limits(unittest.TestCase):
    def test_rules_file_cannot_raise_common_weight_above_25(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "rules.json"
            f.write_text(json.dumps({"weights": {"unsigned": 90, "fake_system_name": 50}}), encoding="utf-8")
            with mock.patch.object(R, "RULES_FILE", f):
                rules = R.load()
        self.assertEqual(rules["weights"]["unsigned"], 25)
        self.assertEqual(rules["weights"]["fake_system_name"], 50)  # regra forte pode subir
        for k, w in rules["weights"].items():
            if k not in R.STRONG:
                self.assertLessEqual(w, R.MAX_WEIGHT)


if __name__ == "__main__":
    unittest.main()
