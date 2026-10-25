"""Testes da otimização e do funil da IA. A limpeza roda só em pastas temporárias criadas aqui.

    .venv\\Scripts\\python.exe -m unittest discover -s tests -v
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import ai, firewall, optimize as O, tools  # noqa: E402


def touch(path: Path, days_old: float = 0, size: int = 100) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)
    t = time.time() - days_old * 86400
    os.utime(path, (t, t))
    return path


class Cleanup(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def item(self, path, age=1):
        return {"id": "t", "label": "teste", "paths": [str(path)], "age": age, "default": True, "how": "files", "desc": ""}

    def test_only_old_files_are_deleted_and_root_stays(self):
        d = self.root / "temp"
        old, new = touch(d / "a" / "velho.tmp", days_old=3), touch(d / "novo.tmp", days_old=0)
        with mock.patch.object(O, "BY_ID", {"t": self.item(d)}):
            r = O.clean(["t"])[0]
        self.assertFalse(old.exists())
        self.assertTrue(new.exists())
        self.assertTrue(d.exists())                  # a pasta do item fica
        self.assertFalse((d / "a").exists())         # subpasta que esvaziou sai
        self.assertEqual((r["files"], r["freed"]), (1, 100))

    def test_junction_is_not_followed(self):
        """Um link de pasta dentro do Temp não pode levar a limpeza para outra pasta (ex.: Documentos)."""
        d, outside = self.root / "temp", self.root / "documentos"
        keep = touch(outside / "importante.docx", days_old=30)
        d.mkdir()
        subprocess.run(["cmd", "/c", "mklink", "/J", str(d / "link"), str(outside)], capture_output=True, check=True)
        with mock.patch.object(O, "BY_ID", {"t": self.item(d)}):
            O.clean(["t"])
        self.assertTrue(keep.exists())
        self.assertEqual(list(O._walk(str(d), 0)), [])

    def test_unknown_or_unchecked_items_are_untouched(self):
        a, b = touch(self.root / "a" / "x.tmp", 5), touch(self.root / "b" / "y.tmp", 5)
        items = {"a": self.item(self.root / "a") | {"id": "a"}, "b": self.item(self.root / "b") | {"id": "b"}}
        with mock.patch.object(O, "BY_ID", items):
            O.clean(["a", "nao_existe"])
        self.assertFalse(a.exists())
        self.assertTrue(b.exists())

    def test_analyze_never_deletes(self):
        f = touch(self.root / "temp" / "x.tmp", 5)
        item = self.item(self.root / "temp")
        with mock.patch.object(O, "ITEMS", [item]):
            r = O.analyze()
        self.assertTrue(f.exists())
        self.assertEqual((r[0]["size"], r[0]["count"]), (100, 1))

    def test_file_in_use_is_skipped(self):
        f = touch(self.root / "temp" / "aberto.tmp", 5)
        with open(f, "rb"), mock.patch.object(O, "BY_ID", {"t": self.item(self.root / "temp")}):
            r = O.clean(["t"])[0]
        self.assertTrue(f.exists())
        self.assertEqual(r["skipped"], 1)

    def test_no_prefetch_or_windows_update_folder(self):
        paths = " ".join(p for it in O.ITEMS for p in it["paths"]).lower()
        self.assertNotIn("prefetch", paths)
        self.assertNotIn("softwaredistribution", paths)
        self.assertIn("Prefetch", [n for n, _ in O.NOT_DONE])


class Funnel(unittest.TestCase):
    """O laço de ferramentas, com um LM Studio falso."""

    def reply(self, content="", calls=None, finish="stop"):
        msg = {"content": content}
        if calls:
            msg["tool_calls"] = [{"id": f"c{i}", "type": "function", "function": {"name": n, "arguments": a}}
                                 for i, (n, a) in enumerate(calls)]
        return {"model": "falso", "choices": [{"message": msg, "finish_reason": finish}]}

    def test_tool_then_answer(self):
        answers = [self.reply(calls=[("portas", '{"exposicao": "alcancaveis"}')]), self.reply("### Diagnóstico\nok")]
        seen = []
        with mock.patch.object(ai, "_post", side_effect=lambda *a, **k: answers.pop(0)) as post:
            r = ai.chat("http://x/v1", "m", "sys", [{"role": "user", "content": "portas?"}], tools=tools.TOOLS,
                        execute=lambda n, a, lim: seen.append((n, a)) or "resultado", context_tokens=25000)
        self.assertEqual(seen, [("portas", {"exposicao": "alcancaveis"})])
        self.assertEqual(r["text"], "### Diagnóstico\nok")
        sent = post.call_args_list[1].args[1]["messages"]
        self.assertEqual(sent[-1], {"role": "tool", "tool_call_id": "c0", "name": "portas", "content": "resultado"})

    def test_rounds_are_limited_and_last_round_has_no_tools(self):
        bodies = []

        def post(base, body, timeout):
            bodies.append(body)
            return self.reply("fim") if "tools" not in body else self.reply(calls=[("sistema", "{}")])
        with mock.patch.object(ai, "_post", side_effect=post):
            r = ai.chat("http://x/v1", "m", "sys", [{"role": "user", "content": "?"}], tools=tools.TOOLS,
                        execute=lambda n, a, lim: "x", context_tokens=100000)
        self.assertEqual(r["text"], "fim")
        self.assertEqual(len(bodies), ai.MAX_ROUNDS + 1)
        self.assertNotIn("tools", bodies[-1])

    def test_bad_arguments_do_not_break(self):
        answers = [self.reply(calls=[("processo", "{isso não é json")]), self.reply("respondi")]
        with mock.patch.object(ai, "_post", side_effect=lambda *a, **k: answers.pop(0)):
            r = ai.chat("http://x/v1", "m", "sys", [{"role": "user", "content": "?"}], tools=tools.TOOLS,
                        execute=lambda n, a, lim: f"args={a}")
        self.assertEqual(r["tools"], [("processo", {})])

    def test_tool_errors_come_back_as_text(self):
        self.assertIn("desconhecida", tools.run(None, "apagar_tudo", {}))
        self.assertIn("argumentos inválidos", tools.run(None, "sistema", {"x": 1}))

    def test_every_tool_has_a_function(self):
        for t in tools.TOOLS:
            self.assertTrue(hasattr(tools, "_t_" + t["function"]["name"]), t["function"]["name"])

    def test_prompts(self):
        tec, simp = ai.system_prompt("tecnico", True), ai.system_prompt("simples", False)
        self.assertIn("Próximos passos", tec)
        self.assertIn("funil", tec)
        self.assertNotIn("funil", simp)
        self.assertIn("Prefetch", tec)


class FirewallText(unittest.TestCase):
    def test_describe_rule(self):
        r = firewall.parse_rule("v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=27036|App=C:\\Steam\\steam.exe|Name=Steam|")
        self.assertEqual(firewall.describe(r), 'regra "Steam" (programa steam.exe, portas 27036, qualquer origem, todos os perfis)')

    def test_windows_resource_names_are_not_shown_raw(self):
        r = firewall.parse_rule("v2.33|Action=Allow|Dir=In|Name=@FirewallAPI.dll,-28502|")
        self.assertTrue(firewall.describe(r).startswith("regra do Windows"))


if __name__ == "__main__":
    unittest.main()
