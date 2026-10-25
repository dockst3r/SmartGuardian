"""Proteções das ações perigosas (Encerrar e Quarentena). Nada é encerrado nem movido de verdade:
psutil.process_iter, shutil.move e write_json são trocados por versões vazias.

    .venv\\Scripts\\python.exe -m unittest discover -s tests -v
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import psutil  # noqa: E402

from core import guard as G  # noqa: E402

FAKE_SELF = SimpleNamespace(_sha=lambda exe: "0" * 64)


def quarantine(exe: str) -> list[str]:
    moved = []
    with mock.patch.object(G.psutil, "process_iter", lambda *a, **k: []), \
         mock.patch.object(G.shutil, "move", lambda a, b: moved.append(a)), \
         mock.patch.object(G, "write_json", lambda *a, **k: None), \
         mock.patch.object(G, "QUARANTINE", Path(tempfile.gettempdir()) / "sg-teste-quarentena"):
        G.Guard.quarantine(FAKE_SELF, exe)
    return moved


class Quarantine(unittest.TestCase):
    def test_refuses_windows_files(self):
        with self.assertRaises(RuntimeError):
            quarantine(os.path.join(os.environ["SystemRoot"], r"System32\notepad.exe"))

    def test_refuses_signed_program_in_program_files(self):
        chrome = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        if not os.path.exists(chrome):
            self.skipTest("Chrome não instalado")
        with self.assertRaises(RuntimeError):
            quarantine(chrome)

    def test_refuses_own_python(self):
        with self.assertRaises(RuntimeError):
            quarantine(sys.executable)


class Kill(unittest.TestCase):
    def check(self, name):
        p = next((x for x in psutil.process_iter(["name"]) if x.info["name"] == name), None)
        if p is None:
            self.skipTest(f"{name} não encontrado")
        with self.assertRaises(RuntimeError):
            G.Guard._check_can_touch(None, p)

    def test_refuses_csrss(self):
        self.check("csrss.exe")

    def test_refuses_lsass(self):
        self.check("lsass.exe")

    def test_refuses_registry_pseudo_process(self):
        self.check("Registry")

    def test_refuses_itself(self):
        with self.assertRaises(RuntimeError):
            G.Guard._check_can_touch(None, psutil.Process(os.getpid()))


if __name__ == "__main__":
    unittest.main()
