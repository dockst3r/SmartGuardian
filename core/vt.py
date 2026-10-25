"""Consulta opcional do hash no VirusTotal. Envia só o SHA-256, nunca o arquivo."""
from __future__ import annotations

import json
import urllib.error
import urllib.request


def lookup(sha256: str, key: str) -> dict:
    if not key:
        raise RuntimeError("Coloque sua chave da API do VirusTotal em Configurações.")
    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{sha256}", headers={"x-apikey": key})
    link = f"https://www.virustotal.com/gui/file/{sha256}"
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            stats = json.loads(r.read())["data"]["attributes"]["last_analysis_stats"]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"found": False, "link": link}
        if e.code in (401, 403):
            raise RuntimeError("O VirusTotal recusou a chave da API.") from e
        if e.code == 429:
            raise RuntimeError("Limite de consultas do VirusTotal atingido; tente em um minuto.") from e
        raise RuntimeError(f"VirusTotal respondeu {e.code}.") from e
    except OSError as e:
        raise RuntimeError("Sem conexão com o VirusTotal.") from e
    return {"found": True, "link": link, **{k: stats.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected")}}
