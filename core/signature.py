"""Assinatura digital de executáveis, conferida do mesmo jeito que o Windows confere.

Três caminhos, nesta ordem:
  1. arquivo: assinatura Authenticode embutida no próprio .exe;
  2. catálogo: arquivos do sistema não carregam assinatura própria; o hash deles está num
     .cat assinado pela Microsoft (quase toda a System32 é assim);
  3. pacote: o .exe dentro de WindowsApps (Microsoft Store / MSIX) pode não ser assinado,
     mas o pacote é, e o Windows só registra pacote com assinatura válida.

Nada vai para a internet: a checagem de revogação usa só o cache local do Windows.
"""
from __future__ import annotations

import ctypes
import msvcrt
import os
import re
import threading
import time
import xml.etree.ElementTree as ET
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8)]


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR), ("hFile", wintypes.HANDLE),
                ("pgKnownSubject", ctypes.POINTER(GUID))]


class WINTRUST_CATALOG_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("dwCatalogVersion", wintypes.DWORD),
                ("pcwszCatalogFilePath", wintypes.LPCWSTR), ("pcwszMemberTag", wintypes.LPCWSTR),
                ("pcwszMemberFilePath", wintypes.LPCWSTR), ("hMemberFile", wintypes.HANDLE),
                ("pbCalculatedFileHash", ctypes.POINTER(ctypes.c_ubyte)), ("cbCalculatedFileHash", wintypes.DWORD),
                ("pcCatalogContext", ctypes.c_void_p), ("hCatAdmin", wintypes.HANDLE)]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                ("pInfo", ctypes.c_void_p), ("dwStateAction", wintypes.DWORD), ("hWVTStateData", wintypes.HANDLE),
                ("pwszURLReference", wintypes.LPWSTR), ("dwProvFlags", wintypes.DWORD),
                ("dwUIContext", wintypes.DWORD), ("pSignatureSettings", ctypes.c_void_p)]


class CATALOG_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("wszCatalogFile", wintypes.WCHAR * 260)]


class CRYPT_PROVIDER_CERT(ctypes.Structure):  # só o começo da estrutura; o resto não é usado
    _fields_ = [("cbStruct", wintypes.DWORD), ("pCert", ctypes.c_void_p)]


GENERIC_VERIFY_V2 = GUID(0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
NO_UI = wintypes.HANDLE(-1)  # INVALID_HANDLE_VALUE: nunca mostra janela
WTD_UI_NONE, WTD_REVOKE_NONE = 2, 0
WTD_CHOICE_FILE, WTD_CHOICE_CATALOG = 1, 2
WTD_STATEACTION_VERIFY, WTD_STATEACTION_CLOSE = 1, 2
WTD_REVOCATION_CHECK_NONE, WTD_CACHE_ONLY_URL_RETRIEVAL = 0x10, 0x1000
CERT_NAME_SIMPLE_DISPLAY_TYPE = 4

wintrust.WinVerifyTrust.argtypes = [wintypes.HANDLE, ctypes.POINTER(GUID), ctypes.c_void_p]
wintrust.WinVerifyTrust.restype = wintypes.LONG
wintrust.WTHelperProvDataFromStateData.argtypes = [wintypes.HANDLE]
wintrust.WTHelperProvDataFromStateData.restype = ctypes.c_void_p
wintrust.WTHelperGetProvSignerFromChain.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
wintrust.WTHelperGetProvSignerFromChain.restype = ctypes.c_void_p
wintrust.WTHelperGetProvCertFromChain.argtypes = [ctypes.c_void_p, wintypes.DWORD]
wintrust.WTHelperGetProvCertFromChain.restype = ctypes.POINTER(CRYPT_PROVIDER_CERT)
wintrust.CryptCATAdminAcquireContext2.argtypes = [ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(GUID),
                                                  wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD]
wintrust.CryptCATAdminAcquireContext2.restype = wintypes.BOOL
wintrust.CryptCATAdminCalcHashFromFileHandle2.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
                                                          ctypes.POINTER(ctypes.c_ubyte), wintypes.DWORD]
wintrust.CryptCATAdminCalcHashFromFileHandle2.restype = wintypes.BOOL
wintrust.CryptCATAdminEnumCatalogFromHash.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_ubyte), wintypes.DWORD,
                                                      wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
wintrust.CryptCATAdminEnumCatalogFromHash.restype = wintypes.HANDLE
wintrust.CryptCATCatalogInfoFromContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(CATALOG_INFO), wintypes.DWORD]
wintrust.CryptCATCatalogInfoFromContext.restype = wintypes.BOOL
wintrust.CryptCATAdminReleaseCatalogContext.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD]
wintrust.CryptCATAdminReleaseContext.argtypes = [wintypes.HANDLE, wintypes.DWORD]
crypt32.CertGetNameStringW.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                       wintypes.LPWSTR, wintypes.DWORD]
crypt32.CertGetNameStringW.restype = wintypes.DWORD
kernel32.GetPackagePathByFullName.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_uint32), wintypes.LPWSTR]
kernel32.GetPackagePathByFullName.restype = wintypes.LONG

# Códigos que querem dizer só "não tem assinatura" (e não "assinatura ruim").
NO_SIGNATURE = {0x800B0100, 0x800B0003, 0x800B0001}
PROBLEMS = {
    0x80096010: "arquivo alterado depois de assinado",
    0x800B0109: "certificado de origem não confiável",
    0x800B010C: "certificado revogado",
    0x800B0111: "editora bloqueada no Windows",
    0x80092026: "bloqueado pela política do Windows",
    0x800B010A: "cadeia de certificados incompleta",
}
CERT_E_EXPIRED = 0x800B0101


@dataclass(frozen=True)
class Signature:
    kind: str           # file, catalog, package, none, invalid, unreadable
    signer: str = ""
    detail: str = ""

    @property
    def trusted(self) -> bool:
        return self.kind in ("file", "catalog", "package")


LABELS = {"file": "arquivo", "catalog": "catálogo", "package": "pacote",
          "none": "sem assinatura", "invalid": "assinatura inválida", "unreadable": "sem acesso"}


def _signer(state: int) -> str:
    prov = wintrust.WTHelperProvDataFromStateData(state)
    sgnr = wintrust.WTHelperGetProvSignerFromChain(prov, 0, False, 0) if prov else None
    cert = wintrust.WTHelperGetProvCertFromChain(sgnr, 0) if sgnr else None
    if not cert or not cert.contents.pCert:
        return ""
    buf = ctypes.create_unicode_buffer(256)
    crypt32.CertGetNameStringW(cert.contents.pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, buf, 256)
    return buf.value


def _verify(choice: int, info: ctypes.Structure) -> tuple[int, str]:
    data = WINTRUST_DATA(
        cbStruct=ctypes.sizeof(WINTRUST_DATA), dwUIChoice=WTD_UI_NONE, fdwRevocationChecks=WTD_REVOKE_NONE,
        dwUnionChoice=choice, pInfo=ctypes.cast(ctypes.pointer(info), ctypes.c_void_p),
        dwStateAction=WTD_STATEACTION_VERIFY, dwProvFlags=WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
    )
    code = wintrust.WinVerifyTrust(NO_UI, ctypes.byref(GENERIC_VERIFY_V2), ctypes.byref(data)) & 0xFFFFFFFF
    try:
        signer = _signer(data.hWVTStateData) if data.hWVTStateData else ""
    finally:
        data.dwStateAction = WTD_STATEACTION_CLOSE
        wintrust.WinVerifyTrust(NO_UI, ctypes.byref(GENERIC_VERIFY_V2), ctypes.byref(data))
    return code, signer


def _result(kind: str, code: int, signer: str) -> Signature:
    if code == 0:
        return Signature(kind, signer)
    if code == CERT_E_EXPIRED:
        # Assinatura sem carimbo de tempo cujo certificado venceu depois: comum em programas antigos
        # e legítimos. Conta como assinado, com a observação, para não virar falso positivo.
        return Signature(kind, signer, "certificado vencido")
    return Signature("invalid", signer, PROBLEMS.get(code, f"erro 0x{code:08X}"))


def _embedded(path: str) -> Signature | None:
    info = WINTRUST_FILE_INFO(cbStruct=ctypes.sizeof(WINTRUST_FILE_INFO), pcwszFilePath=path)
    code, signer = _verify(WTD_CHOICE_FILE, info)
    return None if code in NO_SIGNATURE else _result("file", code, signer)


def _catalog(path: str) -> Signature | None:
    with open(path, "rb") as f:
        hfile = msvcrt.get_osfhandle(f.fileno())
        for algorithm in ("SHA256", None):  # catálogos novos usam SHA-256; None = SHA-1 dos antigos
            admin = wintypes.HANDLE()
            if not wintrust.CryptCATAdminAcquireContext2(ctypes.byref(admin), None, algorithm, None, 0):
                continue
            try:
                size = wintypes.DWORD(0)
                wintrust.CryptCATAdminCalcHashFromFileHandle2(admin, hfile, ctypes.byref(size), None, 0)
                if not size.value:
                    continue
                digest = (ctypes.c_ubyte * size.value)()
                if not wintrust.CryptCATAdminCalcHashFromFileHandle2(admin, hfile, ctypes.byref(size), digest, 0):
                    continue
                cat = wintrust.CryptCATAdminEnumCatalogFromHash(admin, digest, size, 0, None)
                if not cat:
                    continue
                try:
                    ci = CATALOG_INFO(cbStruct=ctypes.sizeof(CATALOG_INFO))
                    if not wintrust.CryptCATCatalogInfoFromContext(cat, ctypes.byref(ci), 0):
                        continue
                    info = WINTRUST_CATALOG_INFO(
                        cbStruct=ctypes.sizeof(WINTRUST_CATALOG_INFO), pcwszCatalogFilePath=ci.wszCatalogFile,
                        pcwszMemberTag=bytes(digest).hex().upper(), pcwszMemberFilePath=path,
                        pbCalculatedFileHash=ctypes.cast(digest, ctypes.POINTER(ctypes.c_ubyte)),
                        cbCalculatedFileHash=size.value, hCatAdmin=admin,
                    )
                    code, signer = _verify(WTD_CHOICE_CATALOG, info)
                    return _result("catalog", code, signer)
                finally:
                    wintrust.CryptCATAdminReleaseCatalogContext(admin, cat, 0)
            finally:
                wintrust.CryptCATAdminReleaseContext(admin, 0)
    return None


PACKAGE_DIR = re.compile(r"^(.*\\WindowsApps\\([^\\]+))\\", re.IGNORECASE)


def _package(path: str) -> Signature | None:
    """Pacote registrado no Windows, com assinatura de pacote, e o arquivo dentro da pasta dele."""
    m = PACKAGE_DIR.match(path)
    if not m:
        return None
    folder, full_name = m.groups()
    n = ctypes.c_uint32(0)
    kernel32.GetPackagePathByFullName(full_name, ctypes.byref(n), None)
    if not n.value:
        return None  # pasta com cara de pacote, mas o Windows não conhece esse pacote
    buf = ctypes.create_unicode_buffer(n.value)
    if kernel32.GetPackagePathByFullName(full_name, ctypes.byref(n), buf) != 0:
        return None
    if os.path.normcase(buf.value.rstrip("\\")) != os.path.normcase(folder):
        return None
    root = Path(buf.value)
    if not (root / "AppxSignature.p7x").exists():
        return None
    publisher = ""
    try:
        for el in ET.parse(root / "AppxManifest.xml").getroot():
            if el.tag.endswith("Identity"):
                publisher = el.get("Publisher", "")
                break
    except (OSError, ET.ParseError):
        pass
    cn = re.search(r"CN=([^,]+)", publisher)
    return Signature("package", cn.group(1).strip('"') if cn else publisher)


# Validade do cache: arquivo trocado por outro de mesmo tamanho e com a data restaurada (truque comum)
# não fica "assinado" para sempre; a assinatura é conferida de novo depois disso.
CACHE_TTL = 600
_cache: dict[tuple, tuple[Signature, float]] = {}
_lock = threading.Lock()


def check(path: str) -> Signature:
    """Assinatura de um executável. Guarda o resultado enquanto o arquivo não mudar."""
    try:
        st = os.stat(path)
    except OSError:
        return Signature("unreadable", detail="arquivo não encontrado ou sem permissão")
    key = (os.path.normcase(path), st.st_size, st.st_mtime_ns)
    with _lock:
        hit = _cache.get(key)
        if hit and time.time() - hit[1] < CACHE_TTL:
            return hit[0]
    try:
        sig = _embedded(path) or _catalog(path) or _package(path) or Signature("none")
    except OSError as e:
        sig = Signature("unreadable", detail=e.strerror or str(e))
    with _lock:
        _cache[key] = (sig, time.time())
    return sig
