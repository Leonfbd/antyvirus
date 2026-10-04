"""Warstwa 3: heurystyka strukturalna plików PE (Windows).

To warstwa, która wykrywa malware, którego jeszcze nikt nie zna - nie szuka
konkretnego wirusa, tylko cech charakterystycznych dla złośliwego kodu:
entry point poza sekcją kodu, sekcje W+X, packery, podejrzane importy itd.

Każda reguła jest odporna na wyjątki - uszkodzony nagłówek PE (częsta technika
anty-analityczna) sam w sobie jest sygnałem, a nie powodem do przerwania skanu.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Set

from .base import Detector, ScanContext
from ..models import Severity

# --- flagi sekcji (IMAGE_SCN_*) ---
SCN_CODE = 0x00000020
SCN_EXECUTE = 0x20000000
SCN_WRITE = 0x80000000

# --- nazwy sekcji typowe dla packerów / kryptorów ---
PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".upx": "UPX",
    "aspack": "ASPack", ".aspack": "ASPack", "adata": "ASPack",
    ".nsp0": "NSPack", ".nsp1": "NSPack", ".nsp2": "NSPack", "nsp0": "NSPack",
    "petite": "Petite", ".petite": "Petite",
    ".packed": "nieznany packer", "packed": "nieznany packer",
    "themida": "Themida", ".themida": "Themida", ".taz": "Themida",
    "winlice": "WinLicense", ".winlice": "WinLicense",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect", "vmp0": "VMProtect",
    "enigma": "Enigma", ".enigma": "Enigma",
    ".dyamar": "Dyamar", "dyamar": "Dyamar",
    ".mackt": "ImpRec", ".nicode": "NicoD", ".charmve": "Charmve",
    ".import": "nieznany packer", ".code": "nieznany packer",
    "mnbvcx": "nieznany packer", ".ccg": "CCG", ".scroll": "nieznany packer",
}

# --- importy grupowane według intencji ---
# (nazwa kategorii, waga bazowa, minimalna liczba trafień, opis)
API_CATEGORIES = {
    "injection": (
        32, 1, "wstrzykiwanie kodu do obcego procesu",
        ["virtualallocex", "writeprocessmemory", "openprocess", "ntwritevirtualmemory",
         "zwunmapviewofsection", "ntunmapviewofsection"],
    ),
    "hollowing": (
        30, 1, "process hollowing / podmiana obrazu procesu",
        ["createremotethread", "ntcreatethreadex", "rtlcreateuserthread", "queueuserapc",
         "setthreadcontext", "getthreadcontext", "resumethread", "ntmapviewofsection",
         "zwmapviewofsection", "ntresumethread"],
    ),
    "keylogger": (
        28, 1, "przechwytywanie klawiatury (keylogger)",
        ["getasynckeystate", "getkeystate", "setwindowshookex", "registerrawinputdevices",
         "getrawinputdata", "attachthreadinput", "keybd_event"],
    ),
    "ransomware": (
        25, 2, "zachowanie typowe dla ransomware (szyfrowanie plików masowych)",
        ["cryptencrypt", "cryptacquirecontext", "cryptderivekey", "cryptgenkey",
         "bcryptencrypt", "bcryptgeneratekeypair", "findfirstfile", "findnextfile",
         "getlogicaldrives", "getlogicaldrivestrings", "getdrivetype",
         "deletefile", "movefileex", "setfileattributes", "createfilemapping"],
    ),
    "persistence": (
        15, 2, "utrwalanie się w systemie (persistence)",
        ["regsetvalueex", "regcreatekeyex", "createservice", "startservice",
         "openservice", "changeserviceconfig", "setwindowshookex"],
    ),
    "evasion": (
        12, 3, "wykrywanie debugera / analizy (anti-analysis)",
        ["isdebuggerpresent", "checkremotedebuggerpresent", "outputdebugstring",
         "ntsetinformationthread", "zwsetinformationthread", "ntqueryinformationprocess",
         "ntqueryobject", "gettickcount", "queryperformancecounter",
         "getmodulehandle", "findwindow", "sleep"],
    ),
    "network": (
        12, 3, "komunikacja sieciowa (możliwy kanał C2)",
        ["urldownloadtofile", "urldownloadtofilea", "urldownloadtofilew",
         "internetopen", "internetopenurl", "internetreadfile", "internetconnect",
         "httpsendrequest", "httpsendrequesta", "httpopenrequest",
         "winhttpopen", "winhttpconnect", "wsastartup", "wsasocket", "wsaconnect",
         "connect", "send", "recv", "gethostbyname", "getaddrinfo", "ftpputfile"],
    ),
    "privilege": (
        12, 3, "podnoszenie uprawnień",
        ["adjusttokenprivileges", "lookupprivilegevalue", "openprocesstoken",
         "settokeninformation", "ntsetinformationprocess", " rtladjustprivilege"],
    ),
    "process_enum": (
        10, 3, "wyliczanie procesów (szukanie celu lub analizy)",
        ["createtoolhelp32snapshot", "process32first", "process32next",
         "enumprocesses", "enumprocessmodules", "ntquerysysteminformation"],
    ),
}

LOADER_STUB_APIS = {"loadlibrarya", "loadlibraryw", "getprocaddress", "virtualalloc",
                    "virtualprotect", "exitprocess", "ldrloaddll", "ldrgetprocedureaddress"}

KNOWN_PACKER_IMPHASH: Dict[str, str] = {}

RE_URL = re.compile(rb"https?://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;=%]{6,}", re.I)
RE_IPPORT = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b")
RE_CMDLINE = re.compile(rb"(?i)(cmd\.exe|powershell|wscript|cscript|rundll32|regsvr32|mshta|certutil|bitsadmin|schtasks)")


class PEHeuristicsDetector(Detector):
    name = "pe_heuristics"
    description = "Heurystyka strukturalna plików wykonywalnych Windows (PE)"

    def applies_to(self, ctx: ScanContext) -> bool:
        return ctx.file_type == "pe" and ctx.pe is not None

    def run(self, ctx: ScanContext) -> List[Finding]:
        pe = ctx.pe
        checks: List[Callable[[ScanContext, Any], None]] = [
            _check_entry_point,
            _check_sections,
            _check_packer_names,
            _check_imports,
            _check_tls_callbacks,
            _check_overlay,
            _check_timestamps,
            _check_checksum,
            _check_signature,
            _check_header_anomalies,
            _check_resources,
            _check_embedded_pe,
            _check_strings,
        ]
        for check in checks:
            try:
                check(ctx, pe)
            except Exception as exc:  # pojedyncza reguła nie może przerwać skanu
                ctx.add(
                    self.name, "analysis_error", Severity.INFO,
                    f"Reguła {check.__name__} nie powiodła się (możliwa próba anty-analizy)",
                    weight=6, evidence=f"{type(exc).__name__}: {exc}"[:300],
                )
        return ctx.result.findings


# --------------------------------------------------------------------------
# poszczególne reguły
# --------------------------------------------------------------------------

def _check_entry_point(ctx: ScanContext, pe: Any) -> None:
    try:
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        image_base = pe.OPTIONAL_HEADER.ImageBase
    except Exception:
        return
    sections = list(pe.sections)
    if not sections:
        ctx.add("pe_heuristics", "no_sections", Severity.HIGH,
                "Plik PE nie zawiera żadnych sekcji", weight=35)
        return

    containing = None
    for idx, s in enumerate(sections):
        if s.VirtualAddress <= ep < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            containing = (idx, s)
            break

    if containing is None:
        ctx.add("pe_heuristics", "entry_outside_sections", Severity.HIGH,
                "Entry point wskazuje poza wszystkie sekcje - typowe dla packerów",
                weight=30, evidence=f"EP RVA=0x{ep:x}")
    else:
        idx, s = containing
        name = _sname(s)
        if idx == len(sections) - 1 and len(sections) > 1:
            ctx.add("pe_heuristics", "entry_in_last_section", Severity.HIGH,
                    "Entry point znajduje się w ostatniej sekcji - klasyczna cecha packera",
                    weight=25, evidence=f"EP RVA=0x{ep:x} -> sekcja '{name}' (#{idx})")
        if s.Characteristics & SCN_WRITE:
            ctx.add("pe_heuristics", "entry_in_writable_section", Severity.HIGH,
                    "Entry point w sekcji z prawem zapisu - kod może się sam modyfikować",
                    weight=30, evidence=f"sekcja '{name}' jest zapisywalna")
        if not (s.Characteristics & SCN_EXECUTE):
            ctx.add("pe_heuristics", "entry_not_executable", Severity.MEDIUM,
                    "Sekcja z entry pointem nie ma prawa wykonania",
                    weight=20, evidence=f"sekcja '{name}'")
        if ep == 0:
            ctx.add("pe_heuristics", "entry_point_zero", Severity.MEDIUM,
                    "Entry point = 0 (netypowe dla poprawnego pliku wykonywalnego)",
                    weight=15)


def _check_sections(ctx: ScanContext, pe: Any) -> None:
    sections = list(pe.sections)
    for s in sections:
        name = _sname(s)
        is_w = bool(s.Characteristics & SCN_WRITE)
        is_x = bool(s.Characteristics & SCN_EXECUTE)
        if is_w and is_x:
            ctx.add("pe_heuristics", "section_wx", Severity.HIGH,
                    f"Sekcja '{name}' jest jednocześnie zapisywalna i wykonywalna (W+X)",
                    weight=25,
                    evidence="W+X omija W^X/DEP i jest standardem w shellcode loaderach")

    if len(sections) >= 10:
        ctx.add("pe_heuristics", "many_sections", Severity.MEDIUM,
                f"Nietypowo dużo sekcji ({len(sections)}) - częste w pakowanych plikach",
                weight=12)

    for s in sections:
        name = _sname(s)
        raw = s.SizeOfRawData
        vsize = s.Misc_VirtualSize
        if raw == 0 and vsize > 0:
            ctx.add("pe_heuristics", "empty_raw_section", Severity.MEDIUM,
                    f"Sekcja '{name}' nie zajmuje miejsca w pliku, ale rezerwuje {vsize} B w pamięci",
                    weight=12,
                    evidence="packer rozpakowuje kod dopiero w pamięci")
        elif raw > 0 and vsize > raw * 5 and vsize > 65536:
            ctx.add("pe_heuristics", "section_size_mismatch", Severity.MEDIUM,
                    f"Sekcja '{name}' w pamięci jest {vsize // max(1, raw)}x większa niż w pliku",
                    weight=12, evidence=f"raw={raw} virtual={vsize}")

    # Uwaga: nie obcinamy wiodącej kropki przed porównaniem - inaczej
    # sekcja ".text" zamienia się w "text" i reguła daje fałszywy alarm.
    names = [_sname(s).lower().strip() for s in sections]
    if not any(n.lstrip(".").startswith(("text", "code")) for n in names):
        ctx.add("pe_heuristics", "no_text_section", Severity.MEDIUM,
                "Brak sekcji wykonywalnej o standardowej nazwie (.text/CODE)",
                weight=10, evidence=f"sekcje: {', '.join(_sname(s) for s in sections)[:200]}")


def _check_packer_names(ctx: ScanContext, pe: Any) -> None:
    found: Set[str] = set()
    for s in pe.sections:
        raw_name = s.Name.rstrip(b"\x00").decode("latin-1", "ignore")
        key = raw_name.lower().rstrip("\x00")
        key_clean = key.lstrip(".")
        if key in PACKER_SECTIONS:
            found.add(PACKER_SECTIONS[key])
        elif key_clean in PACKER_SECTIONS:
            found.add(PACKER_SECTIONS[key_clean])
    for packer in sorted(found):
        ctx.add("pe_heuristics", "packer_section", Severity.HIGH,
                f"Wykryto sekcję charakterystyczną dla packera: {packer}",
                weight=30, evidence=f"znane sekcje packera: {packer}")


def _check_imports(ctx: ScanContext, pe: Any) -> None:
    imports = _collect_imports(pe)
    if not imports:
        ctx.add("pe_heuristics", "no_imports", Severity.MEDIUM,
                "Plik nie importuje żadnych funkcji - kod rozwiązuje API samodzielnie",
                weight=20, evidence="technika typowa dla shellcode i kryptorów")
        return

    names_lower = {n.lower() for n in imports}

    for category, (weight, min_hits, description, api_list) in API_CATEGORIES.items():
        hits = sorted({a for a in api_list if a.strip() in names_lower})
        if len(hits) >= min_hits:
            bonus = min(8, 3 * (len(hits) - min_hits))
            ctx.add("pe_heuristics", f"api_{category}", Severity.HIGH if weight >= 25 else Severity.MEDIUM,
                    f"{description.capitalize()}: {', '.join(hits[:6])}",
                    weight=weight + bonus,
                    evidence=f"kategoria={category} trafienia={len(hits)}")

    # Stub ładujący: mało importów, same funkcje do ładowania kodu.
    if len(imports) <= 8:
        loader_hits = names_lower & LOADER_STUB_APIS
        if len(loader_hits) >= 3:
            ctx.add("pe_heuristics", "loader_stub", Severity.MEDIUM,
                    "Minimalistyczny stub ładujący (LoadLibrary/GetProcAddress/VirtualAlloc)",
                    weight=18,
                    evidence=f"importy ({len(imports)}): {', '.join(sorted(imports))[:200]}")

    if names_lower and len(names_lower) == len(names_lower & LOADER_STUB_APIS):
        ctx.add("pe_heuristics", "only_loader_apis", Severity.HIGH,
                "Wszystkie importy to funkcje do ładowania kodu w pamięci",
                weight=25)

    # Importy po numerach porządkowych (ordinals) - utrudniają analizę.
    ordinal_only = 0
    total = 0
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for imp in entry.imports:
            total += 1
            if imp.ordinal is not None and not imp.name:
                ordinal_only += 1
    if total and ordinal_only / total > 0.3:
        ctx.add("pe_heuristics", "ordinal_imports", Severity.LOW,
                f"{ordinal_only}/{total} importów po numerach porządkowych (zaciemnianie)",
                weight=8)


def _check_tls_callbacks(ctx: ScanContext, pe: Any) -> None:
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if tls is None:
        return
    try:
        cb = tls.struct.AddressOfCallBacks
    except Exception:
        return
    if cb:
        ctx.add("pe_heuristics", "tls_callback", Severity.MEDIUM,
                "Obecne TLS callbacks - kod wykona się przed właściwym entry pointem",
                weight=15, evidence=f"AddressOfCallBacks=0x{cb:x}")


def _check_overlay(ctx: ScanContext, pe: Any) -> None:
    try:
        offset = pe.get_overlay_data_start_offset()
    except Exception:
        return
    if offset is None or offset >= len(ctx.data):
        return
    overlay = ctx.data[offset:]
    if len(overlay) < 64:
        return
    from ..entropy import shannon_entropy
    ent = shannon_entropy(overlay)
    if len(overlay) > 1024:
        ctx.add("pe_heuristics", "overlay_data", Severity.LOW,
                f"Za obrazem PE jest {len(overlay)} B nadmiarowych danych (overlay)",
                weight=8 if ent < 7.2 else 18,
                evidence=f"entropia overlay={ent:.2f} ({'zaszyfrowany payload' if ent >= 7.2 else 'dane/sygnatura'})")


def _check_timestamps(ctx: ScanContext, pe: Any) -> None:
    import time
    ts = getattr(pe.FILE_HEADER, "TimeDateStamp", 0)
    if ts == 0:
        ctx.add("pe_heuristics", "timestamp_zero", Severity.LOW,
                "Wyzerowana data kompilacji (zacieranie śladów)", weight=8)
        return
    now = int(time.time())
    # 0x78563412 i 0x12345678 to ulubione "śmieszne" wartości packerów
    if ts in (0x78563412, 0x12345678, 0x2A425E19, 0x210E1E19):
        ctx.add("pe_heuristics", "timestamp_fake", Severity.MEDIUM,
                f"Data kompilacji ma podejrzaną, 'ręcznie ustawioną' wartość (0x{ts:x})",
                weight=15)
    elif ts > now + 86400:
        ctx.add("pe_heuristics", "timestamp_future", Severity.MEDIUM,
                "Data kompilacji jest w przyszłości", weight=12)
    elif 0 < ts < 631152000:  # przed 1990
        ctx.add("pe_heuristics", "timestamp_old", Severity.LOW,
                "Data kompilacji wcześniejsza niż 1990", weight=6)


def _check_checksum(ctx: ScanContext, pe: Any) -> None:
    try:
        stored = pe.OPTIONAL_HEADER.CheckSum
        if stored == 0:
            return
        if not pe.verify_checksum():
            ctx.add("pe_heuristics", "bad_checksum", Severity.LOW,
                    "Suma kontrolna PE nie zgadza się z zawartością pliku",
                    weight=6,
                    evidence="plik był modyfikowany po kompilacji (patching/packer)")
    except Exception:
        pass


def _check_signature(ctx: ScanContext, pe: Any) -> None:
    try:
        has_sec_dir = bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size)
    except Exception:
        has_sec_dir = bool(getattr(pe, "DIRECTORY_ENTRY_SECURITY", None))
    if not has_sec_dir:
        ctx.add("pe_heuristics", "unsigned", Severity.INFO,
                "Plik nie jest podpisany cyfrowo (brak Authenticode)", weight=3,
                evidence="podpis cyfrowy to warunek konieczny, nie wystarczający - malware też bywa podpisany")


def _check_header_anomalies(ctx: ScanContext, pe: Any) -> None:
    try:
        if pe.FILE_HEADER.Characteristics & 0x0001:  # IMAGE_FILE_RELOCS_STRIPPED
            ctx.add("pe_heuristics", "relocs_stripped", Severity.LOW,
                    "Usunięte relokacje - typowe dla packerów", weight=6)
    except Exception:
        pass

    try:
        ib = pe.OPTIONAL_HEADER.ImageBase
        is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        expected = 0x10000000 if is_dll else 0x400000
        if ib not in (expected, 0x140000000, 0x180000000, 0x10000000, 0x400000):
            ctx.add("pe_heuristics", "unusual_imagebase", Severity.INFO,
                    f"Nietypowy ImageBase (0x{ib:x})", weight=4)
    except Exception:
        pass

    # Zmodyfikowany DOS stub (narzędzia packujące go podmieniają).
    try:
        stub = pe.get_data(0x40, min(64, pe.DOS_HEADER.e_lfanew - 0x40)) if pe.DOS_HEADER.e_lfanew > 0x40 else b""
        if stub and b"This program cannot be run in DOS mode" not in stub:
            ctx.add("pe_heuristics", "modified_dos_stub", Severity.LOW,
                    "Niestandardowy DOS stub (podmieniony przez packer)", weight=6)
    except Exception:
        pass


def _check_resources(ctx: ScanContext, pe: Any) -> None:
    from ..entropy import shannon_entropy
    try:
        res = pe.DIRECTORY_ENTRY_RESOURCE
    except Exception:
        return
    try:
        for entry in getattr(res, "entries", []):
            for rsrc in _iter_rsrc(entry):
                try:
                    data = pe.get_data(rsrc.data.struct.OffsetToData, rsrc.data.struct.Size)
                except Exception:
                    continue
                if len(data) < 2048:
                    continue
                ent = shannon_entropy(data)
                if ent > 7.3:
                    ctx.add("pe_heuristics", "encrypted_resource", Severity.MEDIUM,
                            f"Zasób w katalogu {entry.id} ma wysoką entropię ({ent:.2f}) - ukryty payload",
                            weight=15, evidence=f"rozmiar={len(data)} B")
                    break
    except Exception:
        pass


def _check_embedded_pe(ctx: ScanContext, pe: Any) -> None:
    """Szuka drugiego nagłówka MZ w overlayu - czyli dołączonego pliku wykonywalnego."""
    try:
        offset = pe.get_overlay_data_start_offset()
    except Exception:
        return
    if not offset:
        return
    overlay = ctx.data[offset:]
    hits = overlay.find(b"MZ")
    if hits > 0:
        ctx.add("pe_heuristics", "embedded_pe", Severity.MEDIUM,
                "W overlayu znaleziono kolejny nagłówek MZ (dołączony plik wykonywalny)",
                weight=20, evidence=f"offset=0x{offset + hits:x}")


def _check_strings(ctx: ScanContext, pe: Any) -> None:
    data = ctx.data
    urls = {u.decode("latin-1") for u in RE_URL.findall(data)}
    suspicious_cmd = {c.decode("latin-1").lower() for c in RE_CMDLINE.findall(data)}
    ipports = {i.decode("latin-1") for i in RE_IPPORT.findall(data)}

    # Filtrujemy adresy, które są powszechne w legalnym oprogramowaniu.
    benign_hints = ("microsoft.com", "w3.org", "schemas.", "adobe.com", "openssl",
                    "gnu.org", "python.org", "github.com", "apache.org", "jquery")
    urls = {u for u in urls if not any(h in u.lower() for h in benign_hints)}

    if ipports and len(ipports) <= 3:
        ctx.add("pe_heuristics", "hardcoded_ip_port", Severity.MEDIUM,
                "Zakodowany na stałe adres IP z portem - potencjalny serwer C2",
                weight=15, evidence=", ".join(sorted(ipports)[:3]))
    elif ipports:
        ctx.add("pe_heuristics", "hardcoded_ips", Severity.LOW,
                f"Zakodowane na stałe adresy IP ({len(ipports)})", weight=8,
                evidence=", ".join(sorted(ipports)[:3]))

    dangerous_cmd = suspicious_cmd & {"powershell", "certutil", "bitsadmin", "rundll32", "mshta", "regsvr32"}
    if dangerous_cmd:
        ctx.add("pe_heuristics", "living_off_the_land", Severity.MEDIUM,
                "Odwołania do narzędzi systemowych używanych do 'living off the land'",
                weight=15, evidence=", ".join(sorted(dangerous_cmd)))

    if urls and _has_exec_indicators(data):
        ctx.add("pe_heuristics", "url_and_exec", Severity.LOW,
                f"Plik zawiera {len(urls)} adresów URL oraz funkcje uruchamiające kod",
                weight=8, evidence="; ".join(sorted(urls)[:3]))


# --------------------------------------------------------------------------
# pomocnicze
# --------------------------------------------------------------------------

def _sname(section: Any) -> str:
    try:
        return section.Name.rstrip(b"\x00").decode("utf-8", "ignore") or "?"
    except Exception:
        return "?"


def _collect_imports(pe: Any) -> List[str]:
    out: List[str] = []
    try:
        entries = pe.DIRECTORY_ENTRY_IMPORT
    except Exception:
        return out
    for entry in entries or []:
        for imp in entry.imports:
            if imp.name:
                name = imp.name.decode("utf-8", "ignore")
                if name.startswith("_") and "@" in name:
                    name = name.split("@")[0].lstrip("_")
                out.append(name)
            elif imp.ordinal is not None:
                out.append(f"ord{imp.ordinal}")
    return out


def _iter_rsrc(entry: Any):
    """Spłaszcza drzewo zasobów do liści z danymi."""
    if hasattr(entry, "directory"):
        for e in entry.directory.entries:
            yield from _iter_rsrc(e)
    else:
        yield entry


def _has_exec_indicators(data: bytes) -> bool:
    lowered = data.lower()
    return any(x in lowered for x in (b"winexec", b"shellexecute", b"createprocess",
                                      b"urldownloadtofile", b"create remotethread"))
