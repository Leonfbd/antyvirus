"""Warstwa 5: heurystyka skryptów (PowerShell, JS, VBS, BAT, HTA, makra).

Współczesny malware rzadko jest plikiem .exe - zaczyna się od dokumentu albo
skryptu. Ta warstwa szuka wzorców "fileless" i technik living-off-the-land.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import List, Tuple

from .base import Detector, ScanContext
from ..models import Severity

# (nazwa, wyrażenie, waga, opis)
POWERSHELL_RULES: List[Tuple[str, str, int, str]] = [
    ("ps_encoded", r"(?i)-e(nc|ncodedcommand|ncoded)\b", 30,
     "PowerShell uruchamiany z zakodowanym poleceniem (-enc)"),
    ("ps_iex", r"(?i)\b(i`?e`?x|invoke-expression)\s*[\(\s]", 25,
     "Invoke-Expression - wykonanie kodu zbudowanego w czasie działania"),
    ("ps_download", r"(?i)(net\.webclient|downloadstring|downloadfile|download-data|invoke-webrequest|iwr\b|start-bitstransfer)",
     25, "Pobieranie kodu z sieci do pamięci"),
    ("ps_frombase64", r"(?i)(frombase64string|convert\s+from-base64)", 20,
     "Dekodowanie Base64 - typowy sposób ukrycia payloadu"),
    ("ps_amsi_bypass", r"(?i)(amsiutils|amsi\.dll|amsiInitFailed|setvalue\([^)]*amsi|reflection\.assembly.*amsi)", 40,
     "Próba wyłączenia AMSI (Antimalware Scan Interface)"),
    ("ps_defender_off", r"(?i)(set-mppreference|add-mppreference|set-processmitigation.*-disable|DisableRealtimeMonitoring|tamperprotection)",
     40, "Próba wyłączenia ochrony Windows Defender"),
    ("ps_hidden", r"(?i)(-w(indowstyle)?\s+hidden|-noprofile|-noexit|-noninteractive|-executionpolicy\s+bypass)", 12,
     "Uruchomienie ukryte / z obejściem polityki wykonywania"),
    ("ps_invoke_obf", r"(?i)(invoke-obfuscation|invoke-cradle|invoke-psimage|invoke-shellcode|invoke-dllinjection|invoke-mimikatz)",
     45, "Użycie znanych narzędzi ofensywnych (Invoke-*)"),
    ("ps_reflection", r"(?i)(\[reflection\.assembly\]::load|\[system\.reflection\]|loadwithpartialname)", 18,
     "Ładowanie zestawu .NET z pamięci (reflection)"),
    ("ps_shellcode", r"(?i)(virtualalloc|marshal::copy|getdelegateforfunctionpointer|0x(?:fc|e8|48|8b|89|55))", 20,
     "Wzorce uruchamiania shellcode'u w pamięci"),
    ("ps_persist", r"(?i)(new-itemproperty.*\\\\run|hkcu:\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run|schtasks|new-scheduledtask)",
     30, "Utrwalanie się w systemie (Run / zadania harmonogramu)"),
    ("ps_cred", r"(?i)(mimikatz|sekurlsa|lsass|invoke-kerberoast|convertto-securestring|get-credential)", 35,
     "Operacje na poświadczeniach (kradzież haseł)"),
]

JS_RULES: List[Tuple[str, str, int, str]] = [
    ("js_eval", r"(?i)\beval\s*\(", 22, "eval() - wykonanie dynamicznie zbudowanego kodu"),
    ("js_unescape", r"(?i)(unescape|decodeuricomponent|fromcharcode)", 18,
     "Dekodowanie ciągu znaków (zaciemnianie)"),
    ("js_activex", r"(?i)(activexobject|wscript\.shell|shell\.application|scripting\.filesystemobject)",
     30, "Użycie obiektów ActiveX do operacji na systemie"),
    ("js_run", r"(?i)\.(run|exec|shellexecute)\s*\(", 20, "Uruchamianie zewnętrznego procesu"),
    ("js_download", r"(?i)(msxml2\.xmlhttp|adodb\.stream|winhttp|curl|wget|\$\(\s*new-object\s+net\.webclient)", 25,
     "Pobieranie plików z internetu"),
    ("js_hta_drop", r"(?i)(savetofile|writealltext|adodb\.stream)", 18, "Zapis pobranych danych na dysk"),
]

BAT_RULES: List[Tuple[str, str, int, str]] = [
    ("bat_powershell", r"(?i)powershell(\.exe)?\b", 18, "Wywołanie PowerShella z BAT-a"),
    ("bat_certutil", r"(?i)certutil\s+(-decode|-urlcache|-split)", 35,
     "certutil użyty do dekodowania/pobierania - znana technika LOLBIN"),
    ("bat_bitsadmin", r"(?i)bitsadmin\s+/transfer", 35, "bitsadmin do pobrania payloadu (LOLBIN)"),
    ("bat_shadowcopy", r"(?i)(vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|vssadmin\s+resize)", 45,
     "Usuwanie kopii w tle - przygotowanie do ataku ransomware"),
    ("bat_bcdedit", r"(?i)(bcdedit\s+/set\s+.{0,40}(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures))", 40,
     "Wyłączenie odzyskiwania systemu (ransomware)"),
    ("bat_cipher", r"(?i)cipher\s+/w\s*:", 25, "Bezpieczne kasowanie danych (cipher /w) - niszczenie śladów"),
    ("bat_persist", r"(?i)(reg\s+add\s+.{0,80}(run|runonce)|schtasks\s+/create|sc\s+create)", 25,
     "Utrwalanie się w systemie"),
    ("bat_disable_av", r"(?i)(net\s+stop\s+.{0,30}(defender|avp|mcafee|symantec)|taskkill\s+/f\s+/im\s+(msmpeng|avp))", 45,
     "Próba zatrzymania antywirusa"),
    ("bat_encoded", r"(?i)(-e(nc)?\s+[A-Za-z0-9+/=]{100,}|-[eE][nN][cC][oO][dD][eE][dD][cC][oO][mM][mM][aA][nN][dD])", 35,
     "Zakodowane polecenie (Base64) w skrypcie wsadowym"),
]

MACRO_RULES: List[Tuple[str, str, int, str]] = [
    ("macro_auto", r"(?i)\b(auto_open|autoopen|document_open|workbook_open|autoexec|auto_close)\b", 25,
     "Makro uruchamiane automatycznie przy otwarciu dokumentu"),
    ("macro_shell", r"(?i)(createobject\(\s*[\"'](wscript\.shell|shell\.application)|shell\s*\()", 35,
     "Makro uruchamia powłokę systemową"),
    ("macro_download", r"(?i)(urldownloadtofile|msxml2\.xmlhttp|adodb\.stream|winhttprequest)", 35,
     "Makro pobiera pliki z internetu"),
    ("macro_powershell", r"(?i)powershell", 25, "Makro wywołuje PowerShella"),
    ("macro_obfuscate", r"(?i)(chr\(\s*\d+|chrb|chrw|stremp|executeexcel4macro)", 20,
     "Zaciemnianie kodu makra (budowanie ciągów znak po znaku)"),
    ("macro_environ", r"(?i)(environ\(\s*[\"'](temp|appdata|public|userprofile))", 20,
     "Odwołanie do katalogów tymczasowych - typowy dropper"),
]

RE_LONG_B64 = re.compile(rb"[A-Za-z0-9+/]{200,}={0,2}")
RE_HEX_BLOB = re.compile(rb"(?:\\x[0-9A-Fa-f]{2}){24,}|(?:[0-9A-Fa-f]{2}){200,}")
RE_IP_URL = re.compile(rb"https?://(?:\d{1,3}\.){3}\d{1,3}[^\s\"'<>]{0,80}")


class ScriptHeuristicsDetector(Detector):
    name = "script_heuristics"
    description = "Heurystyka skryptów PowerShell/JS/VBS/BAT i makr Office"

    def applies_to(self, ctx: ScanContext) -> bool:
        if ctx.file_type not in {"script", "text", "xml", "binary", "ole", "zip"}:
            return False
        return len(ctx.data) > 0

    def run(self, ctx: ScanContext) -> List[Finding]:
        try:
            text = ctx.data.decode("utf-8", "ignore")
        except Exception:
            return ctx.result.findings
        low = ctx.path.lower()
        hits = 0

        # PowerShell - włączamy, gdy rozszerzenie wskazuje PS albo treść go używa.
        is_ps = low.endswith((".ps1", ".psm1", ".psd1")) or "powershell" in text.lower()
        if is_ps:
            hits += self._apply(ctx, text, "powershell", POWERSHELL_RULES)

        is_js = low.endswith((".js", ".jse", ".hta", ".wsf", ".vbs", ".vbe")) or "<script" in text.lower()
        if is_js:
            hits += self._apply(ctx, text, "script", JS_RULES)

        is_bat = low.endswith((".bat", ".cmd"))
        if is_bat:
            hits += self._apply(ctx, text, "batch", BAT_RULES)

        if ctx.file_type == "ole" or low.endswith((".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm")):
            hits += self._apply(ctx, text, "macro", MACRO_RULES)

        # --- generyczne wskaźniki zaciemniania (niezależne od języka) ---
        self._check_blobs(ctx, text, hits)
        return ctx.result.findings

    def _apply(self, ctx: ScanContext, text: str, family: str,
               rules: List[Tuple[str, str, int, str]]) -> int:
        hits = 0
        for name, pattern, weight, description in rules:
            try:
                if re.search(pattern, text):
                    hit = re.search(pattern, text)
                    evidence = (hit.group(0) or "")[:120].replace("\n", " ")
                    sev = (Severity.CRITICAL if weight >= 40
                           else Severity.HIGH if weight >= 25
                           else Severity.MEDIUM if weight >= 15 else Severity.LOW)
                    ctx.add(self.name, f"{family}.{name}", sev, description,
                            weight=weight, evidence=f"...{evidence}...")
                    hits += 1
            except re.error:
                continue
        return hits

    def _check_blobs(self, ctx: ScanContext, text: str, prior_hits: int) -> None:
        raw = ctx.data

        b64 = RE_LONG_B64.search(raw)
        if b64:
            blob = b64.group(0)
            decoded_ok = False
            try:
                decoded = base64.b64decode(blob[:4096] + b"===", validate=False)
                decoded_ok = len(decoded) > 32 and sum(32 <= b < 127 for b in decoded[:64]) / 64 > 0.4
            except (binascii.Error, ValueError):
                pass
            weight = 25 if decoded_ok else 10
            # Sam Base64 jest neutralny - staje się podejrzany w towarzystwie
            # innych wskaźników albo gdy da się zdekodować do czytelnego kodu.
            if decoded_ok or prior_hits:
                ctx.add(self.name, "obfuscation.long_base64", Severity.MEDIUM,
                        f"Długi ciąg Base64 ({len(blob)} zn.)"
                        + (" który dekoduje się do czytelnej treści" if decoded_ok else ""),
                        weight=weight, evidence=blob[:80].decode("latin-1", "ignore"))

        if RE_HEX_BLOB.search(raw):
            ctx.add(self.name, "obfuscation.hex_blob", Severity.LOW,
                    "Długi ciąg szesnastkowy (escaped hex) - typowy nośnik shellcode'u",
                    weight=12)

        ip_url = RE_IP_URL.search(raw)
        if ip_url:
            ctx.add(self.name, "network.raw_ip_url", Severity.MEDIUM,
                    "Adres URL zamiast nazwy domenowej wskazuje bezpośrednio na IP",
                    weight=18, evidence=ip_url.group(0).decode("latin-1", "ignore")[:120])

        # Bardzo długie linie to klasyczny objaw zaciemniania (minifikacja ładunku).
        lines = raw.split(b"\n")
        longest = max((len(l) for l in lines), default=0)
        if longest > 5000:
            ctx.add(self.name, "obfuscation.long_line", Severity.LOW,
                    f"Znaleziono linię o długości {longest} znaków (zaciemnianie)", weight=8)
