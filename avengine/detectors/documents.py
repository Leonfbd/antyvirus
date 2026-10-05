"""Warstwa 9: dokumenty Office (OLE i OOXML) oraz PDF.

Dokumenty to dziś najczęstszy wektor infekcji — nie pliki .exe. Przykładowy
przebieg: faktura .docm z makrem `AutoOpen`, które przez `WScript.Shell`
uruchamia PowerShella, a ten pobiera kolejny etap. Żadna z tych rzeczy nie
jest plikiem wykonywalnym, więc skaner patrzący tylko na PE nic nie zauważy.

Obsługiwane:
  * **OLE2** (stare .doc/.xls/.ppt) — strumienie VBA, osadzone obiekty
    (`\\x01Ole10Native` z nazwą pliku!), pola DDE.
  * **OOXML** (.docm/.xlsm/.pptm i zwykłe .docx) — `vbaProject.bin`,
    osadzenia, ActiveX, szablony zdalne, relacje zewnętrzne, DDE.
  * **PDF** — JavaScript, automatyczne akcje (`/OpenAction`, `/AA`),
    `/Launch`, osadzone pliki, linki, XFA, ukryte treści po dekompresji
    strumieni FlateDecode.
"""

from __future__ import annotations

import io
import re
import zipfile
import zlib
from typing import List, Optional, Tuple

from .base import Detector, ScanContext
from ..models import Severity

# --- słowa kluczowe VBA (makra są kompilowane do strumieni OLE) ---
VBA_RULES: List[Tuple[str, str, int, str]] = [
    ("vba_autorun", r"(?i)\b(auto_open|autoopen|auto_close|document_open|document_close|"
     r"document_beforeclose|workbook_open|workbook_activate|autoexec|auto_exit)\b",
     30, "Makro uruchamia się automatycznie przy otwarciu dokumentu"),
    ("macro_shell", r"(?i)(wscript\.shell|shell\s*\(|shellexecute|createobject\s*\(\s*[\"']shell)",
     35, "Makro uruchamia powłokę systemową"),
    ("macro_powershell", r"(?i)powershell", 25, "Makro wywołuje PowerShella"),
    ("macro_download", r"(?i)(urldownloadtofile|msxml2\.xmlhttp|adodb\.stream|"
     r"winhttprequest|internetopen|internetreadfile|createobject\s*\(\s*[\"']microsoft\.xmlhttp)",
     35, "Makro pobiera dane z internetu"),
    ("macro_obfuscate", r"(?i)(chr\s*\(\s*\d|chrw\s*\(|chrb\s*\(|strreverse|"
     r"executeexcel4macro|callbyname|base64)",
     20, "Zaciemnianie kodu makra (budowanie ciągów znak po znaku)"),
    ("macro_environ", r"(?i)environ\s*\(\s*[\"'](temp|appdata|public|userprofile|systemroot)",
     15, "Odwołanie do katalogów systemowych - typowy dropper"),
    ("macro_persistence", r"(?i)(regwrite|registry|savesetting|createtextfile)",
     25, "Makro zapisuje dane w systemie / rejestrze"),
    ("macro_evasion", r"(?i)(application\.displayalerts\s*=\s*false|enableevents\s*=\s*false|"
     r"application\.visible\s*=\s*false)",
     12, "Wyłączanie ostrzeżeń - ukrywanie działań przed użytkownikiem"),
    ("macro_dde", r"(?i)(ddeinitiate|ddeexecute|dderequest|ddepoke)",
     30, "Komunikacja DDE - technika bez plików wykonywalnych"),
]

# --- wzorce PDF ---
PDF_PATTERNS = {
    "js": rb"/JavaScript|/JS\s",
    "openaction": rb"/OpenAction|/AA\s|/AA>|/OpenAction\b",
    "launch": rb"/Launch\b",
    "embedded": rb"/EmbeddedFile|/Type\s*/Filespec",
    "uri": rb"/URI\s",
    "goto_r": rb"/GoToR\b",
    "xfa": rb"/XFA\b",
    "encrypt": rb"/Encrypt\b",
    "objstm": rb"/ObjStm\b",
    "acroform": rb"/AcroForm\b",
}
# Słowa kluczowe w kodzie JavaScript wewnątrz PDF-a (często zaciemnionego).
PDF_JS_RULES: List[Tuple[str, str, int, str]] = [
    ("pdf_js_obfuscated", r"(?i)(unescape|string\.fromcharcode|eval\s*\(|atob)",
     30, "Zaciemniony JavaScript w PDF"),
    ("pdf_js_shell", r"(?i)(app\.launch|doc\.exportDataObject|this\.exportDataObject|"
     r"app\.openDoc|getURL|submitForm)",
     35, "JavaScript w PDF próbuje uruchomić plik lub wysłać dane"),
    ("pdf_js_print", r"(?i)(this\.print|util\.printf|app\.alert)", 12,
     "JavaScript w PDF steruje drukowaniem / komunikatami"),
    ("pdf_js_shellcode", r"(?i)(heap\s*spray|0x0c0c0c0c|\\u9090|\\x90{20,}|shellcode)",
     45, "Wzorce shellcode'u w JavaScript PDF"),
]

OOXML_MACRO_PATHS = ("word/vbaproject.bin", "xl/vbaproject.bin", "ppt/vbaproject.bin",
                     "vbaproject.bin")
OOXML_EMBEDDED = ("embeddings/", "/oleobject", "oleobject")
OOXML_ACTIVEX = ("activex/", "activex")


class DocumentDetector(Detector):
    name = "documents"
    description = "Dokumenty Office (makra, osadzenia, DDE) i PDF (JavaScript, auto-akcje)"
    expensive = False

    def applies_to(self, ctx: ScanContext) -> bool:
        return ctx.file_type in {"ole", "pdf", "zip"} and len(ctx.data) > 0

    def run(self, ctx: ScanContext) -> List:
        if ctx.file_type == "ole":
            self._analyze_ole(ctx)
        elif ctx.file_type == "pdf":
            self._analyze_pdf(ctx)
        elif ctx.file_type == "zip":
            self._analyze_ooxml(ctx)
        return ctx.result.findings

    # ------------------------------------------------------------------- OLE
    def _analyze_ole(self, ctx: ScanContext) -> None:
        try:
            import olefile
        except ImportError:
            ctx.add(self.name, "ole_unavailable", Severity.INFO.value,
                    "Brak biblioteki olefile - nie sprawdzono struktury OLE", weight=0)
            return

        try:
            ole = olefile.OleFileIO(io.BytesIO(ctx.data))
        except Exception as exc:
            ctx.add(self.name, "ole_broken", Severity.LOW.value,
                    f"Nie udało się otworzyć struktury OLE ({exc})", weight=5)
            return

        with ole:
            try:
                entries = ["/".join(part) for part in ole.listdir()]
            except Exception:
                entries = []

            macro_containers = [e for e in entries
                                if "vba" in e.lower() or "macro" in e.lower()
                                or "_vba_project_cur" in e.lower()]
            if macro_containers:
                ctx.add(self.name, "ole_macro_container", Severity.HIGH.value,
                        "Dokument zawiera projekt VBA (makra)", 25,
                        ", ".join(macro_containers[:3]))

            # --- treść makr ---
            collected = bytearray()
            for entry in entries:
                lowered = entry.lower()
                if "vba" in lowered or "macro" in lowered or "dir" in lowered:
                    try:
                        collected += ole.openstream(entry.split("/")).read() or b""
                    except Exception:
                        continue
            if collected:
                self._scan_vba(ctx, bytes(collected), source="VBA (OLE)")

            # --- osadzone obiekty (np. \\x01Ole10Native niesie NAZWĘ pliku) ---
            for entry in entries:
                if "ole10native" in entry.lower() or "ole" == entry.lower()[:3] and "native" in entry.lower():
                    try:
                        blob = ole.openstream(entry.split("/")).read()
                    except Exception:
                        continue
                    self._check_ole_native(ctx, blob)

            # --- pola DDE w treści dokumentu ---
            if re.search(rb"(?i)ddeauto|dde\s|\\field\s*\\*\s*\\f\d", ctx.data):
                ctx.add(self.name, "dde_field", Severity.HIGH.value,
                        "Dokument zawiera pole DDE - technika infekcji bez plików "
                        "wykonywalnych (np. przez cmd / rundll32)", 30,
                        "DDEAUTO/DDE wykonuje polecenie przy otwarciu dokumentu")

    def _check_ole_native(self, ctx: ScanContext, blob: bytes) -> None:
        """\\x01Ole10Native: [oryginalna nazwa][ścieżka][dane] - nazwa to wskazówka."""
        try:
            parts = blob.split(b"\x00")
            names = [p for p in parts if 3 < len(p) < 260]
            for candidate in names[:4]:
                text = candidate.decode("latin-1", "ignore")
                if re.search(r"\.(exe|dll|scr|bat|cmd|ps1|vbs|js|hta|lnk|jar)$", text, re.I):
                    ctx.add(self.name, "ole_embedded_executable", Severity.HIGH.value,
                            f"W dokumencie osadzono plik wykonywalny: {text}", 35,
                            "osadzony obiekt OLE z własną nazwą pliku")
                    return
            if names:
                ctx.add(self.name, "ole_embedded", Severity.LOW.value,
                        "Dokument zawiera osadzony obiekt OLE", 8,
                        (names[0].decode("latin-1", "ignore"))[:120])
        except Exception:
            pass

    # ----------------------------------------------------------------- OOXML
    def _analyze_ooxml(self, ctx: ScanContext) -> None:
        """OOXML to ZIP - sprawdzamy, czy to dokument, czy zwykłe archiwum."""
        try:
            zf = zipfile.ZipFile(io.BytesIO(ctx.data))
        except Exception:
            return

        # Uwaga: `with zf:` zamyka archiwum - wszystkie odczyty muszą odbyć
        # się wewnątrz bloku (albo przed jawnym close()), inaczej skończą się
        # błędem "I/O operation on closed file".
        macro_raw: Optional[bytes] = None
        external: List[str] = []
        try:
            names = [i.filename.lower() for i in zf.infolist()]

            is_ooxml = any(n.startswith(("word/", "xl/", "ppt/", "_rels/", "docprops/"))
                           or n == "[content_types].xml" for n in names)
            if not is_ooxml:
                return   # zwykły ZIP - zajmuje się nim warstwa archiwów

            macros = [n for n in names
                      if n in OOXML_MACRO_PATHS or n.endswith("vbaproject.bin")]
            if macros:
                ctx.add(self.name, "ooxml_macro", Severity.HIGH.value,
                        "Dokument Office zawiera makra (vbaProject.bin)", 28,
                        ", ".join(macros[:3]))
                real_name = next((n for n in zf.namelist() if n.lower() in macros), None)
                if real_name:
                    try:
                        with zf.open(real_name) as fh:
                            macro_raw = fh.read()
                    except Exception:
                        macro_raw = None

            embedded = [n for n in names if any(token in n for token in OOXML_EMBEDDED)]
            if embedded:
                ctx.add(self.name, "ooxml_embedded", Severity.MEDIUM.value,
                        f"Dokument zawiera {len(embedded)} osadzonych obiektów OLE", 15,
                        ", ".join(embedded[:3]))

            activex = [n for n in names if any(token in n for token in OOXML_ACTIVEX)]
            if activex:
                ctx.add(self.name, "ooxml_activex", Severity.HIGH.value,
                        "Dokument zawiera kontrolki ActiveX", 25, ", ".join(activex[:3]))

            # Relacje zewnętrzne i zdalne szablony (T1221).
            external = self._collect_external_refs(zf, names)
        finally:
            zf.close()

        if macro_raw:
            # Treść VBA jest pakowana (MS-OVBA), ale ciągi ASCII w większości
            # przetrwają, więc skanujemy surowo - i tak wyłapujemy AutoOpen,
            # WScript.Shell, URLDownloadToFile i spółkę.
            self._scan_vba(ctx, macro_raw, source="vbaProject.bin")
        if external:
            ctx.add(self.name, "ooxml_external_ref", Severity.MEDIUM.value,
                    "Dokument odwołuje się do zasobów zewnętrznych "
                    "(szablon / obraz / treść z sieci)", 20,
                    "; ".join(external[:3])[:200])

    def _collect_external_refs(self, zf, names: List[str]) -> List[str]:
        external: List[str] = []
        for name in names:
            if not name.endswith(".rels"):
                continue
            try:
                with zf.open(name) as fh:
                    text = fh.read().decode("utf-8", "ignore")
            except Exception:
                continue
            for match in re.finditer(r'Target="([^"]+)"[^>]*TargetMode="External"', text, re.I):
                external.append(match.group(1))
            for match in re.finditer(r'(?i)Target="(https?://[^"]*)"', text):
                external.append(match.group(1))
        return [e for e in external if e.startswith(("http", "ftp", "\\"))]

    # ------------------------------------------------------------------- PDF
    def _analyze_pdf(self, ctx: ScanContext) -> None:
        data = ctx.data
        found = {key: bool(re.search(pattern, data))
                 for key, pattern in PDF_PATTERNS.items()}

        # Dekompresja strumieni FlateDecode - tam ukrywa się działający kod.
        decompressed = self._decompress_streams(data)
        blob = data + b"\n" + decompressed
        found = {key: bool(re.search(pattern, blob))
                 for key, pattern in PDF_PATTERNS.items()}

        if found["js"]:
            auto = found["openaction"] or found["acroform"]
            if auto:
                ctx.add(self.name, "pdf_js_auto", Severity.CRITICAL.value,
                        "PDF zawiera JavaScript uruchamiany automatycznie "
                        "(/OpenAction lub /AA) - wykonuje się przy otwarciu pliku",
                        45, "najczęstszy nośnik exploitów w PDF")
            else:
                ctx.add(self.name, "pdf_js", Severity.HIGH.value,
                        "PDF zawiera JavaScript", 30)

        if found["launch"]:
            ctx.add(self.name, "pdf_launch", Severity.CRITICAL.value,
                    "PDF zawiera akcję /Launch - może uruchomić zewnętrzny program",
                    45, "/Launch pozwala odpalić polecenie systemowe")

        if found["embedded"]:
            ctx.add(self.name, "pdf_embedded", Severity.MEDIUM.value,
                    "PDF zawiera osadzony plik (/EmbeddedFile)", 18,
                    "osadzone pliki bywają nośnikiem drugiego etapu infekcji")

        if found["xfa"]:
            ctx.add(self.name, "pdf_xfa", Severity.MEDIUM.value,
                    "PDF zawiera formularz XFA (rzadko używany, często nadużywany)",
                    12)

        if found["uri"] or found["goto_r"]:
            urls = re.findall(rb"/URI\s*\(([^)]{4,200})\)", blob)
            ctx.add(self.name, "pdf_uri", Severity.LOW.value,
                    f"PDF zawiera {max(1, len(urls))} odnośników zewnętrznych", 8,
                    "; ".join(u.decode("latin-1", "ignore") for u in urls[:2]) or None)

        # Plik bez tablicy xref jest uszkodzony - bywa to wynikiem celowego
        # zniekształcenia, żeby parsery (i skanery) widziały co innego niż
        # czytnik ofiary. Wynik to osobny, lekki sygnał - uszkodzenie nie jest
        # jeszcze dowodem złośliwości.
        if not re.search(rb"\bxref\b", data) or not re.search(rb"\bstartxref\b", data):
            ctx.add(self.name, "pdf_malformed", Severity.LOW.value,
                    "PDF bez poprawnej tablicy xref / startxref - plik uszkodzony "
                    "lub celowo zniekształcony, co utrudnia analizę", 5)

        if found["encrypt"]:
            ctx.add(self.name, "pdf_encrypted", Severity.INFO.value,
                    "PDF jest zaszyfrowany - część treści pozostaje nieprzebadana", 5)

        # Kod JavaScript wewnątrz PDF-a nierzadko jest zaciemniony.
        if found["js"]:
            for name, pattern, weight, description in PDF_JS_RULES:
                if re.search(pattern, blob.decode("latin-1", "ignore")):
                    ctx.add(self.name, name,
                            Severity.CRITICAL.value if weight >= 45 else Severity.HIGH.value
                            if weight >= 30 else Severity.MEDIUM.value,
                            description, weight)

    @staticmethod
    def _decompress_streams(data: bytes, limit: int = 8 * 1024 * 1024) -> bytes:
        """Dekompresuje strumienie FlateDecode, żeby zobaczyć ukrytą treść."""
        out = bytearray()
        for match in re.finditer(rb"stream\r?\n", data):
            start = match.end()
            end = data.find(b"endstream", start)
            if end < 0:
                continue
            chunk = data[start:end]
            for attempt in (chunk, chunk.strip(b"\r\n")):
                try:
                    out += zlib.decompress(attempt)
                    break
                except zlib.error:
                    try:
                        out += zlib.decompressobj().decompress(attempt)
                        break
                    except Exception:
                        continue
            if len(out) > limit:
                break
        return bytes(out)

    # -------------------------------------------------------------------- VBA
    def _scan_vba(self, ctx: ScanContext, blob: bytes, source: str) -> None:
        """Skanuje (ewentualnie spakowany) kod VBA w poszukiwaniu wzorców."""
        try:
            text = blob.decode("latin-1", "ignore")
        except Exception:
            return
        printable = sum(1 for ch in text[:200000] if 32 <= ord(ch) < 127 or ch in "\r\n\t")
        if printable / max(1, len(text[:200000])) < 0.3:
            # Strumień jest spakowany - szukamy tylko ciągów ASCII.
            text = "\n".join(_ascii_strings(blob))

        for name, pattern, weight, description in VBA_RULES:
            if re.search(pattern, text):
                severity = (Severity.CRITICAL if weight >= 35
                            else Severity.HIGH if weight >= 25
                            else Severity.MEDIUM)
                match = re.search(pattern, text)
                ctx.add(self.name, name, severity, description, weight,
                        f"{source}: ...{(match.group(0) if match else '')[:60]}...")


def _ascii_strings(data: bytes, min_length: int = 5) -> List[str]:
    """Wyciąga ciągi znaków ASCII - działa też na spakowanych strumieniach VBA."""
    found: List[str] = []
    current = bytearray()
    for byte in data:
        if 32 <= byte < 127:
            current.append(byte)
        else:
            if len(current) >= min_length:
                found.append(current.decode("latin-1"))
            current = bytearray()
    if len(current) >= min_length:
        found.append(current.decode("latin-1"))
    return found
