"""Rozpoznawanie typu pliku na podstawie magii (nie rozszerzenia).

Rozszerzenie jest kontrolowane przez atakującego, więc silnik decyduje
na podstawie zawartości. To warunek konieczny: malware udający .txt/.jpg
musi trafić do właściwego analizatora.
"""

from __future__ import annotations

from typing import Optional


SIGNATURES = [
    (b"MZ", "pe", "dos/pe-executable"),
    (b"\x7fELF", "elf", "elf-executable"),
    (b"\xcf\xfa\xed\xfe", "macho", "mach-o (64-bit)"),
    (b"\xce\xfa\xed\xfe", "macho", "mach-o (32-bit)"),
    (b"\xfe\xed\xfa\xce", "macho", "mach-o (fat)"),
    (b"PK\x03\x04", "zip", "zip/office/jar/apk"),
    (b"Rar!\x1a\x07", "rar", "rar-archive"),
    (b"7z\xbc\xaf\x27\x1c", "7z", "7z-archive"),
    (b"\x1f\x8b", "gzip", "gzip"),
    (b"\xfd7zXZ\x00", "xz", "xz-archive"),
    (b"\x04\x22\x4d\x18", "lz4", "lz4"),
    (b"\x28\xb5\x2f\xfd", "zstd", "zstd"),
    (b"%PDF", "pdf", "pdf"),
    (b"\x89PNG\r\n\x1a\n", "image", "png"),
    (b"\xff\xd8\xff", "image", "jpeg"),
    (b"GIF87a", "image", "gif"),
    (b"GIF89a", "image", "gif"),
    (b"BM", "image", "bmp"),
    (b"ID3", "audio", "mp3"),
    (b"OggS", "audio", "ogg"),
    (b"RIFF", "media", "riff/wav/avi"),
    (b"\xd0\xcf\x11\xe0", "ole", "ole2 (stare office)"),
    (b"SQLite format 3\x00", "sqlite", "sqlite-db"),
    (b"#!", "script", "shebang-script"),
    (b"<?xml", "xml", "xml"),
]

# Rozszerzenia, które same w sobie nie są groźne, ale bywają nośnikami.
CONTAINER_EXT = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".jar", ".apk",
    ".docm", ".xlsm", ".pptm", ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt",
}
SCRIPT_EXT = {
    ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".wsh", ".hta", ".sh", ".py", ".pl", ".rb", ".php", ".lnk",
}
EXEC_EXT = {".exe", ".dll", ".scr", ".com", ".sys", ".drv", ".ocx", ".cpl", ".efi", ".mui", ".msi"}


def detect(data: bytes, path: str = "") -> str:
    """Zwraca identyfikator typu: pe | elf | script | zip | ... | text | binary."""
    head = data[:4096]

    for magic, kind, _label in SIGNATURES:
        if head.startswith(magic):
            if kind == "pe":
                return "pe" if is_pe(data) else "dos"
            if kind == "script":
                return "script"
            return kind

    # Pliki bez magii - rozstrzygamy po rozszerzeniu i treści.
    ext = _ext(path)
    if ext in SCRIPT_EXT:
        return "script"
    if ext in CONTAINER_EXT:
        return "archive"

    if not data:
        return "empty"

    # Heurystyka tekst/binaria: obecność bajtów sterujących.
    sample = data[:8192]
    if b"\x00" in sample:
        return "binary"
    non_text = sum(1 for b in sample if b < 9 or (13 < b < 32) or b > 126)
    if non_text / max(1, len(sample)) > 0.05:
        return "binary"
    return "text"


def is_pe(data: bytes) -> bool:
    if len(data) < 0x40 or not data.startswith(b"MZ"):
        return False
    try:
        e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
        return 0 < e_lfanew < len(data) - 4 and data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"
    except Exception:
        return False


def pretty(data: bytes, path: str = "") -> str:
    """Czytelna nazwa typu, do raportów i GUI."""
    head = data[:4096]
    for magic, kind, label in SIGNATURES:
        if head.startswith(magic):
            if kind == "pe":
                return label if is_pe(data) else "dos-executable (16-bit)"
            return label
    return detect(data, path)


def _ext(path: str) -> str:
    if not path:
        return ""
    idx = path.rfind(".")
    return path[idx:].lower() if idx > 0 else ""


def is_scannable(kind: str) -> bool:
    """Czy typ pliku niesie ryzyko warte analizy."""
    return kind in {
        "pe", "elf", "macho", "dos", "script", "archive", "zip", "rar", "7z",
        "ole", "pdf", "binary", "xml",
    }


def is_likely_double_extension(path: str) -> Optional[str]:
    """Wykrywa nazwy typu `faktura.pdf.exe` (podwójne rozszerzenie)."""
    name = path.replace("\\", "/").rsplit("/", 1)[-1]
    parts = name.split(".")
    if len(parts) >= 3 and parts[-1].lower() in EXEC_EXT | SCRIPT_EXT:
        return name
    return None
