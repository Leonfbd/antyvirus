"""Analiza archiwów - rozpakowanie i skanowanie zawartości.

Archiwa to najczęstszy sposób dostarczania malware („faktura.zip" z
`faktura.pdf.exe` w środku). Skaner, który nie zagląda do środka, przepuszcza
większość realnych infekcji.

Bezpieczeństwo samego rozpakowywania jest tu równie ważne jak wykrywanie:

  * **bomba zip** - plik 1 MB rozpakowujący się do 100 GB potrafi położyć
    skaner. Sprawdzamy współczynnik kompresji każdego elementu i łączny
    rozmiar przed rozpakowaniem.
  * **path traversal** - elementy o nazwach `../../evil.exe` to technika
    ataku (CVE-many), nie przypadek.
  * **zaszyfrowane archiwa** - nie da się zajrzeć do środka, więc werdykt
    brzmi „nieprzebadane", a nie „czyste".
  * **zagnieżdżenie** - ograniczona głębokość, żeby archiwum w archiwum
    w archiwum nie zamieniło się w wykładniczy wybuch pracy.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

from .filetype import EXEC_EXT, SCRIPT_EXT
from .models import Finding, ScanResult, Severity

# Domyślne limity (można nadpisać w Config).
MAX_DEPTH = 3
MAX_MEMBERS = 300
MAX_MEMBER_SIZE = 50 * 1024 * 1024
MAX_TOTAL_SIZE = 200 * 1024 * 1024
MAX_RATIO = 200          # stosunek rozmiaru po rozpakowaniu do skompresowanego

ARCHIVE_TYPES = {"zip", "gzip", "7z", "rar", "xz", "zstd"}
EXECUTABLE_INSIDE = EXEC_EXT | SCRIPT_EXT


@dataclass
class ArchiveMember:
    name: str
    size: int
    data: Optional[bytes] = None
    encrypted: bool = False
    skipped: Optional[str] = None

    @property
    def scannable(self) -> bool:
        return self.data is not None and not self.encrypted


@dataclass
class ArchiveReport:
    path: str
    kind: str
    members: int = 0
    scanned: int = 0
    threats: List[ScanResult] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "kind": self.kind,
            "members": self.members,
            "scanned": self.scanned,
            "threats": [t.to_dict() for t in self.threats],
            "notes": self.notes,
        }


class ArchiveScanner:
    """Rozpakowuje archiwum w pamięci i skanuje każdy element."""

    def __init__(self, engine) -> None:
        self.engine = engine
        cfg = engine.config
        self.max_depth = getattr(cfg, "max_archive_depth", MAX_DEPTH)
        self.max_members = getattr(cfg, "max_archive_members", MAX_MEMBERS)
        self.max_member_size = getattr(cfg, "max_member_size", MAX_MEMBER_SIZE)
        self.max_total = getattr(cfg, "max_total_extracted", MAX_TOTAL_SIZE)
        self.max_ratio = getattr(cfg, "max_compression_ratio", MAX_RATIO)

    # ------------------------------------------------------------------ API
    def iter_members(self, data: bytes, kind: str) -> Iterator[ArchiveMember]:
        """Wydobywa elementy archiwum z zachowaniem limitów bezpieczeństwa."""
        budget = {"bytes": 0, "count": 0}

        if kind == "zip":
            yield from self._iter_zip(data, budget)
        elif kind in {"gzip", "xz", "zstd"}:
            yield from self._iter_single_stream(data, kind)
        elif kind == "7z":
            yield from self._iter_7z(data, budget)
        elif kind == "rar":
            yield from self._iter_rar(data, budget)

    def scan(self, path: str, data: bytes, kind: str,
             depth: int = 0) -> Tuple[List[Finding], ArchiveReport]:
        """Skanuje zawartość archiwum; zwraca znaleziska dla pliku-rodzica."""
        report = ArchiveReport(path=path, kind=kind)
        findings: List[Finding] = []

        if depth >= self.max_depth:
            report.notes.append(f"osiągnięto maksymalną głębokość zagnieżdżenia ({self.max_depth})")
            return findings, report

        encrypted_members = 0
        executables: List[str] = []

        for member in self.iter_members(data, kind):
            report.members += 1

            if report.members > self.max_members:
                report.notes.append(f"przerwano po {self.max_members} elementach")
                break

            if member.name and _is_path_traversal(member.name):
                findings.append(Finding(
                    "archive", "path_traversal", Severity.HIGH.value,
                    f"Element archiwum próbuje wyjść poza katalog: {member.name[:80]}",
                    30, "technika znana z CVE-2007-5199 i podobnych"))
                continue

            if member.skipped:
                report.notes.append(f"{member.name[:60]}: {member.skipped}")
                if "zaszyfrowan" in (member.skipped or ""):
                    encrypted_members += 1
                continue

            if member.encrypted:
                encrypted_members += 1
                continue

            if member.data is None:
                continue

            suffix = Path(member.name or "").suffix.lower()
            if suffix in EXECUTABLE_INSIDE:
                executables.append(member.name)

            report.scanned += 1
            virtual_path = f"{path}::{member.name}"
            try:
                result = self.engine.scan_bytes(virtual_path, member.data, depth=depth + 1)
            except Exception as exc:
                report.notes.append(f"{member.name[:60]}: błąd skanu ({exc})")
                continue

            if result.verdict in ("malicious", "suspicious"):
                report.threats.append(result)
                weight = 100 if result.verdict == "malicious" else 35
                findings.append(Finding(
                    "archive", "nested_threat",
                    Severity.CRITICAL.value if weight == 100 else Severity.HIGH.value,
                    f"Wewnątrz archiwum wykryto zagrożenie: {member.name} "
                    f"({result.verdict}, {result.score} pkt)",
                    weight,
                    "; ".join(f"{f.detector}/{f.rule}" for f in result.findings[:3])[:300]))

        if encrypted_members:
            findings.append(Finding(
                "archive", "encrypted_archive", Severity.MEDIUM.value,
                f"Archiwum zawiera {encrypted_members} zaszyfrowanych elementów - "
                "nie można zweryfikować zawartości",
                15, "zaszyfrowane archiwum to standardowy sposób omijania skanerów"))

            if encrypted_members == report.members and report.members:
                findings.append(Finding(
                    "archive", "unscannable", Severity.LOW.value,
                    "Cała zawartość archiwum jest zaszyfrowana - plik pozostaje nieprzebadany",
                    5, None))

        if executables:
            findings.append(Finding(
                "archive", "executable_inside", Severity.LOW.value,
                f"Archiwum zawiera {len(executables)} plików wykonywalnych lub skryptów",
                8, ", ".join(executables[:4])))

        return findings, report

    # -------------------------------------------------------------- formaty
    def _iter_zip(self, data: bytes, budget: dict) -> Iterator[ArchiveMember]:
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except Exception as exc:
            yield ArchiveMember("?", 0, skipped=f"nie udało się otworzyć ZIP ({exc})")
            return

        with zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if budget["count"] >= self.max_members:
                    return

                # --- bomba zip: sprawdzamy PRZED rozpakowaniem ---
                compressed = max(1, info.compress_size)
                if info.file_size and info.file_size / compressed > self.max_ratio:
                    yield ArchiveMember(
                        info.filename, info.file_size,
                        skipped=f"podejrzenie bomby zip (współczynnik "
                                f"{info.file_size // compressed}:1)")
                    continue
                if info.file_size > self.max_member_size:
                    yield ArchiveMember(info.filename, info.file_size,
                                        skipped="element za duży")
                    continue
                if budget["bytes"] + info.file_size > self.max_total:
                    yield ArchiveMember(info.filename, info.file_size,
                                        skipped="przekroczono łączny budżet rozpakowania")
                    continue

                try:
                    payload = zf.read(info)
                except RuntimeError as exc:
                    # zipfile rzuca RuntimeError dla zaszyfrowanych elementów
                    yield ArchiveMember(info.filename, info.file_size,
                                        encrypted="password" in str(exc).lower()
                                        or "encrypted" in str(exc).lower())
                    continue
                except Exception as exc:
                    yield ArchiveMember(info.filename, info.file_size,
                                        skipped=f"błąd odczytu ({exc})")
                    continue

                budget["bytes"] += len(payload)
                budget["count"] += 1
                yield ArchiveMember(info.filename, len(payload), data=payload)

    def _iter_7z(self, data: bytes, budget: dict) -> Iterator[ArchiveMember]:
        """7z przez ekstrakcję do katalogu tymczasowego.

        API py7zr zmieniało się między wersjami (`readall`, potem `read`,
        potem `extract`), więc zamiast zgadywać korzystamy z mechanizmu
        wspólnego dla wszystkich wersji: extractall do katalogu.
        """
        import tempfile
        try:
            import py7zr
        except ImportError:
            yield ArchiveMember("?", 0, skipped="brak biblioteki py7zr (pip install py7zr)")
            return

        try:
            archive = py7zr.SevenZipFile(io.BytesIO(data))
        except Exception as exc:
            if "password" in str(exc).lower():
                yield ArchiveMember("?", 0, encrypted=True)
            else:
                yield ArchiveMember("?", 0, skipped=f"nie udało się otworzyć 7z ({exc})")
            return

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                needs_password = archive.needs_password()
            except Exception:
                needs_password = False
            if needs_password:
                yield ArchiveMember("?", 0, encrypted=True)
                archive.close()
                return
            try:
                archive.extractall(path=tmpdir)
            except Exception as exc:
                text = str(exc).lower()
                if "password" in text or "encrypt" in text:
                    yield ArchiveMember("?", 0, encrypted=True)
                else:
                    yield ArchiveMember("?", 0, skipped=f"błąd rozpakowania 7z ({exc})")
                archive.close()
                return
            archive.close()
            yield from self._walk_extracted(tmpdir, budget)

    def _iter_rar(self, data: bytes, budget: dict) -> Iterator[ArchiveMember]:
        """RAR wymaga biblioteki rarfile i zewnętrznego narzędzia (unrar/bsdtar)."""
        import tempfile
        try:
            import rarfile  # type: ignore
        except ImportError:
            yield ArchiveMember("?", 0, skipped="RAR wymaga biblioteki rarfile")
            return
        try:
            archive = rarfile.RarFile(io.BytesIO(data))
        except Exception as exc:
            yield ArchiveMember("?", 0, skipped=f"nie udało się otworzyć RAR ({exc})")
            return
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                archive.extractall(path=tmpdir)
            except Exception as exc:
                text = str(exc).lower()
                if "password" in text or "encrypt" in text:
                    yield ArchiveMember("?", 0, encrypted=True)
                else:
                    yield ArchiveMember("?", 0, skipped=f"błąd rozpakowania RAR ({exc})")
                return
            yield from self._walk_extracted(tmpdir, budget)

    def _walk_extracted(self, root: str, budget: dict) -> Iterator[ArchiveMember]:
        """Wydobywa pliki z katalogu, do którego rozpakowano archiwum."""
        import os
        for dirpath, _dirnames, filenames in os.walk(root):
            for filename in filenames:
                full = os.path.join(dirpath, filename)
                relative = os.path.relpath(full, root).replace("\\", "/")
                try:
                    size = os.path.getsize(full)
                except OSError:
                    continue
                if budget["count"] >= self.max_members:
                    return
                if size > self.max_member_size:
                    yield ArchiveMember(relative, size, skipped="element za duży")
                    continue
                if budget["bytes"] + size > self.max_total:
                    yield ArchiveMember(relative, size,
                                        skipped="przekroczono łączny budżet rozpakowania")
                    continue
                try:
                    with open(full, "rb") as fh:
                        payload = fh.read()
                except Exception as exc:
                    yield ArchiveMember(relative, size, skipped=f"błąd odczytu ({exc})")
                    continue
                budget["bytes"] += len(payload)
                budget["count"] += 1
                yield ArchiveMember(relative, len(payload), data=payload)

    def _iter_single_stream(self, data: bytes, kind: str) -> Iterator[ArchiveMember]:
        """gzip / xz / zstd zawierają jeden strumień danych."""
        try:
            if kind == "gzip":
                import gzip
                payload = gzip.decompress(data)
            elif kind == "xz":
                import lzma
                payload = lzma.decompress(data)
            else:
                try:
                    import zstandard  # type: ignore
                    payload = zstandard.ZstdDecompressor().decompress(data)
                except ImportError:
                    yield ArchiveMember("?", 0, skipped="zstd wymaga biblioteki zstandard")
                    return
        except Exception as exc:
            yield ArchiveMember("?", 0, skipped=f"błąd dekompresji ({exc})")
            return

        if len(payload) > self.max_member_size:
            yield ArchiveMember("content", len(payload), skipped="zawartość za duża")
            return
        yield ArchiveMember("content", len(payload), data=payload)


def _is_path_traversal(name: str) -> bool:
    if not name:
        return False
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        return True
    return ".." in normalized.split("/")


def is_archive(kind: str) -> bool:
    return kind in ARCHIVE_TYPES
