"""Warstwa kryptograficzna i fuzzy-hashing.

Trzy rodziny haszy, każda do czego innego:
  * md5 / sha1 / sha256 - identyfikacja exact-match (porównanie z bazą sygnatur)
  * ssdeep (context triggered piecewise hash) - podobieństwo do znanych próbek
  * imphash - "odcisk palca" tabeli importów PE; ten sam imphash = ten sam
    packer/kompilator/rodzina malware, nawet gdy bajty pliku się różnią
"""

from __future__ import annotations

import hashlib
from typing import Dict, Optional

try:
    import ppdeep as _ppdeep
except Exception:  # pragma: no cover - opcjonalne
    _ppdeep = None


CHUNK = 1024 * 1024


def file_hashes(path: str) -> Dict[str, str]:
    """Zwraca md5/sha1/sha256 pliku, czytając go strumieniowo."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def bytes_hashes(data: bytes) -> Dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def ssdeep_hash(data: bytes) -> str:
    """Fuzzy hash ssdeep. Zwraca "" gdy biblioteka niedostępna lub plik za mały."""
    if _ppdeep is None:
        return ""
    try:
        return _ppdeep.hash(data) or ""
    except Exception:
        return ""


def ssdeep_compare(a: str, b: str) -> int:
    """Porównanie dwóch haszy ssdeep -> 0..100.

    Uwaga: ssdeep potrafi zwrócić wynik >0 dla całkiem różnych plików,
    dlatego wywołujący kod traktuje próg podobieństwa ostrożnie.
    """
    if not a or not b or _ppdeep is None:
        return 0
    try:
        return int(_ppdeep.compare(a, b))
    except Exception:
        return 0


def imphash(pe) -> str:
    """Import hash (wzorowany na Mandiant imphash).

    Kolejność: DLL w kolejności deskryptorów, nazwa bez rozszerzenia,
    potem nazwa funkcji (lub `ordNNN` gdy import po numerze porządkowym).
    """
    try:
        entries = getattr(pe, "DIRECTORY_ENTRY_IMPORT", None)
        if not entries:
            return ""
        parts: list[str] = []
        for entry in entries:
            dll = (entry.dll or b"").decode("utf-8", "ignore").lower()
            if not dll:
                continue
            if dll.endswith(".dll"):
                dll = dll[:-4]
            elif dll.endswith(".sys"):
                dll = dll[:-4]
            elif "." in dll:
                dll = dll.split(".")[0]
            for imp in entry.imports:
                if imp.name:
                    name = imp.name.decode("utf-8", "ignore")
                    if name.startswith("_") and "@" in name:
                        name = name.split("@")[0].lstrip("_")
                elif imp.ordinal is not None:
                    name = f"ord{imp.ordinal}"
                else:
                    name = "unknown"
                parts.append(f"{dll}.{name}".lower())
        if not parts:
            return ""
        return hashlib.md5(",".join(parts).encode()).hexdigest()
    except Exception:
        return ""


def section_hashes(pe) -> Dict[str, str]:
    """sha256 każdej sekcji PE - przydatne do korelacji między próbkami."""
    out: Dict[str, str] = {}
    try:
        for section in pe.sections:
            name = section.Name.rstrip(b"\x00").decode("utf-8", "ignore") or "?"
            data = section.get_data() or b""
            if data:
                out[name] = hashlib.sha256(data).hexdigest()
    except Exception:
        pass
    return out
