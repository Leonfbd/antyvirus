"""Importer baz sygnatur ClamAV.

Obsługiwane formaty (zgodne z dokumentacją ClamAV):
  .hdb  md5:size:name              - skróty MD5 całych plików
  .hsb  sha256:size:name           - skróty SHA256
  .hsu  sha1:size:name             - skróty SHA1
  .imp  md5:name                   - import-hashe (odcisk tablicy importów)
  .ndb  name:target:offset:hexsig  - sygnatury wzorcowe z symbolami wieloznacznymi
  .cvd  skompresowany kontener z powyższymi plikami

Nieobsługiwane (wymagają wirtualnej maszyny bajtkowej ClamAV): .cbc, .ldb.
Są odnotowywane jako pominięte, żeby użytkownik wiedział, czego brakuje.

Dopasowywanie wzorców .ndb nie jest naiwnym regexem po całym pliku: dla każdej
sygnatury wyliczany jest najdłuższy dosłowny prefiks, a dopasowania kandydujące
szukane są jednym przejściem po danych (skompilowana alternacja prefiksów).
"""

from __future__ import annotations

import gzip
import io
import logging
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

log = logging.getLogger(__name__)

HEX_EXT = {".hdb", ".hsb", ".hsu", ".imp", ".mdb", ".msb"}
NDB_EXT = {".ndb", ".gdb", ".wdb", ".pdb", ".ndu"}
SKIP_EXT = {".cbc", ".ldb", ".ftm", ".info", ".zmd", ".rmd", ".cfg", ".crb"}

# Maksymalna liczba sygnatur wzorcowych ładowanych do pamięci (ochrona przed OOM).
MAX_PATTERN_SIGS = 250_000
CHUNK_PREFIXES = 2000


@dataclass
class PatternSig:
    name: str
    target: int
    offset: str
    regex: "re.Pattern[bytes]"
    prefix: bytes
    min_fl: int = 0
    max_fl: int = 0


class ClamAVDB:
    def __init__(self) -> None:
        self.file_hashes: Dict[str, str] = {}
        self.import_hashes: Dict[str, str] = {}
        self.patterns: List[PatternSig] = []
        self.skipped: Dict[str, int] = {}
        self.sources: List[str] = []
        self._prefix_index: Dict[bytes, List[PatternSig]] = {}
        self._no_prefix: List[PatternSig] = []
        self._compiled_prefix_scanner: Optional["re.Pattern[bytes]"] = None

    # ------------------------------------------------------------------ API
    def count(self) -> int:
        return len(self.file_hashes) + len(self.import_hashes) + len(self.patterns)

    def load_directory(self, directory: Path) -> int:
        directory = Path(directory)
        if not directory.exists():
            return 0
        for path in sorted(directory.rglob("*")):
            if not path.is_file():
                continue
            suffix = path.suffix.lower()
            if suffix in HEX_EXT:
                self.load_hash_file(path)
            elif suffix in NDB_EXT:
                self.load_pattern_file(path)
            elif suffix == ".cvd" or path.name.endswith(".cvd"):
                self.load_cvd(path)
            elif suffix in SKIP_EXT:
                self.skipped[suffix] = self.skipped.get(suffix, 0) + 1
        self._reindex()
        return self.count()

    def load_hash_file(self, path: Path) -> int:
        kind = path.suffix.lower()
        added = 0
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":")
                    if kind == ".imp":
                        if len(parts) >= 2 and len(parts[0]) == 32:
                            self.import_hashes[parts[0].lower()] = parts[1]
                            added += 1
                        continue
                    # hdb / hsb / hsu / mdb: hash:size:name
                    if len(parts) >= 3:
                        digest = parts[0].strip().lower()
                        name = parts[2].strip()
                        if digest and name:
                            self.file_hashes[digest] = name
                            added += 1
        except Exception as exc:
            log.warning("Nie wczytano %s: %s", path, exc)
        if added:
            self.sources.append(path.name)
        return added

    def load_pattern_file(self, path: Path, limit: int = MAX_PATTERN_SIGS) -> int:
        added = 0
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    if len(self.patterns) >= limit:
                        self.skipped["limit"] = self.skipped.get("limit", 0) + 1
                        break
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    sig = self._parse_ndb_line(line)
                    if sig:
                        self.patterns.append(sig)
                        added += 1
        except Exception as exc:
            log.warning("Nie wczytano %s: %s", path, exc)
        if added:
            self.sources.append(path.name)
        return added

    def load_cvd(self, path: Path) -> int:
        """Rozpakowuje kontener .cvd (nagłówek tekstowy + gzip + tar)."""
        total = 0
        try:
            raw = path.read_bytes()
            nl = raw.find(b"\n")
            if nl < 0:
                return 0
            self.cvd_header = raw[:nl].decode("latin-1", "ignore")
            payload = raw[nl + 1:]
            # Czasem przed strumieniem gzip jest bajt długości.
            if payload[:1] not in (b"\x1f",):
                idx = payload.find(b"\x1f\x8b")
                payload = payload[idx:] if idx >= 0 else payload
            data = gzip.decompress(payload)
            with tarfile.open(fileobj=io.BytesIO(data)) as tar:
                for member in tar.getmembers():
                    if not member.isfile():
                        continue
                    suffix = Path(member.name).suffix.lower()
                    if suffix not in HEX_EXT | NDB_EXT:
                        continue
                    extracted = tar.extractfile(member)
                    if extracted is None:
                        continue
                    content = extracted.read().decode("utf-8", "ignore")
                    if suffix in NDB_EXT:
                        total += self._load_pattern_text(content)
                    else:
                        total += self._load_hash_text(content, suffix)
            self.sources.append(path.name)
        except Exception as exc:
            log.warning("Nie rozpakowano %s: %s", path, exc)
        return total

    def _load_hash_text(self, text: str, kind: str) -> int:
        added = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if kind == ".imp" and len(parts) >= 2 and len(parts[0]) == 32:
                self.import_hashes[parts[0].lower()] = parts[1]
                added += 1
            elif len(parts) >= 3 and parts[0]:
                self.file_hashes[parts[0].strip().lower()] = parts[2].strip()
                added += 1
        return added

    def _load_pattern_text(self, text: str) -> int:
        added = 0
        for line in text.splitlines():
            if len(self.patterns) >= MAX_PATTERN_SIGS:
                break
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            sig = self._parse_ndb_line(line)
            if sig:
                self.patterns.append(sig)
                added += 1
        return added

    # ----------------------------------------------------------- wyszukiwanie
    def lookup_hash(self, digest: str) -> Optional[str]:
        return self.file_hashes.get(digest.lower())

    def lookup_imphash(self, digest: str) -> Optional[str]:
        return self.import_hashes.get(digest.lower())

    def match(self, data: bytes, max_hits: int = 15) -> List[Tuple[str, int]]:
        """Zwraca listę (nazwa, offset) dopasowanych sygnatur wzorcowych."""
        if not self.patterns:
            return []
        hits: List[Tuple[str, int]] = []
        seen: Set[str] = set()

        scanner = self._prefix_scanner()
        if scanner is not None:
            for m in scanner.finditer(data):
                for sig in self._prefix_index.get(m.group(0), ()):
                    key = sig.name
                    if key in seen:
                        continue
                    if sig.regex.match(data, m.start()):
                        seen.add(key)
                        hits.append((sig.name, m.start()))
                        if len(hits) >= max_hits:
                            return hits

        # Sygnatury bez dosłownego prefiksu - wolniejsza ścieżka.
        for sig in self._no_prefix:
            if sig.name in seen:
                continue
            m = sig.regex.search(data)
            if m:
                seen.add(sig.name)
                hits.append((sig.name, m.start()))
                if len(hits) >= max_hits:
                    break
        return hits

    # ------------------------------------------------------------- internals
    def _reindex(self) -> None:
        self._prefix_index = {}
        self._no_prefix = []
        for sig in self.patterns:
            if len(sig.prefix) >= 2:
                self._prefix_index.setdefault(sig.prefix[:2], []).append(sig)
            else:
                self._no_prefix.append(sig)
        self._compiled_prefix_scanner = None
        # Bardzo kosztowne sygnatury bez prefiksu ucinamy, żeby nie blokować skanu.
        if len(self._no_prefix) > 500:
            self._no_prefix = self._no_prefix[:500]

    def _prefix_scanner(self) -> Optional["re.Pattern[bytes]"]:
        if self._compiled_prefix_scanner is not None:
            return self._compiled_prefix_scanner
        keys = [k for k in self._prefix_index.keys() if len(k) == 2]
        if not keys:
            return None
        chunks = [keys[i:i + CHUNK_PREFIXES] for i in range(0, len(keys), CHUNK_PREFIXES)]
        parts = [b"|".join(re.escape(k) for k in chunk) for chunk in chunks]
        try:
            self._compiled_prefix_scanner = re.compile(b"|".join(parts), re.DOTALL)
        except Exception:
            self._compiled_prefix_scanner = None
        return self._compiled_prefix_scanner

    # ---------------------------------------------------------- parsowanie
    def _parse_ndb_line(self, line: str) -> Optional[PatternSig]:
        parts = line.split(":")
        if len(parts) < 4:
            return None
        name = parts[0].strip()
        try:
            target = int(parts[1])
        except ValueError:
            target = 0
        offset = parts[2].strip() or "*"
        hexsig = ":".join(parts[3:]).strip()

        try:
            regex_src, prefix = hexsig_to_regex(hexsig)
        except Exception:
            self.skipped["unparsable"] = self.skipped.get("unparsable", 0) + 1
            return None
        if not regex_src:
            return None

        min_fl = max_fl = 0
        if len(parts) >= 6:
            try:
                min_fl = int(parts[4])
                max_fl = int(parts[5])
            except ValueError:
                min_fl = max_fl = 0

        # Kotwica: offset liczbowy oznacza "od tego bajtu", * oznacza dowolne miejsce.
        if offset != "*" and offset.isdigit():
            anchor = f".{{{int(offset)}}}"
            regex_src = anchor + regex_src
        try:
            compiled = re.compile(regex_src.encode("latin-1"), re.DOTALL)
        except Exception:
            self.skipped["unparsable"] = self.skipped.get("unparsable", 0) + 1
            return None
        return PatternSig(name, target, offset, compiled, prefix, min_fl, max_fl)


# --------------------------------------------------------------------------
# konwersja składni sygnatur ClamAV na wyrażenie regularne
# --------------------------------------------------------------------------

def hexsig_to_regex(sig: str) -> Tuple[str, bytes]:
    """Zamienia sygnaturę szesnastkową ClamAV na (źródło regexa, prefiks dosłowny)."""
    out: List[str] = []
    prefix = bytearray()
    prefix_complete = False
    i = 0
    n = len(sig)

    def emit_byte(value: Optional[int], negated: bool = False,
                  alternatives: Optional[Sequence[int]] = None) -> None:
        nonlocal prefix_complete
        if alternatives is not None:
            body = "|".join(_b(v) for v in alternatives)
            out.append(("(?:%s)" % body) if not negated else ("(?:[^\x00-\xff]|%s)" % ""))
            if not negated:
                # alternatywa nie jest dosłownym prefiksem
                prefix_complete = True
            return
        if value is None:
            out.append(".")
            prefix_complete = True
            return
        out.append(_b(value))
        if not prefix_complete:
            prefix.append(value)

    while i < n:
        ch = sig[i]
        if ch.isspace():
            i += 1
            continue
        if ch == "*":
            out.append(".*?")
            prefix_complete = True
            i += 1
            continue
        if ch == "{":
            end = sig.find("}", i)
            if end < 0:
                raise ValueError("niezamknięte {}")
            body = sig[i + 1:end].strip()
            out.append(_repeat(body))
            prefix_complete = True
            i = end + 1
            continue
        if ch == "(":
            end = sig.find(")", i)
            if end < 0:
                raise ValueError("niezamknięte ()")
            body = sig[i + 1:end]
            alts = [_hex_byte(a.strip()) for a in body.split("|") if a.strip()]
            alts = [a for a in alts if a is not None]
            if alts:
                emit_byte(None, alternatives=alts)
            else:
                emit_byte(None)
            i = end + 1
            continue
        if ch == "!" and i + 1 < n and sig[i + 1] in "([":
            # negacja - rzadko używana, traktujemy jako dowolny bajt z dopiskiem
            j = i + 1
            open_ch = sig[j]
            close_ch = ")" if open_ch == "(" else "]"
            end = sig.find(close_ch, j)
            if end < 0:
                raise ValueError("niezamknięta negacja")
            out.append("(?!%s)[\\x00-\\xff]" % "|".join(
                _b(v) for v in [_hex_byte(a.strip()) for a in sig[j + 1:end].split("|")] if v is not None
            ) if open_ch == "(" else "[^%s]" % _range_body(sig[j + 1:end]))
            prefix_complete = True
            i = end + 1
            continue
        if ch == "[":
            end = sig.find("]", i)
            if end < 0:
                raise ValueError("niezamknięte []")
            out.append("[%s]" % _range_body(sig[i + 1:end]))
            prefix_complete = True
            i = end + 1
            continue
        # zwykły bajt (z możliwymi symbolami wieloznacznymi na półbajtach)
        if i + 1 < n and (ch in "0123456789abcdefABCDEF?") :
            hi, lo = ch, sig[i + 1]
            if lo not in "0123456789abcdefABCDEF?":
                raise ValueError(f"nieprawidłowy bajt: {ch}{lo}")
            if hi == "?" and lo == "?":
                emit_byte(None)
            elif hi == "?":
                lo_v = int(lo, 16)
                out.append("[\\x%02x-\\x%02x]" % (lo_v, 0x0F | (lo_v << 0) | 0x00) if False else
                           "[%s]" % "|".join(_b((h << 4) | lo_v) for h in range(16)))
                prefix_complete = True
            elif lo == "?":
                hi_v = int(hi, 16)
                out.append("[%s]" % "|".join(_b((hi_v << 4) | l) for l in range(16)))
                prefix_complete = True
            else:
                emit_byte(int(hi + lo, 16))
            i += 2
            continue
        raise ValueError(f"nieoczekiwany znak: {ch!r}")

    return "".join(out), bytes(prefix)


def _b(value: int) -> str:
    return "\\x%02x" % (value & 0xFF)


def _hex_byte(token: str) -> Optional[int]:
    token = token.strip()
    if len(token) != 2 or any(c not in "0123456789abcdefABCDEF" for c in token):
        return None
    return int(token, 16)


def _repeat(body: str) -> str:
    """{n}, {-n}, {n-m} -> kwantyfikator."""
    if "-" in body[1:] if body.startswith("-") else "-" in body:
        lo, _, hi = body.partition("-")
        if lo == "":
            return ".{0,%d}" % int(hi)
        return ".{%s,%s}" % (int(lo), int(hi))
    return ".{%d}" % int(body)


def _range_body(body: str) -> str:
    """[AA-BB] -> \xaa-\xbb"""
    out = []
    for part in body.split(":"):
        part = part.strip()
        if "-" in part:
            lo, _, hi = part.partition("-")
            lo_v, hi_v = _hex_byte(lo), _hex_byte(hi)
            if lo_v is None or hi_v is None:
                continue
            out.append("\\x%02x-\\x%02x" % (lo_v, hi_v))
        else:
            v = _hex_byte(part)
            if v is not None:
                out.append("\\x%02x" % v)
    return "".join(out) or "\\x00-\\xff"
