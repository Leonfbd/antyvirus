"""Magazyn sygnatur: skróty, imphashe, fuzzy hashe, reguły YARA, sygnatury ClamAV.

Baza jest ładowana do pamięci przy starcie silnika (słowniki haszy dają
wyszukiwanie O(1)), a zmiany zapisywane są do JSON-a w katalogu danych.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..detectors.yara_layer import YaraDetector
from ..hashing import ssdeep_compare
from .clamav import ClamAVDB

log = logging.getLogger(__name__)

# Oficjalny plik testowy EICAR - bezpieczny, standardowy w branży.
BUILTIN_HASHES: Dict[str, str] = {
    "44d88612fea8a8f36de82e1278abb02f": "EICAR-Test-File",
    "3395856ce81f2b7382dee72602f798b642f14140": "EICAR-Test-File",
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File",
}


@dataclass
class SignatureStats:
    hashes: int = 0
    imphash: int = 0
    fuzzy: int = 0
    yara_rules: int = 0
    yara_errors: int = 0
    clamav_sigs: int = 0
    updated_at: float = 0.0
    sources: List[Dict[str, object]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            **self.__dict__,
            "updated_at_human": (
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.updated_at))
                if self.updated_at else "nigdy"
            ),
        }


class SignatureStore:
    def __init__(self, config) -> None:
        self.config = config
        self.hashes: Dict[str, str] = dict(BUILTIN_HASHES)
        self.imphashes: Dict[str, str] = {}
        self.fuzzy: List[Tuple[str, str]] = []      # (ssdeep, nazwa)
        self.yara = YaraDetector()
        self.clamav = ClamAVDB()
        self.stats = SignatureStats()
        self.hashlists_dir = config.sigs_dir / "hashlists"
        self.cache_path = config.sigs_dir / "store.json"

    # ---------------------------------------------------------------- load
    def load(self, load_yara: bool = True, sources: Optional[List[Dict]] = None) -> SignatureStats:
        self.config.ensure_dirs()
        self.hashlists_dir.mkdir(parents=True, exist_ok=True)

        self._load_hashlists()
        if self.cache_path.exists():
            self._load_cache()

        if load_yara:
            count = self.yara.load_directory(self.config.yara_dir)
            log.info("Załadowano %d plików reguł YARA", count)
            if count == 0:
                self._load_builtin_yara()

        self.clamav.load_directory(self.config.sigs_dir)

        self.stats = SignatureStats(
            hashes=len(self.hashes),
            imphash=len(self.imphashes),
            fuzzy=len(self.fuzzy),
            yara_rules=self.yara.rule_count,
            yara_errors=len(self.yara.errors),
            clamav_sigs=self.clamav.count(),
            updated_at=time.time(),
            sources=sources or [],
        )
        return self.stats

    def _load_hashlists(self) -> None:
        """Wczytuje pliki z listami IOC.

        Akceptowane formaty (jeden rekord na linię):
            <hash>
            <hash>:<nazwa>
            <hash>  <nazwa>
            <sha256>,<md5>,<sha1>,<nazwa>     (format MalwareBazaar / CSV)
        Linie zaczynające się od # są komentarzem.
        """
        if not self.hashlists_dir.exists():
            return
        for path in sorted(self.hashlists_dir.rglob("*")):
            if not path.is_file() or path.suffix.lower() in {".json"}:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                self._parse_ioc_line(line)

    def _parse_ioc_line(self, line: str) -> None:
        parts = [p.strip() for p in line.replace("\t", ",").split(",")]
        if len(parts) >= 4:
            # CSV w stylu MalwareBazaar: sha256,md5,sha1,...nazwa
            name = parts[-1] or "unknown"
            for value in parts[:3]:
                self._add_hash(value, name)
            return
        if ":" in line:
            value, name = line.split(":", 1)
            self._add_hash(value.strip(), name.strip() or "unknown")
            return
        value = parts[0]
        rest = line[len(value):].strip()
        self._add_hash(value, rest or "unknown")

    def _add_hash(self, value: str, name: str) -> None:
        v = value.strip().lower()
        if len(v) == 32:
            self.hashes.setdefault(v, name)
        elif len(v) == 40:
            self.hashes.setdefault(v, name)
        elif len(v) == 64:
            self.hashes.setdefault(v, name)

    def _load_cache(self) -> None:
        """Dopisuje IOC dodane przez użytkownika (CLI / GUI)."""
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except Exception:
            return
        for h, name in (data.get("hashes") or {}).items():
            self.hashes.setdefault(h, name)
        for h, name in (data.get("imphashes") or {}).items():
            self.imphashes.setdefault(h, name)
        for ss, name in (data.get("fuzzy") or []):
            if (ss, name) not in self.fuzzy:
                self.fuzzy.append((ss, name))

    def _load_builtin_yara(self) -> None:
        """Minimalny zestaw reguł, żeby silnik miał czym pracować bez sieci."""
        builtin = r'''
rule EICAR_Test_File {
    meta:
        description = "Oficjalny plik testowy EICAR (nie jest groźny)"
        severity = "critical"
        type = "test"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}

rule Suspicious_AutoRun_Registry {
    meta:
        description = "Odwołania do kluczy autostartu"
        severity = "low"
    strings:
        $a = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii
        $b = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide ascii
    condition:
        any of them
}

rule Suspicious_Crypto_Wallet_Clipper {
    meta:
        description = "Wzorce klippera podmieniającego adresy portfeli krypto"
        severity = "high"
        type = "malware"
    strings:
        $bc1 = "bc1q" ascii wide
        $eth = /0x[a-fA-F0-9]{40}/ ascii wide
        $clip = "GetClipboardData" ascii wide
        $clip2 = "SetClipboardData" ascii wide
        $cb = "OpenClipboard" ascii wide
    condition:
        ($bc1 or $eth) and 2 of ($clip, $clip2, $cb)
}
'''
        self.yara.add_inline("builtin", builtin)

    # ------------------------------------------------------------- lookup
    def lookup_hash(self, value: str) -> Optional[str]:
        return self.hashes.get(value.lower())

    def lookup_imphash(self, value: str) -> Optional[str]:
        return self.imphashes.get(value.lower())

    def fuzzy_match(self, ssdeep: str, threshold: int) -> Optional[Tuple[str, int]]:
        best: Optional[Tuple[str, int]] = None
        for candidate, name in self.fuzzy:
            score = ssdeep_compare(ssdeep, candidate)
            if score >= threshold and (best is None or score > best[1]):
                best = (name, score)
        return best

    def clamav_match(self, data: bytes) -> List[Tuple[str, int]]:
        return self.clamav.match(data)

    # ------------------------------------------------------------- mutate
    def add_ioc(self, hash_value: str, name: str) -> bool:
        v = hash_value.strip().lower()
        if len(v) not in (32, 40, 64):
            return False
        self.hashes[v] = name
        self._persist()
        return True

    def add_ssdeep(self, value: str, name: str) -> bool:
        if not value or ":" not in value:
            return False
        self.fuzzy.append((value, name))
        self._persist()
        return True

    def add_imphash(self, value: str, name: str) -> bool:
        if len(value) != 32:
            return False
        self.imphashes[value.lower()] = name
        self._persist()
        return True

    def _persist(self) -> None:
        self.config.ensure_dirs()
        payload = {
            "hashes": self.hashes,
            "imphashes": self.imphashes,
            "fuzzy": self.fuzzy,
        }
        try:
            self.cache_path.write_text(
                json.dumps(payload, indent=1, ensure_ascii=False), encoding="utf-8")
        except Exception as exc:
            log.warning("Nie zapisano bazy IOC: %s", exc)
