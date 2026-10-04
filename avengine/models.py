"""Modele danych współdzielone przez wszystkie warstwy silnika."""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Waga przypisana do każdej wagi - służy do obliczania wyniku ryzyka.
SEVERITY_WEIGHT: Dict[str, int] = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 30,
    Severity.CRITICAL: 50,
}


class Verdict(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class Finding:
    """Pojedyncze znalezisko wyprodukowane przez detektor."""

    detector: str
    rule: str
    severity: str
    description: str
    weight: int = 0
    evidence: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.weight:
            self.weight = SEVERITY_WEIGHT.get(self.severity, 5)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    path: str
    size: int = 0
    file_type: str = "unknown"
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    ssdeep: str = ""
    imphash: str = ""
    score: int = 0
    verdict: str = Verdict.CLEAN.value
    findings: List[Finding] = field(default_factory=list)
    elapsed_ms: int = 0
    error: Optional[str] = None
    quarantined: bool = False
    scanned_at: float = field(default_factory=time.time)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def finalize(self, suspicious_threshold: int = 25, malicious_threshold: int = 60) -> "ScanResult":
        """Sumuje wagi znalezisk i wyprowadza werdykt.

        Zasada "hard fail": pojedyncze znalezisko o wadze >= 50 (CRITICAL) albo
        sygnatura exact-match automatycznie daje werdykt MALICIOUS, nawet jeśli
        suma punktów jest niska. Zapobiega to sytuacji, w której znany wirus
        zostałby zaklasyfikowany tylko jako "podejrzany".
        """
        if self.error:
            self.verdict = Verdict.ERROR.value
            return self

        total = sum(f.weight for f in self.findings)
        self.score = min(100, max(0, total))

        has_hard_hit = any(f.weight >= 50 for f in self.findings)

        if has_hard_hit or self.score >= malicious_threshold:
            self.verdict = Verdict.MALICIOUS.value
        elif self.score >= suspicious_threshold:
            self.verdict = Verdict.SUSPICIOUS.value
        else:
            self.verdict = Verdict.CLEAN.value
        return self

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["findings"] = [f.to_dict() if hasattr(f, "to_dict") else f for f in self.findings]
        return d


@dataclass
class ScanSummary:
    """Podsumowanie skanu katalogu / wielu plików."""

    total: int = 0
    clean: int = 0
    suspicious: int = 0
    malicious: int = 0
    errors: int = 0
    skipped: int = 0
    bytes_scanned: int = 0
    elapsed_ms: int = 0
    results: List[ScanResult] = field(default_factory=list)

    def ingest(self, r: ScanResult) -> None:
        self.total += 1
        self.bytes_scanned += r.size
        if r.verdict == Verdict.CLEAN.value:
            self.clean += 1
        elif r.verdict == Verdict.SUSPICIOUS.value:
            self.suspicious += 1
        elif r.verdict == Verdict.MALICIOUS.value:
            self.malicious += 1
        elif r.verdict == Verdict.ERROR.value:
            self.errors += 1
        else:
            self.skipped += 1

    def to_dict(self, include_results: bool = True) -> Dict[str, Any]:
        d = {
            "total": self.total,
            "clean": self.clean,
            "suspicious": self.suspicious,
            "malicious": self.malicious,
            "errors": self.errors,
            "skipped": self.skipped,
            "bytes_scanned": self.bytes_scanned,
            "elapsed_ms": self.elapsed_ms,
        }
        if include_results:
            d["results"] = [r.to_dict() for r in self.results]
        return d
