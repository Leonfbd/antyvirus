"""Wspólny kontekst skanowania i interfejs detektora."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from ..models import Finding, ScanResult

if TYPE_CHECKING:  # pragma: no cover
    from ..config import Config
    from ..sigs.store import SignatureStore


@dataclass
class ScanContext:
    """Wszystko, co detektor dostaje na wejściu.

    Dane są ładowane do pamięci tylko raz i współdzielone przez detektory,
    żeby skanowanie katalogu nie oznaczało wielokrotnego czytania pliku.
    """

    path: str
    data: bytes
    file_type: str
    result: ScanResult
    config: "Config"
    store: Optional["SignatureStore"] = None
    pe: Any = None           # sparsowany pefile.PE, gdy plik jest PE
    pe_error: Optional[str] = None
    cache: Dict[str, Any] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return len(self.data)

    def add(self, detector: str, rule: str, severity: str, description: str,
            weight: int = 0, evidence: Optional[str] = None) -> None:
        sev = severity.value if hasattr(severity, "value") else severity
        self.result.add(Finding(detector, rule, sev, description, weight, evidence))


class Detector:
    """Bazowa klasa detektora. Nadpisz `applies_to` i `run`."""

    name = "base"
    description = ""

    def applies_to(self, ctx: ScanContext) -> bool:
        return True

    def run(self, ctx: ScanContext) -> List[Finding]:
        raise NotImplementedError
