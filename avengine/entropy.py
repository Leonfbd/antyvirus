"""Analiza entropii - wykrywanie pakowania, szyfrowania i kompresji.

Entropia Shannona w bajtach: 0.0 = dane jednostajne, 8.0 = idealnie losowe.
Kod wykonywalny (x86) mieści się zwykle w 5.5-7.0; sekcje powyżej ~7.2 są
silnym wskaźnikiem packera, kryptora lub zaszyfrowanego payloadu.
"""

from __future__ import annotations

import math
from typing import Dict, List, Tuple


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return entropy


def entropy_windowed(data: bytes, window: int = 4096, step: int = 4096) -> List[Tuple[int, float]]:
    """Entropia w oknach - pozwala znaleźć zaszyfrowany fragment wewnątrz pliku."""
    out: List[Tuple[int, float]] = []
    if not data:
        return out
    for offset in range(0, len(data), step):
        chunk = data[offset : offset + window]
        if not chunk:
            break
        out.append((offset, shannon_entropy(chunk)))
    return out


def max_window_entropy(data: bytes, window: int = 4096, step: int = 4096) -> float:
    values = [e for _, e in entropy_windowed(data, window, step)]
    return max(values) if values else 0.0


def byte_histogram(data: bytes) -> List[int]:
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return counts


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data)


def classify_entropy(value: float) -> str:
    if value < 1.0:
        return "jednostajna"
    if value < 4.5:
        return "niska (tekst/dane)"
    if value < 6.8:
        return "normalna dla kodu"
    if value < 7.2:
        return "podwyższona"
    if value < 7.6:
        return "wysoka (możliwe pakowanie)"
    return "bardzo wysoka (szyfr/kompresja)"


def section_entropies(pe) -> Dict[str, float]:
    out: Dict[str, float] = {}
    try:
        for section in pe.sections:
            name = section.Name.rstrip(b"\x00").decode("utf-8", "ignore") or "?"
            data = section.get_data() or b""
            out[name] = shannon_entropy(data)
    except Exception:
        pass
    return out
