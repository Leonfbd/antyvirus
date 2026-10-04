"""Warstwa 4: entropia i wykrywanie pakowania (dla wszystkich typów plików).

Legalny program kompresuje się rzadko i słabo. Malware kompresuje się prawie
zawsze, bo chce ukryć sygnatury przed skanerem. Entropia jest więc jednym z
najtańszych, a zarazem najskuteczniejszych sygnałów - działa nawet wtedy, gdy
nie rozumiemy formatu pliku.
"""

from __future__ import annotations

import zlib
from typing import List

from .base import Detector, ScanContext
from ..entropy import (
    classify_entropy,
    sample_for_entropy,
    entropy_windowed,
    max_window_entropy,
    printable_ratio,
    shannon_entropy,
)
from ..models import Severity


class PackerDetector(Detector):
    name = "entropy"
    description = "Analiza entropii - wykrywanie pakowania, kryptorów i kompresji"

    def applies_to(self, ctx: ScanContext) -> bool:
        return len(ctx.data) >= 512 and ctx.file_type not in {"text", "empty"}

    def run(self, ctx: ScanContext) -> List[Finding]:
        data = ctx.data
        cfg = ctx.config
        # Dla dużych plików liczymy entropię z próbki - wynik statystycznie
        # identyczny, koszt rzędu wielkości mniejszy.
        sample = sample_for_entropy(
            data, cfg.entropy_sample_threshold, cfg.entropy_sample_size)
        ent = shannon_entropy(sample)

        ctx.cache["entropy"] = ent

        if ent >= cfg.entropy_file_threshold:
            ctx.add(self.name, "high_file_entropy", Severity.HIGH,
                    f"Entropia całego pliku jest bardzo wysoka ({ent:.2f})",
                    weight=25,
                    evidence=classify_entropy(ent) + " - kod wykonywalny rzadko przekracza 7.0")
        elif ent >= cfg.entropy_section_threshold:
            ctx.add(self.name, "elevated_file_entropy", Severity.MEDIUM,
                    f"Podwyższona entropia pliku ({ent:.2f})",
                    weight=12, evidence=classify_entropy(ent))

        # Entropia w oknach - wykrywa zaszyfrowany blok wewnątrz dużego pliku.
        if len(sample) >= 64 * 1024:
            peak = max_window_entropy(sample, window=4096, step=8192)
            if peak >= 7.6 and ent < cfg.entropy_file_threshold:
                ctx.add(self.name, "high_entropy_region", Severity.MEDIUM,
                        f"Wewnątrz pliku jest blok o entropii {peak:.2f}",
                        weight=12, evidence="zaszyfrowany lub skompresowany payload")

        # --- sekcje PE ---
        if ctx.pe is not None:
            for section in ctx.pe.sections:
                try:
                    raw = section.get_data() or b""
                except Exception:
                    continue
                if len(raw) < 1024:
                    continue
                name = section.Name.rstrip(b"\x00").decode("utf-8", "ignore") or "?"
                sent = shannon_entropy(raw)
                is_exec = bool(section.Characteristics & 0x20000000)
                if sent >= 7.5:
                    extra = " (wykonywalna)" if is_exec else ""
                    ctx.add(self.name, "high_section_entropy", Severity.MEDIUM,
                            f"Sekcja '{name}'{extra} ma entropię {sent:.2f}",
                            weight=18 if is_exec else 10,
                            evidence="sekcja wykonywalna o takiej entropii = rozpakowywanie w locie")
                elif sent >= cfg.entropy_section_threshold and is_exec:
                    ctx.add(self.name, "elevated_section_entropy", Severity.LOW,
                            f"Sekcja wykonywalna '{name}' ma entropię {sent:.2f}", weight=8)

        # --- proporcja kompresji: zaszyfrowane dane nie kompresują się ---
        if len(sample) >= 8192:
            chunk = sample[:65536]
            ratio = len(zlib.compress(chunk, 6)) / max(1, len(chunk))
            ctx.cache["compress_ratio"] = ratio
            if ratio > 0.98 and ent > 7.0:
                ctx.add(self.name, "incompressible", Severity.MEDIUM,
                        f"Dane praktycznie nie poddają się kompresji (współczynnik {ratio:.2f})",
                        weight=12, evidence="cecha danych zaszyfrowanych, nie kodu")

        # --- tekst udający coś innego ---
        if ctx.file_type in {"text", "script"}:
            ratio = printable_ratio(data)
            if ratio < 0.6:
                ctx.add(self.name, "binary_in_text", Severity.LOW,
                        f"Plik tekstowy zawiera dużo danych binarnych (drukowalne: {ratio:.0%})",
                        weight=8)

        return ctx.result.findings
