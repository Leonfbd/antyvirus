"""Warstwa 7: zawartość archiwów (ZIP, TAR, 7z, RAR, gzip, xz).

Podpięta jako zwykły detektor, więc dziedziczy wszystkie mechanizmy silnika
(limity, raportowanie, short-circuit). Zagnieżdżone archiwa są rozpakowywane
rekurencyjnie - do konfigurowalnej głębokości.
"""

from __future__ import annotations

from typing import List

from .base import Detector, ScanContext
from ..archives import is_archive
from ..models import Severity


class ArchiveDetector(Detector):
    name = "archive"
    description = "Rozpakowanie i skanowanie zawartości archiwów"

    def applies_to(self, ctx: ScanContext) -> bool:
        if not ctx.config.scan_archives:
            return False
        if not is_archive(ctx.file_type):
            return False
        engine = ctx.cache.get("engine")
        return engine is not None

    def run(self, ctx: ScanContext) -> List:
        engine = ctx.cache.get("engine")
        if engine is None:
            return ctx.result.findings

        from ..archives import ArchiveScanner

        scanner = ArchiveScanner(engine)
        depth = ctx.cache.get("depth", 0)
        findings, report = scanner.scan(ctx.path, ctx.data, ctx.file_type, depth=depth)

        for finding in findings:
            ctx.result.add(finding)

        # Zapisujemy raport, żeby GUI/CLI mogły pokazać zawartość archiwum.
        ctx.cache.setdefault("archive_reports", []).append(report)
        return ctx.result.findings
