"""Warstwa 1b: sygnatury bajtowe ClamAV (.ndb) - dopasowanie wzorców z wildcardami."""

from __future__ import annotations

from typing import List

from .base import Detector, ScanContext
from ..models import Severity


class ClamAVDetector(Detector):
    """Używa zaimportowanych sygnatur wzorcowych ClamAV (jeśli są dostępne)."""

    name = "clamav"
    description = "Sygnatury wzorcowe ClamAV (.hdb/.hsb/.ndb)"

    def applies_to(self, ctx: ScanContext) -> bool:
        store = ctx.store
        return store is not None and bool(store.clamav.patterns or store.clamav.file_hashes)

    def run(self, ctx: ScanContext) -> List[Finding]:
        store = ctx.store
        if store is None:
            return ctx.result.findings

        # Skróty plików z baz ClamAV (.hdb/.hsb/.hsu)
        for digest in (ctx.result.sha256, ctx.result.sha1, ctx.result.md5):
            name = store.clamav.lookup_hash(digest)
            if name:
                ctx.add(self.name, "clamav.hash", Severity.CRITICAL,
                        f"Znane zagrożenie (baza ClamAV): {name}",
                        weight=100, evidence=f"{digest} -> {name}")
                return ctx.result.findings

        if ctx.result.imphash:
            name = store.clamav.lookup_imphash(ctx.result.imphash)
            if name:
                ctx.add(self.name, "clamav.imphash", Severity.HIGH,
                        f"Import-hash znany z bazy ClamAV: {name}", weight=45,
                        evidence=ctx.result.imphash)

        # Wzorce bajtowe (.ndb)
        for name, offset in store.clamav.match(ctx.data):
            ctx.add(self.name, "clamav.pattern", Severity.CRITICAL,
                    f"Dopasowano sygnaturę ClamAV: {name}",
                    weight=100, evidence=f"offset=0x{offset:x}")

        return ctx.result.findings
