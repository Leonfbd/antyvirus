"""Warstwa 1: reputacja haszowa (exact-match) + fuzzy hashing.

To najpewniejsza warstwa - jeśli plik jest znany, nie ma co gdybać nad
heurystyką. Kolejność: sha256 -> sha1 -> md5 -> imphash -> ssdeep.
"""

from __future__ import annotations

from typing import List

from .base import Detector, ScanContext
from ..hashing import ssdeep_hash, ssdeep_compare
from ..models import Severity


class SignatureDetector(Detector):
    name = "signature"
    description = "Porównanie skrótów z bazą znanych zagrożeń"

    def run(self, ctx: ScanContext) -> List[Finding]:
        store = ctx.store
        if store is None:
            return []

        # --- exact match po sha256 / sha1 / md5 ---
        for algo, value in (
            ("sha256", ctx.result.sha256),
            ("sha1", ctx.result.sha1),
            ("md5", ctx.result.md5),
        ):
            if not value:
                continue
            hit = store.lookup_hash(value)
            if hit:
                ctx.add(
                    self.name,
                    f"hash.{algo}",
                    Severity.CRITICAL,
                    f"Plik rozpoznany jako znane zagrożenie: {hit}",
                    weight=100,
                    evidence=f"{algo}={value} -> {hit}",
                )
                return ctx.result.findings

        # --- imphash: ten sam packer/rodzina, mimo innych bajtów ---
        if ctx.result.imphash:
            hit = store.lookup_imphash(ctx.result.imphash)
            if hit:
                ctx.add(
                    self.name,
                    "imphash",
                    Severity.HIGH,
                    f"Tabela importów identyczna ze znanym zagrożeniem: {hit}",
                    weight=45,
                    evidence=f"imphash={ctx.result.imphash}",
                )

        # --- fuzzy hash: podobieństwo do znanej próbki ---
        if ctx.result.ssdeep:
            match = store.fuzzy_match(ctx.result.ssdeep, ctx.config.fuzzy_similarity_threshold)
            if match:
                name, score = match
                ctx.add(
                    self.name,
                    "fuzzy.ssdeep",
                    Severity.HIGH,
                    f"Plik w {score}% podobny do znanej próbki: {name}",
                    weight=40,
                    evidence=f"ssdeep={ctx.result.ssdeep} ({score}% vs {name})",
                )

        return ctx.result.findings
