"""Warstwa 8: korelacja znalezisk i ocena łańcucha ataku.

Działa na wynikach pozostałych warstw i robi dwie rzeczy, które bezpośrednio
podnoszą precyzję silnika:

1. **Premia za spójny łańcuch.** Zestaw słabych sygnałów układających się
   w kolejne fazy ataku (dostarczenie → wykonanie → utrwalenie → unikanie
   analizy → wpływ) jest czymś zupełnie innym niż kilka niezwiązanych
   ciekawostek. Trzy i więcej różnych taktyk MITRE ATT&CK daje wyraźną premię.

2. **Rabat za kontekst zaufany.** Pliki w katalogach zarządzanych przez
   system (`/usr/bin`, `C:\\Windows\\System32`) dostają obniżone wagi
   *heurystyk*, bo heurystyka statystyczna ma tam najwyższy odsetek
   fałszywych alarmów. Rabat NIE dotyczy sygnatur exact-match — znany
   wirus jest wirusem niezależnie od katalogu.
"""

from __future__ import annotations

from typing import List, Optional, Set

from .base import Detector, ScanContext
from .. import mitre
from ..models import Severity

# Katalogi zarządzane przez system operacyjny (zapis wymaga uprawnień
# administratora, więc szansa na malware jest mniejsza, a koszt fałszywego
# alarmu wyższy - uszkodzony plik systemowy nie nadaje się do użycia).
TRUSTED_DIRS = (
    "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec", "/bin", "/sbin",
    "/lib", "/lib64", "/usr/share",
    "c:\\windows\\system32", "c:\\windows\\syswow64", "c:\\windows\\winsxs",
    "c:\\program files\\", "c:\\program files (x86)\\",
)
# Warstwy, których wyniki podlegają rabatowi (tylko heurystyki statystyczne).
DISCOUNTED_DETECTORS = {"pe_heuristics", "entropy", "script_heuristics", "archive"}


def _plural(count: int, one: str, few: str, many: str) -> str:
    """Polska odmiana: 1 taktykę, 2-4 taktyki, 5+ taktyk."""
    if count == 1:
        return f"{count} {one}"
    if 2 <= count % 10 <= 4 and not 12 <= count % 100 <= 14:
        return f"{count} {few}"
    return f"{count} {many}"


class CorrelationDetector(Detector):
    name = "correlation"
    description = "Korelacja znalezisk, łańcuch ataku wg MITRE ATT&CK, rabat za kontekst"
    expensive = False

    def applies_to(self, ctx: ScanContext) -> bool:
        return bool(ctx.result.findings)

    def run(self, ctx: ScanContext) -> List:
        findings = ctx.result.findings
        if not findings:
            return findings

        self._apply_context_discount(ctx)
        self._annotate_and_score_chain(ctx)
        return ctx.result.findings

    # -------------------------------------------------------------- kontekst
    def _apply_context_discount(self, ctx: ScanContext) -> None:
        """Obniża wagi heurystyk dla plików w katalogach systemowych."""
        if not ctx.config.trust_system_dirs:
            return
        normalized = ctx.path.replace("\\", "/").lower()
        trusted = next((d for d in TRUSTED_DIRS if d in normalized), None)
        if not trusted:
            return

        factor = ctx.config.system_dir_discount
        reduced = 0
        for finding in ctx.result.findings:
            if finding.detector in DISCOUNTED_DETECTORS and finding.weight > 0:
                new_weight = int(finding.weight * factor)
                reduced += finding.weight - new_weight
                finding.weight = new_weight
        if reduced:
            ctx.add(self.name, "trusted_location", Severity.INFO.value,
                    f"Plik w katalogu systemowym ({trusted}) — wagi heurystyk "
                    f"obniżone o {reduced} pkt. Sygnatury exact-match nie podlegają rabatowi.",
                    weight=0)

    # --------------------------------------------------------------- łańcuch
    def _annotate_and_score_chain(self, ctx: ScanContext) -> None:
        findings = ctx.result.findings
        # Dopisujemy technikę do każdego znaleziska - przydaje się w raporcie
        # i w panelu, bo od razu widać, co dany sygnał oznacza.
        for finding in findings:
            technique = mitre.map_finding(finding.detector, finding.rule)
            if technique:
                finding.mitre = f"{technique.id} {technique.name}"

        techniques = mitre.techniques_of(findings)
        tactics: Set[str] = {t["tactic"] for t in techniques}

        if not techniques:
            return

        # Zapisujemy mapowanie na potrzeby raportu i panelu.
        ctx.cache.setdefault("mitre", []).extend(techniques)

        bonus = mitre.chain_bonus(len(tactics))
        if bonus:
            names = ", ".join(
                f"{mitre.TACTIC_PL.get(t, t)}" for t in sorted(
                    tactics, key=lambda x: mitre.TACTICS.index(x) if x in mitre.TACTICS else 99))
            ctx.add(
                self.name, "attack_chain",
                Severity.HIGH.value if bonus >= 20 else Severity.MEDIUM.value,
                f"Znaleziska układają się w łańcuch ataku obejmujący "
                f"{_plural(len(tactics), 'taktykę', 'taktyki', 'taktyk')}: {names}. "
                f"Techniki: {', '.join(t['id'] for t in techniques[:6])}",
                weight=bonus,
                evidence="spójność wielu niezależnych sygnałów jest silniejszym "
                         "dowodem niż każdy z nich osobno")

        # Jawna wzmianka o najważniejszej technice, żeby analityk widział
        # od razu, z czym ma do czynienia.
        primary = techniques[0]
        if primary["tactic"] in {"impact", "credential-access", "defense-evasion"}:
            ctx.add(self.name, f"mitre.{primary['id']}", Severity.INFO.value,
                    f"Technika {primary['id']}: {primary['name']} "
                    f"({primary['tactic_pl']})", weight=0)
