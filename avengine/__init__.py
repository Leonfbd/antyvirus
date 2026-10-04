"""AntyVirus — wielowarstwowy silnik detekcji zagrożeń.

Architektura (każda warstwa dokłada punkty do wspólnego wyniku ryzyka):

    1. Reputacja haszowa   md5 / sha1 / sha256 / imphash / ssdeep
    2. Sygnatury ClamAV    skróty (.hdb/.hsb) + wzorce bajtowe (.ndb)
    3. Reguły YARA         bazy społecznościowe + własne, z modułem PE
    4. Heurystyka PE       struktura plików wykonywalnych Windows
    5. Entropia            wykrywanie pakowania, kryptorów, kompresji
    6. Skrypty i makra     PowerShell / JS / VBS / BAT / makra Office

Cel projektu jest edukacyjny i diagnostyczny: silnik jest w pełni działający,
ale nie zastępuje komercyjnego produktu AV z telemetrią chmurową.
"""

from .config import Config
from .engine import Engine
from .models import Finding, ScanResult, ScanSummary, Severity, Verdict

__version__ = "0.1.0"

__all__ = [
    "Config", "Engine", "Finding", "ScanResult", "ScanSummary",
    "Severity", "Verdict", "__version__",
]
