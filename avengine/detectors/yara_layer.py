"""Warstwa 2: reguły YARA (silnik libyara wraz z modułem `pe`).

NAJWAŻNIEJSZA ZASADA TEJ WARSTWY: nie każde dopasowanie reguły to malware.

Publiczne bazy (Yara-Rules/rules, Neo23x0/signature-base) zawierają trzy
zupełnie różne rodzaje reguł i potraktowanie ich jednakowo daje lawinę
fałszywych alarmów:

  * identyfikacyjne  - "IsPE32", "Microsoft_Visual_Cpp_8", "UPX", "contains_base64",
                       "domain", "IP"  -> mówią, CZYM plik jest, nie czy jest zły.
                       Wynik: 0 punktów, tylko adnotacja.
  * behawioralne     - "anti_dbg", "capa_*", "gen_susp_*" -> podejrzane możliwości.
                       Wynik: kilka punktów, z limitem sumarycznym.
  * detekcyjne       - "apt_*", "gen_mal_*", "crim_*", "Emotet", "webshell"
                       -> właściwe sygnatury malware. Wynik: decydujący.

Klasyfikacja opiera się na metadanych reguły, jej nazwie oraz ścieżce pliku,
z którego pochodzi (wyciąganej podczas ładowania).
"""

from __future__ import annotations

import logging
import os
import random
import re
import sys
import warnings
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .base import Detector, ScanContext
from ..models import Severity

log = logging.getLogger(__name__)

try:
    import yara  # type: ignore
except Exception:  # pragma: no cover
    yara = None

# Zmienne zewnętrzne, których oczekują reguły pisane dla skanerów LOKI/Thor
# (Neo23x0/signature-base). Bez nich te reguły w ogóle się nie kompilują.
EXTERNALS: Dict[str, str] = {
    "filename": "",
    "filepath": "",
    "extension": "",
    "filetype": "",
}

# --- kategorie i wagi ---
MALWARE, EXPLOIT, SUSPICIOUS, INFO, UNKNOWN = "malware", "exploit", "suspicious", "info", "unknown"

CATEGORY_WEIGHT = {
    MALWARE: 40,      # właściwa sygnatura malware
    EXPLOIT: 30,      # exploit / CVE
    SUSPICIOUS: 8,    # podejrzana możliwość
    UNKNOWN: 6,       # reguła niezaklasyfikowana - ostrożnie
    INFO: 0,          # czysta informacja o pliku
}
CATEGORY_SEVERITY = {
    MALWARE: Severity.HIGH,
    EXPLOIT: Severity.HIGH,
    SUSPICIOUS: Severity.MEDIUM,
    UNKNOWN: Severity.LOW,
    INFO: Severity.INFO,
}
CATEGORY_LABEL = {
    MALWARE: "sygnatura malware",
    EXPLOIT: "exploit/CVE",
    SUSPICIOUS: "podejrzana możliwość",
    UNKNOWN: "reguła niezaklasyfikowana",
    INFO: "informacja o pliku (0 pkt)",
}

# Reguły o słabych sygnałach nie mogą same skazać pliku.
MAX_WEAK_SCORE = 20
MAX_REPORTED = 20

MALWARE_PATH_HINTS = (
    "malware/", "mobile_malware/", "webshells/", "web_shells/", "maldocs/",
    "emerging_threats/", "payloads/", "apt", "trojan", "ransom", "backdoor",
)
EXPLOIT_PATH_HINTS = ("exploits/", "cve_rules/", "cve", "expl_")
INFO_PATH_HINTS = (
    "packers/", "peid/", "crypto/", "antidebug/", "capabilities/", "utils/",
    "deprecated/", "ssl/", "email/", "others/", "yara_mixed", "capa_",
    "identification", "signsrch", "compiler",
)

MALWARE_NAME_HINTS = (
    "trojan", "backdoor", "ransom", "webshell", "web_shell", "miner", "stealer",
    "keylog", "rootkit", "dropper", "botnet", "worm", "apt_", "crim_", "gen_mal",
    "mal_", "malware", "hacktool", "cryptor", "shellcode", "inject", "rat_",
    "emotet", "trickbot", "mimikatz", "cobalt", "agenttesla", "redline",
    "njrat", "asyncrat", "formbook", "guloader", "icedid", "qakbot", "conti",
    "lockbit", "revil", "metasploit", "cve-", "mirai", "gafgyt", "lazarus",
)
SUSPICIOUS_NAME_HINTS = (
    "anti_dbg", "antidebug", "anti_vm", "antivm", "anti-analysis", "evasion",
    "obfuscat", "susp", "capa_", "packed", "packer_", "hide", "bypass",
)
INFO_NAME_HINTS = (
    "ispe32", "ispe64", "ispe", "iswindows", "isdll", "iself", "is_", "is32",
    "is64", "contains_", "has_", "upx", "aspack", "petite", "themida",
    "vmprotect", "microsoft_visual", "borland", "delphi", "visual_basic",
    "packer", "compiler", "peid", "entropy", "base64", "domain", "ip",
    "url", "email", "hash_", "md5", "sha1", "sha256", "imphash", "checksum",
    "section", "pe_", "peid", "yara", "generic_",
)
EXPLOIT_NAME_HINTS = ("exploit", "expl_", "cve_", "cve-", "cve20")

RE_RULE_NAME = re.compile(r"^\s*rule\s+([A-Za-z_]\w*)", re.MULTILINE)


class YaraDetector(Detector):
    name = "yara"
    description = "Dopasowanie reguł YARA (bazy społecznościowe + własne)"

    def __init__(self) -> None:
        self.rules: List[Tuple[str, "yara.Rules"]] = []        # decydujące (zawsze)
        self.info_rules: List[Tuple[str, "yara.Rules"]] = []   # tylko informacyjne
        self.file_categories: Dict[str, set] = {}
        self.rule_count = 0
        self.errors: List[str] = []
        self.loaded = False
        self.rule_category: Dict[str, str] = {}   # nazwa reguły -> kategoria
        self.category_counts: Dict[str, int] = {}
        self.noisy_rules: set = set()             # reguły odrzucone testem kanarkowym
        self.suppressed_rules: set = set()        # reguły wyłączone ręcznie (lista tłumień)
        self.canary_count = 0

    # --- ładowanie ---
    def load_directory(self, directory: Path, chunk: int = 400) -> int:
        """Kompiluje wszystkie pliki *.yar/*.yara z katalogu (rekurencyjnie).

        Dwufazowo, bo skala ma znaczenie (bazy społecznościowe to ~1300 plików):

        Faza 1 - walidacja: każdy plik kompilowany jest osobno, a wynik
                odrzucany. Wyłapujemy reguły błędne lub wymagające modułów,
                których libyara nie ma (np. reguły Androida, `cuckoo`),
                oraz odczytujemy nazwy reguł do ich klasyfikacji.

        Faza 2 - wsad: poprawne pliki kompilowane są partiami po `chunk`
                do JEDNEGO obiektu reguł. Jeden obiekt = jedno przejście
                automatem Aho-Corasick po danych przy skanie, więc 4 obiekty
                zamiast 1300 to kilkunastokrotnie szybszy skan i rząd
                wielkości mniej pamięci (zmierzone: 734 MB -> 129 MB).
        """
        if yara is None:
            self.errors.append("yara-python nie jest zainstalowany")
            return 0

        directory = Path(directory)
        if not directory.exists():
            return 0

        self.rules = []
        self.info_rules = []
        self.errors = []
        self.rule_count = 0
        self.rule_category = {}
        self.file_categories = {}

        files = sorted(
            p for p in directory.rglob("*")
            if p.is_file() and p.suffix.lower() in {".yar", ".yara", ".rule", ".rules"}
        )

        # --- faza 1: walidacja + klasyfikacja ---
        good: List[Path] = []
        for path in files:
            try:
                yara.compile(filepath=str(path), externals=EXTERNALS)
            except Exception as exc:
                self.errors.append(f"{path.name}: {str(exc).splitlines()[0][:160]}")
                log.debug("Reguła YARA odrzucona %s: %s", path, exc)
                continue
            good.append(path)
            self._register_rule_names(path, directory)

        # --- faza 2: kompilacja wsadowa, osobno dla reguł decydujących
        #     i informacyjnych ---
        # Reguły informacyjne (IsPE32, contains_base64, domain…) dają 0 punktów,
        # a są najdroższe w dopasowaniu, bo pasują do wszystkiego. Trzymamy je
        # osobno, żeby na dużych plikach można je było pominąć.
        decisive = [p for p in good
                    if self.file_categories.get(str(p), {UNKNOWN}) - {INFO}]
        info_only = [p for p in good if p not in set(decisive)]

        self.rules = self._compile_group(decisive, directory, chunk, "dec")
        self.info_rules = self._compile_group(info_only, directory, chunk, "info")
        self.rule_count = len(decisive) + len(info_only)

        self.category_counts = {}
        for category in self.rule_category.values():
            self.category_counts[category] = self.category_counts.get(category, 0) + 1

        # Reguły, które dopasowują się do wszystkiego, wyłączamy z punktacji.
        self.load_suppressions()
        self.detect_noisy_rules()

        self.loaded = bool(self.rules)
        return self.rule_count

    def _compile_group(self, files: "list[Path]", root: Path, chunk: int,
                       prefix: str) -> "list[Tuple[str, yara.Rules]]":
        compiled_group = []
        for start in range(0, len(files), chunk):
            batch = files[start:start + chunk]
            mapping = {}
            for idx, path in enumerate(batch):
                namespace = _safe_namespace(path, root)
                while namespace in mapping:
                    namespace = f"{namespace}_{idx}"
                mapping[namespace] = str(path)
            try:
                compiled_group.append(
                    (f"{prefix}{len(compiled_group)}",
                     yara.compile(filepaths=mapping, externals=EXTERNALS)))
            except Exception as exc:  # nie powinno się zdarzyć po walidacji
                self.errors.append(f"wsad {prefix}{start}: {str(exc).splitlines()[0][:160]}")
        return compiled_group

    def _register_rule_names(self, path: Path, root: Path) -> None:
        """Wyciąga nazwy reguł z pliku i przypisuje im kategorię."""
        try:
            rel = str(path.relative_to(root)).replace("\\", "/")
        except ValueError:
            rel = path.name
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return
        categories = set()
        for name in RE_RULE_NAME.findall(text):
            category = classify_rule(rel, name)
            self.rule_category[name] = category
            categories.add(category)
        self.file_categories[str(path)] = categories or {UNKNOWN}

    def add_inline(self, name: str, source: str) -> bool:
        if yara is None:
            return False
        try:
            self.rules.append((name, yara.compile(source=source, externals=EXTERNALS)))
            self.loaded = True
            self.rule_count += 1
            for rule_name in RE_RULE_NAME.findall(source):
                self.rule_category[rule_name] = classify_rule(name, rule_name)
            return True
        except Exception as exc:
            self.errors.append(f"{name}: {exc}")
            return False

    # --- test kanarkowy (odrzucanie reguł generujących fałszywe alarmy) ---
    def _build_canaries(self) -> List[bytes]:
        """Zestaw próbek, na których POPRAWNA reguła nie ma prawa zadziałać.

        Publiczne bazy reguł zawierają reguły zepsute. Klasyczny przykład:
        `/BADD|Bad Error Happened|/` - pusta gałąź alternatywy pasuje do
        pustego ciągu, więc wzorzec dopasowuje się do KAŻDEGO pliku; w parze
        z `/version|ls|cd|.../` daje regułę, która flaguje niemal wszystko.

        Zamiast ręcznie utrzymywać czarną listę, sprawdzamy reguły empirycznie:
        ta, która dopasuje się do danych kanarkowych, jest zbyt ogólna, by
        mogła wnosić cokolwiek do decyzji.
        """
        canaries: List[bytes] = []

        rnd = random.Random(20240101)             # deterministycznie, by wyniki były powtarzalne
        canaries.append(bytes(rnd.getrandbits(8) for _ in range(65536)))
        canaries.append(b"\x00" * 65536)

        words = ("version ls cd exit download upload tasklist taskkill register "
                 "compress jobs shot hid link mv cp sysinfo the and that this "
                 "with from your have which one would there their").split()
        text = " ".join(words * 400)
        canaries.append(text.encode()[:65536])

        # Prawdziwe pliki wykonywalne systemowe - najlepszy test na reguły,
        # które dopasowują się do czegokolwiek binarnego. Bierzemy kilka,
        # bo reguła bywa zbyt ogólna tylko dla konkretnego typu binarki
        # (np. statycznie linkowany Go z kryptografią).
        candidates = [sys.executable, "/usr/bin/envd", "/bin/ls", "/bin/bash",
                      "/usr/bin/git", "/usr/bin/sshd", "/usr/bin/python3"]
        taken = 0
        for candidate in candidates:
            if taken >= 4:
                break
            try:
                if candidate and os.path.isfile(candidate):
                    with open(candidate, "rb") as fh:
                        canaries.append(fh.read(1 << 19))   # pierwsze 512 kB
                    taken += 1
            except Exception:
                continue
        return canaries

    def load_suppressions(self, extra_path: "Optional[Path]" = None) -> int:
        """Wczytuje ręczną listę tłumień (reguły wyłączone z punktacji)."""
        self.suppressed_rules = set()
        candidates = [
            Path(__file__).resolve().parent.parent / "sigs" / "suppressed_rules.txt",
            extra_path,
        ]
        for path in candidates:
            if path is None or not Path(path).exists():
                continue
            try:
                for line in Path(path).read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.suppressed_rules.add(line)
            except Exception:
                continue
        return len(self.suppressed_rules)

    def detect_noisy_rules(self) -> int:
        """Oznacza reguły dopasowujące się do danych kanarkowych."""
        self.noisy_rules = set()
        canaries = self._build_canaries()
        self.canary_count = len(canaries)
        all_rules = list(self.rules) + list(self.info_rules)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for _namespace, rules in all_rules:
                for canary in canaries:
                    try:
                        for m in rules.match(data=canary, timeout=60):
                            self.noisy_rules.add(m.rule)
                    except Exception:
                        continue
        log.info("Test kanarkowy odrzucił %d reguł (zbyt ogólne)", len(self.noisy_rules))
        return len(self.noisy_rules)

    # --- skanowanie ---
    def applies_to(self, ctx: ScanContext) -> bool:
        return self.loaded and bool(ctx.data)

    def _rules_for(self, ctx: ScanContext):
        """Które obiekty reguł uruchomić dla tego pliku.

        Reguły czysto informacyjne pomijamy na dużych plikach - dają 0 punktów,
        a potrafią zdominować czas skanu (zmierzone: ~40% czasu YARY na 12 MB).
        """
        if not self.info_rules:
            return self.rules
        limit = getattr(ctx.config, "yara_info_max_size", 1024 * 1024)
        if len(ctx.data) <= limit:
            return list(self.rules) + list(self.info_rules)
        return self.rules

    def run(self, ctx: ScanContext) -> List:
        """Dopasowuje reguły, klasyfikuje trafienia i dolicza punkty z limitem."""
        if not self.rules and not self.info_rules:
            return ctx.result.findings

        matches: Dict[str, dict] = {}
        for namespace, rules in self._rules_for(ctx):
            try:
                # libyara potrafi rzucać RuntimeWarning "too many matches for
                # string" - to tylko szum diagnostyczny, nie błąd skanowania.
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    yara_matches = rules.match(data=ctx.data, timeout=60)
            except Exception as exc:
                log.debug("yara match error on %s: %s", ctx.path, exc)
                continue
            for m in yara_matches:
                # Ta sama reguła bywa w kilku plikach - liczymy ją raz.
                if m.rule in matches:
                    continue
                matches[m.rule] = {
                    "rule": m.rule,
                    "namespace": namespace,
                    "meta": dict(m.meta or {}),
                    "strings": list(m.strings or []),
                }

        hits = list(matches.values())
        if not hits:
            return ctx.result.findings

        scored: List[Tuple[int, str, str, str, str, Optional[str]]] = []
        for hit in hits:
            meta = hit["meta"]
            if hit["rule"] in self.suppressed_rules:
                ctx.add(self.name, f"suppressed.{hit['rule']}", Severity.INFO.value,
                        f"Reguła na liście tłumień (znany fałszywy alarm): {hit['rule']}",
                        weight=0, evidence="zobacz avengine/sigs/suppressed_rules.txt")
                continue
            if hit["rule"] in self.noisy_rules:
                # Reguła dopasowuje się do danych kanarkowych - nie wnosi nic
                # do decyzji, a produkuje fałszywe alarmy na każdym pliku.
                ctx.add(self.name, f"noisy.{hit['rule']}", Severity.INFO.value,
                        f"Reguła odrzucona testem kanarkowym (zbyt ogólna): {hit['rule']}",
                        weight=0, evidence="dopasowuje się do danych losowych/zerowych")
                continue
            category = meta_category(meta) or self.rule_category.get(hit["rule"], UNKNOWN)
            weight = CATEGORY_WEIGHT[category]
            severity = CATEGORY_SEVERITY[category]

            # Jawna informacja w metadanych podbija wagę do decydującej.
            if category == MALWARE and str(meta.get("severity", "")).lower() == "critical":
                weight = 60
                severity = Severity.CRITICAL

            strings = []
            for s in hit["strings"][:3]:
                try:
                    strings.append(f"{s.identifier}@0x{s.instances[0].offset:x}")
                except Exception:
                    strings.append(str(getattr(s, "identifier", "?")))

            threat = meta.get("threat_name") or meta.get("malware") or meta.get("family")
            desc = meta.get("description") or f"Dopasowano regułę YARA: {hit['rule']}"
            if threat:
                desc = f"{desc} (rodzina: {threat})"
            desc = f"[{CATEGORY_LABEL[category]}] {desc}"

            scored.append((weight, category, hit["rule"], severity, desc,
                           ", ".join(strings) or None))

        # Sygnały decydujące liczą się w pełni; słabe - tylko do ustalonego limitu.
        scored.sort(key=lambda item: item[0], reverse=True)
        weak_total = 0
        emitted = 0
        for weight, category, rule_name, severity, desc, evidence in scored:
            if emitted >= MAX_REPORTED:
                break
            if weight < 30:
                if weak_total >= MAX_WEAK_SCORE:
                    continue
                weight = min(weight, MAX_WEAK_SCORE - weak_total)
                weak_total += weight
            ctx.add(self.name, f"{category}.{rule_name}", severity, desc,
                    weight=weight, evidence=evidence)
            emitted += 1
            if weight >= 50:
                break  # mamy pewny werdykt, dalej nie ma sensu

        return ctx.result.findings

    def category_stats(self) -> Dict[str, int]:
        return dict(self.category_counts)


# --------------------------------------------------------------------------
# klasyfikacja reguł
# --------------------------------------------------------------------------

def classify_rule(rel_path: str, rule_name: str) -> str:
    """Przypisuje regułę do kategorii na podstawie ścieżki i nazwy."""
    path = rel_path.lower()
    name = rule_name.lower()

    for hint in MALWARE_PATH_HINTS:
        if hint in path:
            return MALWARE
    for hint in EXPLOIT_PATH_HINTS:
        if hint in path:
            return EXPLOIT
    for hint in INFO_PATH_HINTS:
        if hint in path:
            return INFO

    for hint in MALWARE_NAME_HINTS:
        if hint in name:
            return MALWARE
    for hint in SUSPICIOUS_NAME_HINTS:
        if hint in name:
            return SUSPICIOUS
    for hint in EXPLOIT_NAME_HINTS:
        if hint in name:
            return EXPLOIT
    for hint in INFO_NAME_HINTS:
        if hint in name:
            return INFO
    return UNKNOWN


def meta_category(meta: Dict) -> Optional[str]:
    """Kategoria wynikająca wprost z metadanych reguły (ma priorytet)."""
    if meta.get("threat_name") or meta.get("malware") or meta.get("family"):
        return MALWARE
    kind = str(meta.get("type") or meta.get("category") or "").lower()
    if kind in {"malware", "ransomware", "trojan", "backdoor", "apt",
                "webshell", "miner", "rat", "stealer", "banker"}:
        return MALWARE
    if kind in {"exploit", "cve", "vulnerability"}:
        return EXPLOIT
    if kind in {"info", "informational", "info_only", "packer", "compiler"}:
        return INFO
    if kind in {"suspicious", "heuristic", "capability"}:
        return SUSPICIOUS
    return None


def _safe_namespace(path: Path, root: Path) -> str:
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = Path(path.name)
    stem = str(rel.with_suffix("")).replace("/", "_").replace("\\", "_")
    cleaned = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in stem)
    return cleaned[:64] or "rule"
