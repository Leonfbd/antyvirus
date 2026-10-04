"""Silnik skanujący - orkiestracja wszystkich warstw detekcji."""

from __future__ import annotations

import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional

from .config import Config
from .detectors.base import Detector, ScanContext
from .detectors.clamav_sig import ClamAVDetector
from .detectors.packer import PackerDetector
from .detectors.pe_heuristics import PEHeuristicsDetector
from .detectors.script_heuristics import ScriptHeuristicsDetector
from .detectors.signature import SignatureDetector
from .detectors.yara_layer import YaraDetector
from .filetype import detect, is_scannable, pretty
from .hashing import bytes_hashes, imphash, ssdeep_hash
from .models import ScanResult, ScanSummary, Verdict
from .sigs.store import SignatureStore

logging.getLogger("pefile").setLevel(logging.ERROR)
log = logging.getLogger(__name__)

try:
    import pefile  # type: ignore
except Exception:  # pragma: no cover
    pefile = None


class Engine:
    """Główny punkt wejścia: ładuje sygnatury, skanuje pliki i katalogi."""

    VERSION = "0.1.0"

    def __init__(self, config: Optional[Config] = None, storage=None) -> None:
        self.config = config or Config()
        self.config.ensure_dirs()
        self.storage = storage
        self.store = SignatureStore(self.config)

        # Kolejność ma znaczenie: od najtańszych i najpewniejszych do najdroższych.
        self.detectors: List[Detector] = [
            SignatureDetector(),
            ClamAVDetector(),
            self.store.yara,
            PEHeuristicsDetector(),
            PackerDetector(),
            ScriptHeuristicsDetector(),
        ]
        self.loaded = False

    # ------------------------------------------------------------------ start
    def load(self, load_yara: bool = True, sources: Optional[List[Dict]] = None):
        stats = self.store.load(load_yara=load_yara, sources=sources)
        self.loaded = True
        return stats

    def stats(self):
        return self.store.stats

    # ------------------------------------------------------------------- scan
    def scan_file(self, path: str | Path) -> ScanResult:
        path = str(path)
        started = time.perf_counter()
        result = ScanResult(path=path)

        try:
            st = os.stat(path)
            if not os.path.isfile(path):
                result.verdict = Verdict.SKIPPED.value
                result.elapsed_ms = _ms(started)
                return result
            result.size = st.st_size
            if st.st_size > self.config.max_file_size:
                result.verdict = Verdict.SKIPPED.value
                result.error = f"Plik większy niż limit ({st.st_size} B)"
                result.elapsed_ms = _ms(started)
                return result
            with open(path, "rb") as fh:
                data = fh.read()
        except Exception as exc:
            result.error = f"{type(exc).__name__}: {exc}"
            result.finalize()
            result.elapsed_ms = _ms(started)
            return result

        return self.scan_bytes(path, data, started=started, result=result)

    def scan_bytes(self, path: str, data: bytes, started: Optional[float] = None,
                   result: Optional[ScanResult] = None) -> ScanResult:
        started = started if started is not None else time.perf_counter()
        result = result or ScanResult(path=path)
        result.size = len(data)

        result.file_type = detect(data, path)
        hashes = bytes_hashes(data)
        result.md5, result.sha1, result.sha256 = hashes["md5"], hashes["sha1"], hashes["sha256"]
        result.ssdeep = ssdeep_hash(data) if len(data) >= 4096 else ""

        pe = None
        pe_error = None
        if result.file_type == "pe" and pefile is not None:
            try:
                pe = pefile.PE(data=data)
                result.imphash = imphash(pe)
            except Exception as exc:
                pe_error = f"{type(exc).__name__}: {exc}"[:200]
                # Uszkodzony nagłówek PE to sam w sobie sygnał.
                from .models import Severity
                result.add(type("F", (), {})() if False else _finding(
                    "pe_heuristics", "corrupt_pe", Severity.MEDIUM,
                    "Nagłówek PE jest uszkodzony lub celowo zniekształcony",
                    18, pe_error))

        ctx = ScanContext(
            path=path, data=data, file_type=result.file_type, result=result,
            config=self.config, store=self.store, pe=pe, pe_error=pe_error,
        )

        for detector in self.detectors:
            try:
                if not detector.applies_to(ctx):
                    continue
            except Exception:
                continue
            try:
                detector.run(ctx)
            except Exception as exc:
                log.warning("Detektor %s nie powiódł się dla %s: %s",
                            detector.name, path, exc)
            # Short-circuit: mamy pewny werdykt, nie traćmy czasu na resztę.
            if result.findings and result.findings[-1].weight >= 100:
                break

        result.finalize(self.config.suspicious_threshold, self.config.malicious_threshold)
        result.elapsed_ms = _ms(started)
        return result

    # -------------------------------------------------------------- bulk scan
    def scan_paths(self, paths: Iterable[str | Path],
                   progress: Optional[Callable[[int, int, ScanResult], None]] = None,
                   workers: Optional[int] = None) -> ScanSummary:
        started = time.perf_counter()
        summary = ScanSummary()
        files = list(_iter_files(paths, follow_symlinks=self.config.follow_symlinks))
        total = len(files)
        done = 0

        workers = max(1, workers or self.config.max_workers)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self.scan_file, f): f for f in files}
            for fut in as_completed(futures):
                try:
                    result = fut.result()
                except Exception as exc:
                    result = ScanResult(path=str(futures[fut]), error=str(exc))
                    result.finalize()
                summary.ingest(result)
                summary.results.append(result)
                if self.storage is not None and result.findings:
                    try:
                        self.storage.record_detections(result)
                    except Exception:
                        pass
                done += 1
                if progress:
                    progress(done, total, result)

        summary.elapsed_ms = _ms(started)
        return summary

    def scan_directory(self, path: str | Path, **kwargs) -> ScanSummary:
        return self.scan_paths([path], **kwargs)

    # -------------------------------------------------------------- kwarantanna
    def should_quarantine(self, result: ScanResult,
                          override: Optional[bool] = None) -> bool:
        """Czy plik powinien trafić do kwarantanny.

        `override` pozwala wymusić decyzję dla konkretnego skanu
        (np. skan demonstracyjny bez izolowania), nie zmieniając konfiguracji.
        """
        if override is False:
            return False
        if override is True:
            return result.verdict in (Verdict.MALICIOUS.value, Verdict.SUSPICIOUS.value)
        if not self.config.quarantine_enabled:
            return False
        if result.verdict == Verdict.MALICIOUS.value:
            return self.config.quarantine_on_malicious
        if result.verdict == Verdict.SUSPICIOUS.value:
            return self.config.quarantine_on_suspicious
        return False


def _finding(detector: str, rule: str, severity, description: str, weight: int, evidence=None):
    from .models import Finding
    sev = severity.value if hasattr(severity, "value") else severity
    return Finding(detector, rule, sev, description, weight, evidence)


def _ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


def _iter_files(paths: Iterable[str | Path], follow_symlinks: bool = False) -> Iterable[Path]:
    for raw in paths:
        p = Path(raw)
        if p.is_file():
            yield p
            continue
        if not p.exists():
            continue
        for root, dirs, files in os.walk(p, followlinks=follow_symlinks):
            # Pomijamy własne katalogi robocze silnika.
            dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "quarantine", "__pycache__"}]
            for name in files:
                full = Path(root) / name
                if full.is_symlink() and not follow_symlinks:
                    continue
                yield full
