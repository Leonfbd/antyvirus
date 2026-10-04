"""Monitoring w czasie rzeczywistym (real-time protection).

Działa na watchdogu: na Linuksie inotify, na Windows ReadDirectoryChangesW.
Zdarzenia trafiają do kolejki, a wątek roboczy skanuje pliki z opóźnieniem
(debounce) - zapisywany plik raportowany bywa kilkanaście razy, a my chcemy
zeskanować go raz, dopiero gdy przestanie się zmieniać.
"""

from __future__ import annotations

import logging
import os
import queue
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

log = logging.getLogger(__name__)

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except Exception:  # pragma: no cover
    FileSystemEventHandler = object  # type: ignore
    Observer = None  # type: ignore

# Odczekujemy, aż plik przestanie rosnąć (kopiowanie z sieci bywa powolne).
SETTLE_SECONDS = 1.2
MAX_SETTLE_WAIT = 15.0


class _Handler(FileSystemEventHandler):  # type: ignore[misc]
    def __init__(self, sink: "queue.Queue[str]") -> None:
        self.sink = sink

    def on_created(self, event) -> None:
        if not event.is_directory:
            self.sink.put(event.src_path)

    def on_modified(self, event) -> None:
        if not event.is_directory:
            self.sink.put(event.src_path)

    def on_moved(self, event) -> None:
        if not event.is_directory:
            self.sink.put(getattr(event, "dest_path", event.src_path))


class RealtimeMonitor:
    def __init__(self, engine, storage=None, quarantine=None,
                 on_event: Optional[Callable[[str, str, str], None]] = None) -> None:
        self.engine = engine
        self.storage = storage
        self.quarantine = quarantine
        self.on_event = on_event
        self._queue: "queue.Queue[str]" = queue.Queue()
        self._observers: List = []
        self._worker: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.running = False
        self.watched: List[str] = []
        self.scanned_count = 0
        self.threat_count = 0

    # ----------------------------------------------------------------- kontrola
    def start(self, paths: Optional[List[str]] = None, recursive: bool = True) -> Dict:
        if Observer is None:
            raise RuntimeError("watchdog nie jest zainstalowany (pip install watchdog)")
        if self.running:
            return {"status": "already_running", "paths": self.watched}

        paths = paths or self.engine.config.watched_paths
        paths = [str(Path(p).expanduser()) for p in paths if p]
        existing = [p for p in paths if os.path.isdir(p)]
        missing = [p for p in paths if p not in existing]

        self.watched = existing
        self._stop.clear()
        for path in existing:
            try:
                observer = Observer()
                observer.schedule(_Handler(self._queue), path, recursive=recursive)
                observer.start()
                self._observers.append(observer)
            except Exception as exc:
                log.warning("Nie można obserwować %s: %s", path, exc)
                missing.append(path)

        self._worker = threading.Thread(target=self._loop, daemon=True)
        self._worker.start()
        self.running = True
        self._emit("realtime_started", "", f"Obserwowane katalogi: {', '.join(existing)}")
        return {"status": "started", "paths": existing, "missing": missing}

    def stop(self) -> Dict:
        if not self.running:
            return {"status": "not_running"}
        self._stop.set()
        for observer in self._observers:
            try:
                observer.stop()
                observer.join(timeout=3)
            except Exception:
                pass
        self._observers = []
        self.running = False
        self._emit("realtime_stopped", "", "Monitoring zatrzymany")
        return {"status": "stopped"}

    # -------------------------------------------------------------------- pętla
    def _loop(self) -> None:
        pending: Dict[str, float] = {}
        while not self._stop.is_set():
            try:
                path = self._queue.get(timeout=0.5)
                if path:
                    pending[path] = time.time()
            except queue.Empty:
                pass

            now = time.time()
            for path, seen in list(pending.items()):
                if now - seen < SETTLE_SECONDS:
                    continue
                if not _stable(path, pending[path]):
                    pending[path] = now
                    continue
                del pending[path]
                try:
                    self._handle(path)
                except Exception as exc:
                    log.warning("Błąd skanu real-time %s: %s", path, exc)

    def _handle(self, path: str) -> None:
        # Nie skanujemy własnego katalogu danych - inaczej zapętlimy się
        # między kwarantanną a zdarzeniami.
        data_dir = str(self.engine.config.data_dir)
        if path.startswith(data_dir):
            return
        if not os.path.isfile(path):
            return

        try:
            result = self.engine.scan_file(path)
        except Exception as exc:
            log.debug("real-time: pominięto %s (%s)", path, exc)
            return

        self.scanned_count += 1

        if result.verdict in ("malicious", "suspicious"):
            self.threat_count += 1
            reason = "; ".join(f"{f.rule}" for f in result.findings[:3])
            self._emit("threat_detected", path,
                       f"{result.verdict.upper()} ({result.score} pkt): {reason}")

            if self.storage is not None:
                try:
                    self.storage.record_detections(result)
                except Exception:
                    pass

            if self.engine.should_quarantine(result) and self.quarantine is not None:
                entry = self.quarantine.add(path, result)
                if entry:
                    result.quarantined = True
                    self._emit("quarantined", path,
                               f"Przeniesiono do kwarantanny: {entry.id[:16]}...")
        elif result.verdict == "clean":
            self._emit("file_clean", path, f"Czysty ({result.elapsed_ms} ms)")

    def _emit(self, kind: str, path: str, message: str) -> None:
        if self.storage is not None:
            try:
                self.storage.add_event(kind, path, message)
            except Exception:
                pass
        if self.on_event:
            try:
                self.on_event(kind, path, message)
            except Exception:
                pass

    def status(self) -> Dict:
        return {
            "running": self.running,
            "paths": self.watched,
            "scanned": self.scanned_count,
            "threats": self.threat_count,
        }


def _stable(path: str, since: float) -> bool:
    """Czeka, aż rozmiar pliku przestanie się zmieniać."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return False
    deadline = time.time() + MAX_SETTLE_WAIT
    while time.time() < deadline:
        time.sleep(0.25)
        try:
            new_size = os.path.getsize(path)
        except OSError:
            return False
        if new_size == size:
            return True
        size = new_size
    return False
