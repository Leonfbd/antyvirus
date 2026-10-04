"""Interfejs WWW (FastAPI): pulpitu sterowania, API REST i obsługa skanów."""

from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from ..config import Config
from ..models import Verdict
from .api_models import ConfigUpdate, IOCRequest, RealtimeRequest, ScanRequest

log = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"


class ScanJob:
    def __init__(self, job_id: str, paths: List[str],
                 quarantine: Optional[bool] = None) -> None:
        self.id = job_id
        self.paths = paths
        self.quarantine = quarantine
        self.state = "running"
        self.done = 0
        self.total = 0
        self.started_at = time.time()
        self.summary: Optional[Dict[str, Any]] = None
        self.current: Optional[str] = None
        self.threats: List[Dict[str, Any]] = []


class AVWebApp:
    def __init__(self, engine, storage=None, quarantine=None, monitor=None,
                 config: Optional[Config] = None) -> None:
        self.engine = engine
        self.storage = storage
        self.quarantine = quarantine
        self.monitor = monitor
        self.config = config or engine.config
        self.jobs: Dict[str, ScanJob] = {}
        self._lock = threading.Lock()
        self.app = self._build()

    # ------------------------------------------------------------------ budowa
    def _build(self) -> FastAPI:
        app = FastAPI(title="AntyVirus", version=self.engine.VERSION,
                      docs_url="/api/docs", redoc_url=None)

        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

        @app.get("/", include_in_schema=False)
        def index():
            return FileResponse(STATIC_DIR / "index.html")

        @app.get("/api/status")
        def status():
            return self._status()

        @app.post("/api/scan")
        def scan(req: ScanRequest):
            return self._start_scan(req)

        @app.get("/api/scan/{job_id}")
        def scan_status(job_id: str):
            job = self.jobs.get(job_id)
            if not job:
                raise HTTPException(404, "Nie ma takiego zadania")
            return self._job_payload(job)

        @app.get("/api/jobs")
        def jobs():
            return [self._job_payload(j) for j in self.jobs.values()]

        @app.get("/api/detections")
        def detections(limit: int = 200, verdict: Optional[str] = None):
            if self.storage is None:
                return []
            return self.storage.recent_detections(limit=limit, verdict=verdict)

        @app.get("/api/events")
        def events(limit: int = 100):
            if self.storage is None:
                return []
            return self.storage.recent_events(limit=limit)

        @app.get("/api/history")
        def history(limit: int = 20):
            if self.storage is None:
                return []
            return self.storage.recent_scans(limit=limit)

        @app.get("/api/quarantine")
        def quarantine_list():
            if self.quarantine is None:
                return []
            return self.quarantine.list()

        @app.post("/api/quarantine/{entry_id}/restore")
        def quarantine_restore(entry_id: str):
            if self.quarantine is None:
                raise HTTPException(503, "Kwarantanna niedostępna")
            dest = self.quarantine.restore(entry_id)
            if not dest:
                raise HTTPException(404, "Nie znaleziono wpisu")
            if self.storage:
                self.storage.add_event("restored", dest, "Przywrócono z kwarantanny")
            return {"status": "restored", "path": dest}

        @app.delete("/api/quarantine/{entry_id}")
        def quarantine_delete(entry_id: str):
            if self.quarantine is None:
                raise HTTPException(503, "Kwarantanna niedostępna")
            ok = self.quarantine.delete(entry_id)
            if not ok:
                raise HTTPException(404, "Nie znaleziono wpisu")
            if self.storage:
                self.storage.add_event("deleted", entry_id, "Usunięto z kwarantanny")
            return {"status": "deleted"}

        @app.post("/api/sigs/update")
        def sigs_update(background: BackgroundTasks):
            return self._update_sigs(background)

        @app.get("/api/sigs/status")
        def sigs_status():
            from ..sigs.updater import SignatureUpdater
            updater = SignatureUpdater(self.config)
            return updater.status()

        @app.post("/api/ioc")
        def add_ioc(req: IOCRequest):
            ok = self.engine.store.add_ioc(req.hash_value, req.name)
            if not ok:
                raise HTTPException(400, "Skrót musi mieć 32 (md5), 40 (sha1) lub 64 (sha256) znaki")
            return {"status": "added", "total": len(self.engine.store.hashes)}

        @app.post("/api/realtime")
        def realtime(req: RealtimeRequest):
            return self._set_realtime(req)

        @app.get("/api/config")
        def get_config():
            return self.config.to_dict()

        @app.post("/api/config")
        def update_config(update: ConfigUpdate):
            data = update.dict(exclude_none=True)
            for key, value in data.items():
                setattr(self.config, key, value)
            self.config.save()
            return self.config.to_dict()

        @app.get("/api/browse")
        def browse(path: str = ""):
            """Podpowiadacz ścieżek dla pola skanowania."""
            return self._browse(path)

        return app

    # ---------------------------------------------------------------- endpointy
    def _status(self) -> Dict[str, Any]:
        stats = self.engine.store.stats.to_dict()
        rt = self.monitor.status() if self.monitor else {"running": False, "paths": []}
        qcount = len(self.quarantine.list()) if self.quarantine else 0
        db_stats = self.storage.stats() if self.storage else {}
        package_root = Path(__file__).resolve().parents[2]
        return {
            "version": self.engine.VERSION,
            "protection": "on" if rt.get("running") else "off",
            "signatures": stats,
            "realtime": rt,
            "quarantine_count": qcount,
            "database": db_stats,
            "platform": os.name,
            "hostname": os.uname().nodename if hasattr(os, "uname") else "windows",
            "home_dir": str(Path.home()),
            "samples_dir": str(package_root / "samples"),
        }

    def _start_scan(self, req: ScanRequest) -> Dict[str, Any]:
        paths = [p for p in (req.paths or []) if p]
        if not paths:
            paths = [str(Path.home())]
        existing = [p for p in paths if os.path.exists(p)]
        if not existing:
            raise HTTPException(400, f"Nie znaleziono ścieżek: {paths}")

        job_id = uuid.uuid4().hex[:12]
        job = ScanJob(job_id, existing, quarantine=req.quarantine)
        with self._lock:
            self.jobs[job_id] = job

        if self.storage:
            job.scan_id = self.storage.start_scan(", ".join(existing), "manual")

        thread = threading.Thread(
            target=self._run_scan,
            args=(job, req.workers or self.config.max_workers),
            daemon=True,
        )
        thread.start()
        return {"job_id": job_id, "paths": existing}

    def _run_scan(self, job: ScanJob, workers: int) -> None:
        try:
            def progress(done: int, total: int, result) -> None:
                job.done = done
                job.total = total
                job.current = result.path
                if result.verdict in (Verdict.MALICIOUS.value, Verdict.SUSPICIOUS.value):
                    job.threats.append({
                        "path": result.path,
                        "verdict": result.verdict,
                        "score": result.score,
                        "rules": [f"{f.detector}/{f.rule}" for f in result.findings[:4]],
                        "sha256": result.sha256,
                        "size": result.size,
                    })
                    if self.engine.should_quarantine(result, job.quarantine) and self.quarantine:
                        entry = self.quarantine.add(result.path, result)
                        if entry:
                            result.quarantined = True
                            if self.storage:
                                self.storage.add_event(
                                    "quarantined", result.path,
                                    f"{result.verdict} ({result.score} pkt)")

            summary = self.engine.scan_paths(job.paths, progress=progress, workers=workers)
            job.summary = summary.to_dict(include_results=True)
            job.state = "done"
            if self.storage:
                self.storage.finish_scan(getattr(job, "scan_id", 0), summary.to_dict(include_results=False))
                self.storage.add_event(
                    "scan_finished", ", ".join(job.paths),
                    f"{summary.total} plików, {summary.malicious} złośliwych, "
                    f"{summary.suspicious} podejrzanych ({summary.elapsed_ms} ms)")
        except Exception as exc:
            job.state = "error"
            job.summary = {"error": str(exc)}
            log.exception("Skan nie powiódł się")

    def _job_payload(self, job: ScanJob) -> Dict[str, Any]:
        percent = int(job.done * 100 / job.total) if job.total else 0
        payload: Dict[str, Any] = {
            "id": job.id,
            "state": job.state,
            "paths": job.paths,
            "done": job.done,
            "total": job.total,
            "percent": percent,
            "current": job.current,
            "threats": job.threats[-100:],
            "elapsed_ms": int((time.time() - job.started_at) * 1000),
        }
        if job.state == "done" and job.summary:
            payload["summary"] = {
                k: v for k, v in job.summary.items() if k != "results"
            }
        return payload

    def _update_sigs(self, background: BackgroundTasks) -> Dict[str, Any]:
        from ..sigs.updater import SignatureUpdater
        updater = SignatureUpdater(self.config)
        try:
            manifest = updater.update()
        except Exception as exc:
            raise HTTPException(500, f"Aktualizacja nie powiodła się: {exc}")
        # Przeładowujemy bazy bez przerywania pracy silnika.
        self.engine.load(sources=manifest.get("sources"))
        if self.storage:
            self.storage.add_event("sigs_updated", "", "Zaktualizowano bazy sygnatur")
        return {"status": "ok", "manifest": manifest,
                "signatures": self.engine.store.stats.to_dict()}

    def _set_realtime(self, req: RealtimeRequest) -> Dict[str, Any]:
        if self.monitor is None:
            raise HTTPException(503, "Moduł real-time niedostępny")
        if req.enabled:
            result = self.monitor.start(paths=req.paths, recursive=req.recursive)
            self.config.realtime_enabled = True
            if req.paths:
                self.config.watched_paths = req.paths
        else:
            result = self.monitor.stop()
            self.config.realtime_enabled = False
        self.config.save()
        return {"realtime": self.monitor.status(), "detail": result}

    def _browse(self, path: str) -> List[Dict[str, str]]:
        base = Path(path).expanduser() if path else Path.home()
        if not base.exists():
            base = Path("/") if os.name != "nt" else Path("C:/")
        if base.is_file():
            base = base.parent
        try:
            entries = sorted(base.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        except PermissionError:
            raise HTTPException(403, "Brak dostępu")
        out = []
        for entry in entries[:200]:
            if entry.name.startswith("."):
                continue
            out.append({
                "name": entry.name,
                "path": str(entry),
                "type": "dir" if entry.is_dir() else "file",
            })
        return out
