"""Baza historii skanów (SQLite ze standardowej biblioteki)."""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at REAL NOT NULL,
    finished_at REAL,
    target TEXT NOT NULL,
    triggered_by TEXT DEFAULT 'manual',
    total INTEGER DEFAULT 0,
    clean INTEGER DEFAULT 0,
    suspicious INTEGER DEFAULT 0,
    malicious INTEGER DEFAULT 0,
    errors INTEGER DEFAULT 0,
    bytes_scanned INTEGER DEFAULT 0,
    elapsed_ms INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    detected_at REAL NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT,
    verdict TEXT,
    score INTEGER,
    detector TEXT,
    rule TEXT,
    severity TEXT,
    description TEXT,
    evidence TEXT,
    quarantined INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    path TEXT,
    message TEXT
);

CREATE INDEX IF NOT EXISTS idx_detections_path ON detections(path);
CREATE INDEX IF NOT EXISTS idx_detections_time ON detections(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(ts DESC);
"""


class Storage:
    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    @contextmanager
    def conn(self):
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _init(self) -> None:
        with self.conn() as c:
            c.executescript(SCHEMA)

    # ------------------------------------------------------------------ skany
    def start_scan(self, target: str, triggered_by: str = "manual") -> int:
        with self.conn() as c:
            cur = c.execute(
                "INSERT INTO scans (started_at, target, triggered_by) VALUES (?, ?, ?)",
                (time.time(), target, triggered_by),
            )
            return int(cur.lastrowid or 0)

    def finish_scan(self, scan_id: int, summary: Dict[str, Any]) -> None:
        with self.conn() as c:
            c.execute(
                """UPDATE scans SET finished_at=?, total=?, clean=?, suspicious=?,
                   malicious=?, errors=?, bytes_scanned=?, elapsed_ms=?
                   WHERE id=?""",
                (time.time(), summary.get("total", 0), summary.get("clean", 0),
                 summary.get("suspicious", 0), summary.get("malicious", 0),
                 summary.get("errors", 0), summary.get("bytes_scanned", 0),
                 summary.get("elapsed_ms", 0), scan_id),
            )

    def record_detections(self, result, scan_id: Optional[int] = None) -> None:
        if not result.findings:
            return
        with self.conn() as c:
            for f in result.findings:
                c.execute(
                    """INSERT INTO detections
                       (scan_id, detected_at, path, sha256, verdict, score, detector,
                        rule, severity, description, evidence, quarantined)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (scan_id, time.time(), result.path, result.sha256, result.verdict,
                     result.score, f.detector, f.rule, f.severity, f.description,
                     (f.evidence or "")[:1000], int(getattr(result, "quarantined", False))),
                )

    # ------------------------------------------------------------------ odczyt
    def recent_scans(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self.conn() as c:
            rows = c.execute(
                "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def recent_detections(self, limit: int = 100, verdict: Optional[str] = None) -> List[Dict[str, Any]]:
        query = "SELECT * FROM detections"
        params: List[Any] = []
        if verdict:
            query += " WHERE verdict = ?"
            params.append(verdict)
        query += " ORDER BY detected_at DESC LIMIT ?"
        params.append(limit)
        with self.conn() as c:
            rows = c.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> Dict[str, Any]:
        with self.conn() as c:
            scans = c.execute("SELECT COUNT(*) n, COALESCE(SUM(total),0) files FROM scans").fetchone()
            threats = c.execute(
                "SELECT COUNT(*) n FROM detections WHERE verdict IN ('malicious','suspicious')").fetchone()
            by_verdict = {
                r["verdict"]: r["n"] for r in c.execute(
                    "SELECT verdict, COUNT(*) n FROM detections GROUP BY verdict")
            }
            top_rules = [
                dict(r) for r in c.execute(
                    """SELECT rule, detector, COUNT(*) n FROM detections
                       GROUP BY rule, detector ORDER BY n DESC LIMIT 10""")
            ]
        return {
            "scans": scans["n"],
            "files_scanned": scans["files"],
            "threats": threats["n"],
            "by_verdict": by_verdict,
            "top_rules": top_rules,
        }

    # ----------------------------------------------------------------- zdarzenia
    def add_event(self, kind: str, path: str = "", message: str = "") -> None:
        with self.conn() as c:
            c.execute(
                "INSERT INTO events (ts, kind, path, message) VALUES (?,?,?,?)",
                (time.time(), kind, path, message))

    def recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.conn() as c:
            rows = c.execute(
                "SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def clear_events(self) -> None:
        with self.conn() as c:
            c.execute("DELETE FROM events")
