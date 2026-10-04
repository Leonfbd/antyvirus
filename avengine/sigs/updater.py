"""Aktualizator baz sygnatur.

Źródła są klonowane przez git (repozytoria społecznościowe z regułami YARA).
Każde źródło leży we własnym podkatalogu, więc uszkodzony feed nie psuje
pozostałych, a wynik aktualizacji jest zapisywany w manifeście.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger(__name__)

MANIFEST = "manifest.json"


class SignatureUpdater:
    def __init__(self, config) -> None:
        self.config = config
        self.manifest_path = config.sigs_dir / MANIFEST

    def update(self, sources: Optional[List[Dict[str, str]]] = None,
               timeout: int = 300) -> Dict[str, object]:
        self.config.ensure_dirs()
        sources = sources if sources is not None else self.config.signature_sources
        results: List[Dict[str, object]] = []

        for src in sources:
            info: Dict[str, object] = {
                "name": src.get("name", "?"),
                "url": src.get("url", ""),
                "status": "pending",
                "rules": 0,
                "error": None,
            }
            target = self.config.yara_dir / str(src.get("path") or src.get("name"))
            try:
                if (target / ".git").exists():
                    self._run(["git", "-C", str(target), "pull", "--depth", "1", "-q"], timeout)
                    info["status"] = "updated"
                else:
                    if target.exists():
                        shutil.rmtree(target, ignore_errors=True)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    self._run(["git", "clone", "--depth", "1", "-q",
                               str(src.get("url")), str(target)], timeout)
                    info["status"] = "cloned"
                info["rules"] = self._count_yara(target)
            except Exception as exc:
                info["status"] = "error"
                info["error"] = str(exc)[:300]
            results.append(info)

        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        (self.config.sigs_dir / "hashlists").mkdir(parents=True, exist_ok=True)

        manifest = {
            "updated_at": time.time(),
            "sources": results,
        }
        self.manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
        return manifest

    def status(self) -> Dict[str, object]:
        if not self.manifest_path.exists():
            return {"updated_at": 0, "sources": []}
        try:
            return json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except Exception:
            return {"updated_at": 0, "sources": []}

    def _run(self, cmd: List[str], timeout: int) -> str:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or proc.stdout or "git error").strip()[:300])
        return proc.stdout or ""

    @staticmethod
    def _count_yara(path: Path) -> int:
        if not path.exists():
            return 0
        return sum(
            1 for p in path.rglob("*")
            if p.is_file() and p.suffix.lower() in {".yar", ".yara", ".rule", ".rules"}
        )
