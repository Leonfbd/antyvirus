"""Kwarantanna - przenoszenie podejrzanych plików poza zasięg systemu.

Plik jest przenoszony (nie kopiowany) do katalogu kwarantanny pod nazwą
będącą jego SHA-256, a obok powstaje metadane (.json) z oryginalną ścieżką,
dzięki czemu możliwe jest przywrócenie na to samo miejsce.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class QuarantineEntry:
    id: str
    original_path: str
    quarantined_at: float
    sha256: str
    md5: str
    size: int
    verdict: str
    score: int
    reason: str

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["quarantined_at_human"] = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(self.quarantined_at))
        d["name"] = os.path.basename(self.original_path)
        return d


class Quarantine:
    EXT = ".quar"

    def __init__(self, directory: Path) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)

    def add(self, path: str, result) -> Optional[QuarantineEntry]:
        src = Path(path)
        if not src.is_file():
            return None
        entry_id = result.sha256 or (str(int(time.time() * 1000)))
        reason = "; ".join(f"{f.detector}/{f.rule}" for f in result.findings[:3]) or "wykryto zagrożenie"

        entry = QuarantineEntry(
            id=entry_id,
            original_path=str(src.resolve()),
            quarantined_at=time.time(),
            sha256=result.sha256,
            md5=result.md5,
            size=result.size,
            verdict=result.verdict,
            score=result.score,
            reason=reason[:400],
        )

        target = self.dir / f"{entry_id}{self.EXT}"
        meta = self.dir / f"{entry_id}.json"
        try:
            # Najpierw zapisujemy metadane - bez nich pliku nie da się przywrócić.
            meta.write_text(json.dumps(entry.to_dict(), indent=2, ensure_ascii=False),
                            encoding="utf-8")
            shutil.move(str(src), str(target))
        except Exception:
            # Jeśli przenoszenie się nie udało, sprzątamy metadane.
            try:
                if meta.exists():
                    meta.unlink()
            except Exception:
                pass
            return None
        return entry

    def list(self) -> List[Dict]:
        out: List[Dict] = []
        for meta in sorted(self.dir.glob(f"*{self.EXT}")):
            meta_file = meta.with_suffix(".json")
            if meta_file.exists():
                try:
                    out.append(json.loads(meta_file.read_text(encoding="utf-8")))
                    continue
                except Exception:
                    pass
            out.append({
                "id": meta.stem,
                "original_path": "(brak metadanych)",
                "name": meta.stem,
                "size": meta.stat().st_size,
                "verdict": "unknown",
                "score": 0,
                "reason": "metadane uszkodzone lub usunięte",
                "quarantined_at": meta.stat().st_mtime,
                "quarantined_at_human": time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(meta.stat().st_mtime)),
            })
        return out

    def restore(self, entry_id: str, target_dir: Optional[str] = None) -> Optional[str]:
        meta_file = self.dir / f"{entry_id}.json"
        stored = self.dir / f"{entry_id}{self.EXT}"
        if not stored.exists():
            return None
        destination = None
        if meta_file.exists():
            try:
                data = json.loads(meta_file.read_text(encoding="utf-8"))
                destination = data.get("original_path")
            except Exception:
                destination = None
        if target_dir:
            destination = os.path.join(target_dir,
                                       (os.path.basename(destination) if destination else entry_id))
        if not destination:
            destination = str(Path.home() / entry_id)
        Path(destination).parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(stored), destination)
        try:
            meta_file.unlink()
        except Exception:
            pass
        return destination

    def delete(self, entry_id: str) -> bool:
        stored = self.dir / f"{entry_id}{self.EXT}"
        meta = self.dir / f"{entry_id}.json"
        ok = False
        for f in (stored, meta):
            try:
                if f.exists():
                    f.unlink()
                    ok = True
            except Exception:
                pass
        return ok

    def purge_older_than(self, days: int) -> int:
        cutoff = time.time() - days * 86400
        removed = 0
        for entry in self.list():
            if entry.get("quarantined_at", 0) < cutoff:
                if self.delete(str(entry.get("id", ""))):
                    removed += 1
        return removed
