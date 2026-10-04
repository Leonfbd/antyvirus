"""Konfiguracja silnika - ładowana z JSON, z rozsądnymi domyślnymi."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List


def default_data_dir() -> Path:
    env = os.environ.get("AVENGINE_DATA")
    if env:
        return Path(env).expanduser().resolve()
    return Path(__file__).resolve().parent.parent / "data"


@dataclass
class Config:
    # --- progi decyzyjne ---
    suspicious_threshold: int = 25
    malicious_threshold: int = 60
    entropy_section_threshold: float = 7.2
    entropy_file_threshold: float = 7.5
    fuzzy_similarity_threshold: int = 85   # % podobieństwa ssdeep do znanej próbki
    max_file_size: int = 200 * 1024 * 1024  # pomijamy większe pliki
    max_workers: int = 8

    # --- archiwa (ochrona przed bombami zip i wykładniczym zagnieżdżeniem) ---
    # --- wydajność ---
    # ssdeep to czysty Python: ~11 s dla 12 MB. Liczymy go tylko wtedy, gdy
    # baza zawiera hasze fuzzy (inaczej i tak nikt go nie użyje).
    max_fuzzy_size: int = 8 * 1024 * 1024
    # Reguły YARA sklasyfikowane jako „info" dają 0 punktów, a kosztują
    # najwięcej (pasują do wszystkiego). Na dużych plikach je pomijamy.
    yara_info_max_size: int = 1024 * 1024
    # Entropia z próbki zamiast z całego pliku powyżej tego rozmiaru.
    entropy_sample_threshold: int = 4 * 1024 * 1024
    entropy_sample_size: int = 2 * 1024 * 1024

    max_archive_depth: int = 3
    max_archive_members: int = 300
    max_member_size: int = 50 * 1024 * 1024
    max_total_extracted: int = 200 * 1024 * 1024
    max_compression_ratio: int = 200

    # --- zachowanie ---
    quarantine_enabled: bool = True
    quarantine_on_malicious: bool = True
    quarantine_on_suspicious: bool = False
    follow_symlinks: bool = False
    scan_archives: bool = True

    # --- real-time ---
    realtime_enabled: bool = False
    watched_paths: List[str] = field(default_factory=lambda: [str(Path.home() / "Downloads")])
    realtime_recursive: bool = True

    # --- aktualizacje sygnatur ---
    signature_sources: List[Dict[str, str]] = field(default_factory=lambda: [
        {
            "name": "yara-rules",
            "type": "git",
            "url": "https://github.com/Yara-Rules/rules.git",
            "path": "yara-rules",
        },
        {
            "name": "signature-base",
            "type": "git",
            "url": "https://github.com/Neo23x0/signature-base.git",
            "path": "signature-base",
        },
    ])
    auto_update_hours: int = 24

    # --- WWW ---
    web_host: str = "0.0.0.0"
    web_port: int = 8080

    def __post_init__(self) -> None:
        self.data_dir = default_data_dir()

    # --- ścieżki pochodne ---
    @property
    def sigs_dir(self) -> Path:
        return self.data_dir / "sigs"

    @property
    def yara_dir(self) -> Path:
        return self.sigs_dir / "yara"

    @property
    def quarantine_dir(self) -> Path:
        return self.data_dir / "quarantine"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "avengine.db"

    @property
    def config_path(self) -> Path:
        return self.data_dir / "config.json"

    def ensure_dirs(self) -> None:
        for p in (self.data_dir, self.sigs_dir, self.yara_dir, self.quarantine_dir):
            p.mkdir(parents=True, exist_ok=True)

    # --- (de)serializacja ---
    def to_dict(self) -> Dict:
        d = asdict(self)
        d.pop("data_dir", None)
        d["data_dir"] = str(self.data_dir)
        return d

    @classmethod
    def from_file(cls, path: Path) -> "Config":
        cfg = cls()
        try:
            if Path(path).exists():
                raw = json.loads(Path(path).read_text(encoding="utf-8"))
                known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
                for k, v in raw.items():
                    if k in known:
                        setattr(cfg, k, v)
        except Exception:
            pass
        return cfg

    def save(self, path: Path | None = None) -> Path:
        target = Path(path) if path else self.config_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        return target
