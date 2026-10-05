"""Modele żądań dla API WWW."""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    paths: List[str] = Field(default_factory=list)
    workers: Optional[int] = None
    quarantine: Optional[bool] = None   # None = zgodnie z konfiguracją silnika


class RealtimeRequest(BaseModel):
    enabled: bool
    paths: Optional[List[str]] = None
    recursive: bool = True


class ConfigUpdate(BaseModel):
    suspicious_threshold: Optional[int] = None
    malicious_threshold: Optional[int] = None
    max_file_size: Optional[int] = None
    max_workers: Optional[int] = None
    quarantine_enabled: Optional[bool] = None
    quarantine_on_malicious: Optional[bool] = None
    quarantine_on_suspicious: Optional[bool] = None
    entropy_file_threshold: Optional[float] = None
    watched_paths: Optional[List[str]] = None
    scan_archives: Optional[bool] = None


class IOCRequest(BaseModel):
    hash_value: str
    name: str = "dodane ręcznie"


class SandboxRequest(BaseModel):
    path: str
    timeout: Optional[int] = None       # sekundy, ograniczone po stronie serwera
