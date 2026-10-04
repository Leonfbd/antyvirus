"""Skanowanie uruchomionych procesów (analiza obrazów w pamięci).

Silnik nie zagląda w pamięć procesu (do tego potrzebny byłby sterownik
kernelowy i uprawnienia SYSTEM), ale weryfikuje to, co widać z przestrzeni
użytkownika i co w praktyce wyłapuje większość infekcji:

  * z jakiego pliku proces wystartował i czy ten plik jest złośliwy
  * czy plik w ogóle jeszcze istnieje (malware kasuje swój dropper)
  * czy proces nie podszywa się pod proces systemowy (`svchost.exe`
    uruchomiony z `%TEMP%` to nie jest systemowy svchost)
  * czy uruchomiono go z katalogu tymczasowego lub do pobierania
  * czy interpretator dostał zakodowane polecenie (`powershell -enc`)
  * czy nasłuchuje na gniazdku (możliwy kanał C2)
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .models import Finding, Severity

# Nazwy, których używa system - ich pojawienie się spoza katalogów systemowych
# jest niemal pewnym wskaźnikiem podszywania się.
SYSTEM_NAMES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "smss.exe", "winlogon.exe",
    "services.exe", "wininit.exe", "explorer.exe", "conhost.exe",
    "dllhost.exe", "rundll32.exe", "spoolsv.exe", "wmiprvse.exe",
    "ctfmon.exe", "taskhostw.exe", "msiexec.exe", "audiodg.exe",
    "lsaiso.exe", "fontdrvhost.exe", "sihost.exe", "systemd", "init",
    "kthreadd", "ksoftirqd", "sshd", "dbus-daemon", "udevd", "cron",
}
SYSTEM_DIRS = (
    "c:\\windows\\system32", "c:\\windows\\syswow64", "c:\\windows\\",
    "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec", "/bin", "/sbin",
    "/lib", "/lib64", "/system/", "/usr/local/bin", "/usr/local/sbin",
)
TEMP_DIRS = (
    "/tmp", "/var/tmp", "/dev/shm",
    "\\temp\\", "\\appdata\\local\\temp", "\\downloads\\",
    "\\appdata\\roaming\\", "/downloads/",
)
INTERPRETERS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "python", "python3",
    "bash", "sh", "zsh", "perl", "ruby",
}
ENCODED_FLAGS = ("-enc", "-encodedcommand", "-e ", "-nop ", "-w hidden",
                 "-executionpolicy bypass", "-eNcOdEdCoMmAnD")


@dataclass
class ProcessInfo:
    pid: int
    name: str
    exe: str = ""
    cmdline: str = ""
    username: str = ""
    ppid: int = 0
    started: str = ""
    verdict: str = "clean"
    score: int = 0
    connections: int = 0
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "pid": self.pid,
            "name": self.name,
            "exe": self.exe,
            "cmdline": self.cmdline[:400],
            "username": self.username,
            "ppid": self.ppid,
            "started": self.started,
            "verdict": self.verdict,
            "score": self.score,
            "connections": self.connections,
            "findings": [f.to_dict() for f in self.findings],
        }


class ProcessScanner:
    def __init__(self, engine) -> None:
        self.engine = engine
        self._cache: Dict[str, object] = {}

    def scan(self, include_connections: bool = True) -> Dict:
        """Skanuje wszystkie dostępne procesy.

        Zwraca słownik z listą procesów oraz wykazem zagrożeń, gotowy
        do pokazania w panelu lub wyeksportowania.
        """
        try:
            import psutil
        except ImportError:
            return {"error": "brak biblioteki psutil (pip install psutil)",
                    "processes": [], "threats": [], "total": 0}

        processes: List[ProcessInfo] = []
        threats: List[ProcessInfo] = []
        scanned_binaries: Dict[str, object] = {}

        attrs = ["pid", "name", "exe", "cmdline", "username", "ppid", "create_time"]
        for proc in psutil.process_iter(attrs=attrs):
            try:
                info = proc.info
            except Exception:
                continue

            p = ProcessInfo(
                pid=int(info.get("pid") or 0),
                name=str(info.get("name") or ""),
                exe=str(info.get("exe") or ""),
                cmdline=" ".join(info.get("cmdline") or [])[:1000],
                username=str(info.get("username") or ""),
                ppid=int(info.get("ppid") or 0),
                started=(time.strftime("%H:%M:%S", time.localtime(info["create_time"]))
                         if info.get("create_time") else ""),
            )

            if include_connections:
                p.connections = _count_connections(proc)

            self._analyze(p, scanned_binaries)
            processes.append(p)
            if p.verdict in ("malicious", "suspicious"):
                threats.append(p)

        processes.sort(key=lambda x: x.score, reverse=True)
        threats.sort(key=lambda x: x.score, reverse=True)

        counts = {
            "total": len(processes),
            "malicious": sum(1 for p in processes if p.verdict == "malicious"),
            "suspicious": sum(1 for p in processes if p.verdict == "suspicious"),
            "clean": sum(1 for p in processes if p.verdict == "clean"),
            "unreadable": sum(1 for p in processes if p.verdict == "unknown"),
        }
        return {
            "processes": [p.to_dict() for p in processes],
            "threats": [p.to_dict() for p in threats],
            "counts": counts,
            "scanned_binaries": len(scanned_binaries),
        }

    # --------------------------------------------------------------- analiza
    def _analyze(self, p: ProcessInfo, cache: Dict[str, object]) -> None:
        name_lower = (p.name or "").lower()
        exe_lower = (p.exe or "").lower()
        cmd_lower = (p.cmdline or "").lower()

        # --- 1. brak obrazu na dysku ---
        # Uwaga: wątki jądra (kthreadd, ksoftirqd) i procesy innych użytkowników
        # nie mają dostępnego /proc/<pid>/exe. Zanim uznamy to za atak,
        # rozróżniamy sytuacje - inaczej każdy wątek jądra wygląda na malware.
        if not p.exe:
            if not p.cmdline:
                p.findings.append(Finding(
                    "process", "kernel_thread", Severity.INFO.value,
                    "Wątek jądra lub proces bez obrazu w przestrzeni użytkownika",
                    0, p.name))
            else:
                p.findings.append(Finding(
                    "process", "no_executable", Severity.MEDIUM.value,
                    "Brak dostępu do pliku wykonywalnego procesu "
                    "(może być usunięty po uruchomieniu lub chroniony uprawnieniami)",
                    12, p.cmdline[:120]))
        elif not os.path.exists(p.exe):
            p.findings.append(Finding(
                "process", "deleted_binary", Severity.HIGH.value,
                "Proces działa z pliku, który został usunięty z dysku", 28,
                p.exe))

        # --- 2. podszywanie się pod proces systemowy ---
        # Tylko gdy znamy ścieżkę: bez niej nie da się ocenić lokalizacji.
        if p.exe and name_lower in SYSTEM_NAMES and not _in_system_dir(exe_lower):
            p.findings.append(Finding(
                "process", "masquerading", Severity.CRITICAL.value,
                f"Proces podszywa się pod proces systemowy: '{p.name}' "
                f"uruchomiony spoza katalogu systemowego", 50, p.exe or p.cmdline[:120]))

        # --- 3. uruchomienie z katalogu tymczasowego ---
        if _in_temp_dir(exe_lower) or (not p.exe and _in_temp_dir(cmd_lower)):
            p.findings.append(Finding(
                "process", "from_temp", Severity.HIGH.value,
                "Proces uruchomiony z katalogu tymczasowego lub do pobierania",
                30, p.exe or p.cmdline[:150]))

        # --- 4. zakodowane polecenie przekazane interpretatorowi ---
        if name_lower in INTERPRETERS or name_lower.endswith((".ps1", ".bat")):
            hit = next((flag for flag in ENCODED_FLAGS if flag in cmd_lower), None)
            if hit:
                p.findings.append(Finding(
                    "process", "encoded_command", Severity.CRITICAL.value,
                    f"Interpretator uruchomiony z zakodowanym poleceniem ('{hit.strip()}')",
                    45, p.cmdline[:200]))

        # --- 5. nasłuchujące gniazdko (możliwy kanał C2) ---
        if p.connections:
            p.findings.append(Finding(
                "process", "listening_socket", Severity.LOW.value,
                f"Proces utrzymuje {p.connections} otwartych połączeń sieciowych",
                5, f"pid={p.pid}"))

        # --- 6. skan samego pliku wykonywalnego ---
        if p.exe and os.path.isfile(p.exe):
            result = cache.get(p.exe)
            if result is None:
                try:
                    result = self.engine.scan_file(p.exe)
                except Exception:
                    result = None
                cache[p.exe] = result
            if result is not None and result.verdict != "clean":
                p.verdict = result.verdict
                weight = 100 if result.verdict == "malicious" else 35
                p.findings.append(Finding(
                    "process", "binary_infected",
                    Severity.CRITICAL.value if weight == 100 else Severity.HIGH.value,
                    f"Plik wykonywalny procesu jest {result.verdict} ({result.score} pkt)",
                    weight,
                    "; ".join(f"{f.detector}/{f.rule}" for f in result.findings[:3])[:300]))

        # --- werdykt łączny ---
        total = sum(f.weight for f in p.findings)
        p.score = min(100, total)
        if any(f.weight >= 50 for f in p.findings) or p.score >= 60:
            p.verdict = "malicious"
        elif p.score >= 25:
            p.verdict = "suspicious"
        elif not p.exe and not p.cmdline:
            p.verdict = "unknown"
        else:
            p.verdict = p.verdict if p.verdict != "clean" else ("clean" if p.score < 25 else "suspicious")


def _in_system_dir(path: str) -> bool:
    return any(path.startswith(d) or f"/{d.strip('/')}/" in path for d in SYSTEM_DIRS) \
        or any(d in path for d in SYSTEM_DIRS)


def _in_temp_dir(path: str) -> bool:
    return any(token in path for token in TEMP_DIRS)


def _count_connections(proc) -> int:
    try:
        return len(proc.connections(kind="inet"))
    except Exception:
        # Wymaga uprawnień - na Windowsie zwykle działa, na Linuksie bywa blokowane.
        return 0
