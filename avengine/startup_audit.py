"""Audyt autostartu - gdzie system uruchamia kod bez pytania użytkownika.

Utrwalanie się (persistence) to drugi krok niemal każdej infekcji: malware
musi przetrwać restart. Ten moduł wylicza wszystkie miejsca autostartu i
sprawdza, co z nich wystartuje - czy plik istnieje, skąd pochodzi i czy
sam nie jest złośliwy.

Obsługiwane lokalizacje:

  Windows: klucze Run / RunOnce (HKCU i HKLM), Winlogon (Shell/Userinit),
           usługi (ImagePath), foldery Startup, zadania harmonogramu
           (plik XML w C:\\Windows\\System32\\Tasks).
  Linux:   ~/.config/autostart, /etc/xdg/autostart, crontab użytkownika
           i /etc/cron.d, jednostki systemd (użytkownika i systemowe),
           /etc/init.d, /etc/rc.local, skrypty startowe powłoki.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .models import Finding, Severity

SYSTEM_NAMES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "smss.exe", "winlogon.exe",
    "services.exe", "explorer.exe", "rundll32.exe", "spoolsv.exe",
    "systemd", "init", "cron", "sshd", "dbus-daemon",
}
USER_WRITABLE = (
    os.path.expanduser("~") if os.path.expanduser("~") else "",
    "appdata", "\\temp\\", "/tmp", "/var/tmp", "/dev/shm", "downloads",
    "/home/", "/users/",
)
SUSPICIOUS_CMD = (
    (r"(?i)powershell.{0,40}-(e|enc|encodedcommand)", 40, "PowerShell z zakodowanym poleceniem"),
    (r"(?i)(certutil|bitsadmin)\s+", 35, "użycie narzędzia systemowego do pobrania kodu (LOLBIN)"),
    (r"(?i)(rundll32|regsvr32|mshta)\s", 30, "uruchomienie kodu przez narzędzie systemowe"),
    (r"(?i)(wscript|cscript)\s", 25, "uruchomienie skryptu WSH"),
    (r"(?i)cmd(\.exe)?\s+/c\s", 15, "polecenie uruchamiane przez cmd /c"),
    (r"(?i)(curl|wget)\s+.{0,60}\|\s*(sh|bash)", 40, "pobranie i uruchomienie skryptu z sieci"),
    (r"(?i)/c\s+.{0,30}(start|\\appdata\\)", 25, "uruchomienie pliku z katalogu użytkownika"),
)


@dataclass
class StartupEntry:
    name: str
    command: str
    location: str
    target: str = ""
    exists: bool = False
    verdict: str = "clean"
    score: int = 0
    findings: List[Finding] = field(default_factory=list)

    @property
    def risk(self) -> str:
        if self.score >= 60:
            return "wysokie"
        if self.score >= 25:
            return "średnie"
        if self.score > 0:
            return "niskie"
        return "brak"

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "command": self.command[:400],
            "location": self.location,
            "target": self.target,
            "exists": self.exists,
            "verdict": self.verdict,
            "score": self.score,
            "risk": self.risk,
            "findings": [f.to_dict() for f in self.findings],
        }


class StartupAuditor:
    def __init__(self, engine) -> None:
        self.engine = engine
        self._cache: Dict[str, object] = {}

    def audit(self) -> Dict:
        entries: List[StartupEntry] = []
        if os.name == "nt":
            entries += self._windows_registry()
            entries += self._windows_startup_folders()
            entries += self._windows_tasks()
        else:
            entries += self._linux_autostart()
            entries += self._linux_cron()
            entries += self._linux_systemd()
            entries += self._linux_shell()

        for entry in entries:
            self._analyze(entry)

        entries.sort(key=lambda e: e.score, reverse=True)
        return {
            "entries": [e.to_dict() for e in entries],
            "counts": {
                "total": len(entries),
                "high_risk": sum(1 for e in entries if e.score >= 60),
                "medium_risk": sum(1 for e in entries if 25 <= e.score < 60),
                "malicious": sum(1 for e in entries if e.verdict == "malicious"),
                "missing_target": sum(1 for e in entries if e.target and not e.exists),
            },
        }

    # --------------------------------------------------------------- Windows
    def _windows_registry(self) -> List[StartupEntry]:
        out: List[StartupEntry] = []
        try:
            import winreg  # type: ignore
        except ImportError:
            return out

        roots = [("HKCU", winreg.HKEY_CURRENT_USER), ("HKLM", winreg.HKEY_LOCAL_MACHINE)]
        keys = [
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        ]
        for root_name, root in roots:
            for key in keys:
                try:
                    handle = winreg.OpenKey(root, key)
                except OSError:
                    continue
                with handle:
                    idx = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(handle, idx)
                        except OSError:
                            break
                        idx += 1
                        out.append(StartupEntry(
                            name=str(name), command=str(value),
                            location=f"{root_name}\\{key}"))

            # Winlogon: Shell i Userinit - rzadko i chętnie nadużywane.
            try:
                handle = winreg.OpenKey(
                    root, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon")
            except OSError:
                continue
            with handle:
                for field_name in ("Shell", "Userinit", "AppSetup"):
                    try:
                        value, _ = winreg.QueryValueEx(handle, field_name)
                    except OSError:
                        continue
                    default = {"Shell": "explorer.exe", "Userinit": "userinit.exe"}[field_name] \
                        if field_name in ("Shell", "Userinit") else ""
                    if str(value).strip().lower() != default.lower():
                        out.append(StartupEntry(
                            name=f"Winlogon:{field_name}", command=str(value),
                            location=f"{root_name}\\...\\Winlogon"))
        return out

    def _windows_startup_folders(self) -> List[StartupEntry]:
        out: List[StartupEntry] = []
        candidates = []
        appdata = os.environ.get("APPDATA", "")
        programdata = os.environ.get("ProgramData", "")
        if appdata:
            candidates.append(Path(appdata) / r"Microsoft\Windows\Start Menu\Programs\Startup")
        if programdata:
            candidates.append(Path(programdata) / r"Microsoft\Windows\Start Menu\Programs\Startup")
        for folder in candidates:
            if not folder.is_dir():
                continue
            for item in folder.iterdir():
                if item.name.lower().endswith((".lnk", ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js")):
                    out.append(StartupEntry(
                        name=item.name, command=str(item),
                        location=f"Folder Startup: {folder}"))
        return out

    def _windows_tasks(self) -> List[StartupEntry]:
        """Zadania harmonogramu - ulubione miejsce utrwalania się malware."""
        out: List[StartupEntry] = []
        tasks_dir = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Tasks"
        if not tasks_dir.is_dir():
            return out
        import xml.etree.ElementTree as ET
        for xml_file in tasks_dir.rglob("*"):
            if not xml_file.is_file():
                continue
            try:
                tree = ET.parse(xml_file)
            except Exception:
                continue
            for command in tree.iter():
                if command.tag.endswith("Command") and command.text:
                    out.append(StartupEntry(
                        name=xml_file.name, command=command.text.strip(),
                        location="Harmonogram zadań"))
                    break
        return out

    # ----------------------------------------------------------------- Linux
    def _linux_autostart(self) -> List[StartupEntry]:
        out: List[StartupEntry] = []
        dirs = [
            Path.home() / ".config" / "autostart",
            Path("/etc/xdg/autostart"),
        ]
        for folder in dirs:
            if not folder.is_dir():
                continue
            for desktop in folder.glob("*.desktop"):
                try:
                    text = desktop.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                exec_line = next(
                    (line.split("=", 1)[1].strip() for line in text.splitlines()
                     if line.strip().startswith("Exec=")), None)
                if exec_line:
                    out.append(StartupEntry(
                        name=desktop.stem, command=exec_line,
                        location=f"autostart: {folder}"))
        return out

    def _linux_cron(self) -> List[StartupEntry]:
        out: List[StartupEntry] = []
        try:
            proc = subprocess.run(["crontab", "-l"], capture_output=True,
                                  text=True, timeout=10)
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        out.append(StartupEntry(
                            name=line[:60], command=line,
                            location="crontab użytkownika"))
        except Exception:
            pass

        for path in [Path("/etc/crontab"), *Path("/etc/cron.d").glob("*")]:
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith(("#", "SHELL=", "PATH=", "MAILTO=")):
                    parts = line.split(None, 5)
                    if len(parts) >= 6:
                        out.append(StartupEntry(
                            name=parts[5][:60], command=parts[5],
                            location=f"cron: {path}"))
        return out

    def _linux_systemd(self) -> List[StartupEntry]:
        out: List[StartupEntry] = []
        dirs = [
            Path.home() / ".config" / "systemd" / "user",
            Path("/etc/systemd/system"),
            Path("/usr/lib/systemd/system"),
        ]
        for folder in dirs:
            if not folder.is_dir():
                continue
            for unit in folder.glob("*.service"):
                try:
                    text = unit.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                enabled = folder.name != "system" or True   # wyliczamy wszystkie
                exec_start = next(
                    (line.split("=", 1)[1].strip() for line in text.splitlines()
                     if line.strip().startswith("ExecStart=")), None)
                if exec_start:
                    out.append(StartupEntry(
                        name=unit.name, command=exec_start,
                        location=f"systemd: {folder}"))
        return out

    def _linux_shell(self) -> List[StartupEntry]:
        """Skrypty startowe powłoki - szukamy w nich podejrzanych poleceń."""
        out: List[StartupEntry] = []
        files = [Path.home() / ".bashrc", Path.home() / ".profile",
                 Path.home() / ".bash_profile", Path("/etc/rc.local")]
        for path in files:
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for line in text.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                for pattern, _weight, _desc in SUSPICIOUS_CMD:
                    if re.search(pattern, stripped):
                        out.append(StartupEntry(
                            name=stripped[:60], command=stripped,
                            location=f"profil powłoki: {path}"))
                        break
        return out

    # --------------------------------------------------------------- analiza
    def _analyze(self, entry: StartupEntry) -> None:
        target = _extract_target(entry.command)
        entry.target = target

        if target:
            entry.exists = os.path.exists(target)
            if not entry.exists:
                entry.findings.append(Finding(
                    "startup", "missing_target", Severity.MEDIUM.value,
                    "Wpis wskazuje na nieistniejący plik - osierocony wpis "
                    "często zostaje po usuniętym malware", 20, target))
            else:
                # Uruchamianie z katalogu, w którym użytkownik może pisać.
                lowered = target.lower()
                if any(token in lowered for token in USER_WRITABLE if token):
                    entry.findings.append(Finding(
                        "startup", "user_writable_path", Severity.MEDIUM.value,
                        "Plik startuje z katalogu zapisywalnego dla użytkownika",
                        15, target))
                if Path(target).name.lower() in SYSTEM_NAMES and "/usr/bin" not in lowered \
                        and "system32" not in lowered:
                    entry.findings.append(Finding(
                        "startup", "masquerading", Severity.CRITICAL.value,
                        f"Wpis podszywa się pod proces systemowy: {Path(target).name}",
                        50, target))

                result = self._cache.get(target)
                if result is None:
                    try:
                        result = self.engine.scan_file(target)
                    except Exception:
                        result = None
                    self._cache[target] = result
                if result is not None and result.verdict in ("malicious", "suspicious"):
                    entry.verdict = result.verdict
                    weight = 100 if result.verdict == "malicious" else 35
                    entry.findings.append(Finding(
                        "startup", "infected_target",
                        Severity.CRITICAL.value if weight == 100 else Severity.HIGH.value,
                        f"Plik uruchamiany przy starcie jest {result.verdict} "
                        f"({result.score} pkt)", weight,
                        "; ".join(f"{f.detector}/{f.rule}" for f in result.findings[:3])[:300]))

        # Podejrzane polecenia w samej komendzie.
        for pattern, weight, description in SUSPICIOUS_CMD:
            if re.search(pattern, entry.command):
                entry.findings.append(Finding(
                    "startup", "suspicious_command",
                    Severity.HIGH.value if weight >= 35 else Severity.MEDIUM.value,
                    description, weight, entry.command[:200]))

        total = sum(f.weight for f in entry.findings)
        entry.score = min(100, total)
        if any(f.weight >= 50 for f in entry.findings) or entry.score >= 60:
            entry.verdict = "malicious" if entry.verdict != "malicious" else entry.verdict


def _extract_target(command: str) -> str:
    """Wyciąga ścieżkę do pliku wykonywalnego z komendy autostartu."""
    if not command:
        return ""
    command = command.strip().strip('"')
    if command.lower().startswith(("http://", "https://")):
        return ""

    # Komendy w rodzaju: /bin/sh -c "/tmp/x.sh", bash -c 'python3 /tmp/a.py'
    parts = _split_command(command)
    for token in parts:
        cleaned = token.strip("\"'")
        if cleaned.startswith("-") or "=" in cleaned:
            continue
        if cleaned.lower() in {"sh", "bash", "zsh", "/bin/sh", "/bin/bash",
                               "cmd", "cmd.exe", "powershell", "powershell.exe",
                               "start", "sudo", "env", "nohup"}:
            continue
        if cleaned.startswith(("/", "\\", "~", "$HOME")) or (
                len(cleaned) > 2 and cleaned[1] == ":"):
            expanded = os.path.expanduser(cleaned)
            if "/" in expanded or "\\" in expanded:
                return expanded
    return ""


def _split_command(command: str) -> List[str]:
    try:
        import shlex
        return shlex.split(command, posix=(os.name != "nt"))
    except Exception:
        return command.split()
