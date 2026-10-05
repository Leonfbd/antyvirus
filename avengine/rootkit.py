"""Kontrola integralności systemu - wykrywanie technik rootkitów.

To nie jest skan plików, tylko konfrontacja dwóch źródeł prawdy o systemie:
tego, co widać w `/proc`, z tym, co zgłasza warstwa API. Rozbieżność między
nimi oznacza, że coś ukrywa się przed narzędziami - czyli właśnie rootkit.

Silnik jest świadomy swoich ograniczeń: bez sterownika kernelowego nie da się
zweryfikować tablicy wywołań systemowych ani wykryć hooków SSDT/IDT. Te
metody (DKOM, hooki jądra) pozostają poza zasięgiem - i są wymienione jako
niepokryte, żeby nikt nie nabrał złudnego poczucia bezpieczeństwa.

Sprawdzenia (Linux - testowane; Windows - implementacja z użyciem rejestru):

  Linux
    * /etc/ld.so.preload i LD_PRELOAD w środowisku procesów   (T1574.006)
    * ukryte procesy: PID-y w /proc nieznane dla psutil       (T1014)
    * uruchomione pliki usunięte z dysku                      (T1036)
    * procesy startujące z /tmp, /dev/shm                     (T1036)
    * ukryte moduły jądra: /proc/modules vs /sys/module       (T1014)
    * ukryte gniazdka: inody /proc/net/tcp vs deskryptory     (T1014)
    * binaria SUID/SGID w katalogach zapisywalnych            (T1548)
    * katalogi systemowe zapisywalne dla wszystkich           (T1222)
    * ukryte pliki w /tmp, /dev/shm                           (T1564.001)
    * konta z UID 0 inne niż root                             (T1136.001)

  Windows (wymaga uruchomienia na Windows)
    * AppInit_DLLs                                            (T1546.010)
    * przejęcie Image File Execution Options (Debugger)       (T1546.012)
    * subskrypcje zdarzeń WMI                                 (T1546.003)
    * pakiety bezpieczeństwa LSA                              (T1547.005)
    * usługi ze ścieżką bez cudzysłowów lub w zapisywalnym katalogu (T1574.009)
    * netsh helper DLLs                                       (T1546.007)
    * wyłączona ochrona Defender / tamper protection          (T1562.001)
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from .models import Finding, Severity
from . import mitre

# Ścieżki jako stałe modułu: dzięki temu testy mogą podstawić własne katalogi
# i sprawdzić wykrywanie bez dotykania /etc i /proc prawdziwego systemu.
PROC_PATH = Path("/proc")
PRELOAD_PATH = Path("/etc/ld.so.preload")
PASSWD_PATH = Path("/etc/passwd")
MODULES_PATH = Path("/proc/modules")
SYS_MODULE_PATH = Path("/sys/module")
NET_TCP_PATHS = (Path("/proc/net/tcp"), Path("/proc/net/tcp6"))

WORLD_WRITABLE_SYSTEM_DIRS = (
    "/usr/bin", "/usr/sbin", "/usr/lib", "/bin", "/sbin", "/lib",
    "/usr/local/bin", "/etc",
)
SHADY_EXEC_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
# Standardowe katalogi ukryte w /tmp - obecność jest normalna, nie podejrzana.
KNOWN_HIDDEN_DIRS = {".", "..", ".x11-unix", ".ice-unix", ".xim-unix", ".font-unix",
                     ".test-unix", ".pulse-native", ".esd-1001", ".com.google.chrome"}


def _counts(items: List[Finding]) -> Dict:
    return {
        "total": len(items),
        "critical": sum(1 for f in items if f.severity == "critical"),
        "high": sum(1 for f in items if f.severity == "high"),
        "medium": sum(1 for f in items if f.severity == "medium"),
    }


@dataclass
class IntegrityReport:
    """Wynik kontroli integralności.

    Rozdzielamy dwie rzeczy, które łatwo pomylić, a które znaczą co innego:
      * `findings`  - oznaki WŁAMANIA (ukryty proces, ld.so.preload, rootkit)
      * `hardening` - słaba KONFIGURACJA (katalog zapisywalny dla wszystkich)
    Druga kategoria nie oznacza infekcji, tylko podatność - wrzucenie jej do
    jednego worka z oznakami włamania dawałoby fałszywe alarmy na wielu
    poprawnie działających maszynach (np. /usr/local/bin bywa zapisywalny).
    """

    platform: str = ""
    findings: List[Finding] = field(default_factory=list)
    hardening: List[Finding] = field(default_factory=list)
    checked: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    not_covered: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return {
            "platform": self.platform,
            "findings": [f.to_dict()
                         for f in sorted(self.findings, key=lambda f: order.get(f.severity, 9))],
            "hardening": [f.to_dict()
                          for f in sorted(self.hardening, key=lambda f: order.get(f.severity, 9))],
            "counts": _counts(self.findings),
            "hardening_counts": _counts(self.hardening),
            "checked": self.checked,
            "skipped": self.skipped,
            "not_covered": self.not_covered,
        }


class IntegrityScanner:
    """Weryfikuje integralność systemu - zaprojektowana do uruchamiania na żądanie."""

    def __init__(self, engine=None) -> None:
        self.engine = engine

    def scan(self) -> Dict:
        report = IntegrityReport(platform=os.name)
        report.not_covered = [
            "hooki tablicy wywołań systemowych (SSDT/IDT) - wymagane sterowniki kernelowe",
            "modyfikacje pamięci jądra (DKOM) - wymagane sterowniki kernelowe",
            "analiza pamięci procesów (skanowanie w locie) - wymagane uprawnienia SYSTEM",
        ]

        if os.name == "nt":
            checks = [
                self._win_appinit, self._win_ifeo, self._win_wmi,
                self._win_services, self._win_lsa, self._win_netsh,
                self._win_defender,
            ]
        else:
            checks = [
                self._ld_preload_file, self._ld_preload_env, self._hidden_processes,
                self._deleted_binaries, self._shady_exec_dirs, self._hidden_modules,
                self._hidden_sockets, self._suid_binaries, self._world_writable_dirs,
                self._hidden_temp_files, self._uid_zero_accounts,
            ]

        for check in checks:
            name = check.__name__.lstrip("_")
            try:
                ok = check(report)
            except PermissionError:
                ok, name = False, f"{name} (brak uprawnień)"
            except Exception as exc:
                ok, name = False, f"{name} ({type(exc).__name__})"
            if ok:
                report.checked.append(name)
            elif not any(name.split()[0] == s.split()[0] for s in report.skipped):
                # Test mógł już wpisać powód pominięcia z dokładniejszym opisem.
                report.skipped.append(name)

        return report.to_dict()

    def _add(self, report: IntegrityReport, rule: str, severity: str,
             description: str, weight: int, evidence: str = "",
             hardening: bool = False) -> None:
        target = report.hardening if hardening else report.findings
        finding = Finding("rootkit", rule, severity, description, weight, evidence)
        technique = mitre.map_finding("rootkit", rule)
        if technique:
            finding.mitre = f"{technique.id} {technique.name}"
        target.append(finding)

    # ----------------------------------------------------------------- Linux
    def _ld_preload_file(self, report: IntegrityReport) -> bool:
        path = PRELOAD_PATH
        if not path.exists():
            return True
        try:
            content = path.read_text(errors="ignore").strip()
        except Exception:
            return True
        if content:
            self._add(report, "ld_so_preload", Severity.CRITICAL.value,
                      "Plik /etc/ld.so.preload wczytuje bibliotekę do KAŻDEGO procesu "
                      "w systemie - klasyczny mechanizm rootkita", 60, content[:300])
        return True

    def _ld_preload_env(self, report: IntegrityReport) -> bool:
        hits: List[str] = []
        for entry in PROC_PATH.iterdir():
            if not entry.name.isdigit():
                continue
            env_path = entry / "environ"
            try:
                raw = env_path.read_bytes()
            except Exception:
                continue
            for chunk in raw.split(b"\x00"):
                if chunk.startswith(b"LD_PRELOAD=") and chunk[11:].strip():
                    hits.append(f"pid={entry.name}: {chunk.decode('latin-1')[:120]}")
                    break
        if hits:
            self._add(report, "ld_preload_env", Severity.HIGH.value,
                      f"Zmienna LD_PRELOAD ustawiona w środowisku {len(hits)} procesów",
                      35, "; ".join(hits[:5]))
        return True

    def _hidden_processes(self, report: IntegrityReport) -> bool:
        try:
            proc_pids = {int(d.name) for d in PROC_PATH.iterdir() if d.name.isdigit()}
        except Exception:
            return False
        try:
            import psutil
            visible = set(psutil.pids())
        except Exception:
            return False

        # psutil pomija procesy, które zdążyły się zakończyć między odczytami,
        # więc sprawdzamy tylko PID-y, które nadal istnieją w /proc.
        hidden = []
        for pid in sorted(proc_pids - visible):
            try:
                cmdline = ((PROC_PATH / str(pid) / "cmdline").read_bytes()
                           .replace(b"\x00", b" ").decode("latin-1", "ignore").strip())
            except Exception:
                continue
            if cmdline:
                hidden.append(f"pid={pid}: {cmdline[:100]}")
        if hidden:
            self._add(report, "hidden_process", Severity.CRITICAL.value,
                      f"{len(hidden)} procesów istnieje w /proc, ale nie jest widocznych "
                      "dla API systemowego - cecha rootkita", 60, "; ".join(hidden[:5]))
        return True

    def _deleted_binaries(self, report: IntegrityReport) -> bool:
        try:
            import psutil
        except ImportError:
            return False
        hits: List[str] = []
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                exe = proc.info.get("exe") or ""
            except Exception:
                continue
            if exe.endswith("(deleted)") or (exe and not os.path.exists(exe)):
                hits.append(f"pid={proc.info.get('pid')}: {proc.info.get('name')} -> {exe}")
        if hits:
            self._add(report, "deleted_binary", Severity.HIGH.value,
                      f"{len(hits)} procesów działa z plików usuniętych z dysku "
                      "(dropper usuwa się po uruchomieniu)", 30, "; ".join(hits[:5]))
        return True

    def _shady_exec_dirs(self, report: IntegrityReport) -> bool:
        try:
            import psutil
        except ImportError:
            return False
        hits: List[str] = []
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            exe = (proc.info.get("exe") or "").lower()
            if any(exe.startswith(d) for d in SHADY_EXEC_DIRS):
                hits.append(f"pid={proc.info.get('pid')}: {exe}")
        if hits:
            self._add(report, "exec_from_temp", Severity.MEDIUM.value,
                      f"{len(hits)} procesów uruchomiono z katalogów tymczasowych "
                      "(/tmp, /dev/shm)", 18, "; ".join(hits[:5]))
        return True

    def _hidden_modules(self, report: IntegrityReport) -> bool:
        """Porównuje /proc/modules z /sys/module - rozbieżność = ukryty moduł."""
        proc_modules: Set[str] = set()
        try:
            for line in MODULES_PATH.read_text(errors="ignore").splitlines():
                name = line.split()[0] if line.split() else ""
                if name:
                    proc_modules.add(name.replace("_", "-"))
        except Exception:
            return False

        sys_modules: Set[str] = set()
        sys_path = SYS_MODULE_PATH
        if sys_path.is_dir():
            try:
                sys_modules = {d.name.replace("_", "-") for d in sys_path.iterdir() if d.is_dir()}
            except Exception:
                return False
        if not sys_modules:
            return False

        hidden = sorted(proc_modules - sys_modules)
        if hidden:
            self._add(report, "hidden_module", Severity.CRITICAL.value,
                      f"Moduły jądra widoczne w /proc/modules, ale nieobecne w /sys/module: "
                      f"{', '.join(hidden[:6])}", 55, "możliwy moduł ukrywający własne ślady")
        return True

    def _hidden_sockets(self, report: IntegrityReport) -> bool:
        """Gniazdka z /proc/net/tcp, których nie da się przypisać do żadnego procesu."""
        # Warunek wstępny: żeby cokolwiek wywnioskować z braku właściciela
        # gniazdka, musimy widzieć deskryptory większości procesów. Bez uprawnień
        # roota /proc/<pid>/fd cudzych procesów jest nieczytelne i KAŻDE gniazdko
        # wyglądałoby na ukryte - stąd fałszywe alarmy. Lepiej odpuścić test.
        proc_inodes: Set[str] = set()
        total = readable = 0
        for entry in PROC_PATH.iterdir():
            if not entry.name.isdigit():
                continue
            total += 1
            fd_dir = entry / "fd"
            try:
                fds = list(fd_dir.iterdir())
                readable += 1
            except Exception:
                continue
            for fd in fds:
                try:
                    target = os.readlink(fd)
                except Exception:
                    continue
                match = re.match(r"socket:\[(\d+)\]", target)
                if match:
                    proc_inodes.add(match.group(1))
        if total and readable / total < 0.5:
            report.skipped.append("hidden_sockets (brak uprawnień do /proc/*/fd - wymagany root)")
            return False

        hidden: List[str] = []
        for path in NET_TCP_PATHS:
            if not path.exists():
                continue
            try:
                lines = path.read_text(errors="ignore").splitlines()[1:]
            except Exception:
                continue
            for line in lines:
                parts = line.split()
                if len(parts) < 10:
                    continue
                state, inode = parts[3], parts[9]
                if state != "0A":        # 0A = LISTEN
                    continue
                if inode not in proc_inodes:
                    hidden.append(f"{filename} inode={inode} {parts[1]}")
        if hidden:
            self._add(report, "hidden_port", Severity.HIGH.value,
                      f"{len(hidden)} nasłuchujących gniazdek nie da się przypisać do "
                      "żadnego procesu - możliwy ukryty kanał C2", 40,
                      "; ".join(hidden[:5]))
        return True

    def _suid_binaries(self, report: IntegrityReport) -> bool:
        hits: List[str] = []
        for directory in SHADY_EXEC_DIRS:
            base = Path(directory)
            if not base.is_dir():
                continue
            try:
                entries = list(base.iterdir())
            except Exception:
                continue
            for entry in entries:
                try:
                    mode = entry.stat().st_mode
                except Exception:
                    continue
                if mode & 0o6000:            # SUID lub SGID
                    hits.append(str(entry))
        if hits:
            self._add(report, "suid_in_writable", Severity.CRITICAL.value,
                      "Pliki z bitem SUID/SGID w katalogu zapisywalnym dla wszystkich - "
                      "gotowy mechanizm podniesienia uprawnień", 55, "; ".join(hits[:5]))
        return True

    def _world_writable_dirs(self, report: IntegrityReport) -> bool:
        hits: List[str] = []
        for directory in WORLD_WRITABLE_SYSTEM_DIRS:
            path = Path(directory)
            if not path.is_dir():
                continue
            try:
                mode = path.stat().st_mode
            except Exception:
                continue
            if mode & 0o002 and not (mode & 0o1000):    # zapisywalny bez sticky bit
                hits.append(directory)
        if hits:
            self._add(report, "world_writable_system", Severity.MEDIUM.value,
                      f"Katalogi systemowe zapisywalne dla każdego użytkownika: "
                      f"{', '.join(hits)}", 18,
                      "każdy może podmienić binarkę, która zostanie uruchomiona - "
                      "słaba konfiguracja, nie oznaka infekcji",
                      hardening=True)
        return True

    def _hidden_temp_files(self, report: IntegrityReport) -> bool:
        hits: List[str] = []
        for directory in SHADY_EXEC_DIRS:
            base = Path(directory)
            if not base.is_dir():
                continue
            try:
                entries = list(base.iterdir())
            except Exception:
                continue
            # Interesują nas tylko ukryte pliki WYKONYWALNE. Zwykłe kropkowe
            # pliki w /tmp to codzienność (.X11-unix, pliki tymczasowe
            # przeglądarek i narzędzi), więc bez tego warunku test dawałby
            # fałszywe alarmy na niemal każdej maszynie.
            hidden = []
            for e in entries:
                if not e.name.startswith(".") or e.name in KNOWN_HIDDEN_DIRS:
                    continue
                if not e.is_file():
                    continue
                try:
                    if e.stat().st_mode & 0o111:      # cokolwiek wykonywalnego
                        hidden.append(e.name)
                except Exception:
                    continue
            if hidden:
                hits.append(f"{directory}: {', '.join(hidden[:5])}")
        if hits:
            self._add(report, "hidden_temp_files", Severity.MEDIUM.value,
                      "Ukryte pliki WYKONYWALNE w katalogach tymczasowych "
                      "(nazwa zaczyna się od kropki)",
                      15, "; ".join(hits[:4]))
        return True

    def _uid_zero_accounts(self, report: IntegrityReport) -> bool:
        path = PASSWD_PATH
        if not path.exists():
            return False
        try:
            content = path.read_text(errors="ignore")
        except Exception:
            return False
        extra: List[str] = []
        for line in content.splitlines():
            parts = line.split(":")
            if len(parts) >= 3 and parts[2] == "0" and parts[0] != "root":
                extra.append(parts[0])
        if extra:
            self._add(report, "uid_zero_account", Severity.CRITICAL.value,
                      f"Konta z UID 0 (uprawnienia roota) inne niż root: {', '.join(extra)}",
                      55, "dodanie takiego konta to standardowa technika utrwalania dostępu")
        return True

    # --------------------------------------------------------------- Windows
    def _win_registry_values(self, root, key: str) -> Dict[str, str]:
        try:
            import winreg  # type: ignore
        except ImportError:
            return {}
        values: Dict[str, str] = {}
        try:
            handle = winreg.OpenKey(root, key)
        except OSError:
            return values
        with handle:
            idx = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(handle, idx)
                except OSError:
                    break
                idx += 1
                values[str(name)] = str(value)
        return values

    def _win_appinit(self, report: IntegrityReport) -> bool:
        try:
            import winreg  # type: ignore
        except ImportError:
            return False
        values = self._win_registry_values(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows")
        dlls = values.get("AppInit_DLLs", "").strip()
        if dlls:
            self._add(report, "appinit", Severity.CRITICAL.value,
                      "AppInit_DLLs wczytuje bibliotekę DLL do każdego procesu "
                      "użytkownika - klasyczny mechanizm rootkita", 55, dlls[:300])
        return True

    def _win_ifeo(self, report: IntegrityReport) -> bool:
        try:
            import winreg  # type: ignore
        except ImportError:
            return False
        base = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        hijacks: List[str] = []
        try:
            handle = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base)
        except OSError:
            return True
        with handle:
            idx = 0
            while True:
                try:
                    name = winreg.EnumKey(handle, idx)
                except OSError:
                    break
                idx += 1
                debugger = self._win_registry_values(
                    winreg.HKEY_LOCAL_MACHINE, f"{base}\\{name}").get("Debugger")
                if debugger:
                    hijacks.append(f"{name} -> {debugger[:120]}")
        if hijacks:
            self._add(report, "ifeo", Severity.CRITICAL.value,
                      f"Przejęcie uruchamiania przez IFEO ({len(hijacks)} wpisów): zamiast "
                      "programu startuje wskazany debugger", 55, "; ".join(hijacks[:5]))
        return True

    def _win_wmi(self, report: IntegrityReport) -> bool:
        try:
            proc = subprocess.run(
                ["wmic", "/namespace:\\\\root\\subscription", "PATH",
                 "__EventFilter", "get", "Name"],
                capture_output=True, text=True, timeout=20)
        except Exception:
            return False
        names = [line.strip() for line in (proc.stdout or "").splitlines()
                 if line.strip() and not line.lower().startswith("name")]
        if names:
            self._add(report, "wmi_subscription", Severity.CRITICAL.value,
                      f"Wykryto {len(names)} subskrypcji zdarzeń WMI - mechanizm "
                      "utrwalania niewidoczny w autostarcie", 50, "; ".join(names[:5]))
        return True

    def _win_services(self, report: IntegrityReport) -> bool:
        try:
            import winreg  # type: ignore
        except ImportError:
            return False
        unquoted: List[str] = []
        base = r"SYSTEM\CurrentControlSet\Services"
        try:
            handle = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base)
        except OSError:
            return True
        with handle:
            idx = 0
            while True:
                try:
                    name = winreg.EnumKey(handle, idx)
                except OSError:
                    break
                idx += 1
                image = self._win_registry_values(
                    winreg.HKEY_LOCAL_MACHINE, f"{base}\\{name}").get("ImagePath", "")
                if image and " " in image and not image.strip().startswith('"') \
                        and not image.startswith("\\??\\") and ".exe" in image.lower():
                    unquoted.append(f"{name}: {image[:120]}")
        if unquoted:
            self._add(report, "unquoted_service", Severity.MEDIUM.value,
                      f"{len(unquoted)} usług ma ścieżkę bez cudzysłowu - Windows "
                      "spróbuje uruchomić inną binarkę z wcześniejszego katalogu",
                      18, "; ".join(unquoted[:5]), hardening=True)
        return True

    def _win_lsa(self, report: IntegrityReport) -> bool:
        try:
            import winreg  # type: ignore
        except ImportError:
            return False
        key = r"SYSTEM\CurrentControlSet\Control\Lsa"
        values = self._win_registry_values(winreg.HKEY_LOCAL_MACHINE, key)
        extra = [name for name in ("Security Packages", "Authentication Packages")
                 if values.get(name) and values[name].strip().lower()
                 not in {"", "kerberos msv1_0 schannel wdigest tspkg pku2u", "msv1_0"}]
        if extra:
            self._add(report, "lsa_package", Severity.CRITICAL.value,
                      "Niestandardowe pakiety LSA - mogą przechwytywać hasła przy logowaniu",
                      55, "; ".join(f"{n}={values[n][:120]}" for n in extra))
        return True

    def _win_netsh(self, report: IntegrityReport) -> bool:
        try:
            import winreg  # type: ignore
        except ImportError:
            return False
        values = self._win_registry_values(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\NetSh")
        if values:
            self._add(report, "netsh_helper", Severity.HIGH.value,
                      f"Zarejestrowane dodatki netsh ({len(values)}) - rzadko używane, "
                      "często nadużywane do utrwalenia", 30, str(values)[:300])
        return True

    def _win_defender(self, report: IntegrityReport) -> bool:
        try:
            import winreg  # type: ignore
        except ImportError:
            return False
        values = self._win_registry_values(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection")
        disabled = [name for name, value in values.items()
                    if name.startswith("Disable") and value in ("1", "True")]
        if disabled:
            self._add(report, "defender_disabled", Severity.HIGH.value,
                      f"Ochrona w czasie rzeczywistym Windows Defender jest wyłączona "
                      f"({', '.join(disabled[:4])})", 35,
                      "wyłączenie ochrony to zwykle przygotowanie do infekcji")
        return True
