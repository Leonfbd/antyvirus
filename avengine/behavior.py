"""Analiza behawioralna: uruchomienie próbki w piaskownicy i obserwacja efektów.

Analiza statyczna odpowiada na pytanie „jak ten plik wygląda”. Ten moduł
odpowiada na pytanie **„co ten plik robi”** — i jest w stanie wykryć zagrożenie,
którego żadna sygnatura nie zna, bo zagrożenie jeszcze nie istniało w chwili
tworzenia bazy.

Jak to działa (Linux):
  1. Kompilujemy `sandbox/interceptor.c` do biblioteki współdzielonej.
  2. Kopiujemy próbkę do odizolowanego katalogu roboczego.
  3. Uruchamiamy ją z `LD_PRELOAD=interceptor.so`, minimalnym środowiskiem,
     ograniczeniami zasobów (CPU, pamięć, rozmiar pliku) i twardym limitem czasu.
  4. Interceptor zapisuje do dziennika każde otwarcie pliku do zapisu,
     uruchomienie procesu i próbę połączenia sieciowego.
  5. Czyścimy zdarzenia i oceniamy je: utrwalanie, kradzież poświadczeń,
     masowe modyfikacje plików, szyfrowanie, C2 — z mapowaniem na MITRE ATT&CK.

Czego to NIE robi (ważne, żeby nie mieć złudzeń):
  * **Nie izoluje naprawdę.** Bez roota nie ma chroota, namespace'ów ani sieci
    per-proces. Próbka działa na tej samej maszynie. Do prawdziwego malware
    użyj kontenera albo maszyny wirtualnej — moduł ostrzega o tym w raporcie.
  * **Nie widzi wszystkiego.** Pliki statycznie zlinkowane, binaria Go
    (surowe syscall-e) i programy setuid omijają LD_PRELOAD.
  * Na Windows potrzebny jest sterownik minifilter albo ETW/Sysmon —
    tam moduł zgłasza brak implementacji zamiast udawać, że działa.
"""

from __future__ import annotations

import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import mitre
from .entropy import shannon_entropy

# --- miejsca, w których zapis oznacza próbę UTRWALENIA się (persistence) ---
PERSISTENCE_PATHS = (
    "/etc/cron", "/etc/systemd", "/etc/init.d", "/etc/rc.local", "/etc/rc.d",
    "/etc/ld.so.preload", "/etc/profile", "/etc/environment",
    ".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile",
    ".config/autostart", "/etc/xdg/autostart", "systemd/user",
    "/etc/sudoers", "/etc/passwd", "/etc/shadow",
)
# --- katalogi systemowe: zapis = manipulacja przy systemie ---
SYSTEM_DIRS = ("/etc/", "/usr/bin", "/usr/sbin", "/bin/", "/sbin/", "/lib",
               "/usr/lib", "/boot", "/sys/", "/proc/")
# --- ścieżki z poświadczeniami: OD CZYT to próba kradzieży ---
CREDENTIAL_PATHS = ("/etc/shadow", "/etc/sudoers", ".ssh/id_", ".aws/credentials",
                    ".gnupg/", "wallet.dat", ".kdbx", ".config/google-chrome",
                    ".mozilla/firefox", ".bash_history", "authorized_keys")
# --- narzędzia do pobierania i uruchamiania z zewnątrz ---
DOWNLOAD_TOOLS = ("curl", "wget", "certutil", "bitsadmin", "powershell",
                  "pwsh", "python", "perl", "nc", "ncat", "netcat", "tftp")
LOLBIN_TOOLS = ("certutil", "bitsadmin", "mshta", "rundll32", "regsvr32",
                "installutil", "regasm", "cmstp", "wmic")
# Porty typowe dla prostych shelli zwrotnych i botnetów.
SUSPICIOUS_PORTS = {4444, 5555, 6666, 6667, 7777, 9001, 1337, 31337, 12345,
                    4443, 8443, 8080, 9999, 5000}
LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}


@dataclass
class BehaviorEvent:
    kind: str
    pid: int
    path: str = ""
    extra: str = ""


@dataclass
class BehaviorFinding:
    rule: str
    severity: str
    weight: int
    description: str
    evidence: str = ""
    mitre: str = ""

    def to_dict(self) -> Dict:
        return {"rule": self.rule, "severity": self.severity, "weight": self.weight,
                "description": self.description, "evidence": self.evidence,
                "mitre": self.mitre}


@dataclass
class BehaviorReport:
    target: str = ""
    platform: str = ""
    executed: bool = False
    error: str = ""
    exit_code: Optional[int] = None
    duration: float = 0.0
    timed_out: bool = False
    stdout: str = ""
    stderr: str = ""
    workdir: str = ""
    processes: List[Dict] = field(default_factory=list)
    file_writes: List[Dict] = field(default_factory=list)
    file_reads: List[Dict] = field(default_factory=list)
    deletes: List[Dict] = field(default_factory=list)
    moves: List[Dict] = field(default_factory=list)
    network: List[Dict] = field(default_factory=list)
    findings: List[BehaviorFinding] = field(default_factory=list)
    score: int = 0
    verdict: str = "unknown"
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "platform": self.platform,
            "executed": self.executed,
            "error": self.error,
            "exit_code": self.exit_code,
            "duration": round(self.duration, 2),
            "timed_out": self.timed_out,
            "stdout": self.stdout[:4000],
            "stderr": self.stderr[:4000],
            "workdir": self.workdir,
            "processes": self.processes,
            "file_writes": self.file_writes,
            "file_reads": self.file_reads,
            "deletes": self.deletes,
            "moves": self.moves,
            "network": self.network,
            "findings": [f.to_dict() for f in self.findings],
            "score": self.score,
            "verdict": self.verdict,
            "limitations": self.limitations,
        }

    def render_text(self) -> str:
        lines = [f"Analiza behawioralna: {self.target}"]
        if self.error:
            lines.append(f"  błąd: {self.error}")
        else:
            lines.append(f"  werdykt: {self.verdict.upper()} ({self.score} pkt) "
                         f"· czas: {self.duration:.1f}s · kod wyjścia: {self.exit_code}")
        if self.processes:
            lines.append("\nUruchomione procesy:")
            for proc in self.processes[:20]:
                lines.append(f"  - {proc['path']} {proc.get('args', '')}".rstrip())
        if self.file_writes:
            lines.append(f"\nZapisy do plików ({len(self.file_writes)}):")
            for item in self.file_writes[:20]:
                lines.append(f"  - [{item['mode']}] {item['path']}")
        if self.deletes:
            lines.append(f"\nUsunięte pliki ({len(self.deletes)}):")
            for item in self.deletes[:20]:
                lines.append(f"  - {item['path']}")
        if self.network:
            lines.append("\nPołączenia sieciowe:")
            for item in self.network[:20]:
                lines.append(f"  - {item['family']} {item['host']}:{item['port']}")
        if self.findings:
            lines.append("\nOcena zachowania:")
            for finding in sorted(self.findings, key=lambda f: -f.weight):
                lines.append(f"  [{finding.severity}] +{finding.weight} "
                             f"{finding.rule}: {finding.description}")
                if finding.evidence:
                    lines.append(f"      ↳ {finding.evidence[:160]}")
        if self.limitations:
            lines.append("\nOgraniczenia tej analizy:")
            for item in self.limitations:
                lines.append(f"  - {item}")
        return "\n".join(lines)


# --------------------------------------------------------------- interceptor

def interceptor_source() -> Path:
    return Path(__file__).resolve().parent / "sandbox" / "interceptor.c"


def build_interceptor(dest_dir: Path) -> Optional[Path]:
    """Kompiluje interceptor do .so. Zwraca None, gdy brak kompilatora."""
    source = interceptor_source()
    dest_dir.mkdir(parents=True, exist_ok=True)
    target = dest_dir / "interceptor.so"
    if target.exists() and target.stat().st_mtime >= source.stat().st_mtime:
        return target
    compiler = shutil.which("gcc") or shutil.which("cc") or shutil.which("clang")
    if not compiler:
        return None
    try:
        proc = subprocess.run(
            [compiler, "-shared", "-fPIC", "-O2", "-o", str(target), str(source), "-ldl"],
            capture_output=True, text=True, timeout=120)
    except Exception as exc:
        (dest_dir / "interceptor.build.log").write_text(str(exc))
        return None
    if proc.returncode != 0 or not target.exists():
        # Błąd kompilacji musi zostać ZAPISANY - inaczej awaria jest niema
        # i pozostaje po niej tylko ogólnik "brak kompilatora".
        (dest_dir / "interceptor.build.log").write_text(
            f"kompilator: {compiler}\nkod: {proc.returncode}\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
        return None
    (dest_dir / "interceptor.build.log").write_text("ok")
    return target


# ----------------------------------------------------------------- sandbox

class BehaviorSandbox:
    """Uruchamia próbkę i obserwuje, co robi."""

    def __init__(self, data_dir: Optional[Path] = None, timeout: int = 20,
                 max_memory_mb: int = 512, max_file_mb: int = 32,
                 network: str = "log") -> None:
        # Ścieżki muszą być bezwzględne: subprocess.Popen z argumentem cwd
        # rozwiązuje ścieżki względne względem katalogu roboczego,
        # co wcześniej kończyło się błędem 'No such file'.
        self.data_dir = Path(data_dir).resolve() if data_dir \
            else Path(tempfile.gettempdir()).resolve()
        self.timeout = timeout
        self.max_memory_mb = max_memory_mb
        self.max_file_mb = max_file_mb
        self.network = network          # "log" | "block" (block wymaga uprawnień)

    # ------------------------------------------------------------------ main
    def run(self, target: Path, argv: Optional[List[str]] = None,
            timeout: Optional[int] = None) -> BehaviorReport:
        import time

        target = Path(target).resolve()
        report = BehaviorReport(target=str(target), platform=os.name)
        report.limitations = self._limitations()

        if os.name == "nt":
            report.error = ("Analiza behawioralna na Windows wymaga sterownika "
                            "minifilter albo subskrypcji ETW - niezaimplementowane.")
            return report

        interceptor = build_interceptor(self.data_dir / "sandbox")
        if not interceptor:
            report.error = ("Brak kompilatora C (gcc) - nie można zbudować "
                            "interceptora wywołań systemowych.")
            return report

        runner = self._prepare_runner(target)
        if runner is None:
            report.error = ("Nie potrafię uruchomić tego pliku na tej platformie "
                            "(skrypty PowerShell i BAT są specyficzne dla Windows).")
            return report

        runs_root = self.data_dir / "sandbox" / "runs"
        self._prune_runs(runs_root)
        root = runs_root / uuid.uuid4().hex[:12]
        work, home, tmp = root / "work", root / "home", root / "tmp"
        for directory in (work, home, tmp):
            directory.mkdir(parents=True, exist_ok=True)

        sandbox_copy = work / target.name
        try:
            shutil.copy2(target, sandbox_copy)
            sandbox_copy.chmod(0o755)
        except Exception as exc:
            report.error = f"Nie udało się przygotować kopii roboczej: {exc}"
            return report

        log_file = root / "behavior.log"
        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(home),
            "TMPDIR": str(tmp),
            "SHELL": "/bin/sh",
            "LANG": "C",
            "LC_ALL": "C",
            "AVY_BEHAVIOR_LOG": str(log_file),
            "LD_PRELOAD": str(interceptor),
        }

        command = runner + (argv or []) + [str(sandbox_copy)]
        report.workdir = str(root)

        def limit_resources() -> None:
            os.setsid()          # własna grupa procesów - da się zabić całe drzewo
            limit = timeout or self.timeout
            resource.setrlimit(resource.RLIMIT_CPU, (limit, limit + 5))
            resource.setrlimit(resource.RLIMIT_AS,
                               (self.max_memory_mb * 1024 * 1024,) * 2)
            resource.setrlimit(resource.RLIMIT_FSIZE,
                               (self.max_file_mb * 1024 * 1024,) * 2)
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

        started = time.time()
        try:
            proc = subprocess.Popen(
                command, cwd=str(work), env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                preexec_fn=limit_resources, text=True, errors="replace")
            try:
                out, err = proc.communicate(timeout=timeout or self.timeout)
                report.exit_code = proc.returncode
                report.timed_out = False
            except subprocess.TimeoutExpired:
                self._kill_tree(proc)
                out, err = proc.communicate()
                report.timed_out = True
                report.exit_code = None
            report.stdout = (out or "")[:8000]
            report.stderr = (err or "")[:8000]
            report.executed = True
        except Exception as exc:
            report.error = f"Nie udało się uruchomić próbki: {exc}"
        report.duration = time.time() - started

        events = self._parse_log(log_file)
        self._analyze(report, events, root, sandbox_copy)
        return report

    # --------------------------------------------------------------- helpers
    @staticmethod
    def _prune_runs(runs_root: Path, keep: int = 10) -> None:
        """Usuwa najstarsze uruchomienia - każde zostawia kilkadziesiąt plików."""
        try:
            if not runs_root.is_dir():
                return
            runs = sorted((d for d in runs_root.iterdir() if d.is_dir()),
                          key=lambda d: d.stat().st_mtime, reverse=True)
            for stale in runs[keep:]:
                shutil.rmtree(stale, ignore_errors=True)
        except Exception:
            pass

    @staticmethod
    def _limitations() -> List[str]:
        return [
            "Brak pełnej izolacji: bez uprawnień roota nie ma chroota ani "
            "namespace'ów - próbka działa na tej samej maszynie. Prawdziwy "
            "malware uruchamiaj w kontenerze lub maszynie wirtualnej.",
            "Pliki statycznie zlinkowane, binaria Go (surowe syscall-e) i "
            "programy setuid omijają LD_PRELOAD - ich działania nie zostaną "
            "zarejestrowane.",
            "Obserwujemy wywołania libc, nie kernel: modyfikacje pamięci "
            "obcych procesów i hooki jądra pozostają niewidoczne.",
        ]

    @staticmethod
    def _prepare_runner(target: Path) -> Optional[List[str]]:
        """Dobiera sposób uruchomienia: shebang, ELF albo jawny interpreter."""
        suffix = target.suffix.lower()
        if suffix in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".dll", ".exe"}:
            # .exe/.dll to PE - na Linuksie nie uruchomimy, chyba że Wine.
            if suffix in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta"}:
                return None
        try:
            head = target.read_bytes()[:2]
        except Exception:
            head = b""
        if head == b"#!":
            return []                       # skrypt z shebangiem - uruchamialny
        if head == b"MZ":
            return None                     # plik Windows
        if head == b"\x7fELF":
            return []
        if suffix in {".py"}:
            return [sys.executable or "python3"]
        if suffix in {".sh"}:
            return ["/bin/sh"]
        return []                           # spróbujmy wprost

    @staticmethod
    def _kill_tree(proc: subprocess.Popen) -> None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    @staticmethod
    def _parse_log(log_file: Path) -> List[BehaviorEvent]:
        events: List[BehaviorEvent] = []
        if not log_file.exists():
            return events
        try:
            content = log_file.read_text(errors="replace")
        except Exception:
            return events
        for line in content.splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            kind, pid = parts[0], parts[1]
            try:
                pid_int = int(pid)
            except ValueError:
                continue
            path = parts[2] if len(parts) > 2 else ""
            extra = "\t".join(parts[3:]) if len(parts) > 3 else ""
            events.append(BehaviorEvent(kind=kind, pid=pid_int, path=path, extra=extra))
        return events

    # --------------------------------------------------------------- analiza
    def _analyze(self, report: BehaviorReport, events: List[BehaviorEvent],
                 root: Path, sample: Path) -> None:
        writes: Dict[str, str] = {}
        reads: Dict[str, str] = {}
        deletes: Dict[str, str] = {}
        moves: List[Tuple[str, str]] = []
        execs: Dict[str, str] = {}
        network: Dict[str, Tuple[str, str, int]] = {}
        sockets: List[str] = []

        for event in events:
            if event.kind == "OPEN":
                mode = event.extra or "write"
                # /dev/null, /dev/urandom i podobne to nie "pliki użytkownika" -
                # bez tego filtru raport zalewałyby wpisy bez wartości.
                if event.path.startswith("/dev/") and event.path != "/dev/shm":
                    continue
                if mode == "read":
                    reads.setdefault(event.path, mode)
                else:
                    writes.setdefault(event.path, mode)
            elif event.kind == "SHELL":
                execs.setdefault("/bin/sh", event.path.strip()[:200])
            elif event.kind == "EXEC":
                execs.setdefault(event.path, event.extra.strip()[:300])
            elif event.kind == "DELETE":
                deletes.setdefault(event.path, "")
            elif event.kind == "MOVED":
                pass
            elif event.kind == "MOVE":
                moves.append((event.path, event.extra))
            elif event.kind == "CONNECT":
                # Dziennik: CONNECT <pid> <rodzina> <host> <port>
                # (rodzina trafia już do path, więc extra to host i port)
                parts = event.extra.split("\t")
                family = event.path or "?"
                host = parts[0] if parts else ""
                try:
                    port = int(parts[1]) if len(parts) > 1 else 0
                except ValueError:
                    port = 0
                key = f"{family}:{host}:{port}"
                network.setdefault(key, (family, host, port))
            elif event.kind == "SOCKET":
                sockets.append(event.extra)

        report.processes = [{"path": p, "args": a} for p, a in execs.items()]
        report.file_writes = [{"path": p, "mode": m} for p, m in writes.items()]
        report.file_reads = [{"path": p, "mode": m} for p, m in reads.items()]
        report.deletes = [{"path": p} for p in deletes]
        report.moves = [{"src": s, "dst": d} for s, d in moves]
        report.network = [{"family": f, "host": h, "port": p}
                          for f, h, p in network.values()]

        findings: List[BehaviorFinding] = []
        add = lambda rule, sev, weight, desc, ev="": findings.append(
            BehaviorFinding(rule, sev, weight, desc, ev,
                            self._technique(rule)))

        # --- uruchamianie powłok i poleceń ---
        shells = [p for p in execs if p.endswith(("/sh", "/bash", "/zsh", "/dash",
                                                  "/cmd.exe", "/powershell.exe"))]
        if shells:
            add("exec_shell", "medium", 14,
                f"Próbka uruchomiła powłokę systemową ({', '.join(shells[:3])})",
                execs.get(shells[0], "")[:120])

        downloaders = [p for p in execs
                       if Path(p).name.lower() in DOWNLOAD_TOOLS]
        if downloaders:
            add("exec_downloader", "high", 25,
                "Uruchomiła narzędzie do pobierania danych z sieci - "
                f"{', '.join(Path(p).name for p in downloaders[:4])}",
                "pobranie i uruchomienie kolejnego etapu to standardowy schemat infekcji")

        lolbins = [p for p in execs if Path(p).name.lower() in LOLBIN_TOOLS]
        if lolbins:
            add("exec_lolbin", "high", 22,
                "Wykorzystała zaufane narzędzie systemowe do nietypowego celu "
                f"({', '.join(Path(p).name for p in lolbins[:4])})",
                "technika 'living off the land' - trudna do wykrycia, bo używa "
                "legalnych programów")

        # --- utrwalanie ---
        persistence = [p for p in writes if self._matches(p, PERSISTENCE_PATHS)]
        if persistence:
            critical = [p for p in persistence
                        if "/etc/passwd" in p or "/etc/shadow" in p
                        or "ld.so.preload" in p or "/etc/sudoers" in p]
            add("persistence_write", "critical" if critical else "high",
                45 if critical else 32,
                f"Zapisała do {len(persistence)} miejsc autostartu / konfiguracji "
                "systemowej - próba utrwalenia się w systemie",
                "; ".join(sorted(persistence)[:4]))
            if critical:
                add("account_or_loader_tamper", "critical", 35,
                    "Zmodyfikowała newralgiczny plik systemowy (konta użytkowników, "
                    "uprawnienia sudo lub loader bibliotek)",
                    "; ".join(sorted(critical)[:3]))

        # --- manipulacje w katalogach systemowych ---
        system_writes = [p for p in writes
                         if p.startswith(SYSTEM_DIRS)
                         and not self._matches(p, PERSISTENCE_PATHS)
                         and not p.startswith(("/proc/", "/sys/"))]
        if system_writes:
            add("system_dir_write", "high", 26,
                f"Zapisała do katalogów systemowych ({len(system_writes)} plików) "
                "- możliwa podmiana binarek",
                "; ".join(sorted(system_writes)[:4]))

        # --- masowe modyfikacje = ransomware? ---
        user_writes = [p for p in writes
                       if p.startswith((str(root / "home"), str(root / "work")))]
        if len(user_writes) >= 20:
            add("mass_file_write", "high", 24,
                f"Zmodyfikowała {len(user_writes)} plików w krótkim czasie - "
                "zachowanie typowe dla ransomware",
                "; ".join(sorted(user_writes)[:3]))

        encrypted = self._high_entropy_writes(root)
        if encrypted:
            add("encrypted_content", "critical", 40,
                f"Pliki zapisane przez próbkę mają bardzo wysoką entropię "
                f"(≥7.5) - wygląda na szyfrowanie zawartości",
                "; ".join(f"{name} ({value})" for name, value in encrypted[:3]))

        if len(deletes) >= 10:
            add("mass_delete", "high", 24,
                f"Usunęła {len(deletes)} plików - niszczenie danych lub zacieranie śladów",
                "; ".join(sorted(deletes)[:3]))
        if any(sample.name in d for d in deletes):
            add("self_delete", "medium", 15,
                "Usunęła własny plik po uruchomieniu - technika zacierania śladów",
                sample.name)

        # --- kradzież poświadczeń ---
        credential_reads = [p for p in reads if self._matches(p, CREDENTIAL_PATHS)]
        if credential_reads:
            add("credential_access", "critical", 38,
                f"Czytała pliki z poświadczeniami ({len(credential_reads)})",
                "; ".join(sorted(credential_reads)[:4]))

        # --- sieć ---
        remote = [(f, h, p) for f, h, p in network.values()
                  if h and h not in LOCAL_HOSTS and not h.startswith("/")]
        if remote:
            add("network_c2", "high", 20,
                f"Nawiązała {len(remote)} połączeń ze zdalnymi adresami - "
                "możliwy kontakt z serwerem C2",
                "; ".join(f"{h}:{p}" for _, h, p in remote[:4]))
        suspicious_ports = [(f, h, p) for f, h, p in network.values()
                            if p in SUSPICIOUS_PORTS and h not in LOCAL_HOSTS]
        if suspicious_ports:
            add("suspicious_port", "medium", 12,
                "Łączyła się z portem typowym dla shelli zwrotnych i botnetów",
                "; ".join(f"{h}:{p}" for _, h, p in suspicious_ports[:4]))
        if sockets and not remote:
            add("socket_created", "low", 5,
                f"Utworzyła {len(sockets)} gniazdek sieciowych, ale nie nawiązała "
                "połączenia (albo korzystała z sieci lokalnej)", "")

        # --- premia za spójny łańcuch (wspólna logika ze skanem statycznym) ---
        tactics = {mitre.map_finding("behavior", f.rule).tactic
                   for f in findings if mitre.map_finding("behavior", f.rule)}
        bonus = mitre.chain_bonus(len(tactics))
        if bonus:
            names = ", ".join(sorted(mitre.TACTIC_PL.get(t, t) for t in tactics))
            findings.append(BehaviorFinding(
                "behavior_chain", "high" if bonus >= 20 else "medium", bonus,
                f"Zaobserwowane zachowania układają się w łańcuch ataku "
                f"obejmujący {len(tactics)} taktyk: {names}", "",
                "obserwacja na żywo - mocniejszy dowód niż statyczna heurystyka"))

        report.findings = findings
        report.score = min(100, sum(f.weight for f in findings))
        report.verdict = ("malicious" if report.score >= 60
                          else "suspicious" if report.score >= 25
                          else "clean" if report.executed else "unknown")

    @staticmethod
    def _technique(rule: str) -> str:
        technique = mitre.map_finding("behavior", rule)
        return f"{technique.id} {technique.name}" if technique else ""

    @staticmethod
    def _matches(path: str, patterns) -> bool:
        return any(pattern in path for pattern in patterns)

    @staticmethod
    def _high_entropy_writes(root: Path, threshold: float = 7.5,
                             limit: int = 5) -> List[Tuple[str, float]]:
        """Sprawdza entropię plików zapisanych w piaskownicy."""
        results: List[Tuple[str, float]] = []
        for directory in (root / "home", root / "work"):
            if not directory.exists():
                continue
            for file_path in directory.rglob("*"):
                if not file_path.is_file() or file_path.stat().st_size < 512:
                    continue
                try:
                    data = file_path.read_bytes()[:262144]
                except Exception:
                    continue
                value = shannon_entropy(data)
                if value >= threshold:
                    results.append((file_path.name, round(value, 2)))
                if len(results) >= limit:
                    return results
        return results
