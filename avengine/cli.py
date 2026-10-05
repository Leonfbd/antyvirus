"""Interfejs wiersza poleceń: `avy`."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import List, Optional

from . import __version__
from .config import Config
from .engine import Engine
from .hashing import file_hashes, ssdeep_hash, imphash
from .models import Verdict
from .quarantine import Quarantine
from .storage import Storage

VERDICT_COLORS = {
    "malicious": "\033[91m",     # czerwony
    "suspicious": "\033[93m",    # żółty
    "clean": "\033[92m",         # zielony
    "error": "\033[90m",
    "skipped": "\033[90m",
}
RESET = "\033[0m"
BOLD = "\033[1m"

VERDICT_PL = {
    "malicious": "ZŁOŚLIWY",
    "suspicious": "PODEJRZANY",
    "clean": "czysty",
    "error": "błąd",
    "skipped": "pominięty",
}


def _color(text: str, verdict: str, use_color: bool = True) -> str:
    if not use_color:
        return text
    return f"{VERDICT_COLORS.get(verdict, '')}{BOLD}{text}{RESET}"


def build_engine(cfg: Optional[Config] = None, load_yara: bool = True) -> Engine:
    cfg = cfg or Config()
    cfg.ensure_dirs()
    engine = Engine(cfg)
    engine.load(load_yara=load_yara)
    return engine


def cmd_scan(args: argparse.Namespace) -> int:
    cfg = Config()
    cfg.ensure_dirs()
    storage = Storage(cfg.db_path)
    engine = Engine(cfg, storage=storage)
    stats = engine.load(load_yara=not args.no_yara)
    quarantine = Quarantine(cfg.quarantine_dir)

    if args.quarantine:
        cfg.quarantine_enabled = True
    if args.no_quarantine:
        cfg.quarantine_enabled = False

    scan_id = storage.start_scan(", ".join(args.paths), "cli")
    started = time.time()
    last_print = [0.0]

    def progress(done: int, total: int, result) -> None:
        if result.verdict in (Verdict.MALICIOUS.value, Verdict.SUSPICIOUS.value):
            print_result(result, cfg, verbose=args.verbose)
        if not args.quiet:
            now = time.time()
            if now - last_print[0] > 0.5 or done == total:
                last_print[0] = now
                pct = int(done * 100 / total) if total else 0
                sys.stdout.write(f"\r  skanowanie… {done}/{total} ({pct}%)   ")
                sys.stdout.flush()

    summary = engine.scan_paths(args.paths, progress=progress, workers=args.workers)
    storage.finish_scan(scan_id, summary.to_dict(include_results=False))
    if not args.quiet:
        sys.stdout.write("\r" + " " * 60 + "\r")

    quarantined = 0
    if cfg.quarantine_enabled:
        for result in summary.results:
            if engine.should_quarantine(result):
                entry = quarantine.add(result.path, result)
                if entry:
                    result.quarantined = True
                    quarantined += 1
                    if not args.quiet:
                        print(f"  {_color('ODIZOLOWANO', 'suspicious')} {result.path}")
                        storage.add_event("quarantined", result.path,
                                          f"{result.verdict} ({result.score} pkt)")

    if args.json:
        print(json.dumps(summary.to_dict(), indent=2, ensure_ascii=False))
        return 1 if summary.malicious else 0

    print()
    print(f"{BOLD}Wynik skanu{RESET}")
    print(f"  plików:       {summary.total}")
    print(f"  czystych:     {_color(str(summary.clean), 'clean')}")
    print(f"  podejrzanych: {_color(str(summary.suspicious), 'suspicious')}")
    print(f"  złośliwych:   {_color(str(summary.malicious), 'malicious')}")
    if summary.errors:
        print(f"  błędów:       {summary.errors}")
    print(f"  odizolowano:  {quarantined}")
    print(f"  dane:         {summary.bytes_scanned / 1024 / 1024:.1f} MB w {summary.elapsed_ms} ms")

    return 1 if summary.malicious else 0


def print_result(result, cfg: Config, verbose: bool = False) -> None:
    label = _color(VERDICT_PL.get(result.verdict, result.verdict), result.verdict)
    print(f"\n{label} {result.path}")
    print(f"  typ: {result.file_type} · rozmiar: {result.size} B · wynik: {result.score} pkt · {result.elapsed_ms} ms")
    if result.sha256:
        print(f"  sha256: {result.sha256}")
    if result.error:
        print(f"  błąd: {result.error}")
    for finding in result.findings:
        marker = "!" if finding.weight >= 30 else "-"
        print(f"   {marker} [{finding.severity:8s}] +{finding.weight:<3} "
              f"{finding.detector}/{finding.rule}")
        print(f"       {finding.description}")
        if finding.evidence and verbose:
            print(f"       ↳ {finding.evidence[:200]}")


def cmd_scan_one(args: argparse.Namespace) -> int:
    """Skan pojedynczego pliku z pełnym raportem."""
    engine = build_engine(load_yara=not args.no_yara)
    result = engine.scan_file(args.path)
    print_result(result, engine.config, verbose=True)
    return 1 if result.verdict == Verdict.MALICIOUS.value else 0


def cmd_update(args: argparse.Namespace) -> int:
    from .sigs.updater import SignatureUpdater
    cfg = Config()
    cfg.ensure_dirs()
    updater = SignatureUpdater(cfg)
    print("Aktualizacja baz sygnatur…")
    manifest = updater.update()
    for src in manifest["sources"]:
        mark = "✓" if src["status"] != "error" else "✗"
        print(f"  {mark} {src['name']}: {src['status']}"
              + (f" ({src['rules']} plików reguł)" if src.get("rules") else "")
              + (f" — {src['error']}" if src.get("error") else ""))

    engine = Engine(cfg)
    stats = engine.load(sources=manifest["sources"])
    print(f"\nBaza po aktualizacji:")
    print(f"  skróty:        {stats.hashes}")
    print(f"  import-hashe:  {stats.imphash}")
    print(f"  reguły YARA:   {stats.yara_rules} plików")
    if stats.yara_errors:
        print(f"  reguł błędnych (pominiętych): {stats.yara_errors}")
    print(f"  ClamAV:        {stats.clamav_sigs}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    cfg = Config()
    cfg.ensure_dirs()
    engine = Engine(cfg)
    stats = engine.load()
    storage = Storage(cfg.db_path)
    from .sigs.updater import SignatureUpdater
    manifest = SignatureUpdater(cfg).status()
    print(f"AntyVirus v{__version__}")
    print(f"  katalog danych: {cfg.data_dir}")
    print("  sygnatury:")
    print(f"    skróty:       {stats.hashes}")
    print(f"    import-hashe: {stats.imphash}")
    print(f"    reguły YARA:  {stats.yara_rules} plików ({stats.yara_errors} odrzuconych)")
    print(f"    ClamAV:       {stats.clamav_sigs}")
    print(f"  ostatnia aktualizacja: {manifest.get('updated_at') or 'nigdy'}")
    db = storage.stats()
    print(f"  historia: {db['scans']} skanów, {db['files_scanned']} plików, {db['threats']} wykryć")
    print(f"  obserwowane katalogi: {', '.join(cfg.watched_paths) or '—'}")
    return 0


def cmd_realtime(args: argparse.Namespace) -> int:
    cfg = Config()
    cfg.ensure_dirs()
    storage = Storage(cfg.db_path)
    engine = Engine(cfg, storage=storage)
    engine.load()
    quarantine = Quarantine(cfg.quarantine_dir)

    from .realtime import RealtimeMonitor

    def on_event(kind: str, path: str, message: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        print(f"[{stamp}] {kind:18s} {message}")
        if path:
            print(f"{' ' * 26}{path}")

    monitor = RealtimeMonitor(engine, storage=storage, quarantine=quarantine,
                              on_event=on_event)
    info = monitor.start(paths=args.paths)
    print(f"Monitoring aktywny: {', '.join(info['paths']) or '—'}")
    if info.get("missing"):
        print(f"Nie znaleziono: {', '.join(info['missing'])}")
    print("Ctrl+C aby zatrzymać.\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
        print("\nZatrzymano.")
    return 0


def cmd_quarantine(args: argparse.Namespace) -> int:
    cfg = Config()
    cfg.ensure_dirs()
    q = Quarantine(cfg.quarantine_dir)
    if args.action == "list":
        items = q.list()
        if not items:
            print("Kwarantanna jest pusta.")
            return 0
        for it in items:
            print(f"{it['id'][:16]}  {it.get('verdict', '?'):10s} {it.get('score', 0):3} pkt  "
                  f"{it.get('original_path', '?')}")
            print(f"{' ' * 18}{it.get('quarantined_at_human', '')} · {it.get('reason', '')[:90]}")
        return 0
    if args.action == "restore":
        dest = q.restore(args.id, target_dir=args.target_dir)
        print(f"Przywrócono do: {dest}" if dest else "Nie znaleziono wpisu.")
        return 0 if dest else 1
    if args.action == "delete":
        ok = q.delete(args.id)
        print("Usunięto." if ok else "Nie znaleziono wpisu.")
        return 0 if ok else 1
    if args.action == "purge":
        n = q.purge_older_than(args.days)
        print(f"Usunięto {n} wpisów starszych niż {args.days} dni.")
        return 0
    return 1


def cmd_ioc(args: argparse.Namespace) -> int:
    cfg = Config()
    cfg.ensure_dirs()
    engine = Engine(cfg)
    engine.load(load_yara=False)
    store = engine.store

    if args.action == "add":
        value = args.value
        name = args.name
        if os.path.isfile(value):
            hashes = file_hashes(value)
            for algo in ("sha256", "sha1", "md5"):
                store.add_ioc(hashes[algo], name or Path(value).name)
            print(f"Dodano skróty pliku {value} jako „{name or Path(value).name}”")
        else:
            ok = store.add_ioc(value, name or "dodane ręcznie")
            print("Dodano." if ok else "Nieprawidłowy skrót (md5/sha1/sha256).")
            return 0 if ok else 1
        return 0

    if args.action == "fuzzy-add":
        data = Path(args.value).read_bytes()
        ss = ssdeep_hash(data)
        ok = store.add_ssdeep(ss, args.name or Path(args.value).name)
        print(f"{'Dodano' if ok else 'Nie dodano'}: {ss}")
        return 0 if ok else 1
    return 1


def cmd_info(args: argparse.Namespace) -> int:
    """Szybki raport o pliku bez uruchamiania pełnego silnika."""
    path = Path(args.path)
    data = path.read_bytes()
    hashes = file_hashes(str(path))
    print(f"plik:   {path}")
    print(f"rozmiar: {len(data)} B")
    for algo in ("md5", "sha1", "sha256"):
        print(f"{algo:7s}: {hashes[algo]}")
    ss = ssdeep_hash(data)
    if ss:
        print(f"ssdeep : {ss}")
    from .filetype import detect, pretty
    print(f"typ    : {pretty(data, str(path))} ({detect(data, str(path))})")
    from .entropy import shannon_entropy
    print(f"entropia: {shannon_entropy(data):.3f}")
    if data[:2] == b"MZ":
        try:
            import pefile
            pe = pefile.PE(data=data)
            print(f"imphash : {imphash(pe)}")
            print("sekcje:")
            from .entropy import shannon_entropy as ent
            for s in pe.sections:
                name = s.Name.rstrip(b"\x00").decode("utf-8", "ignore")
                raw = s.get_data() or b""
                flags = ("R" if s.Characteristics & 0x40000000 else "-") + \
                        ("W" if s.Characteristics & 0x80000000 else "-") + \
                        ("X" if s.Characteristics & 0x20000000 else "-")
                print(f"  {name:10s} {flags}  raw={len(raw):>9}  entropia={ent(raw):.3f}")
        except Exception as exc:
            print(f"  (nie udało się sparsować PE: {exc})")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn
    from .web.app import AVWebApp

    cfg = Config()
    cfg.ensure_dirs()
    storage = Storage(cfg.db_path)
    engine = Engine(cfg, storage=storage)
    print("Ładowanie sygnatur…")
    engine.load()
    quarantine = Quarantine(cfg.quarantine_dir)

    from .realtime import RealtimeMonitor
    monitor = RealtimeMonitor(engine, storage=storage, quarantine=quarantine)

    if args.realtime:
        try:
            monitor.start(paths=args.watch)
            print(f"Ochrona w czasie rzeczywistym: {', '.join(monitor.watched)}")
        except Exception as exc:
            print(f"Nie uruchomiono real-time: {exc}")

    web = AVWebApp(engine, storage=storage, quarantine=quarantine, monitor=monitor, config=cfg)
    print(f"Panel: http://{args.host}:{args.port}")
    uvicorn.run(web.app, host=args.host, port=args.port, log_level="warning")
    return 0


def cmd_processes(args: argparse.Namespace) -> int:
    """Skanuje uruchomione procesy i ocenia ich obrazy na dysku."""
    cfg = Config()
    cfg.ensure_dirs()
    engine = Engine(cfg)
    engine.load()
    try:
        from .processes import ProcessScanner
    except ImportError as exc:
        print(f"Brak zależności: {exc}")
        return 2

    print("Skanowanie procesów…\n")
    report = ProcessScanner(engine).scan()

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 1 if report["counts"]["malicious"] else 0

    counts = report["counts"]
    print(f"{BOLD}Procesy:{RESET} {counts['total']} "
          f"| złośliwe: {_color(str(counts['malicious']), 'malicious')} "
          f"| podejrzane: {_color(str(counts['suspicious']), 'suspicious')} "
          f"| czyste: {counts['clean']}")
    print(f"przeskanowanych plików wykonywalnych: {report.get('scanned_binaries', 0)}\n")

    if not report["threats"]:
        print("Nie wykryto podejrzanych procesów.")
        return 0

    for p in report["threats"][:args.limit]:
        label = _color(VERDICT_PL.get(p["verdict"], p["verdict"]), p["verdict"])
        print(f"{label} pid={p['pid']}  {p['name']}")
        print(f"  exe:     {p['exe'] or '(brak)'}")
        if p["cmdline"]:
            print(f"  cmdline: {p['cmdline'][:150]}")
        print(f"  użytkownik: {p['username']} · połączenia: {p['connections']}")
        for f in p["findings"]:
            print(f"   ! +{f['weight']:<3} {f['rule']}: {f['description']}")
        print()
    return 1 if counts["malicious"] else 0


def cmd_startup(args: argparse.Namespace) -> int:
    """Audyt miejsc autostartu - gdzie system uruchamia kod bez pytania."""
    cfg = Config()
    cfg.ensure_dirs()
    engine = Engine(cfg)
    engine.load()
    from .startup_audit import StartupAuditor

    print("Audyt autostartu…\n")
    report = StartupAuditor(engine).audit()

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 1 if report["counts"]["malicious"] else 0

    counts = report["counts"]
    print(f"{BOLD}Wpisy autostartu:{RESET} {counts['total']} "
          f"| wysokiego ryzyka: {_color(str(counts['high_risk']), 'malicious')} "
          f"| średniego: {_color(str(counts['medium_risk']), 'suspicious')} "
          f"| złośliwych plików: {counts['malicious']} "
          f"| osieroconych: {counts['missing_target']}\n")

    shown = 0
    for entry in report["entries"]:
        if entry["score"] == 0 and not args.all:
            continue
        shown += 1
        if shown > args.limit:
            break
        color = "malicious" if entry["score"] >= 60 else (
            "suspicious" if entry["score"] >= 25 else "clean")
        print(f"{_color(entry['risk'].upper(), color)} "
              f"({entry['score']} pkt) {entry['name']}")
        print(f"  lokalizacja: {entry['location']}")
        print(f"  komenda:     {entry['command'][:160]}")
        if entry["target"]:
            status = "OK" if entry["exists"] else "NIE ISTNIEJE"
            print(f"  plik:        {entry['target']} [{status}]")
        for f in entry["findings"]:
            print(f"   ! +{f['weight']:<3} {f['rule']}: {f['description']}")
        print()
    if not shown:
        print("Nie znaleziono podejrzanych wpisów autostartu.")
    return 1 if counts["malicious"] else 0


def cmd_integrity(args: argparse.Namespace) -> int:
    """Kontrola integralności systemu (techniki rootkitów)."""
    cfg = Config()
    cfg.ensure_dirs()
    engine = Engine(cfg)
    engine.load(load_yara=not args.no_yara)
    from .rootkit import IntegrityScanner

    if not args.json:
        print("Kontrola integralności systemu…\n")
    report = IntegrityScanner(engine).scan()

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 1 if report["counts"]["critical"] else 0

    if not report["findings"]:
        print("Nie wykryto oznak naruszenia integralności.\n")
    for f in report["findings"]:
        label = _color(f["severity"].upper(), "malicious" if f["severity"] == "critical"
                       else "suspicious" if f["severity"] == "high" else "clean")
        print(f"{label} +{f['weight']:<3} {f['rule']}")
        print(f"   {f['description']}")
        if f["evidence"]:
            print(f"   ↳ {f['evidence'][:200]}")
        print()

    if report["hardening"]:
        print("Słaba konfiguracja (podatności, nie infekcja):")
        for f in report["hardening"]:
            print(f"  - [{f['severity']:<8}] {f['rule']}: {f['description']}")
        print()

    print(f"Sprawdzono: {len(report['checked'])} testów"
          + (f" · pominięto: {len(report['skipped'])}" if report["skipped"] else ""))
    if report["skipped"]:
        print(f"  ({', '.join(report['skipped'][:6])})")
    print("\nPoza zasięgiem (wymagają sterownika kernelowego):")
    for item in report["not_covered"]:
        print(f"  - {item}")
    return 1 if report["counts"]["critical"] else 0


def cmd_report(args: argparse.Namespace) -> int:
    """Skan + raport HTML/JSON do pliku."""
    cfg = Config()
    cfg.ensure_dirs()
    storage = Storage(cfg.db_path)
    engine = Engine(cfg, storage=storage)
    engine.load()
    cfg.quarantine_enabled = False       # raport nie powinien niczego przenosić

    summary = engine.scan_paths(args.paths, workers=args.workers)
    meta = {
        "version": engine.VERSION,
        "hostname": os.uname().nodename if hasattr(os, "uname") else "windows",
        "signatures": engine.store.stats.to_dict(),
    }

    from .report import write_report
    target = args.output or f"raport-skanu.{args.format}"
    path = write_report(summary, target, fmt=args.format, meta=meta)
    print(f"Raport zapisany: {path}")
    print(f"  plików: {summary.total} · złośliwych: {summary.malicious} "
          f"· podejrzanych: {summary.suspicious}")
    return 1 if summary.malicious else 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="avy",
        description="AntyVirus — wielowarstwowy silnik detekcji (CLI)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""przykłady:
  avy scan ~/Pobrane                 skanuj katalog
  avy scan plik.exe -v               pełny raport dla jednego pliku
  avy update                         pobierz bazy YARA z GitHub
  avy realtime --paths ~/Pobrane     ochrona w czasie rzeczywistym
  avy serve --port 8080              panel WWW
  avy quarantine list                lista odizolowanych plików
""")
    parser.add_argument("-V", "--version", action="version", version=f"AntyVirus {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    p = sub.add_parser("scan", help="skanuj pliki i katalogi")
    p.add_argument("paths", nargs="+")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--json", action="store_true", help="wynik w formacie JSON")
    p.add_argument("--workers", type=int, default=0)
    p.add_argument("--no-yara", action="store_true", help="pomiń warstwę YARA")
    p.add_argument("--quarantine", action="store_true", help="izoluj wykryte zagrożenia")
    p.add_argument("--no-quarantine", action="store_true", help="nie izoluj niczego")
    p.set_defaults(func=cmd_scan)

    # file
    p = sub.add_parser("file", help="pełna analiza jednego pliku")
    p.add_argument("path")
    p.add_argument("--no-yara", action="store_true")
    p.set_defaults(func=cmd_scan_one)

    # info
    p = sub.add_parser("info", help="szybkie informacje o pliku (hashe, entropia, sekcje)")
    p.add_argument("path")
    p.set_defaults(func=cmd_info)

    # update
    p = sub.add_parser("update", help="aktualizuj bazy sygnatur")
    p.set_defaults(func=cmd_update)

    # status
    p = sub.add_parser("status", help="stan silnika i baz")
    p.set_defaults(func=cmd_status)

    # realtime
    p = sub.add_parser("realtime", help="ochrona w czasie rzeczywistym")
    p.add_argument("--paths", nargs="*", default=None)
    p.set_defaults(func=cmd_realtime)

    # quarantine
    p = sub.add_parser("quarantine", help="zarządzaj kwarantanną")
    p.add_argument("action", choices=["list", "restore", "delete", "purge"])
    p.add_argument("id", nargs="?", default="")
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--target-dir", default=None)
    p.set_defaults(func=cmd_quarantine)

    # ioc
    p = sub.add_parser("ioc", help="zarządzaj własnymi wskaźnikami (IOC)")
    p.add_argument("action", choices=["add", "fuzzy-add"])
    p.add_argument("value", help="plik lub skrót")
    p.add_argument("name", nargs="?", default=None)
    p.set_defaults(func=cmd_ioc)

    # processes
    p = sub.add_parser("processes", help="skanuj uruchomione procesy")
    p.add_argument("--json", action="store_true")
    p.add_argument("--limit", type=int, default=30)
    p.set_defaults(func=cmd_processes)

    # startup
    p = sub.add_parser("startup", help="audyt miejsc autostartu")
    p.add_argument("--json", action="store_true")
    p.add_argument("--all", action="store_true", help="pokaż też wpisy bez ryzyka")
    p.add_argument("--limit", type=int, default=40)
    p.set_defaults(func=cmd_startup)

    # integrity
    p = sub.add_parser("integrity", aliases=["rootkit"],
                       help="kontrola integralności systemu (rootkity)")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-yara", action="store_true")
    p.set_defaults(func=cmd_integrity)

    # report
    p = sub.add_parser("report", help="skan + raport HTML/JSON")
    p.add_argument("paths", nargs="+")
    p.add_argument("--format", choices=["html", "json", "txt"], default="html")
    p.add_argument("-o", "--output", default=None)
    p.add_argument("--workers", type=int, default=0)
    p.set_defaults(func=cmd_report)

    # serve
    p = sub.add_parser("serve", help="uruchom panel WWW")
    p.add_argument("--host", default=Config().web_host)
    p.add_argument("--port", type=int, default=Config().web_port)
    p.add_argument("--realtime", action="store_true", help="od razu włącz ochronę")
    p.add_argument("--watch", nargs="*", default=None)
    p.set_defaults(func=cmd_serve)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nPrzerwano.")
        return 130
    except Exception as exc:
        print(f"Błąd: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
