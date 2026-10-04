"""Generowanie raportów ze skanu (HTML, JSON, tekst).

Raport HTML jest samowystarczalny: jeden plik, bez zewnętrznych zależności,
gotowy do wysłania mailem albo wpięcia do ticketu.
"""

from __future__ import annotations

import html
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import ScanResult, ScanSummary

VERDICT_PL = {
    "malicious": "ZŁOŚLIWY",
    "suspicious": "PODEJRZANY",
    "clean": "czysty",
    "error": "błąd",
    "skipped": "pominięty",
}

STYLE = """
:root { --bg:#0b0f17; --card:#121826; --line:#232c40; --text:#e6ecf7;
        --muted:#8695b3; --red:#f87171; --yellow:#fbbf24; --green:#34d399; --cyan:#22d3ee; }
* { box-sizing: border-box; }
body { margin:0; padding:32px; background:var(--bg); color:var(--text);
       font:15px/1.55 "Segoe UI", Roboto, system-ui, sans-serif; }
.wrap { max-width: 1100px; margin:0 auto; }
h1 { font-size:1.6rem; margin:0 0 4px; }
h2 { font-size:1.1rem; margin:28px 0 12px; }
.sub { color:var(--muted); font-size:.85rem; margin:0 0 24px; }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:14px 16px; }
.card .k { font-size:.72rem; text-transform:uppercase; letter-spacing:.07em; color:var(--muted); }
.card .v { font-size:1.6rem; font-weight:700; }
.badge { font-size:.7rem; font-weight:700; padding:3px 9px; border-radius:999px; }
.badge.malicious { color:var(--red); border:1px solid var(--red); background:rgba(248,113,113,.12); }
.badge.suspicious { color:var(--yellow); border:1px solid var(--yellow); background:rgba(251,191,36,.12); }
.badge.clean { color:var(--green); border:1px solid var(--green); background:rgba(52,211,153,.1); }
.file { background:var(--card); border:1px solid var(--line); border-left:3px solid var(--line);
        border-radius:10px; padding:14px 16px; margin-bottom:12px; }
.file.malicious { border-left-color:var(--red); }
.file.suspicious { border-left-color:var(--yellow); }
.file.clean { border-left-color:var(--green); }
.path { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:.85rem; word-break:break-all; }
.meta { color:var(--muted); font-size:.78rem; margin-top:4px; }
.finding { margin-top:10px; padding-top:10px; border-top:1px dashed var(--line); font-size:.86rem; }
.rule { font-family:ui-monospace,Menlo,Consolas,monospace; color:var(--cyan); }
.ev { color:var(--muted); font-size:.8rem; }
table { width:100%; border-collapse:collapse; font-size:.86rem; }
th,td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); }
th { color:var(--muted); }
footer { margin-top:36px; padding-top:16px; border-top:1px solid var(--line);
         color:var(--muted); font-size:.8rem; }
"""


def render_html(summary: ScanSummary, meta: Optional[Dict[str, Any]] = None,
                extra_sections: Optional[List[Dict[str, Any]]] = None) -> str:
    meta = meta or {}
    esc = html.escape

    parts: List[str] = [
        "<!DOCTYPE html><html lang=\"pl\"><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        f"<title>Raport skanu — AntyVirus {esc(str(meta.get('version', '')))}</title>",
        f"<style>{STYLE}</style></head><body><div class=\"wrap\">",
        "<h1>Raport skanu AntyVirus</h1>",
        f"<p class=\"sub\">Wygenerowano {esc(time.strftime('%Y-%m-%d %H:%M:%S'))}"
        f" · silnik v{esc(str(meta.get('version', '?')))}"
        f" · host {esc(str(meta.get('hostname', '?')))}</p>",
    ]

    parts.append("<div class=\"cards\">")
    for key, value, cls in (
        ("przeskanowanych plików", summary.total, ""),
        ("złośliwych", summary.malicious, "var(--red)"),
        ("podejrzanych", summary.suspicious, "var(--yellow)"),
        ("czystych", summary.clean, "var(--green)"),
        ("błędów", summary.errors, ""),
    ):
        parts.append(
            f"<div class=\"card\"><div class=\"k\">{key}</div>"
            f"<div class=\"v\" style=\"color:{cls}\">{value}</div></div>")
    parts.append("</div>")

    sig = meta.get("signatures") or {}
    if sig:
        parts.append("<h2>Bazy sygnatur</h2><div class=\"cards\">")
        for key, value in (
            ("reguły YARA (plików)", sig.get("yara_rules", 0)),
            ("skróty IOC", sig.get("hashes", 0)),
            ("sygnatury ClamAV", sig.get("clamav_sigs", 0)),
            ("odrzucone reguły", sig.get("yara_errors", 0)),
        ):
            parts.append(f"<div class=\"card\"><div class=\"k\">{key}</div>"
                         f"<div class=\"v\">{value}</div></div>")
        parts.append("</div>")

    interesting = [r for r in summary.results
                   if r.verdict in ("malicious", "suspicious") or r.error]
    parts.append(f"<h2>Wyniki do przejrzenia ({len(interesting)})</h2>")
    if not interesting:
        parts.append("<p class=\"sub\">Nie wykryto zagrożeń.</p>")
    for result in sorted(interesting, key=lambda r: r.score, reverse=True):
        parts.append(_render_file(result, esc))

    for section in extra_sections or []:
        parts.append(f"<h2>{esc(str(section.get('title', '')))}</h2>")
        rows = section.get("rows") or []
        if not rows:
            parts.append("<p class=\"sub\">Brak danych.</p>")
            continue
        parts.append("<table><thead><tr>")
        for column in section.get("columns", []):
            parts.append(f"<th>{esc(str(column))}</th>")
        parts.append("</tr></thead><tbody>")
        for row in rows:
            parts.append("<tr>")
            for cell in row:
                parts.append(f"<td>{esc(str(cell))}</td>")
            parts.append("</tr>")
        parts.append("</tbody></table>")

    parts.append(
        "<footer>AntyVirus — wielowarstwowy silnik detekcji. "
        "Raport ma charakter informacyjny i nie zastępuje komercyjnego "
        "oprogramowania antywirusowego.</footer>")
    parts.append("</div></body></html>")
    return "".join(parts)


def _render_file(result: ScanResult, esc) -> str:
    out = [
        f"<div class=\"file {result.verdict}\">",
        f"<div class=\"path\">{esc(result.path)}</div>",
        f"<div class=\"meta\"><span class=\"badge {result.verdict}\">"
        f"{VERDICT_PL.get(result.verdict, result.verdict)} · {result.score} pkt</span> "
        f"&nbsp; {esc(result.file_type)} · {result.size} B · {result.elapsed_ms} ms",
    ]
    if result.sha256:
        out.append(f"<br>sha256: {esc(result.sha256)}")
    if result.quarantined:
        out.append("<br><b>plik odizolowany w kwarantannie</b>")
    if result.error:
        out.append(f"<br>błąd: {esc(result.error)}")
    out.append("</div>")

    for finding in result.findings:
        out.append(
            f"<div class=\"finding\"><span class=\"badge\">{esc(finding.severity)}</span> "
            f"+{finding.weight} <span class=\"rule\">"
            f"{esc(finding.detector)}/{esc(finding.rule)}</span>"
            f"<div>{esc(finding.description)}</div>")
        if finding.evidence:
            out.append(f"<div class=\"ev\">↳ {esc(finding.evidence[:300])}</div>")
        out.append("</div>")
    out.append("</div>")
    return "".join(out)


def render_json(summary: ScanSummary, meta: Optional[Dict[str, Any]] = None) -> str:
    payload = {
        "generated_at": time.time(),
        "meta": meta or {},
        "summary": summary.to_dict(include_results=False),
        "results": [r.to_dict() for r in summary.results],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_text(summary: ScanSummary) -> str:
    lines = [
        "RAPORT SKANU",
        f"  plików:       {summary.total}",
        f"  złośliwych:   {summary.malicious}",
        f"  podejrzanych: {summary.suspicious}",
        f"  czystych:     {summary.clean}",
        f"  błędów:       {summary.errors}",
        "",
    ]
    for result in summary.results:
        if result.verdict in ("malicious", "suspicious") or result.error:
            lines.append(f"{VERDICT_PL.get(result.verdict, result.verdict)} "
                         f"({result.score} pkt) {result.path}")
            for finding in result.findings:
                lines.append(f"   +{finding.weight:<3} {finding.detector}/{finding.rule}")
    return "\n".join(lines)


def write_report(summary: ScanSummary, target: str, fmt: str = "html",
                 meta: Optional[Dict[str, Any]] = None,
                 extra_sections: Optional[List[Dict[str, Any]]] = None) -> Path:
    path = Path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        content = render_json(summary, meta)
    elif fmt == "txt":
        content = render_text(summary)
    else:
        content = render_html(summary, meta, extra_sections)
    path.write_text(content, encoding="utf-8")
    return path
