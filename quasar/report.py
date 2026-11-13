"""Rendering: a clean rich terminal report, or structured JSON."""
from __future__ import annotations
import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

_BAND_COLOR = {
    "high-risk": "red",
    "likely malicious": "red",
    "suspicious": "yellow",
    "low / unremarkable": "green",
}


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def render(report: dict, console: Console | None = None) -> None:
    console = console or Console()
    f, sc = report["file"], report["score"]
    color = _BAND_COLOR.get(sc["band"], "white")

    head = Text()
    head.append(f'{f["path"]}\n', style="bold")
    head.append(f'{f["type"].upper()}   {f["size"]:,} bytes   entropy {f["entropy"]}\n')
    head.append(f'sha256 {f["sha256"]}\n', style="dim")
    head.append(f' {sc["band"].upper()}  {sc["score"]}/100 ', style=f"bold reverse {color}")
    console.print(Panel(head, title="QUASAR", subtitle=f'v{report["quasar_version"]}', border_style=color))

    ml = report.get("ml", {})
    if ml.get("available"):
        mlcolor = "red" if ml["verdict"] == "malicious" else "green"
        console.print(Text.assemble(
            ("ML classifier (EMBER2024)   ", "bold"),
            (f'P(malicious) = {ml["malware_probability"]:.1%}  →  {ml["verdict"].upper()}', f"bold {mlcolor}"),
        ))

    console.print(Panel(Text(report["summary"]), title="Assessment", border_style="cyan"))

    caps = report["capabilities"]
    if caps:
        t = Table(title="Capabilities — MITRE ATT&CK", expand=True, border_style="dim")
        t.add_column("Capability", style="bold")
        t.add_column("ATT&CK", no_wrap=True)
        t.add_column("Evidence", overflow="fold", style="dim")
        for c in sorted(caps, key=lambda c: -c["weight"]):
            t.add_row(c["name"], f'{c["attck_id"]}  {c["attck_name"]}', ", ".join(c["evidence"]))
        console.print(t)

    yara = report.get("yara") or []
    if yara:
        t = Table(title="YARA matches", expand=True, border_style="dim")
        t.add_column("Rule", style="bold")
        t.add_column("What it flags", overflow="fold")
        for y in yara:
            t.add_row(y["rule"], y.get("description", ""))
        console.print(t)

    if sc["reasons"]:
        t = Table(title="Why this score", expand=True, border_style="dim")
        t.add_column("+", justify="right", style=color, no_wrap=True)
        t.add_column("Reason")
        for pts, why in sc["reasons"]:
            t.add_row(str(pts), why)
        console.print(t)

    iocs = report["iocs"]
    if iocs:
        t = Table(title="Indicators (IOCs)", expand=True, border_style="dim")
        t.add_column("Type", no_wrap=True)
        t.add_column("Values", overflow="fold")
        for k, vals in iocs.items():
            more = f"   (+{len(vals) - 12} more)" if len(vals) > 12 else ""
            t.add_row(k, ", ".join(vals[:12]) + more)
        console.print(t)

    pe = report.get("pe")
    if pe:
        t = Table(title="PE structure", expand=True, border_style="dim")
        t.add_column("field", no_wrap=True)
        t.add_column("value", overflow="fold")
        t.add_row("imphash", pe["imphash"] or "-")
        t.add_row("imports", str(len(pe["imports"])))
        t.add_row("is DLL", "yes" if pe["is_dll"] else "no")
        t.add_row("TLS callbacks", "yes" if pe["has_tls_callbacks"] else "no")
        notable = [f'{s["name"]} (H={s["entropy"]}{", RWX" if s["rwx"] else ""})'
                   for s in pe["sections"] if s["entropy"] >= 7.2 or s["rwx"]]
        t.add_row("notable sections", ", ".join(notable) or "-")
        console.print(t)

    intel = report.get("intel", {})
    if intel:
        console.print(Text(f'intel: {intel.get("mode", "?")} — {intel.get("note", "")}', style="dim"))
    console.print(Text("Static heuristic analysis — the sample was parsed, never executed.", style="dim italic"))
