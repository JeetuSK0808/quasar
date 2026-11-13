"""Top-level orchestration: path in → full structured report out. Reads and parses only."""
from __future__ import annotations
import hashlib

from . import pe as pe_mod
from . import strings as strings_mod
from . import capabilities as cap_mod
from . import score as score_mod
from . import intel as intel_mod
from . import ml as ml_mod
from . import yara_scan as yara_mod

VERSION = "0.6.0"


def _join(items: list[str]) -> str:
    items = list(items)
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " and " + items[-1]


def _narrative(r: dict) -> str:
    sc, caps, f = r["score"], r["capabilities"], r["file"]
    parts = [f'Quasar rates this {f["type"].upper()} sample {sc["band"].upper()} ({sc["score"]}/100).']
    if caps:
        top = [c["name"].lower() for c in sorted(caps, key=lambda c: -c["weight"])[:4]]
        parts.append("It shows capabilities for " + _join(top) + ".")
    else:
        parts.append("No high-signal capabilities surfaced from static analysis alone.")
    net = sum(len(r["iocs"].get(k, [])) for k in ("urls", "ips", "domains"))
    if net:
        parts.append(f"It embeds {net} network indicator(s) (listed under IOCs).")
    y = r.get("yara") or []
    if y:
        parts.append(f'{len(y)} YARA signature(s) matched: {", ".join(z["rule"] for z in y[:4])}.')
    if r.get("pe") and r["pe"]["imphash"]:
        parts.append(f'Its import hash ({r["pe"]["imphash"]}) can be pivoted to find related samples.')
    ml = r.get("ml", {})
    if ml.get("available"):
        parts.append(f'The EMBER2024 ML classifier estimates a {ml["malware_probability"]:.0%} probability of maliciousness.')
    parts.append("This is a static, heuristic assessment with evidence per finding; the sample was not executed.")
    return " ".join(parts)


def analyze(path, intel_enabled: bool = False) -> dict:
    with open(path, "rb") as fh:
        data = fh.read()

    sha256 = hashlib.sha256(data).hexdigest()
    report: dict = {
        "quasar_version": VERSION,
        "file": {
            "path": str(path),
            "size": len(data),
            "type": pe_mod.file_type(data),
            "entropy": round(pe_mod.shannon_entropy(data), 3),
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": sha256,
        },
        "pe": None,
        "strings_count": 0,
        "iocs": {},
        "capabilities": [],
        "lineage": {},
        "intel": {},
        "score": {},
    }

    strs = strings_mod.extract_strings(data)
    report["strings_count"] = len(strs)
    text = "\n".join(strs)
    report["iocs"] = strings_mod.extract_iocs(text)

    pe_info = pe_mod.parse_pe(data)
    import_names: list[str] = []
    if pe_info:
        report["pe"] = pe_info
        import_names = pe_info["import_names"]
        report["lineage"] = {"imphash": pe_info["imphash"]}

    caps = cap_mod.evaluate(import_names, text)
    report["capabilities"] = caps
    report["yara"] = yara_mod.scan(data)
    report["score"] = score_mod.score(caps, pe_info, report["iocs"], report["file"]["entropy"], report["yara"])
    report["intel"] = intel_mod.lookup(sha256, report["iocs"], enabled=intel_enabled)
    report["ml"] = ml_mod.classify(data, report["file"]["type"] == "pe")
    report["summary"] = _narrative(report)
    return report
