"""Transparent, evidence-based risk scoring. Not ML — every point is attributable to a reason
the analyst can inspect. (The optional EMBER2024 ML classifier in ml.py is reported alongside this
heuristic, never merged into it, so the explainable signal is never silently replaced.)
"""
from __future__ import annotations

BANDS = [(80, "high-risk"), (50, "likely malicious"), (20, "suspicious"), (0, "low / unremarkable")]


def _band(score: int) -> str:
    for threshold, label in BANDS:
        if score >= threshold:
            return label
    return "low / unremarkable"


def score(capabilities: list[dict], pe: dict | None, iocs: dict, overall_entropy: float, yara: list | None = None) -> dict:
    reasons: list[tuple[int, str]] = []
    total = 0

    for c in capabilities:
        total += c["weight"]
        reasons.append((c["weight"], f'{c["name"]} [{c["attck_id"]}]'))

    # Packing / encryption: a high-entropy executable section.
    if pe:
        for sec in pe["sections"]:
            if sec["entropy"] >= 7.2 and sec["rawsize"] > 0:
                total += 10
                reasons.append((10, f'High-entropy section "{sec["name"]}" ({sec["entropy"]}) — likely packed/encrypted'))
                break
        if any(sec["rwx"] for sec in pe["sections"]):
            total += 8
            reasons.append((8, "Section mapped read-write-execute (RWX)"))
        if pe["has_tls_callbacks"]:
            total += 5
            reasons.append((5, "TLS callbacks present (code runs before the entry point)"))
    elif overall_entropy >= 7.5:
        total += 8
        reasons.append((8, f"Very high overall entropy ({overall_entropy:.2f}) — likely packed/encrypted"))

    # Behavioural combinations that are much more telling together than apart.
    ids = {c["id"] for c in capabilities}
    if "proc-injection" in ids and (ids & {"anti-debug", "anti-vm"}):
        total += 12
        reasons.append((12, "Combination: process injection + anti-analysis"))
    if (ids & {"c2-network", "download-exec"}) and (ids & {"persist-run", "persist-service", "persist-schtask"}):
        total += 10
        reasons.append((10, "Combination: network activity + persistence"))

    # Network IOCs lend weight only when the binary also shows network capability.
    net_iocs = sum(len(iocs.get(k, [])) for k in ("urls", "ips", "domains"))
    if net_iocs and (ids & {"c2-network", "download-exec"}):
        bump = min(net_iocs, 8)
        total += bump
        reasons.append((bump, f"{net_iocs} network indicator(s) alongside network capability"))

    for y in (yara or []):
        total += 8
        reasons.append((8, f'YARA rule matched: {y["rule"]}'))

    total = max(0, min(total, 100))
    reasons.sort(key=lambda x: -x[0])
    return {"score": total, "band": _band(total), "reasons": reasons}
