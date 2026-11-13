"""Approximate Quasar's transparent risk score on EMBER2024 features (no binaries) and measure how well it separates malicious
from benign files. Reproduces score.py with what EMBER exposes: capability weights from import names (strings unavailable, so
string-only rules cannot fire), high-entropy section (>=7.2, non-empty), RWX section, TLS directory present (proxy for TLS
callbacks), the two combination bonuses, and network-indicator bumps from EMBER's 'http://'/'https://' string counts.
YARA is not applied. Usage: python -I eval/score_eval.py <dir with *.jsonl> <out.json>"""
from pathlib import Path as _P; _ROOT = _P(__file__).resolve().parent.parent
import glob, json, sys
from collections import Counter
import numpy as np
sys.path.insert(0, str(_ROOT))
from quasar import capabilities, score as score_mod
from sklearn.metrics import roc_auc_score
DROP = set(sys.argv[3].split(',')) if len(sys.argv) > 3 else set()

def approx(o):
    imps = [f for funcs in (o.get("imports") or {}).values() for f in funcs if isinstance(f, str)]
    caps = [c for c in capabilities.evaluate(imps, "") if c["id"] not in DROP]
    secs = [{"name": s.get("name", ""), "entropy": round(s.get("entropy", 0), 2), "rawsize": s.get("size", 0),
             "rwx": all(p in (s.get("props") or []) for p in ("MEM_EXECUTE", "MEM_READ", "MEM_WRITE"))}
            for s in (o.get("section") or {}).get("sections", [])]
    tls = any(isinstance(d, dict) and d.get("name") == "TLS" and d.get("size", 0) > 0 for d in (o.get("datadirectories") or []))
    sc = (o.get("strings") or {}).get("string_counts") or {}
    n_net = int(sc.get("http://", 0)) + int(sc.get("https://", 0))
    pe = {"sections": secs, "has_tls_callbacks": tls}
    return score_mod.score(caps, pe, {"urls": ["x"] * n_net}, 0.0, None)["score"]

s, y = [], []
for fp in sorted(glob.glob(f"{sys.argv[1]}/*.jsonl")):
    for line in open(fp):
        o = json.loads(line)
        if o.get("label") in (0, 1): s.append(approx(o)); y.append(o["label"])
s, y = np.asarray(s), np.asarray(y)
band = lambda v: "high-risk" if v >= 80 else "likely malicious" if v >= 50 else "suspicious" if v >= 20 else "low"
res = {"n": int(len(y)), "auc": round(float(roc_auc_score(y, s)), 4),
       "bands": {lab: dict(Counter(band(v) for v in s[y == k])) for lab, k in (("benign", 0), ("malicious", 1))},
       "median_score": {"benign": float(np.median(s[y == 0])), "malicious": float(np.median(s[y == 1]))}}
for thr in (20, 50, 80):
    res[f"at>={thr}"] = {"tpr": round(float((s[y == 1] >= thr).mean()), 4), "fpr": round(float((s[y == 0] >= thr).mean()), 4)}
np.savez_compressed(sys.argv[2].replace('.json', '.npz'), y=y, score=s); json.dump(res, open(sys.argv[2], "w"), indent=1); print(res)
