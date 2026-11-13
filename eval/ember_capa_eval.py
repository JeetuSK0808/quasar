"""Evaluate Quasar's import-based ATT&CK mapping against capa on EMBER2024 (features only; no binaries).

For each EMBER2024 record we run quasar.capabilities.evaluate on the file's import names (EMBER has no raw strings, so
string-only rules cannot fire) and compare the ATT&CK techniques Quasar reports with the techniques capa reported for the same
file (EMBER2024 'ttps'). Matching is at the technique level (T1547.001 counts as T1547). Reports, per Quasar technique:
how often each tool fires, precision/recall/F1 of Quasar against capa, and firing rates on malicious vs benign files.
Usage: python -I eval/ember_capa_eval.py <dir with *.jsonl> <out.json> [--limit N]
"""
from pathlib import Path as _P; _ROOT = _P(__file__).resolve().parent.parent
import glob, json, re, sys, time
from collections import Counter, defaultdict
sys.path.insert(0, str(_ROOT))
from quasar import capabilities

TID = re.compile(r"\[(T\d{4})(?:\.\d{3})?\]")
def parent(t): return t.split(".")[0]

def main():
    d, out = sys.argv[1], sys.argv[2]
    limit = int(sys.argv[sys.argv.index("--limit") + 1]) if "--limit" in sys.argv else None
    rule_t = sorted({parent(r["attck"][0]) for r in capabilities.RULES})
    n = 0; lab = Counter(); t0 = time.time(); qtime = 0.0
    tp, fp, fn = Counter(), Counter(), Counter(); q_fire = Counter(); c_fire = Counter()
    fire_by_label = defaultdict(Counter); files = sorted(glob.glob(f"{d}/*.jsonl"))
    for fpth in files:
        for line in open(fpth):
            o = json.loads(line)
            imps = [f for funcs in (o.get("imports") or {}).values() for f in funcs if isinstance(f, str)]
            t1 = time.time(); hits = capabilities.evaluate(imps, ""); qtime += time.time() - t1
            q = {parent(h["attck_id"]) for h in hits}
            c = {parent(m.group(1)) for t in (o.get("ttps") or []) for m in [TID.search(t.get("Technique", ""))] if m}
            y = o.get("label"); lab[y] += 1
            for t in rule_t:
                a, b = t in q, t in c
                tp[t] += a and b; fp[t] += a and not b; fn[t] += b and not a; q_fire[t] += a; c_fire[t] += b
                fire_by_label[t][y] += a
            n += 1
            if limit and n >= limit: break
        if limit and n >= limit: break
    res = {"files": n, "labels": dict(lab), "quasar_seconds_per_file": round(qtime / max(n, 1), 6), "per_technique": {}}
    for t in rule_t:
        P = tp[t] / (tp[t] + fp[t]) if tp[t] + fp[t] else None; R = tp[t] / (tp[t] + fn[t]) if tp[t] + fn[t] else None
        F = 2 * P * R / (P + R) if P and R else None
        res["per_technique"][t] = {"quasar_fires": q_fire[t], "capa_fires": c_fire[t], "tp": tp[t], "fp": fp[t], "fn": fn[t],
            "precision": round(P, 3) if P is not None else None, "recall": round(R, 3) if R is not None else None,
            "f1": round(F, 3) if F is not None else None,
            "quasar_rate_malicious": round(fire_by_label[t][1] / lab[1], 4) if lab[1] else None,
            "quasar_rate_benign": round(fire_by_label[t][0] / lab[0], 4) if lab[0] else None}
    json.dump(res, open(out, "w"), indent=1); print(json.dumps(res, indent=1)[:3000]); print("elapsed", round(time.time() - t0), "s")

if __name__ == "__main__":
    main()
