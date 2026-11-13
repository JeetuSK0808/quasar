"""Calibrate Quasar's import rules against capa on EMBER2024 with a time split (no binaries involved).

For each rule we record, per file, which of its import names are present. On the calibration weeks we search, per rule,
(a) the minimum number of matching imports and (b) greedy removal of import names that mostly produce disagreements with capa,
choosing the setting with the best F1 against capa (technique level). We then score baseline and calibrated rules on the
held-out later weeks. Usage: python -I eval/calibrate.py <dir with weekly *.jsonl> <out.json>
"""
from pathlib import Path as _P; _ROOT = _P(__file__).resolve().parent.parent
import glob, json, re, sys
from collections import defaultdict
sys.path.insert(0, str(_ROOT))
from quasar import capabilities

TID = re.compile(r"\[(T\d{4})(?:\.\d{3})?\]")
def parent(t): return t.split(".")[0]

def load(files):
    rows = []                        # per file: (label, set of capa parents, {rule_index: frozenset(matched import names)})
    for fp in files:
        for line in open(fp):
            o = json.loads(line)
            imps = [f.lower() for funcs in (o.get("imports") or {}).values() for f in funcs if isinstance(f, str)]
            c = {parent(m.group(1)) for t in (o.get("ttps") or []) for m in [TID.search(t.get("Technique", ""))] if m}
            hit = {}
            for i, r in enumerate(capabilities.RULES):
                names = frozenset(n for n in r["imports"] if any(n.lower() in imp for imp in imps))
                if names: hit[i] = names
            rows.append((o.get("label"), c, hit))
    return rows

def score(rows, i, names, k):
    t = parent(capabilities.RULES[i]["attck"][0]); tp = fp = fn = 0
    for _, c, hit in rows:
        q = len(hit.get(i, frozenset()) & names) >= k if k > 0 else False
        b = t in c; tp += q and b; fp += q and not b; fn += b and not q
    P = tp / (tp + fp) if tp + fp else 0.0; R = tp / (tp + fn) if tp + fn else 0.0
    return (2 * P * R / (P + R) if P + R else 0.0), P, R, tp, fp, fn

def main():
    files = sorted(glob.glob(f"{sys.argv[1]}/*.jsonl")); half = len(files) // 2
    cal, test = load(files[:half]), load(files[half:])
    out = {"calibration_files": [f.split("/")[-1] for f in files[:half]], "test_files": [f.split("/")[-1] for f in files[half:]],
           "n_cal": len(cal), "n_test": len(test), "rules": {}}
    for i, r in enumerate(capabilities.RULES):
        if not r["imports"]: continue
        base = (frozenset(r["imports"]), r["min_imports"])
        best = (score(cal, i, *base)[0], base)
        names = set(r["imports"])
        for k in range(1, len(names) + 1):                       # threshold search with greedy name removal
            cur = set(names)
            while True:
                f_cur = score(cal, i, frozenset(cur), k)[0]
                if f_cur > best[0]: best = (f_cur, (frozenset(cur), k))
                cand = [(score(cal, i, frozenset(cur - {n}), k)[0], n) for n in cur if len(cur) > k]
                if not cand: break
                f_new, n_drop = max(cand)
                if f_new <= f_cur + 1e-4: break
                cur.discard(n_drop)
        (cn, ck) = best[1]
        b_test = score(test, i, *base); c_test = score(test, i, cn, ck)
        out["rules"][r["id"]] = {"attck": r["attck"][0], "baseline": {"min_imports": r["min_imports"], "f1": round(b_test[0], 3),
                                 "precision": round(b_test[1], 3), "recall": round(b_test[2], 3), "tp": b_test[3], "fp": b_test[4], "fn": b_test[5]},
                                 "calibrated": {"min_imports": ck, "imports": sorted(cn), "dropped": sorted(set(r["imports"]) - set(cn)),
                                 "f1": round(c_test[0], 3), "precision": round(c_test[1], 3), "recall": round(c_test[2], 3),
                                 "tp": c_test[3], "fp": c_test[4], "fn": c_test[5]}}
    json.dump(out, open(sys.argv[2], "w"), indent=1)
    for rid, v in out["rules"].items():
        print(f"{rid:16s} {v['attck']:10s} base F1 {v['baseline']['f1']:.3f} (P {v['baseline']['precision']:.2f} R {v['baseline']['recall']:.2f})"
              f" -> cal F1 {v['calibrated']['f1']:.3f} (P {v['calibrated']['precision']:.2f} R {v['calibrated']['recall']:.2f}) k={v['calibrated']['min_imports']}")

if __name__ == "__main__":
    main()
