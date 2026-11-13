"""EMBER2024 challenge set (malware that evaded AV detection at first submission): PE files only.
Reports classifier detection, transparent-score bands, rule firing and agreement with capa, compared with the regular test set.
Usage: .venv-ml/bin/python -I eval/challenge_eval.py <challenge dir> <out.json>"""
from pathlib import Path as _P; _ROOT = _P(__file__).resolve().parent.parent
import glob, json, re, sys
from collections import Counter
import numpy as np, lightgbm as lgb, thrember
sys.path.insert(0, str(_ROOT)); sys.path.insert(0, str(_ROOT / "eval"))
from quasar import capabilities
import importlib.util
spec = importlib.util.spec_from_file_location("se", str(_ROOT / "eval" / "score_eval.py"))
TID = re.compile(r"\[(T\d{4})(?:\.\d{3})?\]")
BEST = ["T1083", "T1115", "T1056", "T1059"]
ex = thrember.PEFeatureExtractor(); model = lgb.Booster(model_file=str(_ROOT / "models" / "ember2024_malware.model"))
from quasar import score as score_mod
def approx(o, caps):
    secs = [{"name": s.get("name", ""), "entropy": round(s.get("entropy", 0), 2), "rawsize": s.get("size", 0),
             "rwx": all(p in (s.get("props") or []) for p in ("MEM_EXECUTE", "MEM_READ", "MEM_WRITE"))}
            for s in (o.get("section") or {}).get("sections", [])]
    tls = any(isinstance(d, dict) and d.get("name") == "TLS" and d.get("size", 0) > 0 for d in (o.get("datadirectories") or []))
    sc = (o.get("strings") or {}).get("string_counts") or {}
    n_net = int(sc.get("http://", 0)) + int(sc.get("https://", 0))
    return score_mod.score(caps, {"sections": secs, "has_tls_callbacks": tls}, {"urls": ["x"] * n_net}, 0.0, None)["score"]
types = Counter(); X = []; S = []; anyq = 0; anyc = 0; packed = 0; nimp = []; tp = fp = fn = 0; fams = Counter(); n = 0
for fpth in sorted(glob.glob(f"{sys.argv[1]}/*.jsonl")):
    for line in open(fpth):
        o = json.loads(line); types[o.get("file_type")] += 1
        if o.get("file_type") not in ("Win32", "Win64"): continue
        imps = [f for funcs in (o.get("imports") or {}).values() for f in funcs if isinstance(f, str)]
        caps = capabilities.evaluate(imps, "")
        q = {h["attck_id"].split(".")[0] for h in caps}
        c = {m.group(1) for t in (o.get("ttps") or []) for m in [TID.search(t.get("Technique", ""))] if m}
        for t in BEST: tp += (t in q) and (t in c); fp += (t in q) and (t not in c); fn += (t in c) and (t not in q)
        anyq += bool(q); anyc += bool(c); packed += bool(o.get("packer")); nimp.append(len(imps)); fams[o.get("family")] += 1
        X.append(ex.process_raw_features(o)); S.append(approx(o, caps)); n += 1
p = model.predict(np.asarray(X, dtype=np.float32)); S = np.asarray(S)
P_ = tp / (tp + fp) if tp + fp else 0; R_ = tp / (tp + fn) if tp + fn else 0
res = {"file_types": dict(types), "pe_files": n, "clf_tpr@0.5": round(float((p >= 0.5).mean()), 4), "clf_tpr@0.9": round(float((p >= 0.9).mean()), 4),
       "median_p": round(float(np.median(p)), 4), "median_score": float(np.median(S)), "score>=20": round(float((S >= 20).mean()), 4),
       "score>=50": round(float((S >= 50).mean()), 4), "any_quasar": round(anyq / n, 4), "any_capa": round(anyc / n, 4),
       "packed": round(packed / n, 4), "median_imports": float(np.median(nimp)), "f1_best4_pooled": round(2 * P_ * R_ / (P_ + R_), 3) if P_ + R_ else 0,
       "top_families": fams.most_common(8)}
np.savez_compressed(sys.argv[2].replace(".json", ".npz"), p=p, score=S); json.dump(res, open(sys.argv[2], "w"), indent=1); print(res)
