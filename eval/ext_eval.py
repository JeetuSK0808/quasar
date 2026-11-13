"""Extended EMBER2024 Win64 analyses for the SoutheastCon paper (features only; no binaries).

Pre-registered before running (9 Nov 2026):
1. Behaviour tags as a second, capa-independent reference. EMBER2024 'behavior' tags come from AV labels. For each tag we fix in
   advance the Quasar techniques that should fire, and report the fire rate on malicious files carrying the tag vs malicious files
   without it (lift), next to capa's rate for the same techniques. Mapping (any listed technique counts):
     keylogger -> T1056; ransom -> T1486; downloader, dropper, loader -> T1105; injector -> T1055;
     stealer, passwordstealer, spyware -> T1003, T1056, T1113, T1115; backdoor, remoteshell -> T1059, T1071;
     autorun, worm -> T1547; coinminer -> T1071.
2. Packing: malicious files with a protector/packer tag vs without: import counts, rule firing, agreement with capa, score and
   classifier detection.
3. Weekly drift: per test week, classifier AUC, score AUC, and F1 against capa for the four best rules.
4. Families: the ten largest families: classifier detection at 0.5, median score, and the most frequent Quasar technique.
Arrays from win64_ml.npz / win64_score.npz are in the same file order (sorted glob, line order).
Usage: python -I eval/ext_eval.py <dir with *.jsonl> <out.json>
"""
from pathlib import Path as _P; _ROOT = _P(__file__).resolve().parent.parent
import glob, json, re, sys
from collections import Counter, defaultdict
import numpy as np
from sklearn.metrics import roc_auc_score
sys.path.insert(0, str(_ROOT))
from quasar import capabilities

TID = re.compile(r"\[(T\d{4})(?:\.\d{3})?\]")
MAP = {"keylogger": {"T1056"}, "ransom": {"T1486"}, "downloader": {"T1105"}, "dropper": {"T1105"}, "loader": {"T1105"},
       "injector": {"T1055"}, "stealer": {"T1003", "T1056", "T1113", "T1115"}, "passwordstealer": {"T1003", "T1056", "T1113", "T1115"},
       "spyware": {"T1003", "T1056", "T1113", "T1115"}, "backdoor": {"T1059", "T1071"}, "remoteshell": {"T1059", "T1071"},
       "autorun": {"T1547"}, "worm": {"T1547"}, "coinminer": {"T1071"}}
BEST = ["T1083", "T1115", "T1056", "T1059"]

def f1(tp, fp, fn):
    P = tp / (tp + fp) if tp + fp else 0; R = tp / (tp + fn) if tp + fn else 0
    return 2 * P * R / (P + R) if P + R else 0

ml = np.load(str(_ROOT / "eval" / "results" / "win64_ml.npz")); sc = np.load(str(_ROOT / "eval" / "results" / "win64_score.npz"))
P, S = ml["score"], sc["score"]
recs = []
i = 0
for fp in sorted(glob.glob(f"{sys.argv[1]}/*.jsonl")):
    for line in open(fp):
        o = json.loads(line)
        if o.get("label") not in (0, 1): continue
        imps = [f for funcs in (o.get("imports") or {}).values() for f in funcs if isinstance(f, str)]
        q = {h["attck_id"].split(".")[0] for h in capabilities.evaluate(imps, "")}
        c = {m.group(1) for t in (o.get("ttps") or []) for m in [TID.search(t.get("Technique", ""))] if m}
        assert int(ml["y"][i]) == o["label"] == int(sc["y"][i])
        recs.append(dict(y=o["label"], wk=o.get("week_id"), q=q, c=c, nimp=len(imps), beh=set(o.get("behavior") or []),
                         packed=bool(o.get("packer")), fam=o.get("family"), p=float(P[i]), s=float(S[i])))
        i += 1
assert i == len(P)
mal = [r for r in recs if r["y"] == 1]
res = {"n": len(recs)}

# 1. behaviour tags
beh = {}
for tag, T in MAP.items():
    a = [r for r in mal if tag in r["beh"]]; b = [r for r in mal if tag not in r["beh"]]
    if len(a) < 30: continue
    qa = np.mean([bool(r["q"] & T) for r in a]); qb = np.mean([bool(r["q"] & T) for r in b])
    ca = np.mean([bool(r["c"] & T) for r in a]); cb = np.mean([bool(r["c"] & T) for r in b])
    beh[tag] = dict(n=len(a), techniques=sorted(T), quasar_tagged=round(qa, 3), quasar_untagged=round(qb, 3),
                    quasar_lift=round(qa / qb, 2) if qb else None, capa_tagged=round(ca, 3), capa_untagged=round(cb, 3),
                    capa_lift=round(ca / cb, 2) if cb else None)
res["behaviour"] = beh

# 2. packing
def grp(rs):
    out = dict(n=len(rs), median_imports=float(np.median([r["nimp"] for r in rs])),
               zero_imports=round(np.mean([r["nimp"] == 0 for r in rs]), 3),
               any_quasar=round(np.mean([bool(r["q"]) for r in rs]), 3), any_capa=round(np.mean([bool(r["c"]) for r in rs]), 3),
               median_score=float(np.median([r["s"] for r in rs])), clf_tpr=round(np.mean([r["p"] >= 0.5 for r in rs]), 4))
    tp = fp = fn = 0
    for r in rs:
        for t in BEST: tp += (t in r["q"]) and (t in r["c"]); fp += (t in r["q"]) and (t not in r["c"]); fn += (t in r["c"]) and (t not in r["q"])
    out["f1_best4_pooled"] = round(f1(tp, fp, fn), 3); return out
res["packing"] = {"packed_malicious": grp([r for r in mal if r["packed"]]), "unpacked_malicious": grp([r for r in mal if not r["packed"]]),
                  "benign": grp([r for r in recs if r["y"] == 0])}

# 3. weekly drift
wk = defaultdict(list)
for r in recs: wk[r["wk"]].append(r)
drift = {}
for w in sorted(wk):
    rs = wk[w]; y = np.array([r["y"] for r in rs])
    d = dict(n=len(rs), clf_auc=round(roc_auc_score(y, [r["p"] for r in rs]), 4), score_auc=round(roc_auc_score(y, [r["s"] for r in rs]), 4))
    for t in BEST:
        tp = sum((t in r["q"]) and (t in r["c"]) for r in rs); fp = sum((t in r["q"]) and (t not in r["c"]) for r in rs)
        fn = sum((t in r["c"]) and (t not in r["q"]) for r in rs); d[f"f1_{t}"] = round(f1(tp, fp, fn), 3)
    drift[str(w)] = d
res["weekly"] = drift

# 4. families
fams = Counter(r["fam"] for r in mal if r["fam"])
fam = {}
for f, n in fams.most_common(10):
    rs = [r for r in mal if r["fam"] == f]; qc = Counter(t for r in rs for t in r["q"])
    fam[f] = dict(n=n, clf_tpr=round(np.mean([r["p"] >= 0.5 for r in rs]), 4), median_score=float(np.median([r["s"] for r in rs])),
                  packed=round(np.mean([r["packed"] for r in rs]), 3), top_quasar=[(t, round(k / n, 2)) for t, k in qc.most_common(3)],
                  any_capa=round(np.mean([bool(r["c"]) for r in rs]), 3))
res["families"] = fam
json.dump(res, open(sys.argv[2], "w"), indent=1); print(json.dumps(res, indent=1))
