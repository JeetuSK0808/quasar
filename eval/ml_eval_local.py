"""Score Quasar's bundled EMBER2024 PE model on local EMBER2024 raw-feature files (same vectorizer as training).
Usage: .venv-ml/bin/python -I eval/ml_eval_local.py <dir with *.jsonl> <out.json>"""
from pathlib import Path as _P; _ROOT = _P(__file__).resolve().parent.parent
import glob, json, sys
import numpy as np, lightgbm as lgb, thrember
from sklearn.metrics import roc_auc_score
ex = thrember.PEFeatureExtractor(); model = lgb.Booster(model_file=str(_ROOT / "models" / "ember2024_malware.model"))
X, y = [], []
for fp in sorted(glob.glob(f"{sys.argv[1]}/*.jsonl")):
    for line in open(fp):
        raw = json.loads(line)
        if raw.get("label") in (0, 1):
            X.append(ex.process_raw_features(raw)); y.append(raw["label"])
X, y = np.asarray(X, dtype=np.float32), np.asarray(y); p = model.predict(X)
fpr_at = {}
for thr in (0.5, 0.9):
    pred = p >= thr; fpr_at[str(thr)] = {"tpr": round(float(pred[y == 1].mean()), 4), "fpr": round(float(pred[y == 0].mean()), 4)}
res = {"n": int(len(y)), "malicious": int((y == 1).sum()), "benign": int((y == 0).sum()), "auc": round(float(roc_auc_score(y, p)), 4),
       "acc@0.5": round(float(((p >= 0.5).astype(int) == y).mean()), 4), "at_threshold": fpr_at}
np.savez_compressed(sys.argv[2].replace('.json', '.npz'), y=y, score=p); json.dump(res, open(sys.argv[2], "w"), indent=1); print(res)
