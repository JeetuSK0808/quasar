"""Reproducible validation of Quasar's EMBER2024 PE classifier on held-out labeled data.

Downloads an EMBER2024 PE test split, vectorizes each row with thrember's extractor (the same
features the model trained on), scores with models/ember2024_malware.model, and reports AUC +
accuracy + per-class mean probability.

Usage:  .venv-ml/bin/python scripts/validate.py [--file-type Dot_Net|Win32|Win64|PE] [--data-dir DIR]
"""
import argparse
import glob
import json
import os
from pathlib import Path

import numpy as np
import lightgbm as lgb
import thrember
from sklearn.metrics import roc_auc_score

ROOT = Path(__file__).resolve().parent.parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file-type", default="Dot_Net", choices=["Dot_Net", "Win32", "Win64", "PE"])
    ap.add_argument("--data-dir", default=str(ROOT / ".venv-ml-data"))
    ap.add_argument("--model", default=str(ROOT / "models" / "ember2024_malware.model"))
    args = ap.parse_args()

    os.makedirs(args.data_dir, exist_ok=True)
    print(f"downloading {args.file_type} test split...", flush=True)
    thrember.download_dataset(args.data_dir, split="test", file_type=args.file_type)

    files = glob.glob(os.path.join(args.data_dir, "**", "*.jsonl"), recursive=True)
    if not files:
        raise SystemExit("no raw feature files found after download")

    ex = thrember.PEFeatureExtractor()
    model = lgb.Booster(model_file=args.model)

    X, y = [], []
    for fp in files:
        with open(fp) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                raw = json.loads(line)
                if raw.get("label") not in (0, 1):
                    continue
                X.append(ex.process_raw_features(raw))
                y.append(raw["label"])

    X, y = np.asarray(X, dtype=np.float32), np.asarray(y)
    p = model.predict(X)
    res = {
        "file_type": args.file_type,
        "n": int(len(y)),
        "malicious": int((y == 1).sum()),
        "benign": int((y == 0).sum()),
        "auc": round(float(roc_auc_score(y, p)), 4),
        "acc@0.5": round(float(((p >= 0.5).astype(int) == y).mean()), 4),
        "mean_p_benign": round(float(p[y == 0].mean()), 4),
        "mean_p_malicious": round(float(p[y == 1].mean()), 4),
    }
    print("RESULT", json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
