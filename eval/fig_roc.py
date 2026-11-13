"""ROC curves on EMBER2024 Win64 test: bundled EMBER2024 classifier vs Quasar's transparent score (and without three noisy rules)."""
from pathlib import Path as _P; _ROOT = _P(__file__).resolve().parent.parent
import numpy as np, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import roc_curve, roc_auc_score
R = str(_ROOT / "eval" / "results") + "/"
plt.rcParams.update({"font.family": "serif", "font.size": 8, "axes.edgecolor": "#888888", "axes.linewidth": 0.6, "pdf.fonttype": 42})
fig, ax = plt.subplots(figsize=(3.4, 2.5))
for f, key, lab, col, ls in (("win64_ml.npz", "score", "EMBER2024 classifier", "#2B4C7E", "-"),
                             ("win64_score_drop.npz", "score", "score, 3 noisy rules removed", "#B5562F", "--"),
                             ("win64_score.npz", "score", "transparent score", "#6B8E23", ":")):
    d = np.load(R + f); y, s = d["y"], d[key]; fpr, tpr, _ = roc_curve(y, s)
    ax.plot(fpr, tpr, color=col, ls=ls, lw=1.4, label=f"{lab} (AUC {roc_auc_score(y, s):.4f})")
ax.plot([0, 1], [0, 1], color="#BBBBBB", lw=0.6)
ax.set_xlabel("False-positive rate (benign files)", fontsize=7); ax.set_ylabel("True-positive rate (malicious files)", fontsize=7)
for sp in ("top", "right"): ax.spines[sp].set_visible(False)
ax.legend(fontsize=6.2, frameon=False, loc="lower right")
fig.tight_layout(); fig.savefig(str(_ROOT / "eval" / "results" / "fig_roc.pdf")); fig.savefig(R + "fig_roc_preview.png", dpi=200)
print("ok")
