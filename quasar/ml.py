"""Optional ML classifier: the EMBER2024 benchmark LightGBM model (feature version 3, via the
`thrember` extractor so train/inference feature spaces match exactly).

Reported ALONGSIDE the explainable heuristic score, never merged into it — two independent signals.
Requires the ML env (lightgbm + thrember) and a downloaded model; degrades gracefully when either is
absent, so Quasar's core always runs.
"""
from __future__ import annotations
import os
from pathlib import Path

_MODEL = None
_LOAD_TRIED = False
_MODEL_PATH = os.environ.get("QUASAR_ML_MODEL") or str(
    Path(__file__).resolve().parent.parent / "models" / "ember2024_malware.model"
)
_THRESHOLD = 0.5


def _load():
    global _MODEL, _LOAD_TRIED
    if _LOAD_TRIED:
        return _MODEL
    _LOAD_TRIED = True
    try:
        import lightgbm as lgb
        if os.path.exists(_MODEL_PATH):
            _MODEL = lgb.Booster(model_file=_MODEL_PATH)
    except Exception:
        _MODEL = None
    return _MODEL


def available() -> bool:
    try:
        import thrember  # noqa: F401
    except Exception:
        return False
    return _load() is not None


def classify(data: bytes, is_pe: bool) -> dict:
    """Return the ML maliciousness probability for a PE sample, or a graceful 'unavailable' note."""
    if not is_pe:
        return {"available": False, "note": "ML model applies to PE files only."}
    try:
        import thrember
    except Exception:
        return {"available": False,
                "note": "ML env not active (thrember/lightgbm unavailable); heuristic score still applies."}
    model = _load()
    if model is None:
        return {"available": False,
                "note": f"EMBER2024 model not found at {_MODEL_PATH} (run the model download)."}
    try:
        p = float(thrember.predict_sample(model, data))
    except Exception as e:
        return {"available": False, "note": f"ML inference error: {str(e)[:140]}"}
    return {
        "available": True,
        "model": "EMBER2024 benchmark (LightGBM, feature v3)",
        "malware_probability": round(p, 4),
        "verdict": "malicious" if p >= _THRESHOLD else "benign",
    }
