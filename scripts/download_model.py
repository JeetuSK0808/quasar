"""Download the EMBER2024 PE benign/malicious benchmark model into models/.

~3.8 MB. Source: the official EMBER2024 benchmark models (CrowdStrike / FutureComputing4AI).
The matching feature extractor is `thrember` (installed by setup_ml.sh), so the model's training
features and Quasar's inference features are the same (feature version 3)."""
import os
import shutil
from pathlib import Path

from huggingface_hub import hf_hub_download

ROOT = Path(__file__).resolve().parent.parent
MODELS = ROOT / "models"
MODELS.mkdir(exist_ok=True)
DST = MODELS / "ember2024_malware.model"

if DST.exists():
    print("already present:", DST)
else:
    src = hf_hub_download(
        repo_id="joyce8/EMBER2024-benchmark-models",
        repo_type="model",
        filename="EMBER2024_PE.model",
    )
    shutil.copy(src, DST)
    print("saved", DST, os.path.getsize(DST), "bytes")
