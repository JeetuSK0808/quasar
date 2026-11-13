#!/bin/bash
# Set up Quasar's optional ML env.
# Uses conda (miniforge) because LightGBM's OpenMP runtime (libomp) comes from conda-forge —
# no Homebrew needed. Creates .venv-ml/ in the repo root (gitignored).
set -e
CONDA="${CONDA:-$HOME/miniforge3/bin/conda}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV="$ROOT/.venv-ml"

"$CONDA" create -y -p "$ENV" -c conda-forge python=3.11 "lightgbm>=4.5" numpy scikit-learn
"$ENV/bin/pip" install -q pefile rich mcp polars tqdm "signify==0.7.1" huggingface_hub matplotlib
# thrember = EMBER2024 feature extractor (feature version 3). --no-deps so the conda LightGBM is kept.
"$ENV/bin/pip" install -q --no-deps "git+https://github.com/futurecomputing4ai/ember2024.git"
# download the benchmark PE model into models/
"$ENV/bin/python" "$ROOT/scripts/download_model.py"

echo "ML env ready: $ENV"
echo "Run Quasar with it:  $ENV/bin/python -m quasar analyze <sample>"
