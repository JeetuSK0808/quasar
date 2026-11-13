"""Optional YARA signature scanning. Compiles rules from the bundled `rules/` directory plus any
directory in QUASAR_YARA_RULES (point this at an open rule repo for broader coverage), and reports
matches. Guarded import so Quasar's core runs fine without yara-python installed."""
from __future__ import annotations
import os
from pathlib import Path

_RULES = None
_TRIED = False
_RULES_DIR = Path(__file__).resolve().parent / "rules"


def _load():
    global _RULES, _TRIED
    if _TRIED:
        return _RULES
    _TRIED = True
    try:
        import yara
    except Exception:
        return None
    filepaths = {}
    dirs = [_RULES_DIR]
    extra = os.environ.get("QUASAR_YARA_RULES")
    if extra:
        dirs.append(Path(extra))
    for d in dirs:
        if d.is_dir():
            for f in list(d.rglob("*.yar")) + list(d.rglob("*.yara")):
                filepaths[str(f)] = str(f)
    if not filepaths:
        return None
    try:
        _RULES = yara.compile(filepaths=filepaths)
    except Exception:
        _RULES = None
    return _RULES


def available() -> bool:
    return _load() is not None


def scan(data: bytes) -> list[dict]:
    """Return a list of matched rules: {rule, tags, description}. Empty if YARA/rules unavailable."""
    rules = _load()
    if rules is None:
        return []
    try:
        matches = rules.match(data=data, timeout=30)
    except Exception:
        return []
    out = []
    for m in matches:
        meta = dict(m.meta or {})
        out.append({"rule": m.rule, "tags": list(m.tags), "description": meta.get("description", "")})
    return out
