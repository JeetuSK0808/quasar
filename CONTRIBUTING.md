# Contributing to Quasar

Thanks for your interest. Quasar is a small, focused static malware analyzer, and
contributions that keep it that way are very welcome.

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e .
pytest -q          # runs the smoke tests
```

The optional ML second opinion lives in a separate conda env; see the README
(`scripts/setup_ml.sh`). You don't need it to work on the core analyzer.

## Ground rules

- **Never commit samples.** No real or test malware binaries in the repo. The
  smoke tests build a synthetic minimal PE and synthetic import lists in memory —
  follow that pattern for new tests (see `tests/test_smoke.py`).
- **Static only.** Quasar parses; it never executes a sample. Contributions must
  preserve that guarantee.
- **Evidence over verdicts.** Every capability or score point must be traceable to
  concrete, inspectable evidence (an import, a string, a section trait). No
  opaque heuristics.
- Keep dependencies minimal and free. The core depends only on `pefile`, `rich`,
  and `mcp`; `yara-python` is an optional extra.

## Submitting changes

1. Open an issue describing the change first for anything non-trivial.
2. Keep pull requests focused; add or update a smoke test when you change behavior.
3. Make sure `pytest -q` passes.

## Scope

Good fits: new capability rules (with the imports/strings that justify them and a
note on precision), more file formats (ELF, Office, scripts), IOC extractors,
report/output improvements, and parser hardening. If you're unsure whether
something fits, open an issue and ask.
