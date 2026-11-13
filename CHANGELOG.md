# Changelog

All notable changes to Quasar. This project follows [Semantic Versioning](https://semver.org/).

## [0.6.0] — Initial public release
- First public, MIT-licensed release.
- Evaluation scripts made portable (no hardcoded paths) and runnable from a clone.
- Added `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`.

Feature set at first release, summarizing earlier internal development:

- **Core static analysis** — file triage (type, size, entropy, hashes), PE parsing
  (headers, sections, imports/exports, imphash, TLS callbacks), capability detection
  mapped to **MITRE ATT&CK** (each with the evidence that triggered it), IOC
  extraction, and a transparent 0–100 risk score where every point is attributable
  to a stated reason.
- **ML second opinion (optional)** — the EMBER2024 benchmark PE classifier (LightGBM,
  `thrember` feature extractor), reported *alongside* the heuristic score, never
  merged into it.
- **Packaging** — pip-installable as `quasar-malware`; `quasar` CLI with text and
  `--json` output, `quasar --version`, and the bundled YARA rules shipped inside the
  wheel. Released to PyPI from GitHub via trusted publishing (OIDC, no stored token).
- **Shareable HTML report** — `--html` export.
- **YARA scanning** — optional, against bundled rules or a rule set you point to.
- **MCP server** — `quasar serve`, so AI agents can call `analyze_file` natively.
- **EMBER2024 evaluation** — reproducible scripts under `eval/` comparing the ML
  classifier and the transparent score, calibrating import rules against capa,
  and measuring behaviour-tag lift, packing, weekly drift, and family breakdowns.
