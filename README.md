# Quasar

[![tests](https://github.com/JeetuSK0808/quasar/actions/workflows/ci.yml/badge.svg)](https://github.com/JeetuSK0808/quasar/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**A static malware analyzer that tells you what a sample *does* — not just whether it's bad.**

Point Quasar at a file and it returns an explained report: a risk verdict with its reasons, the
sample's capabilities mapped to **MITRE ATT&CK** (each with the concrete evidence that triggered
it), the indicators it embeds (URLs, IPs, domains, registry keys, paths), its PE structure, and an
import-hash fingerprint you can pivot on to find related samples. It's an *analyst in a box*: one run
tells you what a sample does, who it's related to, and what to worry about.

Quasar **parses** samples. It never executes them.

*TQG Research — infrastructure for security researchers.*

## Why
The good tools are fragmented and expert-only: one does detection, one does capabilities, one does
unpacking; VirusTotal is a closed box that gives verdicts but not *what a sample does*, and Ghidra
needs an expert. Quasar is the open, one-command layer that hands a researcher a complete, explained,
trustworthy picture — locally, for free, with nothing uploaded.

## Install
```bash
pip install quasar-malware     # once released; the command and import are `quasar`
```
From source:
```bash
python -m venv .venv && . .venv/bin/activate
pip install -e .
```

## Use
```bash
python -m quasar analyze sample.bin      # rendered report
python -m quasar analyze sample.bin --json   # structured JSON for a pipeline
python -m quasar sample.bin              # shorthand
```

### With an AI agent (MCP)
Quasar ships as an MCP server, so Claude Code and other agents can call it natively:
```bash
python -m quasar serve
```
It exposes one tool, `analyze_file(path, intel=false)`, returning the full JSON report.

## Example
Illustrative report for a malicious sample (`quasar analyze sample.exe`):
```text
╭───────────────────── QUASAR ─────────────────────╮
│ sample.exe    PE    412,160 bytes    entropy 7.2  │
│  HIGH-RISK  100/100                               │
╰───────────────────────────────────────────────────╯
ML classifier (EMBER2024)   P(malicious) = 98.1%  →  MALICIOUS

Capabilities — MITRE ATT&CK
  Process injection          T1055       VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
  Credential access (LSASS)  T1003.001   MiniDumpWriteDump
  Persistence (Run key)      T1547.001   '\CurrentVersion\Run'
  Network / C2               T1071       InternetOpen, HttpSendRequest
  Anti-debugging             T1622       IsDebuggerPresent

Indicators: 3 urls, 1 ip, 1 domain, 1 registry key
Why this score: injection + anti-analysis combo (+12), high-entropy section (+10), ...
```
Every capability lists the exact evidence that triggered it, and the sample is parsed, never executed.

## What it does
- **File triage** — type, size, entropy, MD5/SHA-1/SHA-256.
- **PE analysis** — headers, sections (entropy → packing), imports/exports, imphash, TLS callbacks.
- **Capabilities → ATT&CK** — injection, persistence, keylogging, credential access, C2, download-&-exec,
  ransomware-style encryption, anti-debug/anti-VM, and more — each with its evidence.
- **YARA signatures** — scans against bundled original rules (and any repo you point `QUASAR_YARA_RULES`
  at); matches appear in the report and feed the score. Needs `yara-python` (`pip install quasar-malware[yara]`).
- **IOCs** — URLs, IPs, domains, emails, registry keys, Windows/env paths, crypto-wallet addresses.
- **Transparent score** — a 0–100 risk band where every point is attributable to a stated reason.
- **ML second opinion (optional)** — the EMBER2024 PE benchmark classifier reports a maliciousness
  probability *alongside* the heuristic score (see below).
- **Plain-language assessment** — grounded entirely in the findings above.

## ML classifier (EMBER2024)
An optional second opinion: the official **EMBER2024** PE benchmark model (LightGBM), run through the
`thrember` feature extractor so inference features match the model's training features exactly (EMBER
feature version 3). It reports a maliciousness **probability**, shown *alongside* — never merged into —
the explainable heuristic score, so the two signals stay independent.

On the held-out EMBER2024 test set the classifier separates malware from benign very well: **AUC
0.9985** on 240,000 Win64 PE files (98.4% accuracy at the default threshold) and **AUC 0.9983** on
720,000 Win32 files (98.1%). The result JSONs and the scripts that produce them are in [`eval/`](eval/).
For a quick one-command check, `.venv-ml/bin/python scripts/validate.py` downloads the EMBER2024 .NET
test split and prints AUC/accuracy itself (~0.997 AUC).

The **transparent heuristic score is built for explainability, not raw detection** — on the same Win64
set it separates malware from benign at only **AUC ≈ 0.66**. That's exactly why both are shown: the ML
model carries the detection signal, the heuristic score carries the attributable, inspectable reasons.
They are reported side by side and never merged.

It needs a small extra env (LightGBM's OpenMP comes from conda-forge, so no Homebrew needed):
```bash
bash scripts/setup_ml.sh                      # conda env (.venv-ml) + 3.8 MB model
.venv-ml/bin/python -m quasar analyze <sample>
```
Without this env Quasar still runs; the report just omits the ML line.

## Design principles
- **Evidence over verdicts.** Every finding shows exactly what produced it; no black-box guesses.
- **Safe by construction.** Static only — the sample is read and parsed, never run.
- **Local and free.** No cloud upload, no paid APIs. Online threat-intel is opt-in and privacy-safe
  (it would send only a hash/IOC, never the sample), and is off by default.

## Roadmap
- **Safe emulation** of a sample inside a simulated machine (Qiling/Unicorn-style) — observe behavior
  without a real detonation VM.
- **More ML** — a custom model trained on EMBER2024 (beyond the integrated benchmark model) + malware
  family classification.
- **Online intel** — hash + IOC reputation via free abuse.ch feeds (MalwareBazaar / ThreatFox).
- More formats (ELF, Office/scripts) and a `capa`-rule bridge.

## Safety & scope
Quasar is a defensive research tool. It analyzes and explains malware; it does not create, modify, or
run it. Do not commit samples to the repo (`.gitignore` blocks common binary types and `samples/`).
See [SECURITY.md](SECURITY.md) for safe-handling and vulnerability-reporting guidance.

## Contributing & license
Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Quasar is released under the
[MIT License](LICENSE).
