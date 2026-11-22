# AttachmentGuard

![Yara](https://img.shields.io/badge/YARA-rule-important?style=for-the-badge) ![Bulwark](https://img.shields.io/badge/Bulwark-website-important?style=for-the-badge) ![Python](https://img.shields.io/badge/Python-3.13-important?style=for-the-badge) ![PHP2Shell](https://img.shields.io/badge/PHP2Shell-security-important?style=for-the-badge) ![C-Sharp](https://img.shields.io/badge/C%23-.NET-important?style=for-the-badge)

## Purpose

AttachmentGuard is a local, defensive static file-analysis gate. It never executes a scanned file. It is designed to be the first checkpoint for downloads, email attachments, and files found on removable media.

It belongs to a different layer than the C# agent (`AgentInstaller.cs` / `Sentinel.Agent.exe`). While the agent handles installation persistence, AttachmentGuard performs pre-execution inspection and explains every decision.

## Verdicts

- `ALLOW` — Safe under current policy
- `WARN` — Potentially risky; user should confirm
- `QUARANTINE` — Suspicious; isolate for review
- `BLOCK` — Dangerous or policy-violating

Verdict precedence is `BLOCK > QUARANTINE > WARN > ALLOW`. A later check can raise a verdict but never lower it.

## How It Fits the Security Ecosystem

| Project | Role | Relationship |
|---|---|---|
| **Bulwark** | Static website + data pipeline | Provides vulnerability assessment pages, ATT&CK coverage maps, and PHP2Shell detection resources |
| **Sentinel** | C# endpoint agent | Handles installation persistence, event collection, detection, reporting, and response |
| **AttachmentGuard** | Standalone Python file gate | Inspects files statically; outputs verdict + report; can be called from C# or run independently |
| **PHP2Shell** | Critical vulnerability research | The initial trigger that prompted this work; now covered by the rule and report |

## Entry Points

Both entry points use the same `core/` engine, policy file, and report format.

### CLI / static gate

```bash
python cli.py <file> [more-files...] [--quarantine] [--json]
python scanner/guard.py <file> [--quarantine] [--json]
```

- `--quarantine` moves `BLOCK`/`QUARANTINE` files into `quarantine/` with a UUID-based name and `.json` sidecar.
- `--json` prints the scan results as JSON.
- Reports are written to `reports/<yyyy-mm-dd>/<sha256>.json`.

### Desktop GUI

```bash
python main.py
```

Select a folder to monitor. New and existing files are scanned in a worker thread, shown in a table, quarantined when required, and recorded in the local scan history.

## Shared Engine

`core/` is the only implementation of scanning logic. `scanner/` modules are compatibility wrappers for older imports. The shared services provide:

- SHA-256 hashing and file size checks
- Extension allow/block policy from `policy/default_policy.yaml`
- Magic-byte file-type detection and extension mismatch checks
- Non-extracting ZIP inspection with entry-count, depth, double-extension, and compression-ratio checks
- Persistence indicator scanning for `schtasks`, `/create`, `/sc onlogon`, `Environment.ProcessPath`, `%~f0`, `SENTINEL-Agent`, and `--run-agent`
- Optional YARA rule scanning from `rules/`
- Optional ClamAV scanning in the desktop worker
- Quarantine, JSON reports, logs, and scan history

If an enabled YARA, ZIP, or ClamAV check cannot complete, the result fails closed as `QUARANTINE` rather than `ALLOW`.

## Test Set

Tracked fixtures live in `tests/fixtures/`. Useful samples include:

- `safe.txt`, `safe.pdf`, `safe.png` for allowed files
- `fake-image.jpg.exe` for double-extension and extension-mismatch detection
- `archive-with-exe.zip`, `archive-nested.zip`, `path-traversal.zip`, `corrupt.zip` for ZIP checks
- `AgentInstaller.cs` for persistence indicators

`AgentInstaller.cs` is an indicator sample (source code), not a compiled PE.

## Usage From C#

```csharp
Process.Start("python", "\"" + guardPath + "\" \"" + filePath + "\" --json")
```

Parse the JSON verdict, reasons, hash, and report path from stdout.

## Directory Layout

```text
AttachmentGuard/
├── main.py                 # PyQt6 desktop entry point
├── cli.py                  # CLI/static-gate entry point
├── scanner/                # Compatibility wrappers around core/
├── core/                   # Shared scanning and policy services
├── workers/                # PyQt worker and scan manager
├── ui/                     # Qt table model
├── rules/                  # YARA rules
├── policy/                 # Shared policy YAML
├── tests/                  # Tests and fixtures
├── quarantine/             # Isolated suspicious files
├── reports/                # Generated JSON reports
├── .gitignore
├── README.md
├── AGENTS.md
└── requirements.txt
```

## Development

Install dependencies from the project virtual environment, then run:

```bash
python -m pytest -q
python cli.py "tests/fixtures/safe.txt" "tests/AgentInstaller.cs" --json
```

Dependencies are `yara-python`, `PyYAML`, `PyQt6`, and `pytest`. YARA rules are optional; if `rules/` has no `.yar` or `.yara` files, the shared engine skips YARA.

## Limitations

- Does not execute files; it only inspects them.
- YARA rules are hand-crafted and tuned for the current sample set.
- ZIP inspection looks at entry names and metadata; it does not emulate archive contents.
- Persistence heuristics are based on source-code and binary-string patterns; obfuscated code may evade detection.

---

**Built with Python 3.13 · YARA 4.5.4 · Powered by the same security mindset that drives Sentinel and Bulwark.**
