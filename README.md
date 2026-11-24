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
python cli.py <file> [more-files...] [--quarantine] [--clamav] [--json]
python scanner/guard.py <file> [--quarantine] [--clamav] [--json]
python cli.py --restore <uuid> [--restore-to PATH] [--overwrite] [--dry-run] [--json]
```

- `--quarantine` moves `BLOCK`/`QUARANTINE` files into `quarantine/` with a UUID-based name and `.json` sidecar.
- `--restore` verifies the payload SHA-256 against its sidecar before restoring; the sidecar is retained and updated as evidence.
- `--restore-to` overrides the recorded original path. `--overwrite` backs up an existing destination. `--dry-run` previews without moving files.
- `--clamav` enables the optional ClamAV check for this run.
- `--json` prints scan or restore results as JSON.
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
- Bounded in-memory ZIP member inspection: text/script persistence indicators, base64 UTF-8/UTF-16LE decoding, Shannon entropy, OOXML media skipping, and nested archives
- Persistence indicator scanning for `schtasks`, `/create`, `/sc onlogon`, `Environment.ProcessPath`, `%~f0`, `SENTINEL-Agent`, and `--run-agent`
- Policy-driven deobfuscation thresholds and custom rules in `policy/default_policy.yaml`
- Explicit SHA-256-verified quarantine restore by UUID; sidecars are never purged automatically
- Optional YARA rule scanning from `rules/`
- Optional ClamAV scanning in the shared core pipeline (GUI and CLI)
- Quarantine, JSON reports, logs, and scan history

If an enabled YARA, ZIP, or ClamAV check cannot complete, the result fails closed as `QUARANTINE` rather than `ALLOW`.

## Optional ClamAV check

ClamAV is installed separately from Python and is off by default. Enable it for
one CLI run with `--clamav`, or for both entry points by copying
`config.ini.example` to `config.ini` and setting `enabled = true`. Leave the two
executable paths empty to auto-discover `clamdscan`/`clamscan` on PATH and in the
standard Windows install directory; `clamdscan` is preferred, with `clamscan` as
a fallback.

Virus signatures must be installed separately with `freshclam`. Without them,
the check fails closed with `QUARANTINE` and explains that signatures are
missing. Detections produce `BLOCK`, and errors or timeouts produce `QUARANTINE`;
a locally blocked file is never downgraded. `config.ini` is gitignored — never
commit local paths or settings.

## Bounded heuristics and ZIP members

Raw files are sampled statically (up to 1 MiB) and ZIP payloads are read with a
32 MiB cap. The shared engine scans for persistence strings, decodes bounded
base64 UTF-8/UTF-16LE segments, and flags high Shannon entropy using thresholds
from `policy/default_policy.yaml`. Entropy checks skip known container/media
magic so compressed or image formats are not misclassified by raw byte entropy.

ZIP members are inspected in memory only, never extracted to disk. Text/script
members are checked for the same indicators; OOXML media assets are skipped;
nested ZIPs are inspected up to `max_archive_depth`. Findings are attributed to
the full member path (for example, `inner.zip>payload.ps1`). Corrupt, encrypted,
oversized, or unreadable members fail closed as `QUARANTINE`.

Scan results include `deobfuscation` and `archive_inspection` objects with
findings and the verdict each check recommended. Higher-severity verdicts are
never downgraded by later checks.

## Quarantine restore

Restoration is explicit and auditable. Find the UUID in the quarantine sidecar
filename or scan result, then run:

```bash
python cli.py --restore <uuid> --json
python cli.py --restore <uuid> --dry-run --json
python cli.py --restore <uuid> --restore-to "C:\Users\me\Downloads\file.txt" --overwrite --json
```

The payload SHA-256 must match the sidecar. Restores to the recorded original
path by default, refuse destinations inside `quarantine/`, and require
`--overwrite` when the target exists; an existing target is backed up, not
deleted. The sidecar stays in quarantine with `restored_at_utc`,
`restored_to`, and `restore_verified_sha256`. There is no automatic purge.

## Test Set

Tracked fixtures live in `tests/fixtures/`. Useful samples include:

- `safe.txt`, `safe.pdf`, `safe.png` for allowed files
- `fake-image.jpg.exe` for double-extension and extension-mismatch detection
- `archive-with-exe.zip`, `archive-nested.zip`, `path-traversal.zip`, `corrupt.zip` for ZIP checks
- `AgentInstaller.cs` for persistence indicators

`AgentInstaller.cs` is an indicator sample (source code), not a compiled PE.
Additional tests cover deobfuscation heuristics, ZIP member inspection,
quarantine restore, and CLI restore output.

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
├── config.ini.example
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
- ZIP inspection reads bounded member bytes in memory; it does not extract or execute archive contents.
- Persistence heuristics cover common source/binary strings and bounded base64 UTF-8/UTF-16LE; other packing or encryption may evade detection.
- Restore is deliberately manual and requires UUID plus SHA-256 verification; there is no automatic cleanup.

---

**Built with Python 3.13 · YARA 4.5.4 · Powered by the same security mindset that drives Sentinel and Bulwark.**
