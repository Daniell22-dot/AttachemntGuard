# AttachmentGuard (MVP)

![Yara](https://img.shields.io/badge/YARA-rule-important?style=for-the-badge) ![Bulwark](https://img.shields.io/badge/Bulwark-website-important?style=for-the-badge) ![Python](https://img.shields.io/badge/Python-3.13-important?style=for-the-badge) ![PHP2Shell](https://img.shields.io/badge/PHP2Shell-security-important?style=for-the-badge) ![C-Sharp](https://img.shields.io/badge/C%23-.NET-important?style=for-the-badge)

## Purpose

AttachmentGuard is a **static file-analysis gate** that never executes a file. It is designed to be the first defensive checkpoint for any file a user or system encounters — especially files downloaded from the internet, received as attachments, or found on removable media.

It belongs to a different layer than the C# agent (`AgentInstaller.cs` / `Sentinel.Agent.exe`). While the agent handles **installation persistence** (creating a scheduled task to start at logon), AttachmentGuard performs **pre-execution inspection** — determining whether a file is safe, suspicious, or dangerous before it is ever run.

## Verdicts

- `ALLOW` — Safe under current policy
- `WARN` — Potentially risky; user should confirm
- `QUARANTINE` — Suspicious; isolate for review
- `BLOCK` — Dangerous or policy-violating

## How It Fits the Security Ecosystem

| Project | Role | Relationship |
|---|---|---|
| **Bulwark** | Static website + data pipeline | Provides vulnerability assessment pages, ATT&CK coverage maps, and PHP2Shell detection resources |
| **Sentinel** | C# endpoint agent | Handles installation persistence, event collection, detection, reporting, and response |
| **AttachmentGuard** | Standalone Python file gate | Inspects files statically; outputs verdict + report; can be called from C# or run independently |
| **PHP2Shell** | Critical vulnerability research | The initial trigger that prompted this work; now covered by the rule and report |

## Usage

```bash
python scanner/guard.py <file> [--quarantine] [--json]
```

- `--quarantine`: Move suspicious/blocked files to the `quarantine/` folder with metadata
- `--json`: Output JSON instead of human-readable summary

## MVP Features

1. **SHA-256 hash** + size computation
2. **Extension allowlist/blocklist** (`.exe`, `.scr`, `.msi`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.js`, `.jar`, `.hta` blocked by default; `.pdf`, `.png`, `.jpg`, `.docx`, `.xlsx`, `.csv`, `.txt` allowed)
3. **Magic-byte sniffing** (detect real file type regardless of extension; e.g., `invoice.pdf.exe` → `BLOCK` for double‑extension)
4. **ZIP inspection** (list entries without extracting; detect executables/scripts inside ZIPs; enforce entry-count, compression-ratio, and nesting limits)
5. **Persistence indicator scan** (search source text and binary strings for: `schtasks`, `/create`, `/sc onlogon`, `Environment.ProcessPath`, `%~f0`, `SENTINEL-Agent`, `--run-agent`)
6. **Quarantine** (move blocked/quarantined files to `quarantine/` with a UUID‑based name + `.meta.json` containing original path, verdict, reasons, timestamp)
7. **JSON report** in `reports/` with file hash, size, verdict, matched rules, timestamp, and quarantine path if applicable

## Test Set (example files to create)

- `tests/safe.txt`, `tests/safe.pdf` (or dummy files)
- `tests/fake-image.jpg.exe` — double‑extension EXE masquerade
- `tests/archive-with-exe.zip` — ZIP containing `bad.exe`
- `tests/AgentInstaller.cs` — source code (will flag persistence strings like `schtasks`, `/create`, `/sc onlogon`, `Environment.ProcessPath`, `SENTINEL-Agent`)

`AgentInstaller.cs` is treated as an **indicator sample** (source code), not a compiled PE. A compiled binary with the same patterns would be caught by magic bytes + YARA.

## How to Integrate

- **As a Python CLI**: `python scanner/guard.py <file>`
- **From C#**: `Process.Start("python", "\"" + guardPath + "\" \"" + filePath + "\" --json")` and parse the JSON output
- **As a GitHub Action** (see `.github/workflows/ci.yml`) — runs guard against test files on every push

## Directory Layout

```
AttachmentGuard/
├── scanner/          # Core engine (hash, magic, policy, persistence, ZIP, quarantine, YARA)
├── rules/            # YARA persistence rules (persistence.yar)
├── cli.py            # CLI entry-point
├── tests/            # Test fixtures
├── quarantine/       # Isolated suspicious files
├── reports/          # Generated JSON reports
├── .gitignore
├── README.md
├── requirements.txt
└── setup.py (optional)
```

## How This Differs from AgentInstaller.cs

| Aspect | AgentInstaller.cs | AttachmentGuard |
|---|---|---|
| **Purpose** | Creates Windows scheduled‑task persistence | Static file‑gate; never executes the file |
| **What it does** | `schtasks /create /sc onlogon /tr "<exe>" /f` | Hash, magic‑bytes, extension policy, ZIP inspection, persistence‑indicator heuristics, YARA |
| **Output** | Task created; agent starts at logon | Verdict (`ALLOW`/`WARN`/`QUARANTINE`/`BLOCK`) + JSON report |
| **When used** | During agent deployment / installer | During file ingestion / email attachment scanning / media scanning |
| **Coupling** | Part of the C# agent solution | Independent Python project; can be used without touching the C# codebase |

## Limitations

- Does **not** execute files — it only inspects them
- YARA rules are hand‑crafted and tuned for the current sample set; new patterns may need rule updates
- ZIP inspection looks at entry names and basic content; it does not emulate the ZIP contents
- Persistence heuristics are based on source‑code and binary‑string patterns; obfuscated code may evade detection

## Contact & Contributing

- Add new YARA rules under `rules/`
- Add new test fixtures under `tests/`
- Extend `scanner/policy.py` for additional extension rules
- Fork, then submit a pull request

---

**Built with Python 3.13 · YARA 4.5.4 · Powered by the same security mindset that drives Sentinel and Bulwark.**