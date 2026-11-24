# AttachmentGuard Development Guide

## Mission

Build **AttachmentGuard**, a local, defensive file-safety application that scans
files before a user opens them, identifies suspicious attachments, quarantines
risky files, and explains every decision.

The first target is a PyQt6 desktop application for Windows that monitors a
user-selected folder, scans new files safely, displays results, and quarantines
files that violate policy.

This project must remain **defensive only**. It must never execute unknown
samples, disable security controls, conceal its activity, exfiltrate user data,
or provide offensive exploitation capability.

## Authoritative stack decision (2026-11-22)

Both entry points are supported and share the same engine:

- `main.py` is the PyQt6 desktop entry point.
- `cli.py` and `scanner/guard.py` are the CLI/static-gate entry points.
- `core/` is the single source of truth for policy, hashing, magic-byte
  detection, ZIP inspection, bounded archive member inspection, deobfuscation
  heuristics, persistence indicators, YARA, quarantine, reporting, scan
  history, and verdicts.
- `scanner/` contains compatibility wrappers around `core/`; it must not
  implement a second scanning pipeline.
- `README.md` is the user-facing documentation for both entry points.
- ClamAV and YARA are optional checks. YARA runs only when rule files are
  present. ClamAV is off by default and runs only when a service is injected
  from `config.ini` (`enabled = true`), the GUI, or the CLI `--clamav` flag.
  Both entry points share the `core/` merge logic. If an enabled check cannot
  complete, verdicts fail closed: ClamAV detections yield `BLOCK`, while
  errors, timeouts, and missing signature databases yield `QUARANTINE`.
- Scan history is enabled for both entry points and stored outside tracked
  output directories.

Where later sections of this file describe ClamAV, YARA, or local history as
deferred, treat that as "optional and off by default"; the shared `core/`
services govern behavior.

## Non-negotiable principles

1. **Never execute scanned files.**
2. **Never run unknown samples on the developer’s main machine.**
3. **Never delete evidence automatically.** Quarantine first.
4. **Never block the PyQt GUI thread.** All file I/O, hashing, ZIP inspection,
   YARA scanning, and network reputation lookups must run in worker threads.
5. **Never update Qt widgets from a worker thread.** Emit signals; update the
   UI only in main-thread slots.
6. **Never delete a running QThread.** Use cancellation, `quit()`, and `wait()`.
7. **Never store API keys in source control.** Use environment variables or a
   local secrets file excluded by `.gitignore`.
8. **Always produce an explainable verdict.** Every `BLOCK`, `WARN`, or
   `QUARANTINE` result must include human-readable reasons.
9. **Prefer fail-closed behavior.** If a high-risk file cannot be checked, mark
   it `QUARANTINE` or `UNKNOWN`, not `ALLOW`.
10. **Keep the scanning engine independent from the UI.**

## Product scope

### MVP capabilities

Implement these before adding anything else:

1. Select a folder to monitor.
2. Detect new or changed files using `QFileSystemWatcher`.
3. Queue files for scanning.
4. Compute SHA-256 hashes.
5. Check file size and extension policy.
6. Detect the real file type using magic bytes.
7. Inspect ZIP archives without extracting them.
8. Detect executable, script, double-extension, and nested-archive risks.
9. Quarantine files that receive `BLOCK` or `QUARANTINE`.
10. Write a JSON report for every scan.
11. Display scan results in the GUI.
12. Support safe cancellation and application shutdown.
13. Optional ClamAV check, off by default and fail-closed.
14. Bounded deobfuscation and entropy heuristics for raw files and ZIP members.
15. Explicit, SHA-256-verified quarantine restore by UUID.

### Later capabilities

Do not implement these until the MVP is complete and tested:

- YARA rule scanning (implemented as an optional core check).
- VirusTotal hash-only reputation lookup.
- MalwareBazaar hash lookup.
- Office macro and OLE-object detection.
- PDF/JavaScript inspection.
- Local scan-history database.
- C#/XAML desktop dashboard.
- Optional isolated sandbox integration.

## Architecture

Use a layered architecture. UI code must not contain scanning logic.

```text
attachmentguard/
├── main.py
├── AGENT.md
├── requirements.txt
├── config.ini.example
├── .gitignore
├── ui/
│   ├── main_window.py
│   ├── scan_table_model.py
│   └── dialogs.py
├── workers/
│   ├── scan_worker.py
│   ├── folder_scan_worker.py
│   └── scan_manager.py
├── core/
│   ├── scanner.py
│   ├── clamav_service.py
│   ├── hash_service.py
│   ├── file_type_service.py
│   ├── zip_inspector.py
│   ├── archive_inspector.py
│   ├── deobfuscation_heuristics.py
│   ├── policy_service.py
│   ├── quarantine_service.py
│   └── report_writer.py
├── rules/
│   └── suspicious.yar
├── tests/
│   ├── test_hash_service.py
│   ├── test_policy_service.py
│   ├── test_zip_inspector.py
│   └── test_scanner.py
├── policy/
│   └── default_policy.yaml
├── quarantine/
├── reports/
└── logs/
```

### Layer rules

| Layer | Allowed responsibilities | Forbidden |
|---|---|---|
| `ui/` | Widgets, user actions, displaying results | File hashing, ZIP parsing, YARA, network calls |
| `workers/` | Thread lifecycle, cancellation, progress signals | Direct widget updates |
| `core/` | Pure scanning and policy logic | PyQt imports |
| `storage/` or services | Quarantine, reports, cache | UI decisions |
| `tests/` | Unit and integration tests | Network calls by default |

## PyQt threading contract

Use the worker-object pattern.

### Required worker structure

```python
from pathlib import Path

from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot


class ScanWorker(QObject):
    started = pyqtSignal(str)
    progress = pyqtSignal(int)
    finished = pyqtSignal(dict)
    failed = pyqtSignal(str)
    cancelled = pyqtSignal()

    def __init__(self, file_path: str):
        super().__init__()
        self.file_path = Path(file_path)
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    @pyqtSlot()
    def run(self):
        try:
            self.started.emit(self.file_path.name)

            result = self._scan()

            if self._cancelled:
                self.cancelled.emit()
                return

            self.finished.emit(result)

        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")

    def _scan(self) -> dict:
        # Implement hashing, policy checks, file-type checks, ZIP inspection.
        raise NotImplementedError
```

### Required manager structure

```python
from PyQt6.QtCore import QObject, QThread, pyqtSignal, pyqtSlot


class ScanManager(QObject):
    scan_started = pyqtSignal(str)
    scan_progress = pyqtSignal(str, int)
    scan_finished = pyqtSignal(dict)
    scan_failed = pyqtSignal(str, str)
    scan_cancelled = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._thread = None
        self._worker = None

    def start_scan(self, file_path: str):
        self.stop()

        self._thread = QThread(self)
        self._worker = ScanWorker(file_path)

        # Worker must not have a parent before moveToThread().
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)

        self._worker.started.connect(self.scan_started)
        self._worker.progress.connect(self.scan_progress)
        self._worker.finished.connect(self.scan_finished)
        self._worker.failed.connect(self.scan_failed)
        self._worker.cancelled.connect(self.scan_cancelled)

        self._worker.finished.connect(self._thread.quit)
        self._worker.failed.connect(self._thread.quit)
        self._worker.cancelled.connect(self._thread.quit)

        self._thread.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)

        self._thread.start()

    def stop(self):
        if self._worker is not None:
            self._worker.cancel()

        if self._thread is not None:
            self._thread.quit()
            self._thread.wait(5000)

        self._worker = None
        self._thread = None
```

### Threading rules

- A worker must have **no parent** before `moveToThread()`.
- Connect `QThread.started` to `worker.run`; never call `worker.run()` directly.
- Connect worker completion/failure/cancellation signals to `thread.quit()`.
- Connect `thread.finished` to `worker.deleteLater()`.
- Connect `thread.finished` to `thread.deleteLater()`.
- Before replacing a thread, call `worker.cancel()`, `thread.quit()`, and
  `thread.wait(timeout)`.
- Never call `QThread.terminate()`.
- Never delete a `QThread` while `thread.isFinished()` is `False`.
- Use a bounded queue or `QThreadPool` for many files; do not create unlimited
  threads.
- On an old PC, limit concurrent scans to two workers initially.
- Folder enumeration, quarantine moves, report/log writes, and history writes
  must run in worker threads before `finished` reaches the UI.

## Scan pipeline

Every file must pass through this ordered pipeline:

```text
1. Basic validation
2. Hash calculation
3. Extension policy
4. Real file-type detection
5. Archive inspection
6. Static content indicators
7. Optional AV and reputation lookups
8. Verdict decision
9. Quarantine action
10. Report generation
```

### Verdict precedence

Use the highest-severity verdict:

```text
BLOCK > QUARANTINE > WARN > ALLOW
```

A later lower-severity result must never downgrade a higher-severity verdict.

### Required result schema

Every scan must return this JSON structure:

```json
{
  "schema_version": 1,
  "file": "invoice.pdf.exe",
  "path": "C:/Users/user/Downloads/invoice.pdf.exe",
  "size_bytes": 1048576,
  "sha256": "hex-string",
  "detected_extension": ".exe",
  "detected_mime_type": "application/vnd.microsoft.portable-executable",
  "verdict": "BLOCK",
  "reasons": [
    "Executable file type is blocked by policy",
    "Double extension detected",
    "File extension does not match detected file type"
  ],
  "rule_matches": [],
  "quarantined": true,
  "quarantine_path": "quarantine/uuid-invoice.pdf.exe",
  "scanned_at": "2026-10-27T20:00:00Z",
  "scanner_version": "0.1.0"
}
```

## Default policy

Create `policy/default_policy.yaml`:

```yaml
schema_version: 1

max_file_size_mb: 25
max_archive_depth: 2
max_archive_entries: 1000
max_compression_ratio: 100

allowed_extensions:
  - .pdf
  - .png
  - .jpg
  - .jpeg
  - .txt
  - .csv
  - .docx
  - .xlsx

blocked_extensions:
  - .exe
  - .scr
  - .msi
  - .bat
  - .cmd
  - .ps1
  - .vbs
  - .js
  - .jar
  - .hta
  - .lnk

quarantine_if:
  - extension_mismatch
  - double_extension
  - archive_contains_executable
  - archive_contains_script
  - nested_archive
  - excessive_compression_ratio
  - excessive_archive_entries
  - yara_match
  - known_malicious_hash
  - reputation_suspicious

block_if:
  - executable_file_type
  - script_file_type
  - known_malicious_hash
```

## File-type detection

Do not trust extensions alone.

Use magic-byte signatures for at least:

| Type | Magic bytes |
|---|---|
| ZIP / DOCX / XLSX / JAR | `50 4B 03 04` |
| PDF | `%PDF-` |
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| JPEG | `FF D8 FF` |
| Windows PE | `4D 5A` (`MZ`) |
| ELF | `7F 45 4C 46` |
| HTML | Text beginning with `<html`, `<!DOCTYPE html>`, or similar |
| Script | Shebang or recognizable script syntax |

If the extension says one type but magic bytes indicate another, mark the file
`QUARANTINE` with reason `extension_mismatch`.

## ZIP inspection rules

Inspect ZIP archives using Python’s `zipfile` module.

Do not extract archive contents to disk during MVP scanning.

For each ZIP:

- Read the central directory safely.
- Count entries.
- Check nesting depth.
- Calculate compression ratio.
- Detect executable and script extensions.
- Detect ZIP bombs.
- Reject paths containing `..`, absolute paths, drive letters, or suspicious
  control characters.
- Do not follow symlink-like or unusual entries.
- Inspect text and script members in memory for persistence indicators,
  bounded base64 UTF-8/UTF-16LE decoding, and high Shannon entropy. Skip
  OOXML media assets and honor the policy member/size/depth limits.
- Inspect nested ZIP members within `max_archive_depth` and attribute every
  finding to its full member path.

If inspection fails because the archive is corrupt, password-protected,
encrypted, oversized, or unreadable, return `QUARANTINE` with a clear reason.
Do not return `ALLOW`.

## Quarantine rules

Quarantined files must:

- Be moved, not copied, only after the scan result is finalized.
- Receive a new UUID-based filename.
- Retain the original filename, path, hash, verdict, and timestamp in a JSON
  sidecar.
- Be stored under `quarantine/`.
- Remain non-executable in practice: do not restore original executable
  permissions or create shortcuts.
- Never be automatically deleted.

Use atomic move operations where possible. If quarantine fails, retain the
original file, mark the scan `QUARANTINE_FAILED`, and log the error.

### Quarantine restore

Restore is an explicit operational action, never an automatic cleanup:

- Require a UUID and its JSON sidecar.
- Verify the quarantined payload SHA-256 against the sidecar before moving.
- Restore to the recorded original path unless an explicit destination is
  supplied; refuse destinations inside the quarantine directory.
- Require an explicit overwrite flag; back up the existing destination instead
  of deleting it.
- Retain and update the sidecar with restore time, destination, and verified
  hash. Never automatically purge quarantined evidence.

## Reports

Write one JSON report per scan to:

```text
reports/<yyyy-mm-dd>/<sha256>.json
```

Also append a concise line to:

```text
logs/attachmentguard.log
```

Log format:

```text
2026-10-27T20:00:00Z VERDICT=BLOCK FILE=invoice.pdf.exe SHA256=... REASONS=...
```

Never log API keys, full user profiles, email contents, or unrelated personal
data.

## ClamAV integration

ClamAV is an optional static gate. It must never execute the scanned file.

- Copy `config.ini.example` to `config.ini` and set `enabled = true`, or pass
  `--clamav` to `cli.py`/`scanner/guard.py`. The GUI loads `config.ini` once at
  startup and injects the service into the worker; no ClamAV subprocess runs in
  the GUI thread.
- Leave `clamdscan_path`/`clamscan_path` empty for automatic discovery on PATH
  and in the standard Windows install directory. Prefer `clamdscan` and fall
  back to `clamscan` when the daemon is unavailable.
- The shared `core/scanner.py` pipeline runs the check and adds a `clamav`
  object to the result with engine, exit code, verdict, signature, timeout, and
  error details.
- A detection adds `BLOCK`. Unavailable executables, timeouts, oversized files,
  and inconclusive scans add `QUARANTINE` with an explainable reason. A local
  `BLOCK` must never be downgraded by a clean ClamAV result.
- Virus signatures must be installed separately with `freshclam`. A missing
  database must be reported as "ClamAV signatures are missing; run freshclam
  to update the virus database" and must fail closed.
- `config.ini` is gitignored. Never commit local paths, credentials, or scan
  output.

## YARA integration

Add YARA only after the MVP passes tests.

Create `rules/suspicious.yar` with defensive rules. The first required rule
must detect Windows executables containing logon-persistence indicators.

```yara
rule Suspicious_Logon_Persistence_Installer
{
    meta:
        description = "Flags Windows executables that create logon scheduled-task persistence"
        severity = "high"
        category = "persistence"

    strings:
        $schtasks = "schtasks" ascii nocase
        $create = "/create" ascii nocase
        $logon = "/sc onlogon" ascii nocase
        $process_path = "Environment.ProcessPath" ascii nocase
        $task_name = "SENTINEL-Agent" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        2 of ($schtasks, $create, $logon, $process_path, $task_name)
}
```

YARA matches must produce `QUARANTINE`, not automatic deletion.

Do not compile or execute `AgentInstaller.cs` as a test sample. Use it only as
a static source-code indicator fixture unless an authorized isolated lab
provides a compiled binary.

## External reputation lookup

Implement VirusTotal hash lookup only after local scanning is stable.

Rules:

- Query by SHA-256 only.
- Check a local cache before making a network request.
- Require explicit user consent before any external lookup.
- Store the API key in `VIRUSTOTAL_API_KEY`.
- Never upload the file by default.
- Treat HTTP 404 as `UNKNOWN`, not `ALLOW`.
- Treat API failure as `UNKNOWN` for low-risk files and `QUARANTINE` for
  high-risk file types.
- Cache results with a timestamp and expiry.
- Never place API keys in Git, logs, reports, or screenshots.

## UI requirements

The main window must include:

1. Folder-selection button.
2. Current monitored-folder label.
3. Scan-results table.
4. Status bar.
5. Stop/cancel button.
6. Quarantine location display.
7. “Open report” action for a selected result.
8. Clear warning color or icon for `BLOCK` and `QUARANTINE`.

Use a `QTableView` backed by a `QAbstractTableModel`, not a `QTableWidget`, for
the scan history.

Required columns:

| Column | Source |
|---|---|
| File | `file` |
| Verdict | `verdict` |
| Size | `size_bytes` |
| SHA-256 | `sha256` |
| Detected type | `detected_mime_type` |
| Reasons | Joined `reasons` |
| Time | `scanned_at` |
| Action | Quarantined / retained |

## Error handling

Every external operation must handle:

- Missing file.
- Permission denied.
- File changed during scan.
- File deleted during scan.
- Corrupt ZIP.
- Password-protected ZIP.
- ZIP bomb.
- YARA rule error.
- ClamAV executable, signature database, or daemon unavailable.
- ClamAV timeout or inconclusive result.
- Network timeout.
- Invalid API response.
- Disk-full condition.
- Quarantine failure.

Return a structured error, log it, and avoid crashing the GUI.

## Testing requirements

Use `pytest`.

Required tests:

### Hash service

- Hashes a small known file correctly.
- Handles a missing file.
- Handles a permission-denied file.
- Produces lowercase hexadecimal SHA-256.

### Policy service

- Allows an allowed extension.
- Blocks an executable extension.
- Blocks oversized files.
- Handles case-insensitive extensions.
- Handles files without extensions.

### File-type service

- Detects PDF magic bytes.
- Detects PNG magic bytes.
- Detects PE/MZ magic bytes.
- Detects ZIP magic bytes.
- Detects extension mismatch.

### ZIP inspector

- Allows a safe ZIP with text files.
- Flags a ZIP containing `.exe`.
- Flags a ZIP containing `.js`.
- Flags a nested ZIP.
- Rejects path traversal entries.
- Handles corrupt ZIP.
- Handles password-protected ZIP.

### Deobfuscation heuristics

- Loads thresholds, exempt formats, and custom rules from policy.
- Detects persistence patterns in raw text and binary samples.
- Decodes bounded base64 UTF-8 and UTF-16LE segments and scans them.
- Flags high Shannon entropy above configured thresholds.
- Merges verdicts without downgrading a higher verdict.

### Archive member inspection

- Allows safe text members inside a ZIP.
- Attributes encoded/script findings to the full member path.
- Inspects nested ZIP members within the configured depth.
- Fails closed on corrupt, encrypted, oversized, or unreadable members.
- Skips OOXML media assets.

### Scanner integration

- `safe.txt` returns `ALLOW`.
- `fake.pdf.exe` returns `BLOCK`.
- ZIP with executable returns `QUARANTINE`.
- Corrupt ZIP returns `QUARANTINE`.
- A source-code persistence fixture produces the expected indicator result.

### ClamAV optional check

- Disabled by default produces no ClamAV check.
- A clean result does not downgrade a local verdict.
- A detection produces `BLOCK` with a named signature.
- Timeouts, missing databases, and unavailable executables produce
  `QUARANTINE` with a human-readable reason.
- The GUI worker and CLI both use the shared `core/` merge logic.

### Quarantine restore and CLI

- Restores only with a valid UUID and matching sidecar.
- Rejects tampered payloads with a SHA-256 mismatch.
- Supports dry-run and destination overrides.
- Refuses destinations inside the quarantine directory.
- Backs up an existing destination when overwrite is explicitly allowed.
- Keeps and updates the sidecar instead of deleting evidence.
- CLI emits structured JSON for restore actions.

### Threading tests

- Worker emits `finished` exactly once on success.
- Worker emits `failed` on exception.
- Cancellation prevents completion after cancellation is requested.
- Manager cleans up worker and thread after completion.
- Manager does not delete a running thread.

## Git and repository rules

`.gitignore` must include:

```gitignore
__pycache__/
*.py[cod]
.venv/
venv/
.env
*.log
config.ini
quarantine/*
!quarantine/.gitkeep
reports/*
!reports/.gitkeep
logs/*
!logs/.gitkeep
dist/
build/
*.spec
```

Never commit:

- API keys.
- Malware samples.
- Quarantined files.
- User-specific reports.
- Memory dumps.
- Credentials.
- Private scan results.

## Coding standards

- Python 3.11+.
- Type hints for public functions.
- Use `pathlib.Path`, not string path manipulation.
- Use dataclasses or Pydantic models for structured scan results.
- Keep functions small and testable.
- Prefer dependency injection for file system, network, and scanner services.
- Use `logging`, not `print()`, outside simple CLI examples.
- Use UTC ISO-8601 timestamps.
- Use constant time comparisons when comparing secrets, if applicable.
- Do not use `eval`, `exec`, `pickle`, or dynamic imports on scanned content.

## Definition of done

A feature is complete only when:

1. It has unit tests.
2. It has no GUI-thread blocking.
3. It handles failure without crashing.
4. It produces an explainable JSON result.
5. It respects the verdict precedence.
6. It does not execute scanned content.
7. It does not leak secrets or personal data.
8. It passes `pytest`.
9. It updates documentation if behavior changes.
10. It has been manually tested with safe fixtures.

## First implementation milestone

Implement this exact MVP:

```text
Select folder
→ QFileSystemWatcher detects new file
→ enqueue file
→ worker computes SHA-256
→ apply extension and size policy
→ detect magic bytes
→ inspect ZIP if applicable
→ decide verdict
→ quarantine BLOCK/QUARANTINE files
→ write JSON report
→ update PyQt table
```

Do not add VirusTotal, reputation lookups, or a C#/XAML interface until this
MVP is complete, tested, and stable. YARA and ClamAV are optional core checks
that stay off unless explicitly enabled.

## Test fixtures

Create only harmless fixtures:

```text
tests/fixtures/safe.txt
tests/fixtures/safe.pdf
tests/fixtures/safe.png
tests/fixtures/fake-image.jpg.exe
tests/fixtures/archive-safe.zip
tests/fixtures/archive-with-exe.zip
tests/fixtures/archive-nested.zip
tests/fixtures/corrupt.zip
tests/fixtures/agent_installer_source.cs
```

`agent_installer_source.cs` must be a static source-code fixture only. It must
never be compiled or executed by the test suite.

## Agent behavior when uncertain

If a requirement is ambiguous, choose the safer defensive behavior:

- Unknown file type → `QUARANTINE`.
- Corrupt archive → `QUARANTINE`.
- Reputation lookup unavailable → `UNKNOWN` or `QUARANTINE` based on risk.
- Quarantine fails → retain file and raise a clear operational alert.
- Test sample could execute code → do not run it.
- Requirement could enable offensive capability → refuse and propose a
  defensive alternative.

## Final quality bar

AttachmentGuard is successful when a non-technical user can:

1. Select their Downloads folder.
2. See new attachments appear in the UI.
3. Understand why a file was allowed, warned, quarantined, or blocked.
4. Trust that suspicious files were isolated rather than opened.
5. Close the application without crashes, orphaned threads, or lost reports.