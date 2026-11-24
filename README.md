# AttachmentGuard

AttachmentGuard checks files before you open them. It watches a folder you choose, scans new or changed files without executing them, and explains every decision in plain language.

Suspicious files are moved to quarantine, not deleted. The app runs locally; it does not upload your files or need an account.

## Who it is for

AttachmentGuard is a first checkpoint for:

- Downloads from a browser
- Email attachments
- Files from USB drives or shared folders
- Any folder where unexpected files appear

It is a defensive file gate, not a replacement for antivirus or endpoint security.

## Get started on Windows

The release is built for 64-bit Windows. Python is not required.

1. Download `AttachmentGuard-v0.3.0-windows.zip` from the project release or the person who shared it with you.
2. Unzip it into a folder you can write to, such as Downloads. Keep all files in the folder together.
3. Double-click `AttachmentGuard.exe`.
4. Click **Select Folder to Monitor** and choose the folder to watch.
5. Leave the window open while you want monitoring to continue.

Windows may show a SmartScreen warning for a newly downloaded app. Only run releases you trust.

## What you will see

The results table shows each file, its verdict, size, SHA-256 hash, detected type, reasons, scan time, and whether it was quarantined.

| Verdict | Meaning | What to do |
|---|---|---|
| `ALLOW` | No policy problem found | Usually safe to open, but stay alert |
| `WARN` | Something needs review | Check the report before opening |
| `QUARANTINE` | Suspicious; file was isolated | Do not open it until reviewed |
| `BLOCK` | Dangerous or blocked by policy | Do not open it |

A blocked or quarantined row is highlighted. Select a row and click **Open Report**, or double-click the row, to read the full explanation.

**Stop Monitoring** cancels queued and active scans safely. Closing the window also stops monitoring and finishes the current report before the app exits.

## What it checks

AttachmentGuard never opens or runs a scanned file. It inspects files statically:

- SHA-256 hash and file size
- Allowed and blocked file extensions
- Real file type from magic bytes, not just the extension
- Double extensions such as `invoice.pdf.exe`
- ZIP archives without extracting them
- Executable, script, nested-archive, path-traversal, and compression-ratio risks
- Encoded or obfuscated persistence indicators in text, scripts, and archive members
- Optional YARA rules included with the release
- Optional ClamAV scan, when configured

If a check cannot complete for a risky file, the app fails closed: it quarantines the file instead of allowing it.

## Where files go

AttachmentGuard stores its data outside the program folder so it works when installed in a protected location.

Press `Win + R`, paste `%LOCALAPPDATA%\AttachmentGuard`, and press Enter. You will find:

- `quarantine/` — isolated files and JSON evidence sidecars
- `reports/` — one JSON report per scan, organized by date
- `logs/` — concise verdict log
- `scan_history.db` — local scan history
- `config.ini` — optional settings, if you create one

Quarantined files are never deleted automatically. You can leave them there until you decide what to do.

## If a file is quarantined

Do not open the file from quarantine. Open its report first and read the reasons.

Restoring is intentionally an advanced administrator action because it reverses a safety decision. The included `AttachmentGuardCLI.exe` can restore a file only when you provide its UUID, the SHA-256 matches its sidecar, and the destination is safe. Most users should leave suspicious files quarantined until they have reviewed the report or asked an administrator.

## Privacy

- Scanning is local.
- No file contents are uploaded.
- There is no account, telemetry, or network lookup by default.
- Reports contain filenames, paths, hashes, verdicts, and reasons; they do not contain API keys.
- The app does not execute, extract, or open scanned files.

## Optional antivirus check

ClamAV is off by default. To enable it:

1. Install ClamAV for Windows separately and update its signatures with `freshclam`.
2. Copy `config.ini.example` from the release folder to `%LOCALAPPDATA%\AttachmentGuard\config.ini`.
3. Set `enabled = true` in that file.
4. Restart AttachmentGuard.

Leave the executable paths empty to auto-discover `clamdscan` or `clamscan`. A detection blocks the file. Missing signatures, timeouts, or scanner errors quarantine the file with an explanation; a local block is never downgraded.

## Limitations

- AttachmentGuard does not execute files, so packed or encrypted malware may evade static checks.
- YARA and heuristic rules can produce false positives; read the report before restoring.
- ZIP members are inspected in memory with size and depth limits, not extracted.
- The app is a decision-support gate, not a guarantee that any file is safe.

## Advanced command-line use

`AttachmentGuardCLI.exe` is included for administrators and automated checks. It uses the same scanning engine as the desktop app.

```text
AttachmentGuardCLI.exe "C:\Downloads\report.pdf"
AttachmentGuardCLI.exe "C:\Downloads\report.pdf" --json
AttachmentGuardCLI.exe --restore <uuid> --dry-run
AttachmentGuardCLI.exe --restore <uuid>
```

These commands are optional. Desktop users do not need them.

## For developers

You only need this section when working from source.

```bash
pip install -r requirements.txt
python main.py
python cli.py "tests/fixtures/safe.txt" --json
python -m pytest -q
```

The source build uses PyQt6, YARA, PyYAML, and pytest. Released ZIPs are built with PyInstaller and already include everything needed to run.
