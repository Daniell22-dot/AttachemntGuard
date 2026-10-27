# AttachmentGuard (MVP)

Static file gate: never executes files. Inspects hashes, magic bytes, extension policy, ZIP contents, and source-level persistence indicators.

## Verdicts
- `ALLOW` Safe under policy
- `WARN` Potentially risky
- `QUARANTINE` Suspicious; isolate for review
- `BLOCK` Dangerous or policy-violating

## Usage
```bash
python scanner/guard.py <file> [--quarantine] [--json]
```

## MVP features
1. SHA-256 hash + size
2. Extension allowlist/blocklist
3. Magic-byte sniffing + double-extension heuristic
4. ZIP inspection (entries, nested zips, executables/scripts inside)
5. Persistence indicator scan (schtasks/create/sc onlogon/ProcessPath/SENTINEL-Agent)
6. Quarantine with metadata
7. JSON report in `reports/`

## Test set
Create:
- `tests/safe.txt`, `tests/safe.pdf` (or dummy)
- `tests/fake-image.jpg.exe`
- `tests/archive-with-exe.zip`
- `tests/AgentInstaller.cs` (copy from `src/Agents/WindowsAgent/AgentInstaller.cs`)

`AgentInstaller.cs` is source code - treated as indicator sample (will flag persistence strings). A compiled PE would be caught by magic bytes + YARA later.
