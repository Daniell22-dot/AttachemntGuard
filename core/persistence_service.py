import re
from pathlib import Path

PATTERNS = [
    (re.compile(r"schtasks", re.I), "uses schtasks"),
    (re.compile(r"/create", re.I), "creates scheduled task"),
    (re.compile(r"/sc\s+onlogon", re.I), "logon trigger"),
    (re.compile(r"Environment\.ProcessPath", re.I), "self-launch via ProcessPath (same executable)"),
    (re.compile(r"%~f0", re.I), "self-launch via batch/script (%~f0)"),
    (re.compile(r'"[^"]*"\s+--run-agent', re.I), "launches agent with run flag"),
    (re.compile(r"SENTINEL-Agent", re.I), "named task SENTINEL-Agent"),
]


def scan_text(content: str) -> list:
    hits = []
    for pattern, description in PATTERNS:
        if pattern.search(content):
            hits.append(description)
    if re.search(r"/sc\s+onlogon", content, re.I) and re.search(r"Environment\.ProcessPath|%~f0", content, re.I):
        hits.append("self-referential logon persistence (task launches same executable)")
    if re.search(r"/create", content, re.I) and re.search(r"/sc\s+onlogon", content, re.I) and re.search(r"/tr", content, re.I):
        hits.append("scheduled task persistence at user logon")
    return list(dict.fromkeys(hits))


def scan_file_text(path) -> list:
    try:
        return scan_text(Path(path).read_text(encoding="utf-8", errors="ignore"))
    except (PermissionError, OSError, UnicodeError):
        return []


def scan_file_binary_strings(path) -> list:
    try:
        data = Path(path).read_bytes()
    except (PermissionError, OSError):
        return []
    strings = re.findall(rb"[ -~]{4,}", data)
    return scan_text(b"\n".join(strings).decode("latin-1", errors="ignore"))
