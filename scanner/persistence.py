import re

PATTERNS = [
    (re.compile(r'schtasks', re.I), 'uses schtasks'),
    (re.compile(r'/create', re.I), 'creates scheduled task'),
    (re.compile(r'/sc\s+onlogon', re.I), 'logon trigger'),
    (re.compile(r'Environment\.ProcessPath', re.I), 'self-launch via ProcessPath (same executable)'),
    (re.compile(r'%~f0', re.I), 'self-launch via batch/script (%~f0)'),
    (re.compile(r'"[^"]*"\s+--run-agent', re.I), 'launches agent with run flag'),
    (re.compile(r'SENTINEL-Agent', re.I), 'named task SENTINEL-Agent'),
]

def scan_text(content: str) -> list:
    hits = []
    for pat, desc in PATTERNS:
        if pat.search(content):
            hits.append(desc)
    # Extra emphasis for self-referential logon persistence
    if re.search(r'/sc\s+onlogon', content, re.I) and re.search(r'Environment\.ProcessPath|%~f0', content, re.I):
        hits.append('self-referential logon persistence (task launches same executable)')
    if re.search(r'/create', content, re.I) and re.search(r'/sc\s+onlogon', content, re.I) and re.search(r'/tr', content, re.I):
        hits.append('scheduled task persistence at user logon')
    return list(dict.fromkeys(hits))

def scan_file_text(path: str) -> list:
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return scan_text(content)
    except Exception:
        return []

def scan_file_binary_strings(path: str) -> list:
    try:
        with open(path, 'rb') as f:
            data = f.read()
        # simple printable strings
        s = re.findall(rb'[ -~]{4,}', data)
        txt = b'\n'.join(s).decode('latin-1', errors='ignore')
        return scan_text(txt)
    except Exception:
        return []
