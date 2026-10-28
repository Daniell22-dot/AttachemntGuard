from pathlib import Path
from typing import Dict, Tuple, Optional

MAGIC_SIGS = [
    (b'\x89PNG\r\n\x1a\n', 'image/png'),
    (b'\xff\xd8\xff', 'image/jpeg'),
    (b'%PDF-', 'application/pdf'),
    (b'PK\x03\x04', 'application/zip'),
    (b'PK\x05\x06', 'application/zip'),
    (b'PK\x07\x08', 'application/zip'),
    (b'\x50\x4B\x03\x04', 'application/zip'),
    (b'MZ', 'application/x-dosexec'),
    (b'\x7fELF', 'application/x-elf'),
]

EXT_MIME = {
    '.pdf': 'application/pdf',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.docx': 'application/zip',
    '.xlsx': 'application/zip',
    '.csv': 'text/csv',
    '.txt': 'text/plain',
    '.exe': 'application/x-dosexec',
    '.scr': 'application/x-dosexec',
    '.msi': 'application/x-msi',
    '.bat': 'text/plain',
    '.cmd': 'text/plain',
    '.ps1': 'text/plain',
    '.vbs': 'text/vbscript',
    '.js': 'text/javascript',
    '.jar': 'application/java-archive',
    '.hta': 'text/html',
    '.zip': 'application/zip',
}


def detect_magic_bytes(path: Path, sample: bytes = None) -> Tuple[str, bool]:
    if sample is None:
        try:
            with open(path, 'rb') as f:
                sample = f.read(4096)
        except (PermissionError, OSError):
            return 'application/octet-stream', False
    for sig, mime in MAGIC_SIGS:
        if sample.startswith(sig):
            return mime, True
    return 'application/octet-stream', False


def sniff(path: Path) -> Dict[str, str]:
    ext = path.suffix.lower()
    try:
        with open(path, 'rb') as f:
            sample = f.read(4096)
    except (PermissionError, OSError) as e:
        return {'ext': ext, 'mime': 'unknown', 'magic_match': False, 'error': str(e)}
    mime, magic_match = detect_magic_bytes(path, sample)
    return {'ext': ext, 'mime': mime, 'magic_match': magic_match}


def detect_extension_mismatch(path: Path) -> bool:
    info = sniff(path)
    ext = info['ext']
    mime = info['mime']
    if ext == '.exe' and mime != 'application/x-dosexec':
        return True
    if mime == 'application/x-dosexec' and ext not in ('.exe', '.scr'):
        return True
    return False
