import os
from typing import Dict, Tuple

MAGIC = [
    (b'\x89PNG\r\n\x1a\n', 'image/png'),
    (b'\xff\xd8\xff', 'image/jpeg'),
    (b'%PDF-', 'application/pdf'),
    (b'PK\x03\x04', 'application/zip'),
    (b'PK\x05\x06', 'application/zip'),
    (b'PK\x07\x08', 'application/zip'),
    (b'\xD0\xCF\x11\xE0', 'application/msword'),
    (b'\x50\x4B\x03\x04', 'application/zip'),  # docx/xlsx often zip
    (b'MZ', 'application/x-dosexec'),
    (b'\x7fELF', 'application/x-elf'),
]

def detect_magic(path: str, sample: bytes) -> Tuple[str, bool]:
    for sig, mime in MAGIC:
        if sample.startswith(sig):
            return mime, True
    return 'application/octet-stream', False

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

def sniff(path: str) -> Dict[str, str]:
    ext = os.path.splitext(path)[1].lower()
    try:
        with open(path, 'rb') as f:
            sample = f.read(4096)
    except Exception as e:
        return {'ext': ext, 'mime': 'unknown', 'magic_match': False, 'error': str(e)}
    mime, magic_match = detect_magic(path, sample)
    return {'ext': ext, 'mime': mime, 'magic_match': magic_match}
