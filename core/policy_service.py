from pathlib import Path
from typing import Dict, Tuple, Optional

ALLOWED_EXTENSIONS = {'.pdf', '.png', '.jpg', '.jpeg', '.docx', '.xlsx', '.csv', '.txt'}
BLOCKED_EXTENSIONS = {'.exe', '.scr', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.hta', '.lnk'}


def check_extension(path, allowed=None, blocked=None):
    allowed = allowed or ALLOWED_EXTENSIONS
    blocked = blocked or BLOCKED_EXTENSIONS
    ext = path.suffix.lower()
    if ext in blocked:
        return 'BLOCK', f'Blocked extension: {ext}'
    if ext not in allowed:
        return 'WARN', f'Extension not in allowlist: {ext}'
    return 'ALLOW', 'Extension allowed'


def check_size(path, max_mb=25):
    try:
        size_bytes = path.stat().st_size
        max_bytes = max_mb * 1024 * 1024
        if size_bytes > max_bytes:
            return False, f'File too large: {size_bytes // (1024*1024)} MB > {max_mb} MB'
        return True, 'Size OK'
    except (PermissionError, OSError) as e:
        return False, f'Cannot determine size: {e}'

def has_extension(path):
    return path.suffix.lower() in ALLOWED_EXTENSIONS | BLOCKED_EXTENSIONS
