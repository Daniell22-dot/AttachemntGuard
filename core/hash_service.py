import hashlib
from pathlib import Path
from typing import Dict, Optional


def sha256_file(path: Path) -> Optional[str]:
    """Compute SHA-256 hash of a file.

    Returns lowercase hexadecimal hash, or None if the file cannot be read.
    """
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None


def file_info(path: Path) -> Dict[str, object]:
    """Return file size and SHA-256 hash.

    Handles missing file and permission denied gracefully.
    """
    try:
        st = path.stat()
        sha = sha256_file(path)
        return {'path': str(path), 'size': st.st_size, 'sha256': sha}
    except (PermissionError, FileNotFoundError, OSError) as e:
        return {'path': str(path), 'size': 0, 'sha256': None, 'error': str(e)}
