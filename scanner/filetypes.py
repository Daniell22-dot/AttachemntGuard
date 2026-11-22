import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.file_type_service import EXT_MIME, detect_magic_bytes, sniff


def detect_magic(path, sample):
    return detect_magic_bytes(Path(path), sample)
