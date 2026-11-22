import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.persistence_service import (
    scan_file_binary_strings,
    scan_file_text,
    scan_text,
)
