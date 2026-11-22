import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.quarantine_service import quarantine_file as _quarantine_file


def quarantine_file(path, quarantine_dir, report):
    destination = _quarantine_file(Path(path), Path(quarantine_dir), report)
    if destination is None:
        raise RuntimeError("quarantine move failed")
    return destination
