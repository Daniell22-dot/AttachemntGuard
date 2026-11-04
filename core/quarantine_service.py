import json
import logging
import shutil
import uuid
from pathlib import Path
from typing import Dict, Optional, Any

logger = logging.getLogger(__name__)


def quarantine_file(path, quarantine_dir, scan_result) -> Optional[str]:
    """Move a file to quarantine with a UUID-based filename and JSON sidecar.

    Returns the destination path on success, or None if quarantine fails.
    """
    try:
        quarantine_dir.mkdir(parents=True, exist_ok=True)

        original_name = path.name
        orig_str = str(original_name)
        if '.' in orig_str:
            base, suffix = orig_str.rsplit('.', 1)
            uuid_name = f'{uuid.uuid4()}.{suffix}'
        else:
            uuid_name = str(uuid.uuid4())

        dest = quarantine_dir / uuid_name

        shutil.move(str(path), str(dest))

        sidecar: Dict[str, object] = {
            'original_filename': orig_str,
            'original_path': str(path),
            'sha256': scan_result.get('sha256'),
            'verdict': scan_result.get('verdict'),
            'scanned_at': scan_result.get('scanned_at'),
            'scanner_version': scan_result.get('scanner_version'),
        }
        sidecar_path = quarantine_dir / f'{uuid_name}.json'
        with open(sidecar_path, 'w', encoding='utf-8') as f:
            json.dump(sidecar, f, indent=2)

        return str(dest)
    except (PermissionError, shutil.Error, OSError) as e:
        logger.error('Quarantine failed for %s: %s', path, e)
        return None