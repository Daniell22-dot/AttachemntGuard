import json
import shutil
import uuid
from pathlib import Path
from typing import Dict, Optional, Any


def quarantine_file(path, quarantine_dir, scan_result):
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

        sidecar = {
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
        print(f'Quarantine failed for {path}: {{e}}')
        return None
