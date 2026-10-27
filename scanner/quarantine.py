import os
import shutil
import uuid
import json
from datetime import datetime

def quarantine_file(path: str, quarantine_dir: str, report: dict) -> str:
    os.makedirs(quarantine_dir, exist_ok=True)
    base = os.path.basename(path)
    ext = os.path.splitext(base)[1]
    qname = f"{uuid.uuid4()}{ext}.quarantined"
    qpath = os.path.join(quarantine_dir, qname)
    shutil.move(path, qpath)
    meta = {
        'original_path': path,
        'quarantined_as': qpath,
        'quarantined_at': datetime.utcnow().isoformat() + 'Z',
        'report': report
    }
    with open(qpath + '.meta.json', 'w', encoding='utf-8') as f:
        json.dump(meta, f, indent=2)
    return qpath
