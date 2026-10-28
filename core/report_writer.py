import json
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional


def write_report(scan_result, reports_dir):
    try:
        reports_dir.mkdir(parents=True, exist_ok=True)
        today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        daily_dir = reports_dir / today
        daily_dir.mkdir(parents=True, exist_ok=True)

        sha256 = scan_result.get('sha256')
        if not sha256:
            return None

        report_path = daily_dir / f'{sha256}.json'
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(scan_result, f, indent=2)

        return str(report_path)
    except (PermissionError, OSError) as e:
        print(f'Report write failed: {{e}}')
        return None


def append_log(scan_result, log_path):
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        verdict = scan_result.get('verdict', 'UNKNOWN')
        file_name = scan_result.get('file', 'unknown')
        sha256 = scan_result.get('sha256', '')
        reasons = scan_result.get('reasons', [])
        reasons_str = '|'.join(reasons) if reasons else ''
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        log_line = f'{timestamp} VERDICT={{verdict}} FILE={{file_name}} SHA256={{sha256}} REASONS={{reasons_str}}'
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(log_line + chr(10))
    except (PermissionError, OSError) as e:
        print(f'Log append failed: {{e}}')
