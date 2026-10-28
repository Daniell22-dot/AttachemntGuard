import sys
from pathlib import Path
from typing import Dict, Any, List, Optional

from .hash_service import sha256_file, file_info
from .file_type_service import sniff, detect_extension_mismatch
from .policy_service import check_extension, check_size, has_extension
from .zip_inspector import scan_zip


def decide_verdict(current, higher):
    order = {'ALLOW': 0, 'WARN': 1, 'QUARANTINE': 2, 'BLOCK': 3}
    if order.get(higher, 0) > order.get(current, 0):
        return higher
    return current

def scan_file(path, policy_path=None):
    result = {
        'schema_version': 1,
        'file': path.name,
        'path': str(path.resolve()),
        'size_bytes': 0,
        'sha256': '',
        'detected_extension': path.suffix.lower(),
        'detected_mime_type': 'unknown',
        'verdict': 'ALLOW',
        'reasons': [],
        'rule_matches': [],
        'quarantined': False,
        'quarantine_path': '',
        'scanned_at': '',
        'scanner_version': '0.1.0',
    }

    if not path.is_file():
        result['verdict'] = 'QUARANTINE'
        result['reasons'].append('File does not exist')
        return result

    # 2. Hash calculation
    info = file_info(path)
    result['size_bytes'] = info.get('size', 0)
    result['sha256'] = info.get('sha256', '')
    if not result['sha256']:
        result['verdict'] = 'QUARANTINE'
        result['reasons'].append('Failed to compute hash')
        return result

    # 3. Extension policy
    ext_verdict, ext_reason = check_extension(path)
    result['extension_policy'] = {'verdict': ext_verdict, 'reason': ext_reason}
    result['verdict'] = decide_verdict(result['verdict'], ext_verdict)
    if ext_reason:
        result['reasons'].append(ext_reason)

    # 4. Real file-type detection (magic bytes)
    sniff_info = sniff(path)
    result['detected_mime_type'] = sniff_info['mime']
    result['detected_extension'] = sniff_info['ext']

    # Check for extension mismatch
    if detect_extension_mismatch(path):
        result['reasons'].append('File extension does not match detected file type')
        result['verdict'] = 'QUARANTINE'

    # 5. Archive inspection
    zip_result = scan_zip(path)
    result['zip_scan'] = zip_result

    if zip_result.get('is_zip'):
        for entry in zip_result.get('suspicious', []):
            result['reasons'].append(entry)
        if any('nested' in s.lower() for s in zip_result.get('suspicious', [])):
            result['reasons'].append('Nested archive detected')
            result['verdict'] = 'QUARANTINE'
        if zip_result.get('total_entries', 0) > 1000:
            result['reasons'].append('Excessive archive entries')
            result['verdict'] = 'QUARANTINE'

    # 6. Static content indicators (persistence patterns)
    import re
    try:
        with open(path, 'rb') as f:
            data = f.read(65536)
        strings = [s.decode('latin-1', errors='ignore') for s in re.findall(rb'[ -~]{4,}', data)]
        txt = chr(10).join(strings)
        if re.search(r'schtasks', txt, re.I):
            result['reasons'].append('Uses schtasks (persistence indicator)')
            result['verdict'] = 'BLOCK'
        if re.search(r'/create.*s+onlogon', txt, re.I):
            result['reasons'].append('/sc onlogon detected (logon persistence)')
            result['verdict'] = 'BLOCK'
    except (PermissionError, OSError):
        pass

    return result
