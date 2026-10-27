import zipfile
import os

BAD_EXTS = {'.exe', '.scr', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.hta'}

def scan_zip(path: str, max_entries=1000, max_depth=3) -> dict:
    result = {'is_zip': False, 'entries': [], 'suspicious': [], 'errors': []}
    try:
        if not zipfile.is_zipfile(path):
            return result
        result['is_zip'] = True
        with zipfile.ZipFile(path, 'r') as z:
            entries = z.infolist()
            if len(entries) > max_entries:
                result['errors'].append(f'too many entries: {len(entries)}')
            for e in entries[:max_entries]:
                name = e.filename
                result['entries'].append(name)
                ext = os.path.splitext(name)[1].lower()
                if ext in BAD_EXTS:
                    result['suspicious'].append(f'executable/script in zip: {name}')
                if name.count('..') or '\\' in name:
                    result['suspicious'].append(f'suspicious path: {name}')
                # nested zip
                if ext == '.zip':
                    result['suspicious'].append(f'nested archive: {name}')
        return result
    except Exception as e:
        result['errors'].append(str(e))
        return result
