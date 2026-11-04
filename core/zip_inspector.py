import zipfile
from pathlib import Path
from typing import Dict, List, Optional

BAD_EXTS = {'.exe', '.scr', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.hta'}


def scan_zip(path, max_entries=1000, max_depth=2):
    result = {
        'is_zip': False,
        'entries': [],
        'suspicious': [],
        'errors': [],
        'max_depth': 0,
        'total_entries': 0,
    }

    try:
        if not path.is_file():
            result['errors'].append('File not found')
            return result

        # Check if file is a ZIP using is_zipfile
        if zipfile.is_zipfile(str(path)):
            result['is_zip'] = True
            with zipfile.ZipFile(str(path), 'r') as z:
                entries = z.infolist()
                result['total_entries'] = len(entries)

                depth = 0
                for e in entries:
                    parts = [p for p in e.filename.replace(chr(92), '/').split('/') if p]
                    depth = max(depth, len(parts))
                result['max_depth'] = depth

                if len(entries) > max_entries:
                    result['errors'].append(f'Too many entries: {len(entries)} (max {max_entries})')

                for e in entries:
                    name = e.filename
                    result['entries'].append(name)

                    normalized = name.replace(chr(92), '/')
                    if '..' in normalized or name.startswith('/') or ':' in name:
                        result['suspicious'].append(f'Suspicious path: {name}')
                        continue

                    ext = Path(name).suffix.lower()
                    if ext in BAD_EXTS:
                        result['suspicious'].append(f'Executable/script in zip: {name}')

                    if ext == '.zip':
                        result['suspicious'].append(f'Nested archive: {name}')

            return result

        # Fallback: check for ZIP magic bytes (PK\x03\x04 or PK\x05\x06 or PK\x07\x08)
        try:
            with open(path, 'rb') as f:
                header = f.read(8)
        except (PermissionError, OSError):
            return result

        if header[:2] == b'PK':
            # File has ZIP signature but is corrupt/unreadable
            result['is_zip'] = True
            try:
                with zipfile.ZipFile(str(path), 'r') as z:
                    # If we can open it, process normally
                    entries = z.infolist()
                    result['total_entries'] = len(entries)

                    depth = 0
                    for e in entries:
                        parts = [p for p in e.filename.replace(chr(92), '/').split('/') if p]
                        depth = max(depth, len(parts))
                    result['max_depth'] = depth

                    if len(entries) > max_entries:
                        result['errors'].append(f'Too many entries: {len(entries)} (max {max_entries})')

                    for e in entries:
                        name = e.filename
                        result['entries'].append(name)

                        normalized = name.replace(chr(92), '/')
                        if '..' in normalized or name.startswith('/') or ':' in name:
                            result['suspicious'].append(f'Suspicious path: {name}')
                            continue

                        ext = Path(name).suffix.lower()
                        if ext in BAD_EXTS:
                            result['suspicious'].append(f'Executable/script in zip: {name}')

                        if ext == '.zip':
                            result['suspicious'].append(f'Nested archive: {name}')
            except zipfile.BadZipFile as e:
                result['errors'].append(f'Corrupt ZIP: {e}')
            except RuntimeError as e:
                result['errors'].append(f'Password-protected or corrupt ZIP: {e}')
            except Exception as e:
                result['errors'].append(f'ZIP inspection error: {e}')
            return result

        # Not a ZIP file
        return result

    except zipfile.BadZipFile as e:
        result['is_zip'] = True
        result['errors'].append(f'Corrupt ZIP: {e}')
        return result
    except RuntimeError as e:
        result['is_zip'] = True
        result['errors'].append(f'Password-protected or corrupt ZIP: {e}')
        return result
    except Exception as e:
        result['errors'].append(f'ZIP inspection error: {e}')
        return result