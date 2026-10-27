import os

ALLOWED = {'.pdf', '.png', '.jpg', '.jpeg', '.docx', '.xlsx', '.csv', '.txt'}
BLOCK_EXT = {'.exe', '.scr', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.hta'}

def extension_policy(path: str) -> tuple:
    ext = os.path.splitext(path)[1].lower()
    if ext in BLOCK_EXT:
        return 'BLOCK', f'Blocked extension: {ext}'
    if ext not in ALLOWED:
        return 'WARN', f'Extension not in allowlist: {ext}'
    return 'ALLOW', 'Extension allowed'
