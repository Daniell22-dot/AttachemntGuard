import hashlib
import os

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()

def file_info(path: str) -> dict:
    st = os.stat(path)
    return {'path': path, 'size': st.st_size, 'sha256': sha256_file(path)}
