import os
os.makedirs('D:/AttachmentGuard/ui', exist_ok=True)

# Write main.py
content = '''import sys
from pathlib import Path
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, QLabel, QTableView, QFileDialog, QStatusBar
from PyQt6.QtCore import QFileSystemWatcher, QAbstractTableModel, Qt, pyqtSignal, QObject
import hashlib
import json
import os
import zipfile
import shutil
from datetime import datetime, timezone

def compute_sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()

def sniff_file(path):
    MAGIC = [
        (b'\\x89PNG\\r\\n\\x1a\\n', 'image/png'),
        (b'\\xff\\xd8\\xff', 'image/jpeg'),
        (b'%PDF-', 'application/pdf'),
        (b'PK\\x03\\x04', 'application/zip'),
        (b'MZ', 'application/x-dosexec'),
    ]
    ext = Path(path).suffix.lower()
    try:
        with open(path, 'rb') as f:
            sample = f.read(4096)
    except:
        return {'ext': ext, 'mime': 'unknown', 'magic_match': False}
    mime, magic_match = 'unknown', False
    for sig, m in MAGIC:
        if sample.startswith(sig):
            mime, magic_match = m, True
            break
    return {'ext': ext, 'mime': mime, 'magic_match': magic_match}

def check_extension(path):
    allowed = {'.pdf', '.png', '.jpg', '.jpeg', '.docx', '.xlsx', '.csv', '.txt'}
    blocked = {'.exe', '.scr', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.hta', '.lnk'}
    ext = Path(path).suffix.lower()
    if ext in blocked:
        return 'BLOCK', f'Blocked extension: {ext}'
    if ext not in allowed:
        return 'WARN', f'Extension not in allowlist: {ext}'
    return 'ALLOW', 'Extension allowed'

def scan_file_pipeline(path):
    result = {
        'schema_version': 1,
        'file': Path(path).name,
        'path': str(Path(path).resolve()),
        'size_bytes': 0,
        'sha256': '',
        'detected_extension': Path(path).suffix.lower(),
        'detected_mime_type': 'unknown',
        'verdict': 'ALLOW',
        'reasons': [],
        'rule_matches': [],
        'quarantined': False,
        'quarantine_path': '',
        'scanned_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'scanner_version': '0.1.0',
    }
    if not Path(path).is_file():
        result['verdict'] = 'QUARANTINE'
        result['reasons'].append('File does not exist')
        return result
    result['size_bytes'] = Path(path).stat().st_size
    result['sha256'] = compute_sha256(path)
    if not result['sha256']:
        result['verdict'] = 'QUARANTINE'
        result['reasons'].append('Failed to compute hash')
        return result
    ext_verdict, ext_reason = check_extension(path)
    result['extension_policy'] = {'verdict': ext_verdict, 'reason': ext_reason}
    if ext_reason:
        result['reasons'].append(ext_reason)
    sniff_info = sniff_file(path)
    result['detected_mime_type'] = sniff_info['mime']
    result['detected_extension'] = sniff_info['ext']
    if sniff_info['ext'] == '.exe' and sniff_info['mime'] != 'application/x-dosexec':
        result['reasons'].append('File extension does not match detected file type')
        result['verdict'] = 'QUARANTINE'
    try:
        with zipfile.ZipFile(path, 'r') as z:
            for name in z.namelist():
                if Path(name).suffix.lower() in {'.exe', '.scr', '.js', '.bat'}:
                    result['reasons'].append(f'Executable/script in file: {name}')
                    result['verdict'] = 'QUARANTINE'
    except:
        pass
    return result

class ScanWorker(QObject):
    started = pyqtSignal(str)
    finished = pyqtSignal(dict)
    failed = pyqtSignal(str)
    cancelled = pyqtSignal()

    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        try:
            self.started.emit(Path(self.file_path).name)
            if self._cancelled:
                self.finished.emit({'verdict': 'CANCELLED', 'file': Path(self.file_path).name})
                return
            result = scan_file_pipeline(self.file_path)
            if self._cancelled:
                self.finished.emit({'verdict': 'CANCELLED', 'file': Path(self.file_path).name})
            else:
                self.finished.emit(result)
        except Exception as e:
            self.failed.emit(f'{type(e).__name__}: {e}')

class ScanTableModel(QAbstractTableModel):
    COLUMNS = ['File', 'Verdict', 'Size', 'SHA-256', 'Detected type', 'Reasons', 'Time', 'Action']
    def __init__(self, data=None, parent=None):
        super().__init__(parent)
        self._data = data or []
        self._headers = self.COLUMNS
    def rowCount(self, parent=None):
        return len(self._data)
    def columnCount(self, parent=None):
        return len(self._headers)
    def headerData(self, section, orientation, role):
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return self._headers[section]
        return str(section)
    def data(self, index, role):
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if not index.isValid():
            return None
        row = index.row()
        col = index.column()
        if row < len(self._data) and col < len(self._data[row]):
            return str(self._data[row][col])
        return None

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('AttachmentGuard')
        self.resize(1000, 600)
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        self.folder_btn = QPushButton('Select Folder to Monitor')
        self.folder_btn.clicked.connect(self.select_folder)
        layout.addWidget(self.folder_btn)
        self.folder_label = QLabel('No folder selected')
        layout.addWidget(self.folder_label)
        self.table_model = ScanTableModel()
        self.table_view = QTableView()
        self.table_view.setModel(self.table_model)
        layout.addWidget(self.table_view)
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage('Ready')
        self.manager = None
        self.quarantine_label = QLabel('Quarantine: quarantine/')
        layout.addWidget(self.quarantine_label)

    def select_folder(self):
        from PyQt6.QtWidgets import QFileDialog
        folder = QFileDialog.getExistingDirectory(self, 'Select Folder to Monitor')
        if folder:
            self.folder_label.setText(folder)
            self._start_monitoring(folder)

    def _start_monitoring(self, folder_path):
        from PyQt6.QtCore import QFileSystemWatcher
        folder_path = str(Path(folder_path).resolve())
        watcher = QFileSystemWatcher()
        if folder_path not in watcher.paths():
            watcher.addPath(folder_path)
        self._scan_existing_files(watcher, folder_path)
        watcher.fileChanged.connect(lambda p: self._on_file_changed(watcher, p))

    def _scan_existing_files(self, watcher, folder_path):
        path = Path(folder_path)
        for item in sorted(path.iterdir()):
            if item.is_file():
                self._scan_file(watcher, item)

    def _on_file_changed(self, watcher, path):
        import threading
        def delayed_scan():
            import time
            time.sleep(0.5)
            p = Path(path)
            if p.exists() and p.is_file():
                self._scan_file(watcher, p)

    def _scan_file(self, watcher, path):
        try:
            worker = ScanWorker(path)
            from PyQt6.QtCore import QThread
            thread = QThread()
            worker.moveToThread(thread)
            thread.started.connect(thread.start)
            worker.finished.connect(lambda r: self._handle_scan_finished(r, path))
            worker.failed.connect(lambda e: self._handle_scan_failed(e, path))
            worker.canceled.connect(lambda: self._handle_scan_cancelled(path))
            thread.finished.connect(thread.quit)
            thread.finished.connect(lambda: (thread.deleteLater(), worker.deleteLater()))
            worker.run()
            self.thread = thread
        except Exception as e:
            self._handle_scan_failed(str(e), path)

    def _handle_scan_finished(self, result, path):
        verdict = result.get('verdict', 'ALLOW')
        file_name = result.get('file', Path(path).name)
        sha256 = result.get('sha256', '')
        reasons = result.get('reasons', [])
        size = result.get('size_bytes', 0)
        mime = result.get('detected_mime_type', 'unknown')
        if self.table_model:
            row = [file_name, verdict, size, sha256, mime, ' | '.join(reasons), 
                   result.get('scanned_at', ''), 'Quarantined' if verdict in ('BLOCK', 'QUARANTINE') else 'Retained']
            self.table_model._data.append(row)
            self.table_model.layoutChanged.emit()
        if verdict in ('BLOCK', 'QUARANTINE'):
            self._quarantine_file(path, result)
        self._write_report(result)
        self._log_scan(result)

    def _handle_scan_failed(self, error, path):
        pass

    def _handle_scan_cancelled(self, path):
        pass

    def _quarantine_file(self, path, result):
        try:
            src = Path(path)
            import uuid
            uuid_name = f'{uuid.uuid4()}{src.suffix}'
            dest = Path('quarantine') / uuid_name
            shutil.move(str(src), str(dest))
            sidecar = {
                'original_filename': src.name,
                'original_path': str(src),
                'sha256': result.get('sha256'),
                'verdict': result.get('verdict'),
                'scanned_at': result.get('scanned_at'),
            }
            with open(dest.with_suffix('.json'), 'w') as f:
                json.dump(sidecar, f, indent=2)
        except Exception as e:
            pass

    def _write_report(self, result):
        try:
            today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
            daily_dir = Path('reports') / today
            daily_dir.mkdir(parents=True, exist_ok=True)
            sha256 = result.get('sha256', 'unknown')
            report_path = daily_dir / f'{sha256}.json'
            with open(report_path, 'w') as f:
                json.dump(result, f, indent=2)
        except:
            pass

    def _log_scan(self, result):
        try:
            verdict = result.get('verdict', 'ALLOW')
            file_name = result.get('file', 'unknown')
            sha256 = result.get('sha256', '')
            reasons = result.get('reasons', [])
            reasons_str = '|'.join(reasons) if reasons else ''
            timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            log_line = f'{timestamp} VERDICT={verdict} FILE={file_name} SHA256={sha256} REASONS={reasons_str}'
            with Path('logs/attachmentguard.log').open('a') as f:
                f.write(log_line + '\n')
        except:
            pass

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
'''
with open('D:/AttachmentGuard/main.py', 'w', encoding='utf-8') as f:
    f.write(content)
print('main.py written successfully')
