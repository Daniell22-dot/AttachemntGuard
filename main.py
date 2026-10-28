import sys
import logging
from pathlib import Path

from PyQt6.QtCore import QFileSystemWatcher, QAbstractTableModel, Qt, QObject, pyqtSignal, QThread
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QPushButton,
    QLabel,
    QTableView,
    QFileDialog,
    QStatusBar,
    QMessageBox,
    QProgressBar,
)

from workers.scan_worker import ScanWorker
from ui.scan_table_model import ScanTableModel
from core.clamav_service import ClamAvService, ClamAvUnavailable
from core.report_writer import write_report, append_log

# Local policy scanning (extension, size, magic bytes)
from core.policy_service import check_extension, check_size
from core.file_type_service import sniff, detect_extension_mismatch
from core.hash_service import sha256_file, file_info

BLOCKED_EXTENSIONS = {
    ".exe", ".scr", ".msi", ".bat", ".cmd",
    ".ps1", ".vbs", ".js", ".jar", ".hta", ".lnk",
}

MAX_SIZE = 25 * 1024 * 1024  # 25 MB


class ScanManager(QObject):
    """Manages scan lifecycle in a QThread using the worker-object pattern."""

    scan_started = pyqtSignal(str)
    scan_progress = pyqtSignal(str, int)
    scan_finished = pyqtSignal(dict)
    scan_failed = pyqtSignal(str, str)
    scan_cancelled = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._thread = None
        self._worker = None

    def start_scan(self, file_path: str):
        self.stop()

        self._thread = QThread(self)
        self._worker = ScanWorker(file_path)

        # Worker must have no parent before moveToThread().
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)

        self._worker.started.connect(self.scan_started)
        self._worker.progress.connect(self.scan_progress)
        self._worker.finished.connect(self.scan_finished)
        self._worker.failed.connect(self.scan_failed)
        self._worker.cancelled.connect(self.scan_cancelled)

        # Clean shutdown: stop thread, then delete worker
        self._worker.finished.connect(self._thread.quit)
        self._worker.failed.connect(self._thread.quit)
        self._worker.cancelled.connect(self._thread.quit)

        self._thread.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)

        self._thread.start()

    def stop(self):
        if self._worker is not None:
            self._worker.cancel()

        if self._thread is not None:
            self._thread.quit()
            self._thread.wait(5000)

        self._worker = None
        self._thread = None


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AttachmentGuard")
        self.resize(1000, 600)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        self.folder_btn = QPushButton("Select Folder to Monitor")
        self.folder_btn.clicked.connect(self.select_folder)
        layout.addWidget(self.folder_btn)

        self.folder_label = QLabel("No folder selected")
        layout.addWidget(self.folder_label)

        self.table_model = ScanTableModel()
        self.table_view = QTableView()
        self.table_view.setModel(self.table_model)
        layout.addWidget(self.table_view)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        layout.addWidget(self.progress_bar)

        self.quarantine_label = QLabel("Quarantine: quarantine/")
        layout.addWidget(self.quarantine_label)

        self.scan_manager = ScanManager(self)
        self.scan_manager.scan_started.connect(self._on_scan_started)
        self.scan_manager.scan_progress.connect(self._on_scan_progress)
        self.scan_manager.scan_finished.connect(self._on_scan_finished)
        self.scan_manager.scan_failed.connect(self._on_scan_failed)

    def select_folder(self):
        from PyQt6.QtWidgets import QFileDialog
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Monitor")
        if not folder:
            return

        folder_path = str(Path(folder).resolve())
        self.folder_label.setText(folder_path)

        # Scan existing files in the folder
        self._scan_existing_files(folder_path)

        # Set up watcher for new files
        from PyQt6.QtCore import QFileSystemWatcher
        self._watcher = QFileSystemWatcher()
        if folder_path not in self._watcher.paths():
            self._watcher.addPath(folder_path)
        self._watcher.fileChanged.connect(
            lambda p: self.scan_manager.start_scan(p)
        )

    def _scan_existing_files(self, folder_path: str):
        path = Path(folder_path)
        for item in sorted(path.iterdir()):
            if item.is_file():
                # Use the scan manager for each file
                self.scan_manager.start_scan(str(item))

    def _on_scan_started(self, file_name: str):
        self.status_bar.showMessage(f"Scanning started: {file_name}")

    def _on_scan_progress(self, file_name: str, value: int):
        self.progress_bar.setValue(value)
        self.status_bar.showMessage(f"Scanning {file_name}: {value}%")

    def _on_scan_finished(self, result: dict):
        verdict = result.get("verdict", "ALLOW")
        file_name = result.get("file", "unknown")
        sha256 = result.get("sha256", "")
        reasons = result.get("reasons", [])
        size = result.get("size_bytes", 0)
        mime = result.get("detected_mime_type", "unknown")
        clamav = result.get("clamav", {})

        # Add row to table
        row = [
            file_name,
            verdict,
            size,
            sha256,
            mime,
            " | ".join(reasons) if reasons else "",
            result.get("scanned_at", ""),
            "Quarantined" if verdict in ("BLOCK", "QUARANTINE") else "Retained",
        ]
        self.table_model._data.append(row)
        self.table_model.layoutChanged.emit()

        # Display status message
        reason_str = "; ".join(reasons) if reasons else "No issues detected"
        self.status_bar.showMessage(f"{verdict}: {file_name} — {reason_str}")

        # Quarantine if BLOCK or QUARANTINE
        if verdict in ("BLOCK", "QUARANTINE"):
            self._quarantine_file(result)

        # Write JSON report
        write_report(result, Path("reports"))

        # Append log line
        append_log(result, Path("logs/attachmentguard.log"))

    def _on_scan_failed(self, error: str, file_path: str):
        self.status_bar.showMessage(f"Scan failed: {error}")
        self.progress_bar.setValue(0)

    def _quarantine_file(self, result: dict):
        from core.quarantine_service import quarantine_file

        path = result.get("path", "")
        verdict = result.get("verdict", "")

        quarantined_path = quarantine_file(Path(path), Path("quarantine"), result)
        if quarantined_path:
            self.quarantine_label.setText(
                f"Quarantine: {quarantined_path}"
            )
            QMessageBox.information(
                self,
                "Quarantined",
                f"File was quarantined:\n{Path(path).name}\n\n"
                f"Reason: {'; '.join(result.get('reasons', []))}"
            )
        else:
            self.quarantine_label.setText(
                f"Quarantine: quarantine/ (error occurred)"
            )

    def closeEvent(self, event):
        # Clean shutdown of any running scan
        self.scan_manager.stop()
        super().closeEvent(event)


def compute_sha256(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sniff_file(path: Path) -> dict:
    """Detect file type using magic bytes."""
    MAGIC_SIGS = [
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"\xff\xd8\xff", "image/jpeg"),
        (b"%PDF-", "application/pdf"),
        (b"PK\x03\x04", "application/zip"),
        (b"PK\x05\x06", "application/zip"),
        (b"PK\x07\x08", "application/zip"),
        (b"\x50\x4B\x03\x04", "application/zip"),
        (b"MZ", "application/x-dosexec"),
        (b"\x7fELF", "application/x-elf"),
    ]

    ext = path.suffix.lower()
    try:
        with open(path, "rb") as f:
            sample = f.read(4096)
    except (PermissionError, OSError):
        return {"ext": ext, "mime": "unknown", "magic_match": False}

    for sig, mime in MAGIC_SIGS:
        if sample.startswith(sig):
            return {"ext": ext, "mime": mime, "magic_match": True}

    return {"ext": ext, "mime": "unknown", "magic_match": False}


def detect_extension_mismatch(path: Path) -> bool:
    """Check if extension matches detected file type."""
    info = sniff(path)
    ext = info["ext"]
    mime = info["mime"]
    if ext == ".exe" and mime != "application/x-dosexec":
        return True
    if mime == "application/x-dosexec" and ext not in (".exe", ".scr"):
        return True
    return False


def scan_file_pipeline(path: str) -> dict:
    """Run the full scan pipeline on a single file.

    Returns a dict matching the required result schema.
    """
    path = Path(path)

    result = {
        "schema_version": 1,
        "file": path.name,
        "path": str(path.resolve()),
        "size_bytes": 0,
        "sha256": "",
        "detected_extension": path.suffix.lower(),
        "detected_mime_type": "unknown",
        "verdict": "ALLOW",
        "reasons": [],
        "rule_matches": [],
        "quarantined": False,
        "quarantine_path": "",
        "scanned_at": "",
        "scanner_version": "0.1.0",
    }

    if not path.is_file():
        result["verdict"] = "QUARANTINE"
        result["reasons"].append("File does not exist")
        return result

    # 1. File info (size + hash)
    info = file_info(path)
    result["size_bytes"] = info.get("size", 0)
    result["sha256"] = info.get("sha256", "")
    if not result["sha256"]:
        result["verdict"] = "QUARANTINE"
        result["reasons"].append("Failed to compute hash")
        return result

    # 2. Extension policy
    ext_verdict, ext_reason = check_extension(path)
    result["extension_policy"] = {"verdict": ext_verdict, "reason": ext_reason}
    result["verdict"] = _decide_verdict(result["verdict"], ext_verdict)
    if ext_reason:
        result["reasons"].append(ext_reason)

    # 3. Real file-type detection (magic bytes)
    sniff_info = sniff_file(path)
    result["detected_mime_type"] = sniff_info["mime"]
    result["detected_extension"] = sniff_info["ext"]

    # Check for extension mismatch
    if detect_extension_mismatch(path):
        result["reasons"].append("File extension does not match detected file type")
        result["verdict"] = "QUARANTINE"

    # 4. Archive inspection
    try:
        import zipfile

        is_zip = zipfile.is_zipfile(str(path))
        zip_suspicious = []
        zip_errors = []

        if is_zip:
            with zipfile.ZipFile(str(path), "r") as z:
                entries = z.infolist()
                for e in entries:
                    name = e.filename
                    normalized = name.replace("\\", "/")

                    # Check for path traversal
                    if ".." in normalized or name.startswith("/") or ":" in name:
                        zip_suspicious.append(f"Suspicious path: {name}")
                        continue

                    ext = Path(name).suffix.lower()
                    BAD_EXTS = {".exe", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".hta"}
                    if ext in BAD_EXTS:
                        zip_suspicious.append(f"Executable/script in zip: {name}")

                    if ext == ".zip":
                        zip_suspicious.append(f"Nested archive: {name}")

            if zip_suspicious:
                for s in zip_suspicious:
                    result["reasons"].append(s)
                # If any suspicious entries, quarantine
                if any("nested" in s.lower() for s in zip_suspicious):
                    result["reasons"].append("Nested archive detected")
                    result["verdict"] = "QUARANTINE"

        result["zip_scan"] = {
            "is_zip": is_zip,
            "suspicious": zip_suspicious,
            "errors": zip_errors,
        }

    except zipfile.BadZipFile:
        result["zip_scan"] = {"is_zip": True, "suspicious": [], "errors": ["Corrupt ZIP archive"]}
        result["reasons"].append("Corrupt ZIP archive")
        result["verdict"] = "QUARANTINE"
    except RuntimeError:
        result["zip_scan"] = {"is_zip": True, "suspicious": [], "errors": ["Password-protected ZIP archive"]}
        result["reasons"].append("Password-protected ZIP archive")
        result["verdict"] = "QUARANTINE"
    except Exception as e:
        result["zip_scan"] = {"is_zip": False, "suspicious": [], "errors": [str(e)]}
        result["reasons"].append(f"ZIP inspection error: {e}")

    # 5. Static content indicators (persistence patterns)
    try:
        with open(path, "rb") as f:
            data = f.read(65536)
        import re
        strings = [s.decode("latin-1", errors="ignore") for s in re.findall(rb"[ -~]{4,}", data)]
        txt = chr(10).join(strings)
        if re.search(r"\schtasks\b", txt, re.I):
            result["reasons"].append("Uses schtasks (persistence indicator)")
            result["verdict"] = "BLOCK"
        if re.search(r"/create\s+.*\s+onlogon", txt, re.I):
            result["reasons"].append("/sc onlogon detected (logon persistence)")
            result["verdict"] = "BLOCK"
    except (PermissionError, OSError):
        pass

    # 6. Set timestamp
    from datetime import datetime, timezone
    result["scanned_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    return result


def _decide_verdict(current: str, higher: str) -> str:
    """Elevate verdict if higher-severity condition applies.

    Precedence: BLOCK > QUARANTINE > WARN > ALLOW
    """
    order = {"ALLOW": 0, "WARN": 1, "QUARANTINE": 2, "BLOCK": 3}
    if order.get(higher, 0) > order.get(current, 0):
        return higher
    return current


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()