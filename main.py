import sys
from pathlib import Path

from PyQt6.QtCore import QFileSystemWatcher
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QPushButton,
    QLabel,
    QTableView,
    QFileDialog,
    QStatusBar,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)

from core.clamav_service import build_clamav_service
from core.quarantine_service import quarantine_file
from core.report_writer import append_log, write_report
from core.scan_history import init_db, record_scan
from ui.scan_table_model import ScanTableModel
from workers.scan_manager import ScanManager

ROOT = Path(__file__).resolve().parent
REPORTS_DIR = ROOT / "reports"
LOGS_DIR = ROOT / "logs" / "attachmentguard.log"
QUARANTINE_DIR = ROOT / "quarantine"


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

        self.stop_btn = QPushButton("Stop Monitoring")
        self.stop_btn.clicked.connect(self._stop_monitoring)
        self.stop_btn.setEnabled(False)
        layout.addWidget(self.stop_btn)

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

        self.quarantine_label = QLabel(f"Quarantine: {QUARANTINE_DIR}")
        layout.addWidget(self.quarantine_label)

        clamav = build_clamav_service(ROOT / "config.ini")
        clamav_status = "enabled" if clamav is not None else "disabled (config.ini)"
        self.clamav_label = QLabel(f"ClamAV: {clamav_status}")
        layout.addWidget(self.clamav_label)

        self._watcher = None
        self.scan_manager = ScanManager(self, clamav=clamav)
        self.scan_manager.scan_started.connect(self._on_scan_started)
        self.scan_manager.scan_progress.connect(self._on_scan_progress)
        self.scan_manager.scan_finished.connect(self._on_scan_finished)
        self.scan_manager.scan_failed.connect(self._on_scan_failed)
        self.scan_manager.scan_cancelled.connect(self._on_scan_cancelled)

    def select_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Monitor")
        if not folder:
            return

        folder_path = str(Path(folder).resolve())
        self.folder_label.setText(folder_path)
        self._scan_existing_files(folder_path)

        if self._watcher is None:
            self._watcher = QFileSystemWatcher()
            self._watcher.fileChanged.connect(
                lambda path: self.scan_manager.start_scan(path)
            )
        if folder_path not in self._watcher.paths():
            self._watcher.addPath(folder_path)

        self.stop_btn.setEnabled(True)

    def _scan_existing_files(self, folder_path: str):
        for item in sorted(Path(folder_path).iterdir()):
            if item.is_file():
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

        if verdict in ("BLOCK", "QUARANTINE") and not result.get("quarantined"):
            self._quarantine_file(result)

        report_path = write_report(result, REPORTS_DIR)
        if report_path:
            result["report_path"] = report_path
        append_log(result, LOGS_DIR)

        init_db()
        record_scan(
            sha256=sha256,
            file_name=file_name,
            file_path=result.get("file_path", result.get("path", "")),
            verdict=verdict,
            detected_mime_type=mime,
            size_bytes=size,
            reasons=reasons,
            scanned_at=result.get("scanned_at", ""),
            scanner_version=result.get("scanner_version", "0.1.0"),
            quarantine=result.get("quarantine_path") or None,
            report_path=report_path,
        )

        self.table_model._data.append([
            file_name,
            verdict,
            size,
            sha256,
            mime,
            " | ".join(reasons) if reasons else "",
            result.get("scanned_at", ""),
            "Quarantined" if result.get("quarantined") else "Retained",
        ])
        self.table_model.layoutChanged.emit()

        reason_str = "; ".join(reasons) if reasons else "No issues detected"
        self.status_bar.showMessage(f"{verdict}: {file_name} — {reason_str}")

    def _quarantine_file(self, result: dict):
        source = Path(result.get("file_path", result.get("path", "")))
        quarantined_to = quarantine_file(source, QUARANTINE_DIR, result)
        if quarantined_to:
            result["quarantined"] = True
            result["quarantine_path"] = quarantined_to
            result["quarantined_to"] = quarantined_to
        else:
            result["reasons"].append("Quarantine failed")

    def _on_scan_failed(self, error: str, file_path: str):
        self.status_bar.showMessage(f"Scan failed: {error}")
        self.progress_bar.setValue(0)

    def _on_scan_cancelled(self, file_path: str):
        self.status_bar.showMessage(f"Scan cancelled: {file_path}")
        self.progress_bar.setValue(0)

    def _stop_monitoring(self):
        self.scan_manager.stop()
        self.stop_btn.setEnabled(False)
        self.folder_label.setText("No folder selected")
        if self._watcher is not None:
            for path in self._watcher.paths():
                self._watcher.removePath(path)
            try:
                self._watcher.fileChanged.disconnect()
            except (TypeError, RuntimeError):
                pass

    def closeEvent(self, event):
        self._stop_monitoring()
        super().closeEvent(event)


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
