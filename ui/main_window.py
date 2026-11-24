from pathlib import Path
from typing import Optional

from PyQt6.QtCore import QFileSystemWatcher, QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QProgressBar,
    QPushButton,
    QStatusBar,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from core.clamav_service import build_clamav_service
from ui.scan_table_model import ScanTableModel
from workers.scan_manager import ScanManager


class MainWindow(QMainWindow):
    def __init__(self, root: Optional[Path] = None, scan_manager: Optional[ScanManager] = None):
        super().__init__()
        self.root = Path(root) if root is not None else Path(__file__).resolve().parents[1]
        self.reports_dir = self.root / "reports"
        self.quarantine_dir = self.root / "quarantine"
        self.log_path = self.root / "logs" / "attachmentguard.log"
        self._known_files: set[str] = set()
        self._retired_paths: set[str] = set()

        self.setWindowTitle("AttachmentGuard")
        self.resize(1100, 650)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        button_row = QHBoxLayout()
        self.folder_btn = QPushButton("Select Folder to Monitor")
        self.folder_btn.clicked.connect(self.select_folder)
        button_row.addWidget(self.folder_btn)

        self.open_report_btn = QPushButton("Open Report")
        self.open_report_btn.clicked.connect(self._open_selected_report)
        button_row.addWidget(self.open_report_btn)

        self.stop_btn = QPushButton("Stop Monitoring")
        self.stop_btn.clicked.connect(self._stop_monitoring)
        self.stop_btn.setEnabled(False)
        button_row.addWidget(self.stop_btn)
        layout.addLayout(button_row)

        self.folder_label = QLabel("No folder selected")
        layout.addWidget(self.folder_label)

        self.table_model = ScanTableModel()
        self.table_view = QTableView()
        self.table_view.setModel(self.table_model)
        self.table_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table_view.doubleClicked.connect(self._open_selected_report)
        self.table_view.horizontalHeader().setStretchLastSection(True)
        self.table_view.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.table_view.verticalHeader().setVisible(False)
        layout.addWidget(self.table_view)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        layout.addWidget(self.progress_bar)

        self.pending_label = QLabel("Queued: 0")
        layout.addWidget(self.pending_label)

        self.quarantine_label = QLabel(f"Quarantine: {self.quarantine_dir}")
        layout.addWidget(self.quarantine_label)

        clamav = getattr(scan_manager, "clamav", None) if scan_manager is not None else None
        if scan_manager is None:
            clamav = build_clamav_service(self.root / "config.ini")
        clamav_status = "enabled" if clamav is not None else "disabled"
        self.clamav_label = QLabel(f"ClamAV: {clamav_status}")
        layout.addWidget(self.clamav_label)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

        self._watcher = QFileSystemWatcher(self)
        self._watcher.directoryChanged.connect(self._on_directory_changed)
        self._watcher.fileChanged.connect(self._on_file_changed)

        if scan_manager is None:
            scan_manager = ScanManager(
                self,
                clamav=clamav,
                quarantine_dir=self.quarantine_dir,
                reports_dir=self.reports_dir,
                log_path=self.log_path,
                record_history=True,
            )
        self.scan_manager = scan_manager
        self.scan_manager.scan_started.connect(self._on_scan_started)
        self.scan_manager.scan_progress.connect(self._on_scan_progress)
        self.scan_manager.scan_finished.connect(self._on_scan_finished)
        self.scan_manager.scan_failed.connect(self._on_scan_failed)
        self.scan_manager.scan_cancelled.connect(self._on_scan_cancelled)
        self.scan_manager.folder_scan_finished.connect(self._on_folder_scan_finished)
        self.scan_manager.folder_scan_failed.connect(self._on_folder_scan_failed)
        self.scan_manager.queue_size_changed.connect(self._on_queue_size_changed)

    def select_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Monitor")
        if not folder:
            return

        folder_path = str(Path(folder).resolve())
        self._clear_watch_paths()
        self._known_files.clear()
        self._retired_paths.clear()
        self.folder_label.setText(folder_path)
        self._watch_directory(folder_path)
        self.scan_manager.scan_folder(folder_path)
        self.stop_btn.setEnabled(True)
        self.status_bar.showMessage(f"Monitoring: {folder_path}")

    def _on_directory_changed(self, path: str) -> None:
        self.scan_manager.scan_folder(path)

    def _on_file_changed(self, path: str) -> None:
        if path in self._retired_paths:
            return
        self._watch_file(path)
        self.scan_manager.start_scan(path)

    def _on_folder_scan_finished(self, folder: str, files: list) -> None:
        self._watch_directory(folder)
        for file_path in files:
            self._watch_file(file_path)
            if file_path in self._retired_paths:
                continue
            if file_path not in self._known_files:
                self._known_files.add(file_path)
                self.scan_manager.start_scan(file_path)

    def _on_folder_scan_failed(self, folder: str, error: str) -> None:
        self.status_bar.showMessage(f"Folder scan failed ({folder}): {error}")

    def _on_scan_started(self, file_name: str) -> None:
        self.progress_bar.setValue(0)
        self.status_bar.showMessage(f"Scanning started: {file_name}")

    def _on_scan_progress(self, file_name: str, value: int) -> None:
        self.progress_bar.setValue(value)
        self.status_bar.showMessage(f"Scanning {file_name}: {value}%")

    def _on_scan_finished(self, result: dict) -> None:
        if result.get("quarantined"):
            original = result.get("file_path", result.get("path", ""))
            if original:
                self._retired_paths.add(str(Path(original)))
        self.table_model.add_result(result)
        self.table_view.resizeColumnToContents(0)
        verdict = result.get("verdict", "ALLOW")
        file_name = result.get("file", "unknown")
        reasons = result.get("reasons", [])
        reason_str = "; ".join(reasons) if reasons else "No issues detected"
        self.status_bar.showMessage(f"{verdict}: {file_name} — {reason_str}")

    def _on_scan_failed(self, error: str, file_path: str) -> None:
        self.status_bar.showMessage(f"Scan failed ({Path(file_path).name}): {error}")
        self.progress_bar.setValue(0)

    def _on_scan_cancelled(self, file_path: str) -> None:
        self.status_bar.showMessage(f"Scan cancelled: {Path(file_path).name}")
        self.progress_bar.setValue(0)

    def _on_queue_size_changed(self, count: int) -> None:
        self.pending_label.setText(f"Queued: {count}")

    def _open_selected_report(self) -> None:
        index = self.table_view.currentIndex()
        if not index.isValid():
            self.status_bar.showMessage("Select a scan result first")
            return

        report_path = self.table_model.report_path(index.row())
        if not report_path:
            self.status_bar.showMessage("No report is available for this result")
            return

        QDesktopServices.openUrl(QUrl.fromLocalFile(report_path))
        self.status_bar.showMessage(f"Opening report: {Path(report_path).name}")

    def _watch_directory(self, path: str) -> None:
        if path not in self._watcher.directories():
            self._watcher.addPath(path)

    def _watch_file(self, path: str) -> None:
        if path not in self._watcher.files():
            self._watcher.addPath(path)

    def _clear_watch_paths(self) -> None:
        for path in self._watcher.directories() + self._watcher.files():
            self._watcher.removePath(path)

    def _stop_monitoring(self) -> None:
        self.scan_manager.stop()
        self._clear_watch_paths()
        self._known_files.clear()
        self._retired_paths.clear()
        self.stop_btn.setEnabled(False)
        self.folder_label.setText("No folder selected")
        self.progress_bar.setValue(0)
        self.pending_label.setText("Queued: 0")
        self.status_bar.showMessage("Monitoring stopped")

    def closeEvent(self, event) -> None:
        self._stop_monitoring()
        super().closeEvent(event)
