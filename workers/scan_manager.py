from pathlib import Path

from PyQt6.QtCore import QObject, QThread, pyqtSignal

from workers.scan_worker import ScanWorker


class ScanManager(QObject):
    scan_started = pyqtSignal(str)
    scan_progress = pyqtSignal(str, int)
    scan_finished = pyqtSignal(dict)
    scan_failed = pyqtSignal(str, str)
    scan_cancelled = pyqtSignal(str)

    def __init__(self, parent=None, clamav=None):
        super().__init__(parent)
        self._thread = None
        self._worker = None
        self._current_file = ""
        self.clamav = clamav

    def start_scan(self, file_path: str):
        self.stop()

        self._current_file = Path(file_path).name
        self._thread = QThread(self)
        self._worker = ScanWorker(file_path, clamav=self.clamav)
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)

        self._worker.started.connect(self._on_worker_started)
        self._worker.progress.connect(self._on_worker_progress)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker.failed.connect(self._on_worker_failed)
        self._worker.cancelled.connect(self._on_worker_cancelled)

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

    def _on_worker_started(self, file_name: str):
        self.scan_started.emit(file_name)

    def _on_worker_progress(self, value: int):
        self.scan_progress.emit(self._current_file, value)

    def _on_worker_finished(self, result: dict):
        self.scan_finished.emit(result)

    def _on_worker_failed(self, error: str):
        self.scan_failed.emit(self._current_file, error)

    def _on_worker_cancelled(self):
        self.scan_cancelled.emit(self._current_file)
