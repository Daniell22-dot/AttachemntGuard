from pathlib import Path

from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot

from core.scanner import scan_file


class ScanWorker(QObject):
    started = pyqtSignal(str)
    progress = pyqtSignal(int)
    finished = pyqtSignal(dict)
    failed = pyqtSignal(str)
    cancelled = pyqtSignal()

    def __init__(self, file_path: str, clamav=None):
        super().__init__()
        self.file_path = Path(file_path)
        self.clamav = clamav
        self.last_result = None
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    @pyqtSlot()
    def run(self):
        try:
            self.started.emit(self.file_path.name)
            self.progress.emit(10)

            result = scan_file(self.file_path, clamav=self.clamav)
            self.progress.emit(50)

            if self._cancelled:
                self.cancelled.emit()
                return

            self.progress.emit(100)
            self.last_result = result
            self.finished.emit(result)

        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")
