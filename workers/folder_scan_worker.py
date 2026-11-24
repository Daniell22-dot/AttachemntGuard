from pathlib import Path

from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot


class FolderScanWorker(QObject):
    files_found = pyqtSignal(str, list)
    failed = pyqtSignal(str, str)

    def __init__(self, folder: str):
        super().__init__()
        self.folder = Path(folder)
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    @pyqtSlot()
    def run(self) -> None:
        folder = str(self.folder)
        try:
            files = [
                str(item.resolve())
                for item in sorted(self.folder.iterdir())
                if item.is_file()
            ]
        except OSError as exc:
            self.failed.emit(folder, f"{type(exc).__name__}: {exc}")
            return

        if self._cancelled:
            return

        self.files_found.emit(folder, files)
