from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import QObject, QThread, pyqtSignal

from workers.folder_scan_worker import FolderScanWorker
from workers.scan_worker import ScanWorker


@dataclass
class _ScanSlot:
    path: str
    thread: QThread
    worker: ScanWorker
    done: bool = False


@dataclass
class _FolderSlot:
    folder: str
    thread: QThread
    worker: FolderScanWorker
    done: bool = False


class ScanManager(QObject):
    MAX_CONCURRENT = 2

    scan_started = pyqtSignal(str)
    scan_progress = pyqtSignal(str, int)
    scan_finished = pyqtSignal(dict)
    scan_failed = pyqtSignal(str, str)
    scan_cancelled = pyqtSignal(str)
    folder_scan_finished = pyqtSignal(str, list)
    folder_scan_failed = pyqtSignal(str, str)
    queue_size_changed = pyqtSignal(int)

    def __init__(
        self,
        parent=None,
        clamav=None,
        *,
        quarantine_dir=None,
        reports_dir=None,
        log_path=None,
        record_history: bool = False,
    ):
        super().__init__(parent)
        self.clamav = clamav
        self.scan_options = {
            "quarantine_dir": str(quarantine_dir) if quarantine_dir else None,
            "reports_dir": str(reports_dir) if reports_dir else None,
            "log_path": str(log_path) if log_path else None,
            "record_history": record_history,
        }
        self._pending: deque[str] = deque()
        self._active: list[_ScanSlot] = []
        self._draining: list[object] = []
        self._pending_folders: deque[str] = deque()
        self._folder_slot: Optional[_FolderSlot] = None
        self._thread: Optional[QThread] = None
        self._worker: Optional[ScanWorker] = None

    def start_scan(self, file_path: str) -> None:
        path = str(Path(file_path))
        if path in self._pending:
            return
        if any(slot.path == path and not slot.done for slot in self._active):
            return

        self._pending.append(path)
        self._pump()

    def scan_folder(self, folder: str) -> None:
        path = str(Path(folder))
        if path in self._pending_folders:
            return
        if self._folder_slot and self._folder_slot.folder == path and not self._folder_slot.done:
            return

        self._pending_folders.append(path)
        self._start_next_folder()

    def stop(self) -> None:
        self._pending.clear()
        self.queue_size_changed.emit(0)

        for slot in list(self._active):
            slot.worker.cancel()
            slot.thread.quit()
        for slot in list(self._active):
            if slot.thread.wait(5000):
                continue
            if slot in self._active:
                self._active.remove(slot)
            self._draining.append(slot)
        self._active.clear()

        if self._folder_slot is not None:
            slot = self._folder_slot
            slot.worker.cancel()
            slot.thread.quit()
            if not slot.thread.wait(5000):
                self._draining.append(slot)
            self._folder_slot = None

        self._pending_folders.clear()
        self._sync_legacy_handles()

    def _pump(self) -> None:
        while self._active and self._active[0].done:
            self._active.pop(0)
        while len(self._active) < self.MAX_CONCURRENT and self._pending:
            self._start_scan(self._pending.popleft())
        self.queue_size_changed.emit(len(self._pending))
        self._sync_legacy_handles()

    def _start_scan(self, path: str) -> None:
        thread = QThread(self)
        worker = ScanWorker(path, clamav=self.clamav, **self.scan_options)
        worker.moveToThread(thread)
        slot = _ScanSlot(path=path, thread=thread, worker=worker)
        self._active.append(slot)

        thread.started.connect(worker.run)
        worker.started.connect(
            lambda file_name, scan_path=path: self._on_worker_started(scan_path, file_name)
        )
        worker.progress.connect(
            lambda value, scan_path=path: self._on_worker_progress(scan_path, value)
        )
        worker.finished.connect(
            lambda result, scan_slot=slot: self._on_worker_finished(scan_slot, result)
        )
        worker.failed.connect(
            lambda error, scan_slot=slot: self._on_worker_failed(scan_slot, error)
        )
        worker.cancelled.connect(
            lambda scan_slot=slot: self._on_worker_cancelled(scan_slot)
        )

        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        worker.cancelled.connect(thread.quit)

        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(lambda scan_slot=slot: self._on_thread_finished(scan_slot))
        thread.start()

    def _complete_slot(self, slot: _ScanSlot) -> bool:
        if slot.done:
            return False
        slot.done = True
        if slot in self._active:
            self._active.remove(slot)
        return True

    def _on_worker_started(self, path: str, file_name: str) -> None:
        self.scan_started.emit(file_name)

    def _on_worker_progress(self, path: str, value: int) -> None:
        self.scan_progress.emit(Path(path).name, value)

    def _on_worker_finished(self, slot: _ScanSlot, result: dict) -> None:
        if not self._complete_slot(slot):
            return
        self.scan_finished.emit(result)
        self._pump()

    def _on_worker_failed(self, slot: _ScanSlot, error: str) -> None:
        if not self._complete_slot(slot):
            return
        self.scan_failed.emit(error, slot.path)
        self._pump()

    def _on_worker_cancelled(self, slot: _ScanSlot) -> None:
        if not self._complete_slot(slot):
            return
        self.scan_cancelled.emit(slot.path)
        self._pump()

    def _on_thread_finished(self, slot: _ScanSlot) -> None:
        if slot in self._active:
            self._active.remove(slot)
        if slot in self._draining:
            self._draining.remove(slot)
        self._sync_legacy_handles()

    def _start_next_folder(self) -> None:
        if self._folder_slot is not None or not self._pending_folders:
            return

        folder = self._pending_folders.popleft()
        thread = QThread(self)
        worker = FolderScanWorker(folder)
        worker.moveToThread(thread)
        slot = _FolderSlot(folder=folder, thread=thread, worker=worker)
        self._folder_slot = slot

        thread.started.connect(worker.run)
        worker.files_found.connect(
            lambda found_folder, files, folder_slot=slot: self._on_folder_files(
                folder_slot, found_folder, files
            )
        )
        worker.failed.connect(
            lambda failed_folder, error, folder_slot=slot: self._on_folder_failed(
                folder_slot, failed_folder, error
            )
        )
        worker.files_found.connect(thread.quit)
        worker.failed.connect(thread.quit)

        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(lambda folder_slot=slot: self._on_folder_thread_finished(folder_slot))
        thread.start()

    def _complete_folder(self, slot: _FolderSlot) -> bool:
        if slot.done:
            return False
        slot.done = True
        if self._folder_slot is slot:
            self._folder_slot = None
        return True

    def _on_folder_files(self, slot: _FolderSlot, folder: str, files: list) -> None:
        if not self._complete_folder(slot):
            return
        self.folder_scan_finished.emit(folder, files)
        self._start_next_folder()

    def _on_folder_failed(self, slot: _FolderSlot, folder: str, error: str) -> None:
        if not self._complete_folder(slot):
            return
        self.folder_scan_failed.emit(folder, error)
        self._start_next_folder()

    def _on_folder_thread_finished(self, slot: _FolderSlot) -> None:
        if self._folder_slot is slot:
            self._folder_slot = None
        if slot in self._draining:
            self._draining.remove(slot)

    def _sync_legacy_handles(self) -> None:
        if self._active:
            self._thread = self._active[0].thread
            self._worker = self._active[0].worker
        else:
            self._thread = None
            self._worker = None
