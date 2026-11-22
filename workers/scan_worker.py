from pathlib import Path

from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot

from core.clamav_service import ClamAvUnavailable
from core.scanner import decide_verdict, scan_file


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

            result = scan_file(self.file_path)
            self.progress.emit(50)

            if self._cancelled:
                self.cancelled.emit()
                return

            if self.clamav is not None:
                try:
                    clamav_result = self.clamav.scan(self.file_path)
                except ClamAvUnavailable as exc:
                    result["verdict"] = decide_verdict(result["verdict"], "QUARANTINE")
                    reason = f"ClamAV unavailable: {exc}"
                    if reason not in result["reasons"]:
                        result["reasons"].append(reason)
                else:
                    result["clamav"] = {
                        "engine": clamav_result.engine,
                        "exit_code": clamav_result.exit_code,
                        "verdict": clamav_result.verdict,
                        "signature": clamav_result.signature,
                        "timed_out": clamav_result.timed_out,
                    }
                    if clamav_result.verdict == "BLOCK":
                        result["verdict"] = "BLOCK"
                        reason = f"ClamAV detected: {clamav_result.signature or 'unknown signature'}"
                    elif clamav_result.verdict == "QUARANTINE":
                        result["verdict"] = decide_verdict(result["verdict"], "QUARANTINE")
                        reason = "ClamAV scan failed, timed out, or was inconclusive"
                    else:
                        reason = ""
                    if reason and reason not in result["reasons"]:
                        result["reasons"].append(reason)

            self.progress.emit(100)
            self.last_result = result
            self.finished.emit(result)

        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")
