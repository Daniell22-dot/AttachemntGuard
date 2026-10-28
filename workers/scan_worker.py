from pathlib import Path

from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot

from core.clamav_service import ClamAvService, ClamAvUnavailable
from core.scanner import scan_file


class ScanWorker(QObject):
    progress = pyqtSignal(int)
    finished = pyqtSignal(dict)
    failed = pyqtSignal(str)
    cancelled = pyqtSignal()

    def __init__(self, file_path: str):
        super().__init__()
        self.file_path = Path(file_path)
        self.clamav = ClamAvService()
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    @pyqtSlot()
    def run(self):
        try:
            self.progress.emit(10)

            result = scan_file(self.file_path)
            self.progress.emit(50)

            if self._cancelled:
                return

            clamav_result = self.clamav.scan(self.file_path)
            self.progress.emit(85)

            result["clamav"] = {
                "engine": clamav_result.engine,
                "exit_code": clamav_result.exit_code,
                "verdict": clamav_result.verdict,
                "signature": clamav_result.signature,
                "timed_out": clamav_result.timed_out,
            }

            if clamav_result.verdict == "BLOCK":
                result["verdict"] = "BLOCK"
                result["reasons"].append(
                    f"ClamAV detected: {clamav_result.signature or 'unknown signature'}"
                )

            elif clamav_result.verdict == "QUARANTINE":
                if result["verdict"] == "ALLOW":
                    result["verdict"] = "QUARANTINE"

                result["reasons"].append(
                    "ClamAV scan failed, timed out, or was inconclusive"
                )

            self.progress.emit(100)
            self.finished.emit(result)

        except ClamAvUnavailable as exc:
            self.failed.emit(str(exc))

        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")