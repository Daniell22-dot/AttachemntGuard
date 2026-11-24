from pathlib import Path
from typing import Any, Optional

from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot

from core.quarantine_service import quarantine_file
from core.report_writer import append_log, write_report
from core.scan_history import record_scan
from core.scanner import scan_file


class ScanWorker(QObject):
    started = pyqtSignal(str)
    progress = pyqtSignal(int)
    finished = pyqtSignal(dict)
    failed = pyqtSignal(str)
    cancelled = pyqtSignal()

    def __init__(
        self,
        file_path: str,
        clamav=None,
        *,
        quarantine_dir: Optional[str] = None,
        reports_dir: Optional[str] = None,
        log_path: Optional[str] = None,
        record_history: bool = False,
    ):
        super().__init__()
        self.file_path = Path(file_path)
        self.clamav = clamav
        self.quarantine_dir = quarantine_dir
        self.reports_dir = reports_dir
        self.log_path = log_path
        self.record_history = record_history
        self.last_result: Optional[dict[str, Any]] = None
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    @pyqtSlot()
    def run(self) -> None:
        try:
            self.started.emit(self.file_path.name)
            self.progress.emit(10)

            result = scan_file(self.file_path, clamav=self.clamav)
            self.progress.emit(50)

            if self._cancelled:
                self.cancelled.emit()
                return

            self._finalize_result(result)
            self.progress.emit(100)

            if self._cancelled:
                self.cancelled.emit()
                return

            self.last_result = result
            self.finished.emit(result)

        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")

    def _finalize_result(self, result: dict[str, Any]) -> None:
        if self.quarantine_dir and result.get("verdict") in {"BLOCK", "QUARANTINE"}:
            self._quarantine_result(result)

        if self.reports_dir:
            report_path = write_report(result, Path(self.reports_dir))
            if report_path:
                result["report_path"] = report_path

        if self.log_path:
            append_log(result, Path(self.log_path))

        if self.record_history:
            record_scan(
                sha256=result.get("sha256", ""),
                file_name=result.get("file", self.file_path.name),
                file_path=result.get("file_path", result.get("path", str(self.file_path))),
                verdict=result.get("verdict", "UNKNOWN"),
                detected_mime_type=result.get("detected_mime_type", "unknown"),
                size_bytes=int(result.get("size_bytes", 0) or 0),
                reasons=list(result.get("reasons", [])),
                scanned_at=result.get("scanned_at", ""),
                scanner_version=result.get("scanner_version", "0.1.0"),
                quarantine=result.get("quarantine_path") or None,
                report_path=result.get("report_path"),
            )

    def _quarantine_result(self, result: dict[str, Any]) -> None:
        source = Path(result.get("file_path", result.get("path", str(self.file_path))))
        try:
            quarantined_to = quarantine_file(source, Path(self.quarantine_dir), result)
        except Exception as exc:
            result["status"] = "QUARANTINE_FAILED"
            result["reasons"].append(f"Quarantine failed: {type(exc).__name__}")
            return

        if quarantined_to:
            result["quarantined"] = True
            result["quarantine_path"] = quarantined_to
            result["quarantined_to"] = quarantined_to
        else:
            result["status"] = "QUARANTINE_FAILED"
            result["reasons"].append("Quarantine failed")
