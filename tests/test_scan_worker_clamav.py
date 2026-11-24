from pathlib import Path

from core.clamav_service import ClamAvResult, ClamAvUnavailable
import workers.scan_worker as scan_worker_module
from workers.scan_worker import ScanWorker


class FakeClamAv:
    def __init__(self, verdict="ALLOW", signature=None, error=None, error_text=None):
        self.verdict = verdict
        self.signature = signature
        self.error = error
        self.error_text = error_text
        self.scanned_path = None

    def scan(self, path: Path) -> ClamAvResult:
        self.scanned_path = path
        if self.error is not None:
            raise self.error
        return ClamAvResult(
            engine="fake-clamav",
            exit_code=2 if self.verdict == "QUARANTINE" else 0,
            verdict=self.verdict,
            signature=self.signature,
            raw_output="",
            timed_out=self.error_text == "ClamAV scan timed out",
            error=self.error_text,
        )


def run_worker(worker: ScanWorker) -> dict:
    worker.run()
    return worker.last_result


def test_clean_file_remains_allowed(safe_txt):
    service = FakeClamAv()
    worker = ScanWorker(str(safe_txt), clamav=service)

    result = run_worker(worker)

    assert result["verdict"] == "ALLOW"
    assert result["clamav"]["verdict"] == "ALLOW"
    assert service.scanned_path == safe_txt


def test_clamav_detection_blocks_clean_local_result(safe_txt):
    worker = ScanWorker(
        str(safe_txt),
        clamav=FakeClamAv(verdict="BLOCK", signature="Test.Sig"),
    )

    result = run_worker(worker)

    assert result["verdict"] == "BLOCK"
    assert any("ClamAV detected" in reason for reason in result["reasons"])


def test_local_block_cannot_be_downgraded(fake_image_jext):
    worker = ScanWorker(str(fake_image_jext), clamav=FakeClamAv())

    result = run_worker(worker)

    assert result["verdict"] == "BLOCK"
    assert result["clamav"]["verdict"] == "ALLOW"


def test_timeout_is_quarantined(safe_txt):
    worker = ScanWorker(
        str(safe_txt),
        clamav=FakeClamAv(
            verdict="QUARANTINE",
            error_text="ClamAV scan timed out",
        ),
    )

    result = run_worker(worker)

    assert result["verdict"] == "QUARANTINE"
    assert result["clamav"]["timed_out"] is True
    assert "ClamAV scan timed out" in result["reasons"]


def test_unavailable_scanner_is_quarantined(safe_txt):
    worker = ScanWorker(
        str(safe_txt),
        clamav=FakeClamAv(error=ClamAvUnavailable("executable not found")),
    )

    result = run_worker(worker)

    assert result["verdict"] == "QUARANTINE"
    assert any("ClamAV unavailable" in reason for reason in result["reasons"])


def test_manager_service_is_passed_to_core_scanner(safe_txt, monkeypatch):
    service = FakeClamAv()
    captured = {}

    def fake_scan_file(path, clamav=None):
        captured["clamav"] = clamav
        return {"verdict": "ALLOW", "reasons": []}

    monkeypatch.setattr(scan_worker_module, "scan_file", fake_scan_file)
    worker = ScanWorker(str(safe_txt), clamav=service)

    result = run_worker(worker)

    assert captured["clamav"] is service
    assert result == {"verdict": "ALLOW", "reasons": []}
