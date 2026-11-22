from pathlib import Path

from core.clamav_service import ClamAvResult
from tests.conftest import make_result
from workers.scan_worker import ScanWorker


class FakeClamAv:
    def __init__(self, result: ClamAvResult):
        self.result = result

    def scan(self, path: Path) -> ClamAvResult:
        return self.result


def run_worker(worker: ScanWorker) -> dict:
    worker.run()
    return worker.last_result


def test_clean_file_remains_allowed(safe_txt):
    worker = ScanWorker(str(safe_txt))
    worker.clamav = FakeClamAv(
        make_result(exit_code=0, verdict="ALLOW", raw_output="OK")
    )

    result = run_worker(worker)

    assert result["verdict"] == "ALLOW"
    assert result["clamav"]["verdict"] == "ALLOW"


def test_clamav_detection_blocks_clean_local_result(safe_txt):
    worker = ScanWorker(str(safe_txt))
    worker.clamav = FakeClamAv(
        make_result(
            exit_code=1,
            verdict="BLOCK",
            signature="Test.Sig",
            raw_output="detected",
        )
    )

    result = run_worker(worker)

    assert result["verdict"] == "BLOCK"
    assert any(
        "ClamAV detected" in reason
        for reason in result["reasons"]
    )


def test_local_block_cannot_be_downgraded(safe_txt, monkeypatch):
    def fake_scan_file(path):
        return {
            "file": Path(path).name,
            "file_path": str(Path(path).resolve()),
            "path": str(Path(path).resolve()),
            "size_bytes": Path(path).stat().st_size,
            "sha256": "0" * 64,
            "detected_extension": ".txt",
            "detected_mime_type": "text/plain",
            "verdict": "BLOCK",
            "reasons": ["Blocked by local policy"],
            "info": {"size": Path(path).stat().st_size, "sha256": "0" * 64},
            "sniff": {},
            "extension_policy": {},
            "persistence_hits": [],
            "zip_scan": {},
            "yara": [],
            "rule_matches": [],
            "quarantined": False,
            "quarantine_path": "",
            "scanned_at": "2026-11-22T00:00:00Z",
            "scanner_version": "0.2.0",
        }

    import workers.scan_worker as scan_worker_module

    monkeypatch.setattr(scan_worker_module, "scan_file", fake_scan_file)
    worker = ScanWorker(str(safe_txt))
    worker.clamav = FakeClamAv(
        make_result(exit_code=0, verdict="ALLOW", raw_output="OK")
    )

    result = run_worker(worker)

    assert result["verdict"] == "BLOCK"


def test_scanner_error_cannot_downgrade_quarantine(safe_txt, monkeypatch):
    def fake_scan_file(path):
        return {
            "file": Path(path).name,
            "file_path": str(Path(path).resolve()),
            "path": str(Path(path).resolve()),
            "size_bytes": Path(path).stat().st_size,
            "sha256": "1" * 64,
            "detected_extension": ".zip",
            "detected_mime_type": "application/zip",
            "verdict": "QUARANTINE",
            "reasons": ["Corrupt archive"],
            "info": {"size": Path(path).stat().st_size, "sha256": "1" * 64},
            "sniff": {},
            "extension_policy": {},
            "persistence_hits": [],
            "zip_scan": {},
            "yara": [],
            "rule_matches": [],
            "quarantined": False,
            "quarantine_path": "",
            "scanned_at": "2026-11-22T00:00:00Z",
            "scanner_version": "0.2.0",
        }

    import workers.scan_worker as scan_worker_module

    monkeypatch.setattr(scan_worker_module, "scan_file", fake_scan_file)
    worker = ScanWorker(str(safe_txt))
    worker.clamav = FakeClamAv(
        make_result(
            exit_code=2,
            verdict="QUARANTINE",
            raw_output="Scanner error",
        )
    )

    result = run_worker(worker)

    assert result["verdict"] == "QUARANTINE"


def test_timeout_is_quarantined(safe_txt):
    worker = ScanWorker(str(safe_txt))
    worker.clamav = FakeClamAv(
        make_result(
            exit_code=2,
            verdict="QUARANTINE",
            raw_output="Timed out",
            timed_out=True,
        )
    )

    result = run_worker(worker)

    assert result["verdict"] == "QUARANTINE"
    assert result["clamav"]["verdict"] == "QUARANTINE"
