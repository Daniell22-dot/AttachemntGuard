from pathlib import Path

import pytest
from PyQt6.QtCore import QCoreApplication, QThread, pyqtSlot

from core.clamav_service import ClamAvResult
from workers.scan_worker import ScanWorker
from tests.conftest import make_result


class FakeClamAv:
    def __init__(self, result: ClamAvResult):
        self.result = result

    def scan(self, path: Path) -> ClamAvResult:
        return self.result


def run_worker(qtbot, worker: ScanWorker) -> dict:
    thread = QThread()
    worker.moveToThread(thread)

    with qtbot.waitSignal(
        worker.finished,
        timeout=10000,
        raising=True,
    ):
        thread.started.connect(worker.run)
        thread.start()

    thread.quit()
    thread.wait(5000)

    return worker.last_result


def test_clean_file_remains_allowed(qtbot, safe_txt, monkeypatch):
    worker = ScanWorker(str(safe_txt))
    worker.clamav = FakeClamAv(
        make_result(exit_code=0, verdict="ALLOW", raw_output="OK")
    )

    result = run_worker(qtbot, worker)

    assert result["verdict"] == "ALLOW"
    assert result["clamav"]["verdict"] == "ALLOW"


def test_clamav_detection_blocks_clean_local_result(
    qtbot,
    safe_txt,
    monkeypatch,
):
    worker = ScanWorker(str(safe_txt))
    worker.clamav = FakeClamAv(
        make_result(
            exit_code=1,
            verdict="BLOCK",
            signature="Test.Sig",
            raw_output="detected",
        )
    )

    result = run_worker(qtbot, worker)

    assert result["verdict"] == "BLOCK"
    assert any(
        "ClamAV detected" in reason
        for reason in result["reasons"]
    )


def test_local_block_cannot_be_downgraded(
    qtbot,
    safe_txt,
    monkeypatch,
):
    worker = ScanWorker(str(safe_txt))

    # Simulate a local policy BLOCK by patching the local scanner.
    def fake_scan_file(path):
        return {
            "file": path.name,
            "path": str(path),
            "size": path.stat().st_size,
            "sha256": "0" * 64,
            "extension": ".txt",
            "verdict": "BLOCK",
            "reasons": ["Blocked by local policy"],
        }

    import workers.scan_worker as sw
    monkeypatch.setattr(sw, "scan_file", fake_scan_file)

    worker.clamav = FakeClamAv(
        make_result(exit_code=0, verdict="ALLOW", raw_output="OK")
    )

    result = run_worker(qtbot, worker)

    assert result["verdict"] == "BLOCK"


def test_scanner_error_cannot_downgrade_quarantine(
    qtbot,
    safe_txt,
    monkeypatch,
):
    worker = ScanWorker(str(safe_txt))

    def fake_scan_file(path):
        return {
            "file": path.name,
            "path": str(path),
            "size": path.stat().st_size,
            "sha256": "1" * 64,
            "extension": ".zip",
            "verdict": "QUARANTINE",
            "reasons": ["Corrupt archive"],
        }

    import workers.scan_worker as sw
    monkeypatch.setattr(sw, "scan_file", fake_scan_file)

    worker.clamav = FakeClamAv(
        make_result(
            exit_code=2,
            verdict="QUARANTINE",
            raw_output="Scanner error",
        )
    )

    result = run_worker(qtbot, worker)

    assert result["verdict"] == "QUARANTINE"


def test_timeout_is_quarantined(qtbot, safe_txt):
    worker = ScanWorker(str(safe_txt))
    worker.clamav = FakeClamAv(
        make_result(
            exit_code=2,
            verdict="QUARANTINE",
            raw_output="Timed out",
            timed_out=True,
        )
    )

    result = run_worker(qtbot, worker)

    assert result["verdict"] == "QUARANTINE"
    assert result["clamav"]["verdict"] == "QUARANTINE"