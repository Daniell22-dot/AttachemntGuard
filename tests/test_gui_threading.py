import os
import time
from collections import deque

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PyQt6.QtCore import QEventLoop, Qt, QTimer
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import QApplication

import workers.scan_worker as scan_worker_module
from ui.main_window import MainWindow
from ui.scan_table_model import ScanTableModel
from workers.scan_manager import ScanManager
from workers.scan_worker import ScanWorker


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


def test_worker_emits_finished_once(monkeypatch, safe_txt):
    monkeypatch.setattr(
        scan_worker_module,
        "scan_file",
        lambda path, clamav=None: {"verdict": "ALLOW", "reasons": []},
    )
    worker = ScanWorker(str(safe_txt))
    finished = []
    failed = []
    worker.finished.connect(finished.append)
    worker.failed.connect(failed.append)

    worker.run()

    assert len(finished) == 1
    assert failed == []
    assert worker.last_result["verdict"] == "ALLOW"


def test_worker_emits_failed_on_exception(monkeypatch, safe_txt):
    def explode(path, clamav=None):
        raise RuntimeError("boom")

    monkeypatch.setattr(scan_worker_module, "scan_file", explode)
    worker = ScanWorker(str(safe_txt))
    failed = []
    worker.failed.connect(failed.append)

    worker.run()

    assert len(failed) == 1
    assert failed[0].startswith("RuntimeError: boom")
    assert worker.last_result is None


def test_cancellation_prevents_completion(monkeypatch, safe_txt):
    def cancel_during_scan(path, clamav=None):
        worker.cancel()
        return {"verdict": "ALLOW", "reasons": []}

    monkeypatch.setattr(scan_worker_module, "scan_file", cancel_during_scan)
    worker = ScanWorker(str(safe_txt))
    finished = []
    cancelled = []
    worker.finished.connect(finished.append)
    worker.cancelled.connect(lambda: cancelled.append(True))

    worker.run()

    assert finished == []
    assert cancelled == [True]
    assert worker.last_result is None


def test_worker_post_processes_in_worker_thread(monkeypatch, tmp_path, safe_txt):
    monkeypatch.setattr(
        scan_worker_module,
        "scan_file",
        lambda path, clamav=None: {
            "verdict": "BLOCK",
            "reasons": ["bad"],
            "file": "sample.exe",
            "file_path": str(safe_txt),
            "sha256": "abc",
            "size_bytes": 1,
            "detected_mime_type": "application/octet-stream",
            "scanned_at": "2026-11-24T00:00:00Z",
        },
    )
    captured = {}
    monkeypatch.setattr(
        scan_worker_module,
        "quarantine_file",
        lambda source, directory, result: str(tmp_path / "quarantined.exe"),
    )
    monkeypatch.setattr(
        scan_worker_module,
        "write_report",
        lambda result, directory: str(tmp_path / "report.json"),
    )
    monkeypatch.setattr(scan_worker_module, "append_log", lambda result, path: None)
    monkeypatch.setattr(
        scan_worker_module,
        "record_scan",
        lambda **kwargs: captured.update(kwargs),
    )
    worker = ScanWorker(
        str(safe_txt),
        quarantine_dir=str(tmp_path / "quarantine"),
        reports_dir=str(tmp_path / "reports"),
        log_path=str(tmp_path / "logs" / "guard.log"),
        record_history=True,
    )
    results = []
    worker.finished.connect(results.append)

    worker.run()

    assert results[0]["quarantined"] is True
    assert results[0]["report_path"].endswith("report.json")
    assert captured["verdict"] == "BLOCK"
    assert captured["report_path"].endswith("report.json")


def test_manager_cleans_up_after_completion(qapp, monkeypatch, tmp_path):
    monkeypatch.setattr(
        scan_worker_module,
        "scan_file",
        lambda path, clamav=None: {"verdict": "ALLOW", "reasons": []},
    )
    sample = tmp_path / "sample.txt"
    sample.write_text("safe", encoding="utf-8")
    manager = ScanManager()
    finished = []
    manager.scan_finished.connect(finished.append)

    loop = QEventLoop()
    timer = QTimer()
    timer.setSingleShot(True)
    timer.timeout.connect(loop.quit)
    manager.scan_finished.connect(lambda result: loop.quit())
    timer.start(5000)
    QTimer.singleShot(0, lambda: manager.start_scan(str(sample)))
    loop.exec()

    qapp.processEvents()
    assert len(finished) == 1
    assert manager._active == []
    assert manager._thread is None
    assert manager._worker is None


def test_manager_stop_clears_pending(qapp, monkeypatch, tmp_path):
    def slow_scan(path, clamav=None):
        time.sleep(0.3)
        return {"verdict": "ALLOW", "reasons": []}

    monkeypatch.setattr(scan_worker_module, "scan_file", slow_scan)
    sample = tmp_path / "sample.txt"
    sample.write_text("safe", encoding="utf-8")
    manager = ScanManager()
    manager.start_scan(str(sample))
    manager.start_scan(str(sample))
    qapp.processEvents()

    manager.stop()

    assert manager._pending == deque()
    assert manager._active == []
    assert manager._thread is None


def test_table_model_exposes_report_and_warning_color(qapp):
    model = ScanTableModel()
    model.add_result(
        {
            "file": "bad.exe",
            "verdict": "BLOCK",
            "size_bytes": 10,
            "sha256": "abc",
            "detected_mime_type": "application/octet-stream",
            "reasons": ["bad"],
            "scanned_at": "now",
            "quarantined": True,
            "report_path": "D:/reports/bad.json",
        }
    )
    index = model.index(0, 1)

    assert model.rowCount() == 1
    assert model.report_path(0) == "D:/reports/bad.json"
    assert model.data(index) == "BLOCK"
    assert model.data(index, role=Qt.ItemDataRole.BackgroundRole) is not None
    assert model.data(model.index(0, 0)) == "bad.exe"


def test_main_window_opens_selected_report(qapp, monkeypatch, tmp_path):
    manager = ScanManager()
    window = MainWindow(root=tmp_path, scan_manager=manager)
    report = tmp_path / "reports" / "report.json"
    report.parent.mkdir(parents=True)
    report.write_text("{}", encoding="utf-8")
    window.table_model.add_result(
        {
            "file": "safe.txt",
            "verdict": "ALLOW",
            "reasons": [],
            "report_path": str(report),
            "size_bytes": 1,
            "sha256": "a",
            "detected_mime_type": "text/plain",
            "scanned_at": "now",
        }
    )
    window.table_view.selectRow(0)
    opened = []
    monkeypatch.setattr(QDesktopServices, "openUrl", lambda url: opened.append(url.toString()))

    window.open_report_btn.click()

    assert len(opened) == 1
    assert opened[0].startswith("file:///")
    window.close()


def test_main_window_watches_and_enqueues_new_files(qapp, tmp_path):
    manager = ScanManager()
    window = MainWindow(root=tmp_path, scan_manager=manager)
    folder = tmp_path / "downloads"
    folder.mkdir()
    sample = folder / "new.txt"
    sample.write_text("new", encoding="utf-8")
    enqueued = []
    manager.start_scan = enqueued.append

    window._on_folder_scan_finished(str(folder), [str(sample)])

    assert str(folder) in window._watcher.directories()
    assert str(sample) in window._watcher.files()
    assert enqueued == [str(sample)]
    window.close()


def test_quarantined_path_is_not_rescanned(qapp, tmp_path):
    manager = ScanManager()
    window = MainWindow(root=tmp_path, scan_manager=manager)
    sample = tmp_path / "bad.exe"
    enqueued = []
    manager.start_scan = enqueued.append

    window._on_scan_finished(
        {
            "file": "bad.exe",
            "verdict": "BLOCK",
            "reasons": ["bad"],
            "file_path": str(sample),
            "quarantined": True,
        }
    )
    window._on_file_changed(str(sample))
    window._on_folder_scan_finished(str(tmp_path), [str(sample)])

    assert enqueued == []
    window.close()
