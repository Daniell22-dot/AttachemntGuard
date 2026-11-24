import subprocess
from pathlib import Path

import pytest

from core.clamav_service import (
    ClamAvConfig,
    ClamAvService,
    ClamAvResult,
    ClamAvUnavailable,
    build_clamav_service,
    load_clamav_config,
    resolve_executable,
)


def test_clean_result_is_allowed(monkeypatch, safe_txt):
    service = ClamAvService()

    def fake_run(self, executable, file_path, engine):
        return ClamAvResult(
            engine=engine,
            exit_code=0,
            verdict="ALLOW",
            signature=None,
            raw_output="OK",
            timed_out=False,
        )

    monkeypatch.setattr(ClamAvService, "_run", fake_run)

    result = service.scan(safe_txt)

    assert result.verdict == "ALLOW"
    assert result.exit_code == 0
    assert result.signature is None


def test_detection_is_blocked(detected_sample, monkeypatch):
    service = ClamAvService()

    def fake_run(self, executable, file_path, engine):
        return ClamAvResult(
            engine=engine,
            exit_code=1,
            verdict="BLOCK",
            signature="Test.Signature",
            raw_output="sample: Test.Signature FOUND",
            timed_out=False,
        )

    monkeypatch.setattr(ClamAvService, "_run", fake_run)

    result = service.scan(detected_sample)

    assert result.verdict == "BLOCK"
    assert result.signature == "Test.Signature"
    assert result.exit_code == 1


def test_timeout_is_quarantined(safe_txt, monkeypatch):
    service = ClamAvService()

    def fake_run(self, executable, file_path, engine):
        return ClamAvResult(
            engine=engine,
            exit_code=2,
            verdict="QUARANTINE",
            signature=None,
            raw_output="Scan timed out",
            timed_out=True,
        )

    monkeypatch.setattr(ClamAvService, "_run", fake_run)

    result = service.scan(safe_txt)

    assert result.verdict == "QUARANTINE"
    assert result.timed_out is True


def test_missing_file_raises_error(tmp_path):
    service = ClamAvService()
    missing = tmp_path / "missing.txt"

    with pytest.raises(FileNotFoundError):
        service.scan(missing)


def test_oversized_file_is_quarantined(tmp_path):
    service = ClamAvService()
    large_file = tmp_path / "large.bin"
    large_file.write_bytes(b"x" * (26 * 1024 * 1024))

    result = service.scan(large_file)

    assert result.verdict == "QUARANTINE"
    assert "exceeds configured ClamAV scan size limit" in result.raw_output


def test_clamav_error_does_not_return_allow(safe_txt, monkeypatch):
    service = ClamAvService()

    def fake_run(self, executable, file_path, engine):
        return ClamAvResult(
            engine=engine,
            exit_code=2,
            verdict="QUARANTINE",
            signature=None,
            raw_output="Unexpected scanner error",
            timed_out=False,
        )

    monkeypatch.setattr(ClamAvService, "_run", fake_run)

    result = service.scan(safe_txt)

    assert result.verdict == "QUARANTINE"


def test_both_scanners_unavailable_raises(monkeypatch):
    """Test that ClamAvUnavailable is raised when both scanners fail."""

    def fake_run(self, executable, file_path, engine):
        if executable == "clamdscan":
            raise ClamAvUnavailable("clamdscan unavailable")
        # fallthrough to clamscan which also fails
        raise ClamAvUnavailable("clamscan unavailable")

    monkeypatch.setattr(ClamAvService, "_run", fake_run)

    service = ClamAvService()

    with pytest.raises(ClamAvUnavailable):
        service.scan(Path("tests/fixtures/safe.txt"))


def test_config_defaults_to_disabled(tmp_path):
    config = load_clamav_config(tmp_path / "missing.ini")

    assert config.enabled is False
    assert config.clamdscan_path == "clamdscan"
    assert config.clamscan_path == "clamscan"
    assert config.timeout_seconds == 60


def test_config_reads_enabled_settings(tmp_path):
    config_file = tmp_path / "config.ini"
    config_file.write_text(
        "[clamav]\n"
        "enabled = true\n"
        "clamdscan_path = clamdscan\n"
        "clamscan_path = clamscan\n"
        "prefer_daemon = false\n"
        "timeout_seconds = 5\n"
        "max_file_size_mb = 3\n",
        encoding="utf-8",
    )

    config = load_clamav_config(config_file)

    assert config.enabled is True
    assert config.prefer_daemon is False
    assert config.timeout_seconds == 5
    assert config.max_file_size_mb == 3


def test_build_service_is_none_when_disabled(tmp_path):
    config_file = tmp_path / "config.ini"
    config_file.write_text("[clamav]\nenabled = false\n", encoding="utf-8")

    assert build_clamav_service(config_file) is None


def test_build_service_can_be_forced_on(tmp_path, monkeypatch):
    config_file = tmp_path / "config.ini"
    config_file.write_text("[clamav]\nenabled = false\n", encoding="utf-8")
    monkeypatch.setattr(
        "core.clamav_service.resolve_executable",
        lambda configured, name: f"/opt/clamav/{name}",
    )

    service = build_clamav_service(config_file, enabled=True)

    assert service is not None
    assert service.clamdscan_path == "/opt/clamav/clamdscan"
    assert service.clamscan_path == "/opt/clamav/clamscan"


def test_empty_paths_discover_local_install(tmp_path, monkeypatch):
    install_dir = tmp_path / "ClamAV"
    install_dir.mkdir()
    (install_dir / "clamscan.exe").write_bytes(b"")
    (install_dir / "clamdscan.exe").write_bytes(b"")
    monkeypatch.setenv("ProgramFiles", str(tmp_path))
    monkeypatch.setenv("ProgramFiles(x86)", str(tmp_path / "missing"))
    monkeypatch.setattr("core.clamav_service.shutil.which", lambda name: None)

    assert resolve_executable("", "clamscan") == str(install_dir / "clamscan.exe")


def test_timeout_is_fail_closed(safe_txt, monkeypatch):
    service = ClamAvService(ClamAvConfig(timeout_seconds=1))
    monkeypatch.setattr(
        "core.clamav_service.subprocess.run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(args[0], kwargs["timeout"])
        ),
    )

    result = service.scan(safe_txt)

    assert result.verdict == "QUARANTINE"
    assert result.timed_out is True
    assert result.error == "ClamAV scan timed out"


def test_missing_database_error_is_explained(safe_txt, monkeypatch):
    service = ClamAvService(ClamAvConfig(prefer_daemon=False))
    output = (
        "LibClamAV Error: cl_load: No such file or directory: "
        "C:\\Program Files\\ClamAV\\database\nERROR: Can't get file status"
    )
    monkeypatch.setattr(
        "core.clamav_service.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 2, "", output),
    )

    result = service.scan(safe_txt)

    assert result.verdict == "QUARANTINE"
    assert result.error and "signatures are missing" in result.error


def test_unavailable_daemon_falls_back_to_clamscan(safe_txt, monkeypatch):
    def fake_run(self, executable, file_path, engine):
        if engine == "clamdscan":
            raise ClamAvUnavailable("no daemon")
        return ClamAvResult(engine, 0, "ALLOW", None, "OK", False)

    monkeypatch.setattr(ClamAvService, "_run", fake_run)
    service = ClamAvService()

    result = service.scan(safe_txt)

    assert result.engine == "clamscan"
    assert result.verdict == "ALLOW"


def test_unconfigured_daemon_falls_back_to_clamscan(safe_txt, monkeypatch):
    def fake_run(self, executable, file_path, engine):
        if engine == "clamdscan":
            return ClamAvResult(
                engine=engine,
                exit_code=2,
                verdict="QUARANTINE",
                signature=None,
                raw_output="ERROR: Can't parse clamd configuration file",
                timed_out=False,
            )
        return ClamAvResult(engine, 0, "ALLOW", None, "OK", False)

    monkeypatch.setattr(ClamAvService, "_run", fake_run)
    service = ClamAvService()

    result = service.scan(safe_txt)

    assert result.engine == "clamscan"
    assert result.verdict == "ALLOW"