from pathlib import Path

from core.clamav_service import ClamAvService, ClamAvResult, ClamAvUnavailable


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
            exit_code=2,
            verdict="QUARANTINE",
            raw_output="Unexpected scanner error",
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