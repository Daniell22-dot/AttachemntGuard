from pathlib import Path

from core.clamav_service import ClamAvResult, ClamAvUnavailable
from core.scanner import scan_file


class FakeClamAv:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.scanned_path = None

    def scan(self, path: Path) -> ClamAvResult:
        self.scanned_path = path
        if self.error is not None:
            raise self.error
        return self.result


def result(verdict, signature=None, error=None, timed_out=False):
    return ClamAvResult(
        engine="fake-clamav",
        exit_code=2 if verdict == "QUARANTINE" else 0,
        verdict=verdict,
        signature=signature,
        raw_output="",
        timed_out=timed_out,
        error=error,
    )


def test_clamav_is_optional_by_default():
    scan = scan_file(Path("tests/fixtures/safe.txt"))

    assert scan["verdict"] == "ALLOW"
    assert scan["clamav"] == {}


def test_clean_clamav_result_stays_allowed():
    service = FakeClamAv(result("ALLOW"))

    scan = scan_file(Path("tests/fixtures/safe.txt"), clamav=service)

    assert scan["verdict"] == "ALLOW"
    assert scan["clamav"]["verdict"] == "ALLOW"
    assert service.scanned_path == Path("tests/fixtures/safe.txt")


def test_clamav_detection_blocks_local_allow():
    service = FakeClamAv(result("BLOCK", signature="Test.Signature"))

    scan = scan_file(Path("tests/fixtures/safe.txt"), clamav=service)

    assert scan["verdict"] == "BLOCK"
    assert any("ClamAV detected: Test.Signature" in r for r in scan["reasons"])


def test_clamav_error_fails_closed():
    service = FakeClamAv(
        result("QUARANTINE", error="ClamAV signatures are missing")
    )

    scan = scan_file(Path("tests/fixtures/safe.txt"), clamav=service)

    assert scan["verdict"] == "QUARANTINE"
    assert "ClamAV signatures are missing" in scan["reasons"]


def test_clamav_unavailable_fails_closed():
    service = FakeClamAv(error=ClamAvUnavailable("executable not found"))

    scan = scan_file(Path("tests/fixtures/safe.txt"), clamav=service)

    assert scan["verdict"] == "QUARANTINE"
    assert any("ClamAV unavailable" in r for r in scan["reasons"])


def test_clamav_unexpected_error_fails_closed():
    service = FakeClamAv(error=RuntimeError("boom"))

    scan = scan_file(Path("tests/fixtures/safe.txt"), clamav=service)

    assert scan["verdict"] == "QUARANTINE"
    assert any("ClamAV check failed: RuntimeError" in r for r in scan["reasons"])


def test_local_block_cannot_be_downgraded():
    service = FakeClamAv(result("ALLOW"))

    scan = scan_file(Path("tests/fixtures/fake-image.jpg.exe"), clamav=service)

    assert scan["verdict"] == "BLOCK"
    assert scan["clamav"]["verdict"] == "ALLOW"
