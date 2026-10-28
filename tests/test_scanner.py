from pathlib import Path

from core.scanner import scan_file, decide_verdict
from core.policy_service import check_extension
from core.file_type_service import detect_extension_mismatch


def test_safe_txt_returns_allow():
    result = scan_file(Path("tests/fixtures/safe.txt"))
    assert result["verdict"] == "ALLOW"
    assert "Blocked" not in str(result["reasons"])


def test_fake_pdf_exe_returns_block():
    result = scan_file(Path("tests/fixtures/fake-image.jpg.exe"))
    assert result["verdict"] in ("BLOCK", "QUARANTINE")


def test_zip_with_exe_returns_quarantine():
    result = scan_file(Path("tests/fixtures/archive-with-exe.zip"))
    # verdict depends on ZIP inspection results
    assert result["verdict"] in ("BLOCK", "QUARANTINE")


def test_corrupt_zip_returns_quarantine():
    result = scan_file(Path("tests/fixtures/corrupt.zip"))
    assert result["verdict"] == "QUARANTINE"


def test_decide_verdict_precedence():
    # BLOCK should override QUARANTINE
    assert decide_verdict("QUARANTINE", "BLOCK") == "BLOCK"
    # QUARANTINE should override WARN
    assert decide_verdict("WARN", "QUARANTINE") == "QUARANTINE"
    # WARN should override ALLOW
    assert decide_verdict("ALLOW", "WARN") == "WARN"
    # ALLOW should stay ALLOW when no higher
    assert decide_verdict("ALLOW", "ALLOW") == "ALLOW"


def test_extension_mismark_flagged():
    result = scan_file(Path("tests/fixtures/fake-image.jpg.exe"))
    # Should detect extension mismatch
    has_mismatch = any("extension does not match" in r for r in result["reasons"])
    assert has_mismatch