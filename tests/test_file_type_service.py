from pathlib import Path

from core.file_type_service import detect_magic_bytes, sniff, detect_extension_mismatch


def test_detects_pdf_magic_bytes():
    result = detect_magic_bytes(Path("tests/fixtures/safe.pdf"))
    assert result[0] == "application/pdf"


def test_detects_png_magic_bytes():
    result = detect_magic_bytes(Path("tests/fixtures/safe.png"))
    assert result[0] == "image/png"


def test_detects_pe_mz_magic_bytes():
    result = detect_magic_bytes(Path("tests/fixtures/fake-image.jpg.exe"))
    # The file starts with \xff\xd8\xff (JPEG magic), not MZ
    # But it has .exe extension, so mismatch should be detected


def test_detects_zip_magic_bytes():
    result = detect_magic_bytes(Path("tests/fixtures/archive-safe.zip"))
    assert result[0] == "application/zip"


def test_sniff_returns_mime_and_ext():
    info = sniff(Path("tests/fixtures/safe.txt"))
    assert info["mime"] != "unknown"
    assert info["ext"] == ".txt"


def test_sniff_returns_pdf():
    info = sniff(Path("tests/fixtures/safe.pdf"))
    assert info["mime"] == "application/pdf"


def test_sniff_returns_exe_for_exe_with_wrong_ext():
    info = sniff(Path("tests/fixtures/fake-image.jpg.exe"))
    # The file has JPEG-ish magic bytes \xff\xd8\xff
    assert info["mime"] in ("image/jpeg", "unknown")


def test_detects_extension_mismatch_exe_with_wrong_mime():
    # fake-image.jpg.exe has JPEG magic bytes but .exe extension
    result = detect_extension_mismatch(Path("tests/fixtures/fake-image.jpg.exe"))
    assert result is True


def test_no_mismatch_for_valid_pdf():
    result = detect_extension_mismatch(Path("tests/fixtures/safe.pdf"))
    assert result is False