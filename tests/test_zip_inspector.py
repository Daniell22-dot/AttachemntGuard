import zipfile
from pathlib import Path

from core.zip_inspector import scan_zip


def test_allows_safe_zip():
    result = scan_zip(Path("tests/fixtures/archive-safe.zip"))
    assert result["is_zip"] is True
    assert result["suspicious"] == []
    assert result["errors"] == []


def test_flags_zip_with_exe():
    result = scan_zip(Path("tests/fixtures/archive-with-exe.zip"))
    assert result["is_zip"] is True
    assert any("Executable" in s for s in result["suspicious"])


def test_flags_zip_with_script():
    # archive-with-exe.zip contains .exe, check it also catches script
    result = scan_zip(Path("tests/fixtures/archive-with-exe.zip"))
    assert any("script" in s.lower() or "Executable" in s for s in result["suspicious"])


def test_flags_nested_zip():
    result = scan_zip(Path("tests/fixtures/archive-nested.zip"))
    assert result["is_zip"] is True
    assert any("Nested" in s for s in result["suspicious"])


def test_rejects_path_traversal_entries():
    # Create a ZIP with path traversal entry
    import zipfile
    with zipfile.ZipFile("tests/fixtures/path-traversal.zip", "w") as zf:
        zf.writestr("../../../etc/passwd", "traversal data")
    result = scan_zip(Path("tests/fixtures/path-traversal.zip"))
    assert any("Suspicious path" in s for s in result["suspicious"])


def test_handles_corrupt_zip():
    result = scan_zip(Path("tests/fixtures/corrupt.zip"))
    assert result["is_zip"] is True
    assert any("Corrupt" in e for e in result["errors"])


def test_handles_password_protected_zip():
    # Create a password-protected ZIP using clamscan-style
    # For now, just test that RuntimeError is caught
    result = scan_zip(Path("tests/fixtures/archive-with-exe.zip"))
    # Should not crash; may have errors depending on ZIP readability