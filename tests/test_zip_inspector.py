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


def test_rejects_path_traversal_entries(tmp_path):
    target = tmp_path / "path-traversal.zip"
    with zipfile.ZipFile(target, "w") as zf:
        zf.writestr("../../../etc/passwd", "traversal data")
    result = scan_zip(target)
    assert any("Suspicious path" in s for s in result["suspicious"])


def test_handles_corrupt_zip():
    result = scan_zip(Path("tests/fixtures/corrupt.zip"))
    assert result["is_zip"] is True
    assert any("Corrupt" in e for e in result["errors"])


def test_handles_unreadable_zip_without_crashing():
    result = scan_zip(Path("tests/fixtures/corrupt.zip"))
    assert result["errors"]
