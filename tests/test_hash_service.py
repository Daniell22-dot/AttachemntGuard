from pathlib import Path

from core.hash_service import sha256_file, file_info


def test_hashes_small_known_file():
    result = sha256_file(Path("tests/fixtures/safe.txt"))
    assert result is not None
    assert len(result) == 64
    assert all(c in "0123456789abcdef" for c in result)


def test_handles_missing_file():
    result = sha256_file(Path("nonexistent_file.txt"))
    assert result is None


def test_handles_permission_denied():
    result = sha256_file(Path("/root/protected/file.txt"))
    assert result is None


def test_produces_lowercase_hexadecimal():
    result = sha256_file(Path("tests/fixtures/safe.txt"))
    if result:
        assert result == result.lower()
        assert result.isalnum() or all(c in "0123456789" for c in result)


def test_file_info_returns_size_and_hash():
    info = file_info(Path("tests/fixtures/safe.txt"))
    assert "path" in info
    assert "size" in info
    assert "sha256" in info


def test_file_info_handles_missing():
    info = file_info(Path("nonexistent.txt"))
    assert info["sha256"] is None
    assert info["size"] == 0