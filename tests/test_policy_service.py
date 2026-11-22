from pathlib import Path

from core.policy_service import check_extension, check_size, has_extension


def test_allows_allowed_extension():
    path = Path("tests/fixtures/safe.txt")
    verdict, _ = check_extension(path)
    assert verdict == "ALLOW"


def test_blocks_executable_extension():
    path = Path("tests/fixtures/fake-image.jpg.exe")
    verdict, _ = check_extension(path)
    assert verdict == "BLOCK"


def test_blocks_oversized_files(tmp_path):
    large = tmp_path / "large.bin"
    large.write_bytes(b"x" * (26 * 1024 * 1024))
    verdict, _ = check_size(large, max_mb=25)
    assert verdict is False


def test_case_insensitive_extensions(tmp_path):
    path = tmp_path / "safe.TXT"
    path.write_text("case insensitive")
    verdict, _ = check_extension(path)
    assert verdict == "ALLOW"


def test_handles_files_without_extensions(tmp_path):
    no_ext = tmp_path / "noextension"
    no_ext.write_text("no extension here")
    verdict, _ = check_extension(no_ext)
    assert verdict == "WARN"


def test_has_extension_returns_true_for_allowed():
    assert has_extension(Path("tests/fixtures/safe.txt")) is True
    assert has_extension(Path("tests/fixtures/safe.png")) is True


def test_has_extension_returns_false_for_blocked():
    assert has_extension(Path("tests/fixtures/fake-image.jpg.exe")) is False
