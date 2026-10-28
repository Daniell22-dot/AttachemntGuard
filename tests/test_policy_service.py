from pathlib import Path

from core.policy_service import check_extension, check_size, has_extension


def test_allows_allowed_extension():
    path = Path("tests/fixtures/safe.txt")
    verdict, reason = check_extension(path)
    assert verdict == "ALLOW"


def test_blocks_executable_extension():
    path = Path("tests/fixtures/fake-image.jpg.exe")
    verdict, reason = check_extension(path)
    assert verdict == "BLOCK"


def test_blocks_oversized_files():
    large = Path("tests/fixtures/large.bin")
    large.parent.mkdir(parents=True, exist_ok=True)
    large.write_bytes(b"x" * (26 * 1024 * 1024))
    verdict, reason = check_size(large, max_mb=25)
    assert verdict is False


def test_case_insensitive_extensions():
    path = Path("tests/fixtures/safe.TXT")
    verdict, reason = check_extension(path)
    assert verdict == "ALLOW"


def test_handles_files_without_extensions():
    from pathlib import Path
    no_ext = Path("tests/fixtures/noextension")
    no_ext.parent.mkdir(parents=True, exist_ok=True)
    no_ext.write_text("no extension here")
    verdict, reason = check_extension(no_ext)
    assert verdict in ("ALLOW", "WARN")


def test_has_extension_returns_true_for_allowed():
    path = Path("tests/fixtures/safe.txt")
    assert has_extension(path) is True


def test_has_extension_returns_false_for_unknown():
    path = Path("tests/fixtures/safe.png")
    assert has_extension(path) is False


def test_has_extension_returns_false_for_blocked():
    path = Path("tests/fixtures/fake-image.jpg.exe")
    assert has_extension(path) is False