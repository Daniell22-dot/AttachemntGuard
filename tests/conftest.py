from pathlib import Path

import pytest

from core.clamav_service import ClamAvResult

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def safe_txt(fixtures_dir: Path) -> Path:
    return fixtures_dir / "safe.txt"


@pytest.fixture
def safe_pdf(fixtures_dir: Path) -> Path:
    return fixtures_dir / "safe.pdf"


@pytest.fixture
def safe_png(fixtures_dir: Path) -> Path:
    return fixtures_dir / "safe.png"


@pytest.fixture
def fake_image_jext(fixtures_dir: Path) -> Path:
    return fixtures_dir / "fake-image.jpg.exe"


@pytest.fixture
def detected_sample(fixtures_dir: Path) -> Path:
    return fixtures_dir / "clamav-test-sample.bin"


@pytest.fixture
def corrupt_zip(fixtures_dir: Path) -> Path:
    return fixtures_dir / "corrupt.zip"


@pytest.fixture
def protected_zip(fixtures_dir: Path) -> Path:
    return fixtures_dir / "protected.zip"


@pytest.fixture
def archive_with_detection(fixtures_dir: Path) -> Path:
    return fixtures_dir / "archive-with-detected-file.zip"


def make_result(
    *,
    exit_code: int,
    verdict: str,
    signature: str | None = None,
    raw_output: str = "",
    timed_out: bool = False,
    engine: str = "mock-clamav",
) -> ClamAvResult:
    return ClamAvResult(
        engine=engine,
        exit_code=exit_code,
        verdict=verdict,
        signature=signature,
        raw_output=raw_output,
        timed_out=timed_out,
    )