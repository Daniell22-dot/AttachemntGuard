import base64
import io
import zipfile
from pathlib import Path

from core.archive_inspector import inspect_zip_members_for_persistence
from core.deobfuscation_heuristics import (
    DeobfuscationPolicyConfig,
    Verdict,
)


def make_zip(tmp_path: Path, name: str, members: dict[str, bytes]) -> Path:
    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as archive:
        for member, data in members.items():
            archive.writestr(member, data)
    return path


def test_safe_members_stay_allowed(tmp_path):
    path = make_zip(tmp_path, "safe.zip", {"readme.txt": b"hello world"})
    data = path.read_bytes()

    result = inspect_zip_members_for_persistence(data)

    assert result.verdict == Verdict.ALLOW
    assert result.inspected_members == 1
    assert result.findings == []


def test_base64_persistence_in_member_blocks(tmp_path):
    payload = base64.b64encode("schtasks /create /sc onlogon".encode("utf-16-le"))
    path = make_zip(tmp_path, "encoded.zip", {"scripts/update.txt": b"cmd " + payload})

    result = inspect_zip_members_for_persistence(path.read_bytes())

    assert result.verdict == Verdict.BLOCK
    assert any(f.rule_id == "schtasks_create" for f in result.findings)
    assert all("scripts/update.txt" in f.description for f in result.findings)


def test_nested_archive_member_is_inspected(tmp_path):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr(
            "dropper.ps1",
            b"Start-Process schtasks.exe /create /sc onlogon",
        )
    path = make_zip(tmp_path, "outer.zip", {"inner.zip": inner.getvalue()})

    result = inspect_zip_members_for_persistence(path.read_bytes())

    assert result.verdict == Verdict.BLOCK
    assert any("inner.zip" in f.source for f in result.findings)


def test_corrupt_archive_fails_closed():
    result = inspect_zip_members_for_persistence(b"PK\x03\x04not-a-zip")

    assert result.verdict == Verdict.QUARANTINE
    assert any(f.rule_id == "malformed_zip_container" for f in result.findings)


def test_oversized_member_fails_closed(tmp_path):
    path = make_zip(tmp_path, "large.zip", {"big.txt": b"x" * 64})
    config = DeobfuscationPolicyConfig(max_member_bytes=16)

    result = inspect_zip_members_for_persistence(path.read_bytes(), config=config)

    assert result.verdict == Verdict.QUARANTINE
    assert any(f.rule_id == "archive_member_size_exceeded" for f in result.findings)


def test_ooxml_media_assets_are_skipped(tmp_path):
    path = make_zip(tmp_path, "doc.zip", {"word/media/image.png": b"\x89PNG\r\n\x1a\n"})

    result = inspect_zip_members_for_persistence(path.read_bytes())

    assert result.verdict == Verdict.ALLOW
    assert any("ooxml_media" in item for item in result.skipped_members)


def test_disabled_config_skips_inspection(tmp_path):
    path = make_zip(tmp_path, "bad.zip", {"payload.txt": b"schtasks /create"})

    result = inspect_zip_members_for_persistence(
        path.read_bytes(), config=DeobfuscationPolicyConfig(enabled=False)
    )

    assert result.verdict == Verdict.ALLOW
    assert result.inspected_members == 0
