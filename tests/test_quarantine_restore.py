import json
from pathlib import Path

import pytest

from core.hash_service import sha256_file
from core.quarantine_service import (
    quarantine_file,
    restore_quarantined_file,
)


@pytest.fixture
def quarantined(tmp_path):
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    sample = incoming / "note.txt"
    sample.write_text("hello", encoding="utf-8")
    digest = sha256_file(sample)
    quarantine_dir = tmp_path / "quarantine"
    payload = quarantine_file(
        sample,
        quarantine_dir,
        {
            "sha256": digest,
            "verdict": "QUARANTINE",
            "scanned_at": "2026-11-24T00:00:00Z",
            "scanner_version": "0.3.0",
        },
    )
    return quarantine_dir, Path(payload).stem, digest, incoming / "note.txt"


def test_restore_verifies_hash_and_keeps_sidecar(quarantined, tmp_path):
    quarantine_dir, qid, digest, _ = quarantined
    target = tmp_path / "restored" / "note.txt"

    result = restore_quarantined_file(
        qid, quarantine_dir=quarantine_dir, destination_override=target
    )

    assert result.restored_to == str(target)
    assert result.sha256 == digest
    assert target.read_text(encoding="utf-8") == "hello"
    assert not any(path.stem == qid and path.suffix == ".txt" for path in quarantine_dir.iterdir())

    sidecar = json.loads((quarantine_dir / f"{qid}.txt.json").read_text(encoding="utf-8"))
    assert sidecar["restored_to"] == str(target)
    assert sidecar["restore_verified_sha256"] == digest


def test_dry_run_leaves_payload_in_place(quarantined, tmp_path):
    quarantine_dir, qid, _, _ = quarantined
    target = tmp_path / "dry.txt"

    result = restore_quarantined_file(
        qid,
        quarantine_dir=quarantine_dir,
        destination_override=target,
        dry_run=True,
    )

    assert result.dry_run is True
    assert not target.exists()
    assert (quarantine_dir / f"{qid}.txt").is_file()


def test_corrupted_payload_is_rejected(quarantined):
    quarantine_dir, qid, _, _ = quarantined
    (quarantine_dir / f"{qid}.txt").write_bytes(b"tampered")

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        restore_quarantined_file(qid, quarantine_dir=quarantine_dir)


def test_invalid_uuid_is_rejected(quarantined):
    quarantine_dir, _, _, _ = quarantined

    with pytest.raises(ValueError, match="Invalid quarantine UUID"):
        restore_quarantined_file("../../../etc/passwd", quarantine_dir=quarantine_dir)


def test_target_inside_quarantine_is_rejected(quarantined):
    quarantine_dir, qid, _, _ = quarantined
    sidecar_path = quarantine_dir / f"{qid}.txt.json"
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    sidecar["original_path"] = str(quarantine_dir / "evil.txt")
    sidecar_path.write_text(json.dumps(sidecar), encoding="utf-8")

    with pytest.raises(ValueError, match="quarantine directory"):
        restore_quarantined_file(qid, quarantine_dir=quarantine_dir)


def test_overwrite_keeps_backup(quarantined, tmp_path):
    quarantine_dir, qid, _, _ = quarantined
    target = tmp_path / "existing.txt"
    target.write_text("original", encoding="utf-8")

    result = restore_quarantined_file(
        qid,
        quarantine_dir=quarantine_dir,
        destination_override=target,
        overwrite=True,
    )

    backups = list(target.parent.glob("existing.txt.overwritten-*"))
    assert len(backups) == 1
    assert backups[0].read_text(encoding="utf-8") == "original"
    assert target.read_text(encoding="utf-8") == "hello"
    assert result.restored_to == str(target)


def test_restore_to_original_path(quarantined):
    quarantine_dir, qid, _, original = quarantined

    result = restore_quarantined_file(qid, quarantine_dir=quarantine_dir)

    assert result.restored_to == str(original.resolve())
    assert original.read_text(encoding="utf-8") == "hello"
