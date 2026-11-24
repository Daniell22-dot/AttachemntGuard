import json
from pathlib import Path

from cli import main
from core.hash_service import sha256_file
from core.quarantine_service import quarantine_file


def quarantined(tmp_path):
    source = tmp_path / "note.txt"
    source.write_text("hello", encoding="utf-8")
    digest = sha256_file(source)
    quarantine_dir = tmp_path / "quarantine"
    payload = quarantine_file(
        source,
        quarantine_dir,
        {"sha256": digest, "verdict": "QUARANTINE"},
    )
    return quarantine_dir, payload


def test_cli_restore_dry_run_json(tmp_path, capsys):
    quarantine_dir, payload = quarantined(tmp_path)
    payload_path = Path(payload)
    qid = payload_path.stem
    target = tmp_path / "restored.txt"

    code = main([
        "--restore", qid,
        "--quarantine-dir", str(quarantine_dir),
        "--restore-to", str(target),
        "--dry-run", "--json",
    ])

    assert code == 0
    assert json.loads(capsys.readouterr().out)["dry_run"] is True
    assert payload_path.is_file()
    assert not target.exists()


def test_cli_restore_reports_invalid_uuid(tmp_path, capsys):
    quarantine_dir, _ = quarantined(tmp_path)

    code = main([
        "--restore", "not-a-uuid",
        "--quarantine-dir", str(quarantine_dir),
        "--json",
    ])

    assert code == 1
    assert "error" in json.loads(capsys.readouterr().out)
