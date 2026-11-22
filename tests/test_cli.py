from pathlib import Path

from cli import scan_path
from core.scanner import scan_file
from scanner.guard import main as guard_main


def test_cli_uses_shared_scanner(tmp_path):
    sample = tmp_path / "note.txt"
    sample.write_text("hello", encoding="utf-8")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    result = scan_path(str(sample), str(tmp_path / "quarantine"), str(rules_dir))

    assert result["verdict"] == "ALLOW"
    assert result["info"]["sha256"]
    assert result["detected_extension"] == ".txt"


def test_guard_entry_point_uses_shared_scanner(tmp_path, capsys):
    sample = tmp_path / "note.txt"
    sample.write_text("hello", encoding="utf-8")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    report_dir = tmp_path / "reports"

    code = guard_main([
        str(sample),
        "--rules-dir", str(rules_dir),
        "--report-dir", str(report_dir),
    ])

    assert code == 0
    assert "[ALLOW]" in capsys.readouterr().out
    assert list(report_dir.glob("**/*.json"))


def test_shared_pipeline_matches_core_result():
    fixture = Path("tests/fixtures/safe.txt")
    from_cli = scan_path(str(fixture), "quarantine", "rules")
    from_core = scan_file(fixture)

    assert from_cli["verdict"] == from_core["verdict"]
    assert from_cli["reasons"] == from_core["reasons"]
