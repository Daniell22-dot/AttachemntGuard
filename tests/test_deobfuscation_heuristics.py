import base64
from pathlib import Path

import pytest

from core.deobfuscation_heuristics import (
    DEFAULT_PERSISTENCE_PATTERNS,
    Verdict,
    analyze_content_for_persistence,
    build_persistence_patterns,
    calculate_shannon_entropy,
    detect_high_entropy_container,
    extract_and_decode_base64,
    load_deobfuscation_config_from_policy,
    merge_verdicts,
)


def write_policy(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_missing_policy_file_returns_defaults(tmp_path):
    config = load_deobfuscation_config_from_policy(tmp_path / "missing.yaml")

    assert config.enabled is True
    assert config.entropy_warn_threshold == 7.2
    assert config.entropy_quarantine_threshold == 7.75
    assert config.min_entropy_sample_bytes == 256
    assert set(config.patterns) == set(DEFAULT_PERSISTENCE_PATTERNS)


def test_rule_override_does_not_mutate_defaults(tmp_path):
    policy = write_policy(tmp_path, """
deobfuscation:
  persistence_rules:
    batch_self_reference:
      verdict: QUARANTINE
      description: "Custom rule for %~f0"
""")

    config = load_deobfuscation_config_from_policy(policy)

    assert config.patterns["batch_self_reference"][1] == Verdict.QUARANTINE
    assert config.patterns["batch_self_reference"][2] == "Custom rule for %~f0"
    assert DEFAULT_PERSISTENCE_PATTERNS["batch_self_reference"][1] == Verdict.WARN


def test_custom_pattern_and_rule_addition(tmp_path):
    policy = write_policy(tmp_path, """
deobfuscation:
  persistence_rules:
    schtasks_create:
      pattern: "schtasks\\\\.exe\\\\s+/create"
      verdict: QUARANTINE
    encoded_command:
      enabled: true
      verdict: BLOCK
      description: "Encoded command execution"
      pattern: "-EncodedCommand"
""")

    config = load_deobfuscation_config_from_policy(policy)
    report = analyze_content_for_persistence(
        b"powershell.exe -EncodedCommand AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
        patterns=config.patterns,
    )

    assert config.patterns["schtasks_create"][1] == Verdict.QUARANTINE
    assert any(f.rule_id == "encoded_command" for f in report.findings)
    assert report.recommended_verdict == Verdict.BLOCK


def test_disabled_rule_is_excluded(tmp_path):
    policy = write_policy(tmp_path, """
deobfuscation:
  persistence_rules:
    dotnet_process_path:
      enabled: false
""")

    config = load_deobfuscation_config_from_policy(policy)
    report = analyze_content_for_persistence(
        b"var exe = Environment.ProcessPath;", patterns=config.patterns
    )

    assert "dotnet_process_path" not in config.patterns
    assert report.findings == []
    assert report.recommended_verdict == Verdict.ALLOW


@pytest.mark.parametrize("bad_regex", ["[unclosed", "(?P<unterminated", "*invalid"])
def test_invalid_regex_raises_value_error(tmp_path, bad_regex):
    escaped = bad_regex.replace("\\", "\\\\")
    policy = write_policy(tmp_path, f"""
deobfuscation:
  persistence_rules:
    bad_rule:
      pattern: "{escaped}"
""")

    with pytest.raises(ValueError, match="bad_rule"):
        load_deobfuscation_config_from_policy(policy)


def test_new_rule_without_pattern_raises_value_error(tmp_path):
    policy = write_policy(tmp_path, """
deobfuscation:
  persistence_rules:
    missing_pattern_rule:
      verdict: WARN
""")

    with pytest.raises(ValueError, match="missing_pattern_rule"):
        load_deobfuscation_config_from_policy(policy)


def test_inverted_thresholds_are_clamped(tmp_path):
    policy = write_policy(tmp_path, """
deobfuscation:
  entropy_warn_threshold: 8.0
  entropy_quarantine_threshold: 6.0
""")

    config = load_deobfuscation_config_from_policy(policy)

    assert config.entropy_quarantine_threshold == 6.0
    assert config.entropy_warn_threshold == 6.0


def test_high_entropy_payload_is_quarantined():
    payload = bytes(range(256)) * 2

    report = analyze_content_for_persistence(
        payload,
        min_entropy_sample_bytes=128,
        entropy_warn_threshold=7.0,
        entropy_quarantine_threshold=7.8,
    )

    assert report.shannon_entropy >= 7.8
    assert report.recommended_verdict == Verdict.QUARANTINE
    assert any(f.rule_id == "high_shannon_entropy_quarantine" for f in report.findings)


def test_container_magic_skips_entropy():
    payload = b"PK\x03\x04" + bytes(range(256)) * 2

    report = analyze_content_for_persistence(payload, min_entropy_sample_bytes=16)

    assert report.skipped_entropy_reason == "matched_container_magic:zip_or_ooxml"
    assert not any(f.rule_id.startswith("high_shannon") for f in report.findings)


def test_utf16_encoded_command_is_decoded_and_flagged():
    payload = base64.b64encode("schtasks /create /sc onlogon".encode("utf-16-le"))
    report = analyze_content_for_persistence(b"cmd " + payload)

    assert any(label == "base64_utf16le" for label, _ in report.decoded_segments)
    assert any(f.rule_id == "schtasks_create" for f in report.findings)
    assert report.recommended_verdict == Verdict.BLOCK


def test_finding_to_dict_is_json_safe():
    patterns = build_persistence_patterns()
    finding = patterns["batch_self_reference"]
    report = analyze_content_for_persistence(b"echo %~f0", patterns=patterns)
    item = report.findings[0].to_dict()

    assert item["verdict"] == "WARN"
    assert item["rule_id"] == "batch_self_reference"
    assert finding[1] == Verdict.WARN


def test_helpers():
    assert calculate_shannon_entropy(b"") == 0.0
    assert detect_high_entropy_container(b"%PDF-1.7") == "pdf"
    assert extract_and_decode_base64("short") == []
    assert merge_verdicts(["WARN", Verdict.BLOCK]) == Verdict.BLOCK
