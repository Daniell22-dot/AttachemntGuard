from __future__ import annotations

import base64
import binascii
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Iterable, Optional

try:
    import yaml
except ImportError:
    yaml = None

from .policy_service import POLICY_PATH


class Verdict(IntEnum):
    ALLOW = 0
    WARN = 1
    QUARANTINE = 2
    BLOCK = 3

    @classmethod
    def from_str(cls, value: str) -> Verdict:
        normalized = str(value).strip().upper()
        if normalized not in cls.__members__:
            raise ValueError(f"Unsupported verdict: {value!r}")
        return cls[normalized]


@dataclass(frozen=True)
class HeuristicFinding:
    rule_id: str
    description: str
    verdict: Verdict
    source: str
    evidence: str = ""

    def to_dict(self, max_evidence_chars: int = 160) -> dict[str, str]:
        sanitized = "".join(
            char if (char.isprintable() or char == " ") else " "
            for char in self.evidence
        ).strip()[:max_evidence_chars]
        return {
            "rule_id": self.rule_id,
            "verdict": self.verdict.name,
            "source": self.source,
            "description": self.description,
            "evidence": sanitized,
        }


@dataclass
class DeobfuscationReport:
    shannon_entropy: float
    byte_length: int
    skipped_entropy_reason: Optional[str] = None
    decoded_segments: list[tuple[str, str]] = field(default_factory=list)
    findings: list[HeuristicFinding] = field(default_factory=list)
    recommended_verdict: Verdict = Verdict.ALLOW

    def escalate(self, candidate: Verdict) -> None:
        if candidate > self.recommended_verdict:
            self.recommended_verdict = candidate


DEFAULT_PERSISTENCE_PATTERNS: dict[str, tuple[re.Pattern[str], Verdict, str]] = {
    "schtasks_create": (
        re.compile(r"\bschtasks(?:\.exe)?\b[^\r\n]{0,200}/create\b", re.I),
        Verdict.BLOCK,
        "Scheduled task creation indicator (schtasks /create)",
    ),
    "logon_trigger": (
        re.compile(r"/sc\s+onlogon", re.I),
        Verdict.BLOCK,
        "Scheduled task logon trigger",
    ),
    "registry_run_key": (
        re.compile(
            r"(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\+(?:SOFTWARE\\+)?"
            r"Microsoft\\+Windows\\+CurrentVersion\\+(?:Run|RunOnce|RunServices)",
            re.I,
        ),
        Verdict.BLOCK,
        "Windows Run/RunOnce registry persistence key reference",
    ),
    "startup_folder_drop": (
        re.compile(
            r"(?:shell:startup|Start Menu\\+Programs\\+Startup)",
            re.I,
        ),
        Verdict.QUARANTINE,
        "Startup folder persistence target",
    ),
    "encoded_command": (
        re.compile(r"-(?:enc|encodedcommand)\b", re.I),
        Verdict.BLOCK,
        "Encoded command execution indicator",
    ),
    "batch_self_reference": (
        re.compile(r"%~f0", re.I),
        Verdict.WARN,
        "Batch self-referencing script path",
    ),
    "dotnet_process_path": (
        re.compile(r"\bEnvironment\.ProcessPath\b"),
        Verdict.WARN,
        "Managed code inspection of current executable path",
    ),
}

HIGH_ENTROPY_CONTAINER_SIGNATURES: dict[str, tuple[bytes, ...]] = {
    "zip_or_ooxml": (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
    "gzip": (b"\x1f\x8b\x08",),
    "bzip2": (b"BZh",),
    "xz": (b"\xfd7zXZ\x00",),
    "zstd": (b"\x28\xb5\x2f\xfd",),
    "7zip": (b"7z\xbc\xaf\x27\x1c",),
    "rar": (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"),
    "pdf": (b"%PDF-",),
    "png": (b"\x89PNG\r\n\x1a\n",),
    "jpeg": (b"\xff\xd8\xff",),
    "gif": (b"GIF87a", b"GIF89a"),
}

_B64_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{24,}={0,2})(?![A-Za-z0-9+/=_-])"
)
_PRINTABLE_RATIO_THRESHOLD = 0.8


@dataclass(frozen=True)
class DeobfuscationPolicyConfig:
    enabled: bool = True
    entropy_warn_threshold: float = 7.2
    entropy_quarantine_threshold: float = 7.75
    min_entropy_sample_bytes: int = 256
    skip_entropy_for_containers: bool = True
    entropy_exempt_formats: frozenset[str] = field(
        default_factory=lambda: frozenset(HIGH_ENTROPY_CONTAINER_SIGNATURES)
    )
    patterns: dict[str, tuple[re.Pattern[str], Verdict, str]] = field(
        default_factory=lambda: dict(DEFAULT_PERSISTENCE_PATTERNS)
    )
    max_decoded_segments: int = 32
    max_member_bytes: int = 2 * 1024 * 1024
    max_total_uncompressed: int = 16 * 1024 * 1024
    max_members: int = 100


def build_persistence_patterns(
    raw_rules: Optional[dict] = None,
) -> dict[str, tuple[re.Pattern[str], Verdict, str]]:
    patterns = dict(DEFAULT_PERSISTENCE_PATTERNS)
    if not isinstance(raw_rules, dict):
        return patterns

    for rule_id, options in raw_rules.items():
        name = str(rule_id)
        if not isinstance(options, dict):
            raise ValueError(f"Invalid options for rule {name}")
        if options.get("enabled") is False:
            patterns.pop(name, None)
            continue

        raw_pattern = options.get("pattern")
        if raw_pattern is None and name not in patterns:
            raise ValueError(f"Missing pattern for rule {name}")
        if raw_pattern is None:
            pattern = patterns[name][0]
        else:
            try:
                pattern = re.compile(str(raw_pattern))
            except re.error as exc:
                raise ValueError(f"Invalid regex for rule {name}: {exc}") from exc

        raw_verdict = options.get("verdict")
        try:
            verdict = Verdict.from_str(str(raw_verdict)) if raw_verdict else (
                patterns[name][1] if name in patterns else Verdict.WARN
            )
        except ValueError as exc:
            raise ValueError(f"Invalid verdict for rule {name}: {exc}") from exc

        description = str(
            options.get("description")
            or (patterns[name][2] if name in patterns else name)
        )
        patterns[name] = (pattern, verdict, description)

    return patterns


def load_deobfuscation_config_from_policy(
    policy_path: Optional[Path] = None,
    policy: Optional[dict] = None,
) -> DeobfuscationPolicyConfig:
    if policy is None:
        if policy_path is None:
            policy = _load_policy_mapping(POLICY_PATH)
        else:
            policy = _load_policy_mapping(Path(policy_path))

    section = policy.get("deobfuscation") if isinstance(policy, dict) else None
    if not isinstance(section, dict):
        section = {}

    warn = _as_float(
        section.get("entropy_warn_threshold"), 7.2, 0.0, 8.0
    )
    quarantine = _as_float(
        section.get("entropy_quarantine_threshold"), 7.75, 0.0, 8.0
    )
    if warn > quarantine:
        warn = quarantine

    exempt = section.get("entropy_exempt_formats")
    if not isinstance(exempt, (list, tuple, set)):
        exempt = HIGH_ENTROPY_CONTAINER_SIGNATURES.keys()

    return DeobfuscationPolicyConfig(
        enabled=bool(section.get("enabled", True)),
        entropy_warn_threshold=warn,
        entropy_quarantine_threshold=quarantine,
        min_entropy_sample_bytes=_as_int(
            section.get("min_entropy_sample_bytes"), 256, 0
        ),
        skip_entropy_for_containers=bool(
            section.get("skip_entropy_for_containers", True)
        ),
        entropy_exempt_formats=frozenset(str(value) for value in exempt),
        patterns=build_persistence_patterns(section.get("persistence_rules")),
        max_decoded_segments=_as_int(section.get("max_decoded_segments"), 32, 1),
        max_member_bytes=_as_int(
            section.get("max_member_bytes"), 2 * 1024 * 1024, 1
        ),
        max_total_uncompressed=_as_int(
            section.get("max_total_uncompressed"), 16 * 1024 * 1024, 1
        ),
        max_members=_as_int(section.get("max_members"), 100, 1),
    )


def _load_policy_mapping(path: Path) -> dict:
    if yaml is None:
        return {}
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError, yaml.YAMLError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _as_float(value, default: float, minimum: float, maximum: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return min(max(number, minimum), maximum)


def _as_int(value, default: int, minimum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(number, minimum)


def calculate_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def detect_high_entropy_container(
    content: bytes,
    allowed_formats: Optional[Iterable[str]] = None,
) -> Optional[str]:
    if not content:
        return None
    formats = set(allowed_formats) if allowed_formats is not None else None
    for name, prefixes in HIGH_ENTROPY_CONTAINER_SIGNATURES.items():
        if formats is not None and name not in formats:
            continue
        if any(content.startswith(prefix) for prefix in prefixes):
            return name
    return None


def _is_mostly_printable(text: str) -> bool:
    if not text:
        return False
    printable = sum(1 for char in text if char.isprintable() or char in "\r\n\t")
    return printable / len(text) >= _PRINTABLE_RATIO_THRESHOLD


def _decode_b64_bytes(token: str) -> Optional[bytes]:
    normalized = token.replace("-", "+").replace("_", "/")
    remainder = len(normalized) % 4
    if remainder == 1:
        return None
    if remainder:
        normalized += "=" * (4 - remainder)
    try:
        decoded = base64.b64decode(normalized, validate=True)
    except (ValueError, binascii.Error):
        return None
    return decoded or None


def extract_and_decode_base64(
    text: str,
    *,
    max_decoded_segments: int = 32,
    max_segment_chars: int = 16384,
) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    seen: set[str] = set()
    for match in _B64_TOKEN_RE.finditer(text):
        if len(results) >= max_decoded_segments:
            break
        decoded = _decode_b64_bytes(match.group(1))
        if not decoded:
            continue
        candidates: list[tuple[str, str]] = []
        try:
            utf8 = decoded.decode("utf-8", errors="strict")
            if _is_mostly_printable(utf8):
                candidates.append(("base64_utf8", utf8))
        except UnicodeDecodeError:
            pass
        if len(decoded) >= 4 and len(decoded) % 2 == 0:
            try:
                utf16 = decoded.decode("utf-16-le", errors="strict")
                if _is_mostly_printable(utf16):
                    candidates.append(("base64_utf16le", utf16))
            except UnicodeDecodeError:
                pass
        for label, value in candidates:
            clipped = value[:max_segment_chars]
            if clipped and clipped not in seen:
                seen.add(clipped)
                results.append((label, clipped))
    return results


def _scan_text_for_persistence(
    text: str,
    source: str,
    patterns: dict[str, tuple[re.Pattern[str], Verdict, str]],
) -> list[HeuristicFinding]:
    hits = []
    for rule_id, (pattern, verdict, description) in patterns.items():
        match = pattern.search(text)
        if match:
            hits.append(
                HeuristicFinding(
                    rule_id=rule_id,
                    description=description,
                    verdict=verdict,
                    source=source,
                    evidence=match.group(0)[:160],
                )
            )
    return hits


def analyze_content_for_persistence(
    content: bytes,
    *,
    initial_verdict: Verdict = Verdict.ALLOW,
    entropy_warn_threshold: float = 7.2,
    entropy_quarantine_threshold: float = 7.75,
    min_entropy_sample_bytes: int = 256,
    skip_entropy_for_containers: bool = True,
    allowed_container_formats: Optional[Iterable[str]] = None,
    patterns: Optional[dict[str, tuple[re.Pattern[str], Verdict, str]]] = None,
    max_decoded_segments: int = 32,
) -> DeobfuscationReport:
    active_patterns = patterns if patterns is not None else DEFAULT_PERSISTENCE_PATTERNS
    entropy = calculate_shannon_entropy(content)
    report = DeobfuscationReport(
        shannon_entropy=entropy,
        byte_length=len(content),
        recommended_verdict=initial_verdict,
    )

    container = (
        detect_high_entropy_container(content, allowed_container_formats)
        if skip_entropy_for_containers
        else None
    )
    if container is not None:
        report.skipped_entropy_reason = f"matched_container_magic:{container}"
    elif len(content) >= min_entropy_sample_bytes:
        if entropy >= entropy_quarantine_threshold:
            finding = HeuristicFinding(
                rule_id="high_shannon_entropy_quarantine",
                description=(
                    f"Very high Shannon entropy ({entropy} >= "
                    f"{entropy_quarantine_threshold} bits/byte)"
                ),
                verdict=Verdict.QUARANTINE,
                source="raw",
                evidence=f"entropy={entropy}, size={len(content)}",
            )
            report.findings.append(finding)
            report.escalate(finding.verdict)
        elif entropy >= entropy_warn_threshold:
            finding = HeuristicFinding(
                rule_id="high_shannon_entropy_warn",
                description=(
                    f"Elevated Shannon entropy ({entropy} >= "
                    f"{entropy_warn_threshold} bits/byte)"
                ),
                verdict=Verdict.WARN,
                source="raw",
                evidence=f"entropy={entropy}, size={len(content)}",
            )
            report.findings.append(finding)
            report.escalate(finding.verdict)

    raw_text = content.decode("utf-8", errors="replace")
    for finding in _scan_text_for_persistence(raw_text, "raw", active_patterns):
        report.findings.append(finding)
        report.escalate(finding.verdict)

    decoded = extract_and_decode_base64(
        raw_text, max_decoded_segments=max_decoded_segments
    )
    report.decoded_segments = decoded
    for label, text in decoded:
        for finding in _scan_text_for_persistence(text, label, active_patterns):
            report.findings.append(finding)
            report.escalate(finding.verdict)

    return report


def merge_verdicts(verdicts: Iterable[Verdict | str]) -> Verdict:
    highest = Verdict.ALLOW
    for item in verdicts:
        verdict = item if isinstance(item, Verdict) else Verdict.from_str(item)
        if verdict > highest:
            highest = verdict
    return highest
