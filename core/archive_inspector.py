from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Optional

from .deobfuscation_heuristics import (
    DeobfuscationPolicyConfig,
    HeuristicFinding,
    Verdict,
    analyze_content_for_persistence,
    detect_high_entropy_container,
)

_OOXML_MEDIA_EXTENSIONS = frozenset(
    {".png", ".jpg", ".jpeg", ".gif", ".webp", ".emf", ".wmf", ".mp3", ".mp4", ".wav"}
)
_TEXT_AND_SCRIPT_EXTENSIONS = frozenset(
    {
        ".xml", ".rels", ".vba", ".ps1", ".psm1", ".bat", ".cmd",
        ".vbs", ".js", ".jse", ".wsf", ".hta", ".py", ".sh", ".txt", ".json",
    }
)


@dataclass
class ArchiveInspectionResult:
    verdict: Verdict = Verdict.ALLOW
    inspected_members: int = 0
    skipped_members: list[str] = field(default_factory=list)
    findings: list[HeuristicFinding] = field(default_factory=list)

    def escalate(self, candidate: Verdict) -> None:
        if candidate > self.verdict:
            self.verdict = candidate


@dataclass
class _State:
    verdict: Verdict
    inspected_members: int = 0
    skipped_members: list[str] = field(default_factory=list)
    findings: list[HeuristicFinding] = field(default_factory=list)
    cumulative_bytes: int = 0

    def add(self, finding: HeuristicFinding) -> None:
        self.findings.append(finding)
        if finding.verdict > self.verdict:
            self.verdict = finding.verdict

    def to_result(self) -> ArchiveInspectionResult:
        return ArchiveInspectionResult(
            verdict=self.verdict,
            inspected_members=self.inspected_members,
            skipped_members=list(self.skipped_members),
            findings=list(self.findings),
        )


def _read_member_bounded(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    max_bytes: int,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    with archive.open(info, "r") as stream:
        while total < max_bytes:
            chunk = stream.read(min(65_536, max_bytes - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total == max_bytes and stream.read(1):
            raise RuntimeError("archive member exceeds inspection limit")
    return b"".join(chunks)


def _is_ooxml_media_asset(member_path: str) -> bool:
    path = PurePosixPath(member_path.replace("\\", "/"))
    if path.suffix.lower() not in _OOXML_MEDIA_EXTENSIONS:
        return False
    return "media" in {part.lower() for part in path.parts}


def _scoped(finding: HeuristicFinding, member: str) -> HeuristicFinding:
    return HeuristicFinding(
        rule_id=finding.rule_id,
        description=f"[{member}] {finding.description}",
        verdict=finding.verdict,
        source=f"zip:{member}:{finding.source}",
        evidence=finding.evidence,
    )


def _finding(rule_id: str, description: str, verdict: Verdict, source: str) -> HeuristicFinding:
    return HeuristicFinding(
        rule_id=rule_id,
        description=description,
        verdict=verdict,
        source=source,
    )


def _inspect_zip_bytes(
    data: bytes,
    state: _State,
    config: DeobfuscationPolicyConfig,
    *,
    depth: int,
    max_depth: int,
    max_members: int,
    max_member_bytes: int,
    max_total_uncompressed: int,
    member_prefix: str = "",
) -> None:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data), "r")
    except (zipfile.BadZipFile, OSError, ValueError, EOFError):
        container = member_prefix.rstrip(">") or "archive"
        state.add(
            _finding(
                "malformed_zip_container",
                f"Archive failed ZIP structure validation: {container}",
                Verdict.QUARANTINE,
                f"zip:{container}",
            )
        )
        return

    with archive:
        for info in archive.infolist():
            if info.is_dir():
                continue

            display_name = f"{member_prefix}{info.filename}"
            if state.inspected_members >= max_members:
                state.skipped_members.append(f"{display_name} (max_members_reached)")
                state.add(
                    _finding(
                        "archive_member_limit",
                        "Archive member inspection limit reached",
                        Verdict.WARN,
                        "archive",
                    )
                )
                return

            if info.flag_bits & 0x1:
                state.add(
                    _finding(
                        "encrypted_archive_member",
                        f"Encrypted archive member evades static inspection: {display_name}",
                        Verdict.QUARANTINE,
                        "archive",
                    )
                )
                continue

            if info.file_size > max_member_bytes or (
                state.cumulative_bytes + info.file_size > max_total_uncompressed
            ):
                state.add(
                    _finding(
                        "archive_member_size_exceeded",
                        f"Member exceeds decompression limit: {display_name}",
                        Verdict.QUARANTINE,
                        "archive",
                    )
                )
                continue

            if _is_ooxml_media_asset(info.filename):
                state.skipped_members.append(f"{display_name} (ooxml_media)")
                continue

            try:
                member_bytes = _read_member_bounded(archive, info, max_member_bytes)
            except (RuntimeError, zipfile.BadZipFile, OSError, EOFError):
                state.add(
                    _finding(
                        "archive_member_extract_error",
                        f"Failed inspecting archive member: {display_name}",
                        Verdict.QUARANTINE,
                        "archive",
                    )
                )
                continue

            state.cumulative_bytes += len(member_bytes)
            state.inspected_members += 1

            container = detect_high_entropy_container(member_bytes)
            if container == "zip_or_ooxml":
                if depth < max_depth:
                    _inspect_zip_bytes(
                        member_bytes,
                        state,
                        config,
                        depth=depth + 1,
                        max_depth=max_depth,
                        max_members=max_members,
                        max_member_bytes=max_member_bytes,
                        max_total_uncompressed=max_total_uncompressed,
                        member_prefix=f"{display_name}>",
                    )
                continue

            suffix = PurePosixPath(info.filename.replace("\\", "/")).suffix.lower()
            is_text_or_script = suffix in _TEXT_AND_SCRIPT_EXTENSIONS
            report = analyze_content_for_persistence(
                member_bytes,
                entropy_warn_threshold=config.entropy_warn_threshold,
                entropy_quarantine_threshold=config.entropy_quarantine_threshold,
                min_entropy_sample_bytes=config.min_entropy_sample_bytes,
                skip_entropy_for_containers=not is_text_or_script,
                allowed_container_formats=config.entropy_exempt_formats,
                patterns=config.patterns,
                max_decoded_segments=config.max_decoded_segments,
            )
            for finding in report.findings:
                state.add(_scoped(finding, display_name))


def inspect_zip_members_for_persistence(
    archive_bytes: bytes,
    *,
    initial_verdict: Verdict = Verdict.ALLOW,
    config: Optional[DeobfuscationPolicyConfig] = None,
    max_depth: int = 2,
) -> ArchiveInspectionResult:
    active_config = config or DeobfuscationPolicyConfig()
    state = _State(verdict=initial_verdict)
    if not active_config.enabled:
        return state.to_result()

    _inspect_zip_bytes(
        archive_bytes,
        state,
        active_config,
        depth=1,
        max_depth=max_depth,
        max_members=active_config.max_members,
        max_member_bytes=active_config.max_member_bytes,
        max_total_uncompressed=active_config.max_total_uncompressed,
    )
    return state.to_result()
