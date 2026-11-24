from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from .clamav_service import ClamAvUnavailable
from .file_type_service import detect_extension_mismatch, sniff
from .hash_service import file_info
from .persistence_service import scan_file_binary_strings, scan_file_text
from .policy_service import check_extension, check_size, load_policy
from .yara_service import scan_with_yara
from .zip_inspector import scan_zip

SCANNER_VERSION = "0.2.0"


def decide_verdict(current: str, higher: str) -> str:
    order = {"ALLOW": 0, "WARN": 1, "QUARANTINE": 2, "BLOCK": 3}
    if order.get(higher, 0) > order.get(current, 0):
        return higher
    return current


def _elevate(result: Dict[str, Any], verdict: str, reason: str = "") -> None:
    result["verdict"] = decide_verdict(result["verdict"], verdict)
    if reason and reason not in result["reasons"]:
        result["reasons"].append(reason)


def _apply_clamav(result: Dict[str, Any], clamav, path: Path) -> None:
    try:
        clamav_result = clamav.scan(path)
    except ClamAvUnavailable as exc:
        _elevate(result, "QUARANTINE", f"ClamAV unavailable: {exc}")
        return
    except Exception as exc:
        _elevate(result, "QUARANTINE", f"ClamAV check failed: {type(exc).__name__}")
        return

    result["clamav"] = {
        "engine": clamav_result.engine,
        "exit_code": clamav_result.exit_code,
        "verdict": clamav_result.verdict,
        "signature": clamav_result.signature,
        "timed_out": clamav_result.timed_out,
        "error": clamav_result.error,
    }

    if clamav_result.verdict == "BLOCK":
        signature = clamav_result.signature or "unknown signature"
        _elevate(result, "BLOCK", f"ClamAV detected: {signature}")
    elif clamav_result.verdict in ("QUARANTINE", "UNKNOWN"):
        reason = clamav_result.error or "ClamAV scan failed, timed out, or was inconclusive"
        _elevate(result, "QUARANTINE", reason)


def scan_file(
    path,
    rules_dir: Optional[str] = None,
    policy: Optional[Dict] = None,
    clamav=None,
) -> Dict[str, Any]:
    path = Path(path)
    policy = policy or load_policy()
    result = {
        "schema_version": 1,
        "file": path.name,
        "file_path": str(path.resolve()),
        "path": str(path.resolve()),
        "size_bytes": 0,
        "sha256": "",
        "detected_extension": path.suffix.lower(),
        "detected_mime_type": "unknown",
        "verdict": "ALLOW",
        "reasons": [],
        "rule_matches": [],
        "quarantined": False,
        "quarantine_path": "",
        "scanned_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "scanner_version": SCANNER_VERSION,
        "info": {"path": str(path), "size": 0, "sha256": ""},
        "sniff": {},
        "extension_policy": {},
        "persistence_hits": [],
        "zip_scan": {},
        "yara": [],
        "clamav": {},
    }

    if not path.is_file():
        _elevate(result, "QUARANTINE", "File does not exist")
        return result

    info = file_info(path)
    result["info"] = info
    result["size_bytes"] = info.get("size", 0)
    result["sha256"] = info.get("sha256", "")
    if not result["sha256"]:
        _elevate(result, "QUARANTINE", info.get("error", "Failed to compute hash"))
        return result

    size_ok, size_reason = check_size(path, policy.get("max_file_size_mb"))
    if not size_ok:
        _elevate(result, "QUARANTINE", size_reason)

    ext_verdict, ext_reason = check_extension(path, policy)
    result["extension_policy"] = {"verdict": ext_verdict, "reason": ext_reason}
    if ext_verdict != "ALLOW":
        _elevate(result, ext_verdict, ext_reason)

    sniff_info = sniff(path)
    result["sniff"] = sniff_info
    result["detected_extension"] = sniff_info.get("ext", path.suffix.lower())
    result["detected_mime_type"] = sniff_info.get("mime", "unknown")
    if sniff_info.get("error"):
        _elevate(result, "QUARANTINE", f"File type check failed: {sniff_info['error']}")

    if detect_extension_mismatch(path):
        _elevate(result, "QUARANTINE", "File extension does not match detected file type")

    blocked_extensions = {
        str(value).lower() for value in policy.get("blocked_extensions", [])
    }
    if path.name.count(".") >= 2 and result["detected_extension"] in blocked_extensions:
        _elevate(result, "BLOCK", f"Double extension suspicious: {path.name}")

    zip_result = scan_zip(
        path,
        max_entries=int(policy.get("max_archive_entries", 1000)),
        max_depth=int(policy.get("max_archive_depth", 2)),
        max_compression_ratio=int(policy.get("max_compression_ratio", 100)),
    )
    result["zip_scan"] = zip_result
    if zip_result.get("is_zip"):
        for suspicious in zip_result.get("suspicious", []):
            _elevate(result, "QUARANTINE", suspicious)
        for error in zip_result.get("errors", []):
            _elevate(result, "QUARANTINE", f"ZIP inspection error: {error}")
        if zip_result.get("max_depth", 0) > int(policy.get("max_archive_depth", 2)):
            _elevate(result, "QUARANTINE", "Archive nesting depth exceeds policy")
        if zip_result.get("total_entries", 0) > int(policy.get("max_archive_entries", 1000)):
            _elevate(result, "QUARANTINE", "Archive entry count exceeds policy")

    hits = sorted(set(scan_file_text(path) + scan_file_binary_strings(path)))
    result["persistence_hits"] = hits
    if hits:
        _elevate(result, "BLOCK", f"Persistence indicators: {', '.join(hits)}")

    if rules_dir:
        yara_result = scan_with_yara(path, rules_dir)
        result["yara"] = yara_result
        for item in yara_result:
            if isinstance(item, dict) and item.get("rule"):
                result["rule_matches"].append(item)
                severity = item.get("meta", {}).get("severity", "high")
                _elevate(result, "BLOCK", f"YARA match: {item['rule']} (severity={severity})")
            elif isinstance(item, dict) and item.get("error"):
                _elevate(result, "QUARANTINE", f"YARA check failed: {item['error']}")

    if clamav is not None:
        _apply_clamav(result, clamav, path)

    return result
