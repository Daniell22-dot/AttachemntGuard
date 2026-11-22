from pathlib import Path
from typing import Dict, Optional, Tuple

try:
    import yaml
except ImportError:
    yaml = None

POLICY_PATH = Path(__file__).resolve().parents[1] / "policy" / "default_policy.yaml"

DEFAULT_POLICY = {
    "schema_version": 1,
    "max_file_size_mb": 25,
    "max_archive_depth": 2,
    "max_archive_entries": 1000,
    "max_compression_ratio": 100,
    "allowed_extensions": [".pdf", ".png", ".jpg", ".jpeg", ".txt", ".csv", ".docx", ".xlsx"],
    "blocked_extensions": [".exe", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".hta", ".lnk"],
}


def load_policy(path: Path = POLICY_PATH) -> Dict:
    policy = dict(DEFAULT_POLICY)
    if yaml is None:
        return policy
    try:
        loaded = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return policy
    if isinstance(loaded, dict):
        policy.update(loaded)
    return policy


def _extensions(values) -> set:
    if not isinstance(values, (list, tuple, set)):
        return set()
    return {str(value).lower() for value in values}


def check_extension(path, policy: Optional[Dict] = None) -> Tuple[str, str]:
    policy = policy or load_policy()
    allowed = _extensions(policy.get("allowed_extensions"))
    blocked = _extensions(policy.get("blocked_extensions"))
    ext = Path(path).suffix.lower()
    if ext in blocked:
        return "BLOCK", f"Blocked extension: {ext}"
    if ext not in allowed:
        return "WARN", f"Extension not in allowlist: {ext}"
    return "ALLOW", "Extension allowed"


def check_size(path, max_mb: Optional[int] = None) -> Tuple[bool, str]:
    policy = load_policy() if max_mb is None else {"max_file_size_mb": max_mb}
    try:
        size_bytes = Path(path).stat().st_size
        max_bytes = int(policy.get("max_file_size_mb", 25)) * 1024 * 1024
        if size_bytes > max_bytes:
            return False, f"File too large: {size_bytes // (1024 * 1024)} MB > {max_bytes // (1024 * 1024)} MB"
        return True, "Size OK"
    except (PermissionError, OSError) as exc:
        return False, f"Cannot determine size: {exc}"


def has_extension(path, policy: Optional[Dict] = None) -> bool:
    policy = policy or load_policy()
    return Path(path).suffix.lower() in _extensions(policy.get("allowed_extensions"))
