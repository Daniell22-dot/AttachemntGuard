import json
import logging
import re
import shutil
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Any

from .hash_service import sha256_file

logger = logging.getLogger(__name__)

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class RestoreResult:
    quarantine_id: str
    restored_to: str
    sha256: str
    verdict_at_quarantine: str
    dry_run: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": "restore",
            "quarantine_id": self.quarantine_id,
            "restored_to": self.restored_to,
            "sha256": self.sha256,
            "verdict_at_quarantine": self.verdict_at_quarantine,
            "dry_run": self.dry_run,
        }


def quarantine_file(path, quarantine_dir, scan_result) -> Optional[str]:
    """Move a file to quarantine with a UUID-based filename and JSON sidecar.

    Returns the destination path on success, or None if quarantine fails.
    """
    try:
        quarantine_dir.mkdir(parents=True, exist_ok=True)

        original_name = path.name
        orig_str = str(original_name)
        if '.' in orig_str:
            base, suffix = orig_str.rsplit('.', 1)
            uuid_name = f'{uuid.uuid4()}.{suffix}'
        else:
            uuid_name = str(uuid.uuid4())

        dest = quarantine_dir / uuid_name

        shutil.move(str(path), str(dest))

        sidecar: Dict[str, object] = {
            'original_filename': orig_str,
            'original_path': str(path),
            'sha256': scan_result.get('sha256'),
            'verdict': scan_result.get('verdict'),
            'scanned_at': scan_result.get('scanned_at'),
            'scanner_version': scan_result.get('scanner_version'),
        }
        sidecar_path = quarantine_dir / f'{uuid_name}.json'
        with open(sidecar_path, 'w', encoding='utf-8') as f:
            json.dump(sidecar, f, indent=2)

        return str(dest)
    except (PermissionError, shutil.Error, OSError) as e:
        logger.error('Quarantine failed for %s: %s', path, e)
        return None


def _validate_quarantine_id(quarantine_id: str) -> str:
    cleaned = str(quarantine_id).strip()
    if not _UUID_RE.match(cleaned):
        raise ValueError(f"Invalid quarantine UUID: {quarantine_id!r}")
    return cleaned.lower()


def _load_sidecar(sidecar_path: Path) -> Dict[str, Any]:
    if not sidecar_path.is_file():
        raise FileNotFoundError(f"Quarantine sidecar not found: {sidecar_path}")
    try:
        data = json.loads(sidecar_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Corrupt quarantine sidecar: {sidecar_path}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"Invalid quarantine sidecar schema: {sidecar_path}")
    return data


def _find_quarantine_files(quarantine_dir: Path, quarantine_id: str):
    directory = quarantine_dir.resolve()
    sidecars = sorted(quarantine_dir.glob(f"{quarantine_id}*.json"))
    if not sidecars:
        raise FileNotFoundError(f"No quarantine sidecar for {quarantine_id}")
    sidecar = sidecars[0].resolve()
    if sidecar.parent != directory:
        raise ValueError("Sidecar path escapes quarantine directory")

    stem = sidecars[0].name[:-len(".json")]
    candidates = [quarantine_dir / stem, quarantine_dir / f"{quarantine_id}.quarantined"]
    candidates.extend(
        path for path in quarantine_dir.glob(f"{quarantine_id}*")
        if path.suffix != ".json"
    )
    for candidate in candidates:
        if candidate.is_file() and candidate.resolve().parent == directory:
            return candidate, sidecar
    raise FileNotFoundError(f"Quarantined payload missing for {quarantine_id}")


def restore_quarantined_file(
    quarantine_id: str,
    *,
    quarantine_dir: str | Path = Path("quarantine"),
    destination_override: str | Path | None = None,
    overwrite: bool = False,
    dry_run: bool = False,
) -> RestoreResult:
    qid = _validate_quarantine_id(quarantine_id)
    directory = Path(quarantine_dir)
    if not directory.is_dir():
        raise FileNotFoundError(f"Quarantine directory not found: {directory}")
    payload, sidecar_path = _find_quarantine_files(directory, qid)

    sidecar = _load_sidecar(sidecar_path)
    file_meta = sidecar.get("file") if isinstance(sidecar.get("file"), dict) else sidecar
    original_path = file_meta.get("original_path")
    if not original_path:
        raise ValueError(f"Sidecar for {qid} has no original_path")

    expected_hash = str(
        file_meta.get("sha256") or sidecar.get("sha256") or ""
    ).lower()
    actual_hash = (sha256_file(payload) or "").lower()
    if not actual_hash:
        raise OSError(f"Cannot read quarantined payload for {qid}")
    if expected_hash and actual_hash != expected_hash:
        raise ValueError(
            f"SHA-256 mismatch for {qid}: expected {expected_hash}, found {actual_hash}"
        )

    target = (
        Path(destination_override).expanduser()
        if destination_override is not None
        else Path(original_path).expanduser()
    ).resolve()
    if target == directory.resolve() or directory.resolve() in target.parents:
        raise ValueError("Refusing to restore into the quarantine directory")
    if target.exists() and not overwrite:
        raise FileExistsError(f"Destination already exists: {target}")

    verdict = str(sidecar.get("verdict", "UNKNOWN"))
    result = RestoreResult(
        quarantine_id=qid,
        restored_to=str(target),
        sha256=actual_hash,
        verdict_at_quarantine=verdict,
        dry_run=dry_run,
    )
    if dry_run:
        return result

    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and overwrite:
        stamp = (
            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            + f"-{uuid.uuid4().hex[:8]}"
        )
        backup = target.with_name(f"{target.name}.overwritten-{stamp}")
        shutil.move(str(target), str(backup))

    shutil.move(str(payload), str(target))
    sidecar["restored_at_utc"] = datetime.now(timezone.utc).isoformat()
    sidecar["restored_to"] = str(target)
    sidecar["restore_verified_sha256"] = actual_hash
    temp_sidecar = sidecar_path.with_suffix(sidecar_path.suffix + ".tmp")
    temp_sidecar.write_text(json.dumps(sidecar, indent=2) + "\n", encoding="utf-8")
    temp_sidecar.replace(sidecar_path)
    logger.info("Restored %s to %s", qid, target)
    return result