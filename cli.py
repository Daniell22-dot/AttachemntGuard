import argparse
import json
import sys
from pathlib import Path

_BOOTSTRAP_ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
if str(_BOOTSTRAP_ROOT) not in sys.path:
    sys.path.insert(0, str(_BOOTSTRAP_ROOT))

from core.clamav_service import build_clamav_service
from core.paths import resource_dir, user_data_dir
from core.quarantine_service import quarantine_file, restore_quarantined_file
from core.report_writer import write_report
from core.scanner import scan_file

ROOT = resource_dir()
DATA_DIR = user_data_dir()


def scan_path(
    path,
    quarantine_dir,
    rules_dir,
    policy=None,
    quarantine=False,
    clamav=None,
):
    result = scan_file(path, rules_dir=rules_dir, policy=policy, clamav=clamav)

    if quarantine and result.get("verdict") in {"BLOCK", "QUARANTINE"}:
        source = Path(result.get("file_path", result.get("path", path)))
        try:
            quarantined_to = quarantine_file(source, Path(quarantine_dir), result)
        except Exception as exc:
            result["reasons"].append(f"quarantine_error: {exc}")
        else:
            if quarantined_to:
                result["quarantined"] = True
                result["quarantine_path"] = quarantined_to
                result["quarantined_to"] = quarantined_to
            else:
                result["reasons"].append("quarantine_error: move failed")

    return result


def build_parser():
    parser = argparse.ArgumentParser(description="AttachmentGuard CLI")
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--quarantine-dir", default=str(DATA_DIR / "quarantine"))
    parser.add_argument("--report-dir", default=str(DATA_DIR / "reports"))
    parser.add_argument("--rules-dir", default=str(ROOT / "rules"))
    parser.add_argument("--quarantine", action="store_true")
    parser.add_argument(
        "--clamav",
        action="store_true",
        help="Enable the optional ClamAV check (off unless configured)",
    )
    parser.add_argument(
        "--clamav-config",
        default=str(DATA_DIR / "config.ini"),
        help="Path to the ClamAV configuration file",
    )
    parser.add_argument("--restore", metavar="UUID", help="Restore a quarantined file by UUID")
    parser.add_argument("--restore-to", metavar="PATH", help="Destination override for --restore")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Back up an existing destination before --restore",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview --restore without changing files",
    )
    parser.add_argument("--json", action="store_true")
    return parser


def handle_restore_command(args) -> int | None:
    if not args.restore:
        return None
    try:
        result = restore_quarantined_file(
            args.restore,
            quarantine_dir=args.quarantine_dir,
            destination_override=args.restore_to,
            overwrite=args.overwrite,
            dry_run=args.dry_run,
        )
    except Exception as exc:
        if args.json:
            print(json.dumps({"error": str(exc), "quarantine_id": args.restore}))
        else:
            print(f"[ERROR] Restore failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        prefix = "[DRY-RUN] Would restore" if result.dry_run else "Restored"
        print(f"{prefix} {result.quarantine_id} -> {result.restored_to} (sha256={result.sha256})")
    return 0


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    restore_code = handle_restore_command(args)
    if restore_code is not None:
        return restore_code
    if not args.paths:
        parser.error("at least one path is required unless --restore is used")

    rules_dir = Path(args.rules_dir)
    report_dir = Path(args.report_dir)
    quarantine_dir = Path(args.quarantine_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    clamav = build_clamav_service(
        Path(args.clamav_config),
        enabled=True if args.clamav else None,
    )

    results = []
    for path_value in args.paths:
        report = scan_path(
            path_value,
            quarantine_dir,
            rules_dir,
            quarantine=args.quarantine,
            clamav=clamav,
        )
        report_path = write_report(report, report_dir)
        if report_path:
            report["report_path"] = report_path
        results.append(report)

        if not args.json:
            print(
                f"[{report['verdict']}] {report.get('file_path', path_value)} "
                f"sha256={report.get('sha256')} - "
                f"{', '.join(report['reasons']) or 'ok'}"
            )

    if args.json:
        print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
