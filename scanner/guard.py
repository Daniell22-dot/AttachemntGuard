#!/usr/bin/env python3
import argparse
import json
import os
import sys
from datetime import datetime, timezone

from hashutil import file_info
from filetypes import sniff
from policy import extension_policy
from persistence import scan_file_text, scan_file_binary_strings
from zipscan import scan_zip
from quarantine import quarantine_file
from yara_scan import scan_with_yara

VERDICTS = ['ALLOW', 'WARN', 'QUARANTINE', 'BLOCK']

def scan(path: str, quarantine_dir: str, rules_dir: str) -> dict:
    report = {
        'file': path,
        'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'info': {},
        'sniff': {},
        'extension_policy': {},
        'persistence_hits': [],
        'zip_scan': {},
        'yara': [],
        'verdict': 'ALLOW',
        'reasons': []
    }
    try:
        report['info'] = file_info(path)
    except Exception as e:
        report['reasons'].append(f'file_info_error: {e}')
        report['verdict'] = 'QUARANTINE'
        return report

    report['sniff'] = sniff(path)
    v, r = extension_policy(path)
    report['extension_policy'] = {'verdict': v, 'reason': r}
    if v == 'BLOCK':
        report['verdict'] = 'BLOCK'
        report['reasons'].append(r)
    elif v == 'WARN' and report['verdict'] == 'ALLOW':
        report['verdict'] = 'WARN'
        report['reasons'].append(r)

    # persistence detection
    hits = scan_file_text(path) + scan_file_binary_strings(path)
    # dedupe while preserving order
    hits = list(dict.fromkeys(hits))
    report['persistence_hits'] = hits
    if hits:
        if report['verdict'] != 'BLOCK':
            report['verdict'] = 'BLOCK'
        # emphasize self-referential persistence
        if any('self-referential' in h.lower() for h in hits) or (any('onlogon' in h.lower() for h in hits) and any('processpath' in h.lower() or '%~f0' in h.lower() for h in hits)):
            report['reasons'].append(f'High-risk: self-launching logon persistence - {", ".join(hits)}')
        else:
            report['reasons'].append(f'Persistence indicators: {", ".join(hits)}')

    # zip inspection
    z = scan_zip(path)
    report['zip_scan'] = z
    if z.get('is_zip'):
        if z.get('suspicious'):
            if report['verdict'] != 'BLOCK':
                report['verdict'] = 'BLOCK'
            for s in z['suspicious']:
                report['reasons'].append(s)
        if z.get('errors'):
            for e in z['errors']:
                report['reasons'].append(f'zip_error: {e}')

    # magic/extension mismatch
    ext = report['sniff'].get('ext')
    mime = report['sniff'].get('mime')
    if ext == '.exe' and mime != 'application/x-dosexec':
        pass
    # double extension heuristic
    base = os.path.basename(path)
    if base.count('.') >= 2 and ext in {'.exe', '.scr', '.bat', '.cmd', '.ps1', '.js', '.hta'}:
        report['verdict'] = 'BLOCK'
        report['reasons'].append(f'Double extension suspicious: {base}')

    # YARA
    yara_res = scan_with_yara(path, rules_dir)
    report['yara'] = yara_res
    for m in yara_res:
        if isinstance(m, dict) and m.get('rule'):
            if report['verdict'] != 'BLOCK':
                report['verdict'] = 'BLOCK'
            sev = m.get('meta', {}).get('severity', 'high')
            report['reasons'].append(f"YARA match: {m['rule']} (severity={sev})")

    return report

def main():
    ap = argparse.ArgumentParser(description='AttachmentGuard - static file gate')
    ap.add_argument('path', help='file path to scan')
    ap.add_argument('--quarantine-dir', default=os.path.join(os.path.dirname(__file__), '..', 'quarantine'))
    ap.add_argument('--report-dir', default=os.path.join(os.path.dirname(__file__), '..', 'reports'))
    ap.add_argument('--rules-dir', default=os.path.join(os.path.dirname(__file__), '..', 'rules'))
    ap.add_argument('--quarantine', action='store_true', help='move blocked/quarantined files to quarantine')
    ap.add_argument('--json', action='store_true', help='output JSON')
    args = ap.parse_args()

    qdir = os.path.abspath(args.quarantine_dir)
    rdir = os.path.abspath(args.report_dir)
    rules_dir = os.path.abspath(args.rules_dir)
    os.makedirs(rdir, exist_ok=True)

    report = scan(args.path, qdir, rules_dir)
    out = os.path.join(rdir, f"{os.path.basename(args.path)}.{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json")
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    if args.quarantine and report['verdict'] in {'BLOCK', 'QUARANTINE'}:
        try:
            qp = quarantine_file(args.path, qdir, report)
            report['quarantined_to'] = qp
        except Exception as e:
            report['reasons'].append(f'quarantine_error: {e}')

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"VERDICT: {report['verdict']}")
        print(f"FILE: {report['file']}")
        print(f"SHA256: {report['info'].get('sha256')}")
        print(f"SIZE: {report['info'].get('size')}")
        print(f"MIME/MAGIC: {report['sniff'].get('mime')} (ext={report['sniff'].get('ext')})")
        if report['reasons']:
            print("REASONS:")
            for r in report['reasons']:
                print(f"  - {r}")
        if report['persistence_hits']:
            print("PERSISTENCE:")
            for h in report['persistence_hits']:
                print(f"  - {h}")
        if report['zip_scan'].get('is_zip'):
            print(f"ZIP ENTRIES: {len(report['zip_scan'].get('entries',[]))}")
            for s in report['zip_scan'].get('suspicious',[]):
                print(f"  - {s}")
        if report['yara']:
            print("YARA:")
            for y in report['yara']:
                if isinstance(y, dict) and y.get('rule'):
                    print(f"  - {y['rule']} {y.get('meta')}")
                else:
                    print(f"  - {y}")
        print(f"REPORT: {out}")
    sys.exit(0)

if __name__ == '__main__':
    main()
