#!/usr/bin/env python3
import argparse
import json
import os
import sys
from datetime import datetime, timezone

# add scanner to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'scanner'))

from hashutil import file_info
from filetypes import sniff
from policy import extension_policy
from persistence import scan_file_text, scan_file_binary_strings
from zipscan import scan_zip
from quarantine import quarantine_file
from yara_scan import scan_with_yara

def scan_path(path: str, quarantine_dir: str, rules_dir: str) -> dict:
    report = {
        'file': os.path.abspath(path),
        'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'info': {}, 'sniff': {}, 'extension_policy': {}, 'persistence_hits': [], 'zip_scan': {}, 'yara': [],
        'verdict': 'ALLOW', 'reasons': []
    }
    try:
        report['info'] = file_info(path)
    except Exception as e:
        report['reasons'].append(f'file_info_error: {e}')
        report['verdict'] = 'QUARANTINE'
        return report

    report['sniff'] = sniff(path)
    v,r = extension_policy(path)
    report['extension_policy'] = {'verdict':v,'reason':r}
    if v=='BLOCK': report['verdict']='BLOCK'; report['reasons'].append(r)
    elif v=='WARN' and report['verdict']=='ALLOW': report['verdict']='WARN'; report['reasons'].append(r)

    hits = sorted(set(scan_file_text(path)+scan_file_binary_strings(path)))
    report['persistence_hits']=hits
    if hits:
        if report['verdict']!='BLOCK': report['verdict']='BLOCK'
        report['reasons'].append(f'Persistence indicators: {", ".join(hits)}')

    z = scan_zip(path)
    report['zip_scan']=z
    if z.get('is_zip'):
        if z.get('suspicious'):
            if report['verdict']!='BLOCK': report['verdict']='BLOCK'
            for s in z['suspicious']: report['reasons'].append(s)
        for e in z.get('errors',[]): report['reasons'].append(f'zip_error: {e}')

    base=os.path.basename(path); ext=report['sniff'].get('ext')
    if base.count('.')>=2 and ext in {'.exe','.scr','.bat','.cmd','.ps1','.js','.hta'}:
        report['verdict']='BLOCK'; report['reasons'].append(f'Double extension suspicious: {base}')

    yr = scan_with_yara(path, rules_dir)
    report['yara']=yr
    for m in yr:
        if isinstance(m,dict) and m.get('rule'):
            if report['verdict']!='BLOCK': report['verdict']='BLOCK'
            report['reasons'].append(f"YARA match: {m['rule']} (severity={m.get('meta',{}).get('severity','high')})")
    return report

def main():
    ap=argparse.ArgumentParser(description='AttachmentGuard CLI')
    ap.add_argument('paths', nargs='+')
    ap.add_argument('--quarantine-dir', default=os.path.join(os.path.dirname(__file__),'quarantine'))
    ap.add_argument('--report-dir', default=os.path.join(os.path.dirname(__file__),'reports'))
    ap.add_argument('--rules-dir', default=os.path.join(os.path.dirname(__file__),'rules'))
    ap.add_argument('--quarantine', action='store_true')
    ap.add_argument('--json', action='store_true')
    args=ap.parse_args()
    qdir=os.path.abspath(args.quarantine_dir); rdir=os.path.abspath(args.report_dir); rules_dir=os.path.abspath(args.rules_dir)
    os.makedirs(rdir,exist_ok=True)
    results=[]
    for p in args.paths:
        rep = scan_path(p,qdir,rules_dir)
        ts=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        out=os.path.join(rdir,f"{os.path.basename(p)}.{ts}.json")
        with open(out,'w',encoding='utf-8') as f: json.dump(rep,f,indent=2)
        if args.quarantine and rep['verdict'] in {'BLOCK','QUARANTINE'}:
            try:
                qp=quarantine_file(p,qdir,rep); rep['quarantined_to']=qp
            except Exception as e: rep['reasons'].append(f'quarantine_error:{e}')
        results.append(rep)
        if not args.json:
            print(f"[{rep['verdict']}] {rep['file']} sha256={rep['info'].get('sha256')} - {', '.join(rep['reasons']) or 'ok'}")
    if args.json: print(json.dumps(results,indent=2))
    sys.exit(0)

if __name__=='__main__': main()
