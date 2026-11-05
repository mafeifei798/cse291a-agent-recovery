#!/usr/bin/env python3
"""Read-only independent formal P4 audit and descriptive standard summaries."""
from __future__ import annotations
import argparse
import csv
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agent_recovery.p4_checker import audit_records, P0
from export_p4_formal import collect


def audit_directory(root, *, p0_root=P0, expected_processed=None, allow_simulated=False):
    return audit_records(collect(root), p0_root=p0_root,
        expected_processed=expected_processed, allow_simulated=allow_simulated)


def write_results(report, destination):
    destination=Path(destination);destination.mkdir(parents=True,exist_ok=True)
    (destination/'independent_audit.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    (destination/'aggregate.json').write_text(json.dumps(report['aggregate'],ensure_ascii=False,indent=2)+'\n')
    for name,rows in (('trials',report['trials']),('steps',report['steps'])):
        (destination/(name+'.jsonl')).write_text(''.join(json.dumps(r,ensure_ascii=False,sort_keys=True)+'\n' for r in rows))
        if rows:
            keys=list(dict.fromkeys(k for r in rows for k in r))
            with (destination/(name+'.csv')).open('w',newline='') as stream:
                writer=csv.DictWriter(stream,fieldnames=keys);writer.writeheader()
                for row in rows:writer.writerow({k:json.dumps(v,ensure_ascii=False,sort_keys=True) if isinstance(v,(list,dict)) else v for k,v in row.items()})


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--run-root');group.add_argument('--records')
    parser.add_argument('--output-dir',required=True)
    parser.add_argument('--expected-processed',type=int)
    parser.add_argument('--allow-simulated',action='store_true')
    args=parser.parse_args()
    if args.run_root:
        report=audit_directory(args.run_root,expected_processed=args.expected_processed,allow_simulated=args.allow_simulated)
    else:
        report=audit_records(json.loads(Path(args.records).read_text()),expected_processed=args.expected_processed,allow_simulated=args.allow_simulated)
    write_results(report,args.output_dir)
    print(json.dumps({'passed':report['passed'],'findings':report['findings'],'aggregate':report['aggregate']},ensure_ascii=False))
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
