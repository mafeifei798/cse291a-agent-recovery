#!/usr/bin/env python3
"""Independently check a saved fixture campaign and export trials.csv."""
from pathlib import Path
import argparse
import json
from offline_tools import check


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',type=Path,required=True,help='The campaign directory')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();out=args.output.resolve();campaign=args.run.resolve()
    if out.exists():parser.error('Choose a new output directory')
    expected=json.loads((campaign/'campaign_report.json').read_text())['processed_slots']
    out.mkdir(parents=True);logs=out/'logs';logs.mkdir()
    audit=check(campaign,out/'audit',expected,logs)
    print(json.dumps({'passed':audit['passed'],'processed':expected,'trials_csv':str(out/'audit/trials.csv')}))


if __name__=='__main__':main()
