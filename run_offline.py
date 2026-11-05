#!/usr/bin/env python3
"""Execute the configuration workflow with scripted model responses and SQLite."""
from collections import Counter
from pathlib import Path
import argparse
import json
import time
from offline_tools import run_script,check,save


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--stop-after',type=int,choices=(14,56,112,168),default=168)
    args=parser.parse_args();out=args.output.resolve()
    if out.exists():parser.error('Choose a new output directory')
    out.mkdir(parents=True);logs=out/'logs';logs.mkdir();start=time.monotonic()
    campaign=out/'campaign';stages=[]
    save(out/'OFFLINE_RUN.json',{'status':'running','simulated':True,'real_API_requests':0})
    try:
        for number in (14,56,112,168):
            if number>args.stop_after:break
            run_script('run_p4_formal.py',['--fixture','--root',campaign,'--stop-after',number],
                log=logs/('run'+str(number)+'.log'),trace=logs/('run'+str(number)+'_reads.json'))
            audit=check(campaign,out/('audit'+str(number)),number,logs)
            report=json.loads((campaign/'campaign_report.json').read_text())
            if report['processed_slots']!=number or report['real_api_requests']!=0:
                raise RuntimeError('Unexpected fixture execution state')
            stages.append({'processed':number,'independent_check_passed':True})
            print(str(number)+'/168 rows processed; independent check passed',flush=True)
        processed=[t for t in audit['trials'] if t['processed']]
        summary={'status':'completed','simulated':True,'processed_rows':args.stop_after,
            'not_started_rows':168-args.stop_after,
            'stages':stages,'outcomes':dict(Counter('not_needed' if t['status']=='not_needed'
                else t['business_outcome'] for t in processed)),
            'real_API_requests':0,'new_training_jobs':0,'network_access_denied':True,
            'elapsed_seconds':time.monotonic()-start,'trials_csv':str(out/('audit'+str(args.stop_after))/'trials.csv')}
        save(out/'OFFLINE_RUN.json',summary);print(json.dumps(summary,indent=2))
    except BaseException as exc:
        save(out/'OFFLINE_RUN.json',{'status':'failed','simulated':True,'completed_stages':stages,
            'error':str(exc),'elapsed_seconds':time.monotonic()-start})
        raise


if __name__=='__main__':main()
