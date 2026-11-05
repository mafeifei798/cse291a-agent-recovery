#!/usr/bin/env python3
"""356-history Reviewer confirmation regression; fake HTTP and no real training."""
import argparse
from pathlib import Path
import sys
sys.dont_write_bytecode = True


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[1])
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--suite',action='store_true')
    p.add_argument('--method',choices=('FULL','CONSERVATIVE','CUTOFF'),default='CUTOFF')
    p.add_argument('--case',default='equivalent')
    a = p.parse_args()
    sys.path[:0] = [str(a.source_root/'src'),str(a.source_root/'scripts')]
    from agent_l_approval_confirm.runner import run_branch,run_suite
    if a.suite:
        rows = run_suite(a.output,a.source_root)
        print({'offline_branches':len(rows),'real_API_calls':0,'real_training':0})
    else:
        result = run_branch(a.output,a.source_root,a.case,a.method)
        print({k:result[k] for k in ('outcome','synthetic_HTTP_calls','simulated_fit_tasks','saved_artifact_admissions')})


if __name__ == '__main__':main()
