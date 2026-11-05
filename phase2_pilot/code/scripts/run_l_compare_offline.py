#!/usr/bin/env python3
"""Three-method comparison; fake HTTP and fake training only."""
import argparse
from pathlib import Path
import sys,json
sys.dont_write_bytecode=True


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[1])
    p.add_argument('--case',default='equivalent')
    p.add_argument('--order',nargs=3,default=['FULL','CONSERVATIVE','CUTOFF'])
    a=p.parse_args();sys.path[:0]=[str(a.source_root/'src'),str(a.source_root/'scripts')]
    from agent_l_compare.launch import launch
    from agent_l_compare.protocol import Config
    s=launch(a.output,source_root=a.source_root,config=Config(order=tuple(a.order)),case=a.case)
    print(json.dumps({'case':s['case'],'rows':s['rows'],'fake_generations':s['new_fake_generations'],'actual_training':0}))


if __name__=='__main__':main()
