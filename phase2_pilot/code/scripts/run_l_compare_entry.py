#!/usr/bin/env python3
"""New 364-history comparison. Fake HTTP by default, live requires fresh permission."""
import argparse
import json
from pathlib import Path
import sys
sys.dont_write_bytecode=True


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[1])
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--live',action='store_true');p.add_argument('--authorize-server-cpu',action='store_true')
    p.add_argument('--fixture-counter',action='store_true');p.add_argument('--case',default='equivalent')
    for name in ('config','permit','acceptance','catalog','models'):p.add_argument('--'+name,type=Path)
    a=p.parse_args();root=a.source_root.resolve();sys.path[:0]=[str(root/'src'),str(root/'scripts')]
    from agent_l_compare_entry.protocol import Config,Permit
    if a.live:
        if not a.authorize_server_cpu or a.fixture_counter or a.case!='equivalent' or not all(
                getattr(a,n) for n in ('config','permit','acceptance','catalog','models')):
            p.error('Live needs fresh complete authorization and target proofs; fake hooks are forbidden')
        c=Config.from_json(json.loads(a.config.read_text()));permit=Permit(**json.loads(a.permit.read_text()))
    else:
        c=Config.from_json(json.loads(a.config.read_text())) if a.config else Config();permit=None
        def offline(event,args):
            if event.startswith('socket.'):raise RuntimeError('CMPE_OFFLINE_NETWORK_DISABLED')
        sys.addaudithook(offline)
    from agent_l_compare_entry.launch import launch
    answer=launch(a.output,source_root=root,config=c,live=a.live,authorized=a.authorize_server_cpu,
        permit=permit,acceptance=a.acceptance,catalog=a.catalog,models=a.models,
        fixture_counter=a.fixture_counter,case=a.case)
    print(json.dumps(answer))


if __name__=='__main__':main()
