#!/usr/bin/env python3
"""356-history CUTOFF entry. Fake HTTP by default; live requires fresh permission."""
import argparse
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[1])
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--live',action='store_true')
    p.add_argument('--authorize-server-cpu',action='store_true')
    p.add_argument('--fixture-counter',action='store_true')
    for name in ('config','permit','acceptance','catalog','models'):p.add_argument('--'+name,type=Path)
    a = p.parse_args();root = a.source_root.resolve()
    sys.path[:0] = [str(root/'src'),str(root/'scripts')]
    from agent_l_confirm_entry.protocol import Config, Permit
    if a.live:
        if not a.authorize_server_cpu or a.fixture_counter or not all(getattr(a,n) for n in
                ('config','permit','acceptance','catalog','models')):
            p.error('Live needs explicit CPU permission and fresh config, permit, target, catalog and model proofs')
        config = Config(**json.loads(a.config.read_text()));permit = Permit(**json.loads(a.permit.read_text()))
    else:
        config,permit = Config(),None
        def offline(event,args):
            if event.startswith('socket.'):raise RuntimeError('ACE_OFFLINE_NETWORK_DISABLED')
        sys.addaudithook(offline)
    from agent_l_confirm_entry.launch import launch
    result = launch(a.output,source_root=root,config=config,live=a.live,authorized=a.authorize_server_cpu,
        permit=permit,acceptance=a.acceptance,catalog=a.catalog,models=a.models,fixture_counter=a.fixture_counter)
    print(json.dumps(result))


if __name__ == '__main__':main()
