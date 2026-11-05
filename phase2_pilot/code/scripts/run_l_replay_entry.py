#!/usr/bin/env python3
"""Independent 350-history entry; fake HTTP and no training by default."""
import argparse
import json
import os
from pathlib import Path
import resource
import sys
sys.dont_write_bytecode = True

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root', type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--method', choices=('FULL','CONSERVATIVE','CUTOFF'), default='CUTOFF')
    p.add_argument('--live', action='store_true')
    p.add_argument('--authorize-server-cpu', action='store_true')
    p.add_argument('--fixture-counter', action='store_true')
    for name in ('config','permit','acceptance','catalog','models'):
        p.add_argument('--'+name, type=Path)
    a = p.parse_args()
    root = a.source_root.resolve()
    sys.path[:0] = [str(root/'src'), str(root/'scripts')]
    from agent_l_replay_live.protocol import Config, Permit
    if a.live:
        if not a.authorize_server_cpu or not all(getattr(a,n) for n in ('config','permit','acceptance','catalog','models')):
            p.error('Live needs explicit CPU permission, config, permit and fresh target/catalog/model proofs')
        if a.fixture_counter:
            p.error('Fixture counter is forbidden live')
        require_resources()
        config = Config(**json.loads(a.config.read_text()))
        permit = Permit(**json.loads(a.permit.read_text()))
    else:
        config, permit = Config(method=a.method), None
        def offline(event, args):
            if event.startswith('socket.'):
                raise RuntimeError('FRL_OFFLINE_NETWORK_DISABLED')
            if event == 'import' and args[0].split('.')[0] in ('sklearn','joblib'):
                raise RuntimeError('FRL_OFFLINE_ESTIMATOR_DISABLED')
        sys.addaudithook(offline)
    from agent_l_replay_live.launch import launch
    result = launch(a.output, source_root=root, config=config, permit=permit,
                    live=a.live, authorized=a.authorize_server_cpu, acceptance=a.acceptance,
                    catalog=a.catalog, models=a.models, fixture_counter=a.fixture_counter)
    print(json.dumps(result))

def require_resources():
    assert sys.platform == 'linux' and len(os.sched_getaffinity(0)) == 1 and os.nice(0) >= 10
    assert resource.getrlimit(resource.RLIMIT_AS)[0] == 8*1024**3
    assert os.environ.get('CUDA_VISIBLE_DEVICES') == ''
    assert all(os.environ.get(k) == '1' for k in ('OMP_NUM_THREADS','OPENBLAS_NUM_THREADS','MKL_NUM_THREADS','NUMEXPR_NUM_THREADS'))

if __name__ == '__main__':
    main()
