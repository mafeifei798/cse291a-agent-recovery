#!/usr/bin/env python3
"""Independent L API pilot; default fake HTTP, live requires matching proof/permit."""
import argparse
import json
import os
from pathlib import Path
import resource
import sys
sys.dont_write_bytecode=True


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[1])
    p.add_argument('--extension-root',type=Path,default=Path(__file__).resolve().parents[1])
    p.add_argument('--history',type=Path);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--native-cpu',action='store_true');p.add_argument('--authorize-server-cpu',action='store_true')
    p.add_argument('--live',action='store_true')
    for key in ('config','permit','acceptance','catalog'):p.add_argument('--'+key,type=Path)
    a=p.parse_args()
    if a.live and not all(getattr(a,k) for k in ('config','permit','acceptance','catalog')):p.error('Live gate requires config, permit, acceptance and catalog; no defaults')
    if a.native_cpu:
        if sys.platform!='linux' or not a.authorize_server_cpu:p.error('Explicit Linux CPU permission required')
        assert len(os.sched_getaffinity(0))==1 and os.nice(0)>=10
        assert resource.getrlimit(resource.RLIMIT_AS)[0]==8*1024**3
        assert os.environ.get('CUDA_VISIBLE_DEVICES')==''
        assert all(os.environ.get(k)=='1' for k in ('OMP_NUM_THREADS','OPENBLAS_NUM_THREADS','MKL_NUM_THREADS','NUMEXPR_NUM_THREADS'))
        assert not any(k in os.environ for k in ('OPENAI_API_KEY','TRITONAI_API_KEY','AWS_SECRET_ACCESS_KEY','AWS_ACCESS_KEY_ID')) or a.live
    if not a.live:
        def no_network(event,details):
            if event.startswith('socket.'):raise RuntimeError('LAPI_FAKE_NETWORK_DISABLED')
        sys.addaudithook(no_network)
    sys.path[:0]=[str(a.extension_root.resolve()/'src'),str(a.source_root.resolve()/'src'),str(a.source_root.resolve())]
    from agent_l_api.launch import launch
    result=launch(a.output,source_root=a.source_root,extension_root=a.extension_root,
        history_path=a.history or a.extension_root/'phase2/l_api_pilot_20261030_v1/HISTORY.json',
        native=a.native_cpu,authorized=a.authorize_server_cpu,live=a.live,
        config_path=a.config,permit_path=a.permit,acceptance=a.acceptance,catalog=a.catalog)
    print(json.dumps({'status':result['status'],'real_API_calls':result['real_API_calls'],'training_jobs':result['training_jobs']}),flush=True)


if __name__=='__main__':main()
