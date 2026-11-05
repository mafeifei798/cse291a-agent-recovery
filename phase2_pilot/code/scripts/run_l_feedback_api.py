#!/usr/bin/env python3
"""Feedback-aware LC04 and three recoveries; 314 prior, 52 new, 64 total."""
import argparse,json,os,resource,sys
from pathlib import Path
sys.dont_write_bytecode=True

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[1])
    p.add_argument('--history',type=Path);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--live',action='store_true');p.add_argument('--native-cpu',action='store_true')
    p.add_argument('--authorize-server-cpu',action='store_true');p.add_argument('--fixture-counter',action='store_true')
    for k in ('config','permit','acceptance','catalog','models'):p.add_argument('--'+k,type=Path)
    a=p.parse_args()
    if a.live and not all(getattr(a,k) for k in ('config','permit','acceptance','catalog','models')):
        p.error('Live requires fresh config, permit, native, catalog and model evidence')
    if a.native_cpu:
        if sys.platform!='linux' or not a.authorize_server_cpu:p.error('Explicit Linux CPU permission required')
        assert len(os.sched_getaffinity(0))==1 and os.nice(0)>=10 and resource.getrlimit(resource.RLIMIT_AS)[0]==8*1024**3
        assert os.environ.get('CUDA_VISIBLE_DEVICES')==''
        assert all(os.environ.get(k)=='1' for k in ('OMP_NUM_THREADS','OPENBLAS_NUM_THREADS','MKL_NUM_THREADS','NUMEXPR_NUM_THREADS'))
    if not a.live:
        def guard(event,args):
            if event.startswith('socket.'):raise RuntimeError('LFA_NO_NETWORK')
            if not a.native_cpu and event=='import' and args[0].split('.')[0] in ('numpy','scipy','sklearn','joblib'):
                raise RuntimeError('LFA_NO_MODEL_IMPORTS')
        sys.addaudithook(guard)
    root=a.source_root.resolve();sys.path[:0]=[str(root/'src'),str(root)]
    from agent_l_feedback_api.launch import launch
    r=launch(a.output,source_root=root,history_path=a.history or root/'phase2/l_feedback_api_20261031_v1/HISTORY.json',
        live=a.live,native=a.native_cpu,authorized=a.authorize_server_cpu,fixture_counter=a.fixture_counter,
        config_path=a.config,permit_path=a.permit,acceptance=a.acceptance,catalog=a.catalog,models=a.models)
    print(json.dumps({'status':r['status'],'units':len(r['units']),'real_API_calls':r['real_API_calls'],
        'note':'batch accounting exported separately; no automatic continuation'}))

if __name__=='__main__':main()
