#!/usr/bin/env python3
"""Future Linux acceptance: pinned tokenizer, fake HTTP, no fit or generation.

Requires a separately prepared, fresh no-fit LR/RF compatibility receipt from
the existing numeric_smoke.py. This script never loads a model or predicts.
"""
import argparse,contextlib,hashlib,importlib.metadata as metadata,json,os,resource,sys,time,unittest
from datetime import datetime,timedelta,timezone
from pathlib import Path
sys.dont_write_bytecode=True

def main(profile='batch-v1'):
    assert profile in ('batch-v1','resume-v2','feedback-v3')
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--numeric-proof',type=Path,required=True)
    a=p.parse_args();root=a.project.resolve();out=a.output.resolve()
    assert sys.platform=='linux' and sys.version.split()[0]=='3.10.12'
    assert len(os.sched_getaffinity(0))==1 and os.nice(0)>=10
    assert resource.getrlimit(resource.RLIMIT_AS)[0]==8*1024**3
    assert not out.exists() and os.environ.get('CUDA_VISIBLE_DEVICES')==''
    assert not any(k in os.environ for k in ('OPENAI_API_KEY','TRITONAI_API_KEY','AWS_SECRET_ACCESS_KEY','AWS_ACCESS_KEY_ID'))
    expected={'numpy':'1.26.3','scipy':'1.11.1','pandas':'2.1.4','scikit-learn':'1.3.0','joblib':'1.2.0',
        'threadpoolctl':'3.6.0','tokenizers':'0.22.1','jsonschema':'4.20.0','Jinja2':'3.1.2'}
    assert {k:metadata.version(k) for k in expected}==expected
    numeric=json.loads(a.numeric_proof.read_text())
    assert 0<=time.time()-a.numeric_proof.stat().st_mtime<3600
    assert numeric['passed'] and numeric['training']==0 and numeric['fit_guard']['installed']
    assert not numeric['fit_guard']['rejected_calls'] and numeric['runtime']==sys.executable
    assert {v['family'] for v in numeric['models']}=={'logistic_regression','random_forest'}
    assert all(all(abs(e)<1e-10 for e in v['max_probability_absolute_error'].values()) for v in numeric['models'])
    out.mkdir(parents=True);sys.path[:0]=[str(root/'src'),str(root/'scripts')]
    def guard(event,args):
        if event.startswith('socket.'):raise RuntimeError('LB_ACCEPTANCE_NETWORK_DISABLED')
        if event=='import' and args[0].split('.')[0] in ('sklearn','joblib','numpy','scipy'):
            raise RuntimeError('LB_ACCEPTANCE_NO_ESTIMATOR_IMPORTS')
    sys.addaudithook(guard)
    loader=unittest.TestLoader();suite=unittest.TestSuite()
    first_pattern={'batch-v1':'test_l_api_batch.py','resume-v2':'test_l_api_resume.py','feedback-v3':'test_l_feedback_api.py'}[profile]
    for pattern in (first_pattern,'test_l_api_native.py'):
        suite.addTests(loader.discover(str(root/'tests'),pattern=pattern))
    with (out/'TESTS.log').open('w') as log:
        result=unittest.TextTestRunner(stream=log,verbosity=2).run(suite)
    assert result.wasSuccessful()
    if profile=='feedback-v3':
        from agent_l_feedback_api.launch import launch
        from agent_l_feedback_api.protocol import source_sha,HISTORY_SHA
        from check_l_feedback_api import check
        history_folder='l_feedback_api_20261031_v1'
    elif profile=='resume-v2':
        from agent_l_resume.launch import launch
        from agent_l_resume.protocol import source_sha,HISTORY_SHA
        from check_l_api_resume import check
        history_folder='l_api_resume_20261031_v1'
    else:
        from agent_l_batch.launch import launch
        from agent_l_batch.protocol import source_sha,HISTORY_SHA
        from check_l_api_batch import check
        history_folder='l_api_batch_20261031_v1'
    launch(out/'fake',source_root=root,history_path=root/'phase2'/history_folder/'HISTORY.json')
    independent=check(out/'fake',root);assert independent['local_full_message_counter_checked']
    (out/'INDEPENDENT.json').write_text(json.dumps(independent,indent=2)+'\n')
    now=datetime.now(timezone.utc)
    proof={'passed':True,'fixture_only':False,'fake_HTTP_only':True,'CPU_fixture_only':True,
        'python':sys.version.split()[0],'tokenizers':'0.22.1','RF_numeric_passed':True,
        'RF_check_scope':'fresh external no-fit numeric receipt; no fit/predict inside this script',
        'numeric_sha256':hashlib.sha256(a.numeric_proof.read_bytes()).hexdigest(),
        'children_reaped':True,'batch_accounting_passed':True,'source_sha256':source_sha(root),
        'history_sha256':HISTORY_SHA,'accepted_utc':now.isoformat(),'expires_utc':(now+timedelta(hours=2)).isoformat(),
        'target_kind':'datahub-course-cpu','real_API_calls':0,'training':0}
    if profile=='feedback-v3':
        proof.update(feedback_protocol='l-feedback-v1',first_total_generation_cap=64,
            new_generation_cap=52,all_recoveries_use_feedback_loop=True)
    (out/'NATIVE_PROOF.json').write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps(proof))

if __name__=='__main__':main()
