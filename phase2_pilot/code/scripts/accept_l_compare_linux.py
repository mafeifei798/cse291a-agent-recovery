#!/usr/bin/env python3
"""Pinned Linux/tokenizer acceptance; training is an explicit, optional capability."""
import argparse
from datetime import datetime,timedelta,timezone
import importlib.metadata as metadata
import json
import multiprocessing
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--authorize-cpu-smoke',action='store_true')
    a=p.parse_args();root,out=a.project.resolve(),a.output.resolve()
    sys.path[:0]=[str(root/'src'),str(root/'scripts'),str(root/'tests')]
    from agent_l_compare_entry.protocol import require_resources,history,HISTORY_SHA,source_sha
    require_resources();assert not out.exists()
    assert not any(k in os.environ for k in ('OPENAI_API_KEY','TRITONAI_API_KEY','AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY'))
    expected={'numpy':'1.26.3','scipy':'1.11.1','pandas':'2.1.4','scikit-learn':'1.3.0','joblib':'1.2.0',
        'threadpoolctl':'3.6.0','tokenizers':'0.22.1','jsonschema':'4.20.0','Jinja2':'3.1.2'}
    assert {n:metadata.version(n) for n in expected}==expected
    def offline(event,args):
        if event.startswith('socket.'):raise RuntimeError('CMPE_ACCEPT_NETWORK_DISABLED')
    sys.addaudithook(offline);out.mkdir(parents=True)
    from agent_l_compare_entry.launch import launch,write
    from check_l_compare_entry import check
    from agent_l_replay_live.evidence import verify_saved_source
    from agent_l_compare_entry.numeric import verify_arrays
    h=history(root);frozen,campaign=verify_saved_source(root);before=source_sha(root)
    cases=[]
    for case in ('equivalent','changed_contract','initial_changed'):
        folder=out/case
        launch(folder,source_root=root,case=case)
        checked=check(folder,root);cases.append(checked)
        for call in json.loads((folder/'LEDGER.json').read_text())['calls']:
            stats=call['sidecar']['local_token_statistics']
            assert stats['local_assets_verified'] and stats['input_messages_dropped']==0 and stats['input_messages_truncated']==0
    names=('test_l_compare_entry','test_l_compare','test_agent_l_api','test_agent_l_v1','test_agent_l_v2',
        'test_agent_l_v3','test_l_api_batch','test_l_api_resume','test_l_feedback','test_l_feedback_api',
        'test_l_feedback_replay','test_l_replay_entry','test_l_api_native','test_l_approval_confirm','test_l_confirm_entry')
    with (out/'TESTS.log').open('x') as f,patch('agent_l_v1.cpu.ActualCPU.fit',side_effect=AssertionError('CMPE_ACCEPT_NO_TRAIN')):
        result=unittest.TextTestRunner(stream=f,verbosity=2).run(unittest.TestLoader().loadTestsFromNames(names))
    assert result.wasSuccessful(),'Preserved failed log: '+str(out/'TESTS.log')
    numeric=verify_arrays(root,campaign,frozen);write(out/'ARRAY_NUMERIC.json',numeric)
    native=None;smoke=None
    if a.authorize_cpu_smoke:
        # Not executed by the default offline acceptance or by this preparation task.
        from agent_l_compare_entry.cpu import NativeCPU,verify_native_origin,models_in
        from agent_l_v3.timing import Timing
        from agent_l_replay_live.numeric_acceptance import verify_models
        saved=verify_native_origin(campaign,frozen)
        cpu=NativeCPU(out/'cpu-smoke',saved,authorized=True,training_authorized=True);cpu.timing=Timing()
        ref=frozen['store_snapshot']['files']['inputs/data.json']
        data=json.loads((campaign/'runs/LI01.PREFIX/artifacts/sha256'/ref['sha256']).read_text())
        values=[cpu.fit(m['contract'],'screen',data,datetime.now(timezone.utc)+timedelta(seconds=192.470543))
            for m in models_in(frozen)[:2]]
        smoke={'passed':cpu.fit_count==2,'real_fits':cpu.fit_count,'results':values,'records':cpu.records}
        write(out/'CPU_SMOKE.json',smoke)
        native=verify_models(root,campaign,frozen,out/'native-numeric')
    history(root);verify_saved_source(root);assert source_sha(root)==before
    assert not multiprocessing.active_children()
    now=datetime.now(timezone.utc)
    proof={'revision':'l-compare-native-v1','passed':True,'source_sha256':before,'history_sha256':HISTORY_SHA,
        'target_root':str(root),'target_kind':'datahub-course-cpu' if os.environ.get('JUPYTERHUB_USER')=='hoding' else 'research-server-offline',
        'python':sys.version.split()[0],'dependencies':expected,'tokenizers':'0.22.1','real_tokenizer_used':True,
        'three_method_fake_HTTP_passed':True,'cases':cases,'array_numeric_passed':numeric['passed'],
        'cpu_fit_smoke_passed':bool(smoke and smoke['passed']),'native_numeric_passed':bool(native and native['passed']),
        'model_fits':smoke['real_fits'] if smoke else 0,'saved_model_loads':3 if native else 0,
        'model_predictions':(native['model_predictions'] if native else 0),
        'real_API_calls':0,'real_key_reads':0,'cloud_starts':0,'tests_passed':result.testsRun,
        'holds_nano':[v['amount_nano'] for v in h['holds']],'old_first_used':62,'old_first_reopened':False,
        'source_artifacts_unchanged':True,'children_reaped':True,
        'accepted_utc':now.isoformat(),'expires_utc':(now+timedelta(hours=2)).isoformat(),
        'live_ready':bool(smoke and native and os.environ.get('JUPYTERHUB_USER')=='hoding'),
        'permission_granted':False,'native_live_integration_executed':False,
        'scope':'No-key offline acceptance. Without explicit CPU smoke, no training, model load or prediction.'}
    write(out/'NATIVE_PROOF.json',proof)
    print(json.dumps({'passed':True,'tests_passed':result.testsRun,'history':364,
        'live_ready':proof['live_ready'],'model_fits':proof['model_fits'],'real_API_calls':0}))


if __name__=='__main__':main()
