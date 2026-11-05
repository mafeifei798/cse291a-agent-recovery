#!/usr/bin/env python3
"""Pinned Linux/tokenizer, fake-HTTP CUTOFF and saved-model no-fit verification."""
import argparse
from datetime import datetime, timedelta, timezone
import importlib.metadata as metadata
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a = p.parse_args();root,out = a.project.resolve(),a.output.resolve()
    sys.path[:0] = [str(root/'src'),str(root/'scripts')]
    from agent_l_confirm_entry.protocol import require_resources,history,HISTORY_REL,HISTORY_SHA,source_sha
    require_resources()
    assert not out.exists()
    assert not any(k in os.environ for k in ('OPENAI_API_KEY','TRITONAI_API_KEY','AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY'))
    expected = {'numpy':'1.26.3','scipy':'1.11.1','pandas':'2.1.4','scikit-learn':'1.3.0','joblib':'1.2.0',
        'threadpoolctl':'3.6.0','tokenizers':'0.22.1','jsonschema':'4.20.0','Jinja2':'3.1.2'}
    assert {n:metadata.version(n) for n in expected} == expected
    def offline(event,args):
        if event.startswith('socket.'):raise RuntimeError('ACE_ACCEPT_NETWORK_DISABLED')
    sys.addaudithook(offline)
    out.mkdir(parents=True)
    from agent_l_confirm_entry.launch import launch
    from check_l_confirm_entry import check
    from agent_l_replay_live.evidence import verify_saved_source
    from agent_l_replay_live.numeric_acceptance import verify_models
    from agent_l_confirm_entry.cpu import NoFitCPU
    h = history(root/HISTORY_REL,root)
    frozen,campaign = verify_saved_source(root)
    # Genuine tokenizer, but synthetic HTTP and hash-only saved admissions.
    fake = out/'fake-CUTOFF'
    launch(fake,source_root=root)
    entry_proof = check(fake,root)
    assert entry_proof['completed_recovery'] and entry_proof['calls_recorded'] == 9
    ledger = json.loads((fake/'LEDGER.json').read_text())
    assert all(c['sidecar']['local_token_statistics']['local_assets_verified']
        and c['sidecar']['local_token_statistics']['input_messages_dropped'] == 0
        and c['sidecar']['local_token_statistics']['input_messages_truncated'] == 0 for c in ledger['calls'])
    suite = unittest.TestSuite()
    names = ('test_agent_l_api.py','test_agent_l_v1.py','test_agent_l_v2.py','test_agent_l_v3.py',
        'test_l_api_batch.py','test_l_api_resume.py','test_l_feedback.py','test_l_feedback_api.py',
        'test_l_feedback_replay.py','test_l_replay_entry.py','test_l_api_native.py',
        'test_l_approval_confirm.py','test_l_confirm_entry.py')
    for name in names:suite.addTests(unittest.defaultTestLoader.discover(str(root/'tests'),pattern=name))
    with (out/'TESTS.log').open('x') as f,patch('agent_l_v1.cpu.ActualCPU.fit',side_effect=AssertionError('ACE_ACCEPT_FIT_DISABLED')):
        result = unittest.TextTestRunner(stream=f,verbosity=2).run(suite)
    assert result.wasSuccessful()
    # Independent saved-model numerical checks; fit guards are installed in
    # the checker itself. Prediction is permitted, training is never enabled.
    numeric = verify_models(root,campaign,frozen,out/'numeric')
    # Recheck the same saved bytes after deserialization and prediction.
    from agent_l_feedback_replay.fixtures import SavedCPU
    from agent_l_feedback_replay.runtime import approved_stage
    guard = SavedCPU(campaign,root)
    old = [approved_stage(frozen)['initial_screen']['payload'],frozen['active']['screen']['payload'],
           frozen['active']['final']['payload']]
    data_ref = frozen['store_snapshot']['files']['inputs/data.json']
    data = json.loads((campaign/'runs/LI01.PREFIX/artifacts/sha256'/data_ref['sha256']).read_text())
    for model in old:guard.validate(model,model['contract'],model['kind'],data)
    history(root/HISTORY_REL,root);verify_saved_source(root)
    try:
        object.__new__(NoFitCPU).fit(None,None,None,None)
        raise AssertionError('Native fit guard did not refuse')
    except Exception as exc:
        assert getattr(exc,'code',None) == 'ACE_RETRAIN_REQUIRED'
    assert numeric['passed'] and numeric['model_fits'] == 0
    now = datetime.now(timezone.utc)
    proof = {'revision':'confirm-entry-native-v1','passed':True,'source_sha256':source_sha(root),
        'history_sha256':HISTORY_SHA,'target_root':str(root),
        'target_kind':'datahub-course-cpu' if os.environ.get('JUPYTERHUB_USER') == 'hoding' else 'research-server-offline',
        'python':sys.version.split()[0],'dependencies':expected,'tokenizers':'0.22.1','real_tokenizer_used':True,
        'confirmation_protocol_checked':True,'no_fit_numeric_passed':True,'native_fit_guard_passed':True,
        'source_artifacts_unchanged':True,'inherited_Bank_calls':h['Bank_calls'],
        'inherited_first_generations':54,'remaining_generations':10,'first_total_generation_cap':64,
        'holds_nano':[v['amount_nano'] for v in h['holds']],'tests_passed':result.testsRun,
        'fake_CUTOFF':entry_proof,'saved_model_predictions':numeric['model_predictions'],
        'saved_model_loads':sum(v['result']['model_loads'] for v in numeric['models']),
        'model_fits':0,'real_API_calls':0,'real_key_reads':0,'cloud_starts':0,'children_reaped':True,
        'accepted_utc':now.isoformat(),'expires_utc':(now+timedelta(hours=2)).isoformat(),
        'permission_granted':False,'native_live_integration_executed':False,
        'scope':'Genuine tokenizer with fake HTTP; saved-model no-fit numbers checked separately. No real LLM inference.'}
    (out/'NATIVE_PROOF.json').write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps({'passed':True,'tests_passed':result.testsRun,'history':356,
        'saved_model_predictions':proof['saved_model_predictions'],'model_fits':0,'real_API_calls':0}))


if __name__ == '__main__':main()
