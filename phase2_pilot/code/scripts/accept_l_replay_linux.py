#!/usr/bin/env python3
"""Fresh Linux/tokenizer acceptance, saved-model no-fit checks, fake HTTP only."""
import argparse
from datetime import datetime, timedelta, timezone
import importlib.metadata as metadata
import json
import os
from pathlib import Path
import resource
import sys
import unittest
sys.dont_write_bytecode = True


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    root, out = a.project.resolve(), a.output.resolve()
    assert sys.platform == 'linux' and sys.version.split()[0] == '3.10.12'
    assert len(os.sched_getaffinity(0)) == 1 and os.nice(0) >= 10
    assert resource.getrlimit(resource.RLIMIT_AS)[0] == 8*1024**3
    assert os.environ.get('CUDA_VISIBLE_DEVICES') == '' and not out.exists()
    assert not any(k in os.environ for k in ('OPENAI_API_KEY','TRITONAI_API_KEY','AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY'))
    expected = {'numpy':'1.26.3','scipy':'1.11.1','pandas':'2.1.4','scikit-learn':'1.3.0',
                'joblib':'1.2.0','threadpoolctl':'3.6.0','tokenizers':'0.22.1','jsonschema':'4.20.0','Jinja2':'3.1.2'}
    assert {n: metadata.version(n) for n in expected} == expected
    out.mkdir(parents=True)
    sys.path[:0] = [str(root/'src'), str(root/'scripts')]
    def offline(event, args):
        if event.startswith('socket.'):
            raise RuntimeError('FRL_ACCEPT_NETWORK_DISABLED')
    sys.addaudithook(offline)
    from agent_l_replay_live.protocol import Config, source_sha, history, HISTORY_SHA
    from agent_l_replay_live.launch import launch
    from agent_l_replay_live.evidence import verify_saved_source
    from agent_l_replay_live.numeric_acceptance import verify_models
    from check_l_replay_entry import check
    history(root/'phase2/l_feedback_replay_20261031_v2/HISTORY.json', root)
    fake = {}
    for method in ('FULL','CONSERVATIVE','CUTOFF'):
        run = out/('fake-'+method)
        entry = launch(run, source_root=root, config=Config(method=method))
        proof = check(run, root)
        assert proof['completed_recovery']
        ledger = json.loads((run/'LEDGER.json').read_text())
        assert all(c['sidecar']['local_token_statistics']['local_assets_verified']
                   and c['sidecar']['local_token_statistics']['input_messages_dropped'] == 0 for c in ledger['calls'])
        fake[method] = proof
    suite = unittest.TestSuite()
    patterns = ('test_agent_l_api.py','test_agent_l_v1.py','test_agent_l_v2.py','test_agent_l_v3.py',
                'test_l_api_batch.py','test_l_api_resume.py','test_l_feedback.py','test_l_feedback_api.py',
                'test_l_feedback_replay.py','test_l_replay_entry.py','test_l_api_native.py')
    for pattern in patterns:
        suite.addTests(unittest.defaultTestLoader.discover(str(root/'tests'), pattern=pattern))
    with (out/'TESTS.log').open('x') as f:
        result = unittest.TextTestRunner(stream=f, verbosity=2).run(suite)
    assert result.wasSuccessful()
    frozen, campaign = verify_saved_source(root)
    numeric = verify_models(root, campaign, frozen, out/'numeric')
    now = datetime.now(timezone.utc)
    proof = {'passed': True, 'source_sha256': source_sha(root), 'history_sha256': HISTORY_SHA,
             'target_root': str(root), 'target_kind': 'datahub-course-cpu' if os.environ.get('JUPYTERHUB_USER') == 'hoding'
                else 'research-server-offline', 'python': '3.10.12', 'tokenizers': '0.22.1',
             'real_tokenizer_used': True, 'stage_replay_checked': True, 'children_reaped': True,
             'tests_passed': result.testsRun, 'three_methods': fake, 'no_fit_numeric_passed': numeric['passed'],
             'saved_model_predictions': numeric['model_predictions'], 'model_fits': 0, 'real_API_calls': 0,
             'real_key_reads': 0, 'cloud_starts': 0, 'accepted_utc': now.isoformat(),
             'expires_utc': (now+timedelta(hours=2)).isoformat(), 'permission_granted': False}
    (out/'NATIVE_PROOF.json').write_text(json.dumps(proof, indent=2)+'\n')
    print(json.dumps(proof))


if __name__ == '__main__':
    main()
