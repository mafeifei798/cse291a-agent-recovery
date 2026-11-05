#!/usr/bin/env python3
"""Read-only accounting and recovery audit, never loads/fits a model."""
import argparse
import json
from pathlib import Path
from check_l_feedback_replay_offline import check_branch


def check(root, source):
    root = Path(root)
    entry = json.loads((root/'ENTRY_RESULT.json').read_text())
    ledger = json.loads((root/'LEDGER.json').read_text())
    assert ledger['L_budget']['Bank_historical_calls'] == 350
    assert ledger['L_budget']['historical_known_nano'] == 254776350
    assert ledger['L_budget']['historical_held_nano'] == 1003252000
    assert not ledger['L_budget']['old_authority_mutated'] and not ledger['L_budget']['old_holds_released']
    assert ledger['L_budget']['first_generations_used'] == 48+len(ledger['calls']) <= 64
    assert len(ledger['calls']) <= entry['new_generation_cap'] <= 10
    assert all(c['run_id'] == 'FR02.'+entry['method'] for c in ledger['calls'])
    assert all(u['body']['duration'] <= 240 for u in ledger['units'])
    assert sum(r['kind']=='GET' for r in ledger['http']) <= 4
    status = entry['business_status']
    complete = status == 'completed_execution' and entry['error'] is None
    recovery = None
    if complete and entry['CPU_fixture_only']:
        recovery = check_branch(root, source)
    if complete and not entry['CPU_fixture_only']:
        doc = json.loads((root/'run/RESULT.json').read_text())
        assert doc['optimization_spent'] == 1 and doc['recovery']['normal_remaining_after'] == 0
        assert doc['recovery']['comparison_stage'] == 'adjustment-1'
        records = json.loads((root/'CPU_RECORDS.json').read_text())
        for row in records:
            ex, response = row['record']['execution'], row['record']['response']
            assert ex['worker_reaped'] and not ex['remaining_processes'] and not ex['inherited_credentials']
            if row['record']['spec']['schema_version'] == 'context-cutoff-numeric-v1':
                assert response['passed'] and response['model_fits'] == 0 and response['fit_guard']['installed']
                assert not response['fit_guard']['rejected_calls']
        if not json.loads((root/'CONFIG.json').read_text())['allow_training']:
            assert doc['new_fit_count'] == 0
    return {'passed': True, 'business_status': status, 'completed_recovery': complete,
            'accounting_status': entry['accounting_status'], 'calls_recorded': len(ledger['calls']),
            'fixture_only': entry['HTTP_fixture_only'], 'real_API_calls': 0 if entry['HTTP_fixture_only'] else len(ledger['calls']),
            'holds_preserved_nano': 1003252000, 'recovery': recovery,
            'provider_invoice_verified': False, 'model_loads': 0, 'fits': 0, 'predict_calls': 0}

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', type=Path, required=True)
    p.add_argument('--source-root', type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    result = check(a.run, a.source_root)
    with a.output.open('x') as f:
        json.dump(result, f, indent=2)
        f.write('\n')
    print(json.dumps(result))
