#!/usr/bin/env python3
"""Independent read-only JSON, SQLite, request and admission audit; no agent imports."""
from contextlib import closing
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3


def read(p):return json.loads(Path(p).read_text())
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()


def check(root,source):
    root,source = Path(root),Path(source)
    e,l,c = read(root/'ENTRY_RESULT.json'),read(root/'LEDGER.json'),read(root/'CONFIG.json')
    h = read(source/'phase2/l_approval_confirm_20261031_v1/HISTORY.json')
    assert h['sha256'] == digest({k:v for k,v in h.items() if k!='sha256'})
    assert len(h['receipts']) == h['Bank_calls'] == 356 and len({r['call_id'] for r in h['receipts']}) == 356
    assert all(sha(source/n) == v for n,v in h['source_files'].items())
    assert e['method'] == c['method'] == 'CUTOFF' and e['unit'] == 'FR04.CUTOFF'
    assert c['allow_training'] is False and e['actual_training_this_entry'] == 0
    assert e['history_real_calls'] == 356 and e['inherited_first_generations'] == 54
    assert e['normal_adjustment_consumed'] == 1 and e['normal_adjustment_remaining'] == 0
    assert not e['automatic_continuation'] and not e['old_holds_released']
    assert 1 <= c['new_generation_cap'] <= 10 and e['new_generation_cap'] == c['new_generation_cap']
    assert c['first_total_generation_cap'] == e['first_total_generation_cap'] == 64
    b = l['L_budget'];calls = l['calls'];fake = e['HTTP_fixture_only']
    assert b['historical_known_nano'] == 255512150 and b['historical_held_nano'] == 1003252000
    assert b['Bank_historical_calls'] == 356 and b['project_historical_dispatches'] == 2834
    assert b['first_historical_generations'] == 54 and b['first_generations_used'] == 54+len(calls) <= 64
    assert [v['amount_nano'] for v in h['holds']] == [503252000,500000000]
    assert (b['project_cap_nano'],b['L_cap_nano'],b['first_cap_nano']) == (20000000000,2000000000,1000000000)
    assert b['simulated_increment_only'] is fake and not b['old_holds_released'] and not b['old_authority_mutated']
    assert len(calls) <= c['new_generation_cap'] and len({v['call_id'] for v in calls}) == len(calls)
    assert {v['call_id'] for v in calls}.isdisjoint({v['call_id'] for v in h['receipts']})
    assert all(v['run_id'] == e['unit'] and v['simulated'] is fake and v['phase'] == 'replay' for v in calls)
    assert all(u['body']['duration'] == 192.470543 for u in l['units'])
    assert read(root/'TIMING.json')['additive_accounting_passed']
    assert len([r for r in l['http'] if r['kind'] == 'GET']) <= 4
    assert e['accounting_status'] == l['batch_accounting']['state']
    proof = {'passed':True,'history_calls':356,'calls_recorded':len(calls),'method':'CUTOFF',
        'HTTP_fixture_only':fake,'completed_recovery':False,'accounting_status':e['accounting_status'],
        'actual_training':0,'old_holds_released':False,'automatic_continuation':False}
    if not (root/'run/RESULT.json').is_file():
        assert e['business_status'] == 'stopped_before_recovery' and e['error']
        return proof
    d,s = read(root/'run/RESULT.json'),read(root/'SUMMARY.json')
    f = read(source/'outputs/l_feedback_real_20261031_r3/evidence/real/campaign/runs/LI01.PREFIX/FREEZE.json')
    assert d['outcome'] == e['business_status'] == s['outcome'] and s['real_fits'] == 0
    assert d['optimization_spent'] == 1 and d['recovery']['normal_remaining_after'] == 0
    assert d['recovery']['new_normal_adjustments_consumed'] == 0
    assert d['store_snapshot']['nodes'][:len(f['store_snapshot']['nodes'])] == f['store_snapshot']['nodes']
    with closing(sqlite3.connect('file:'+str((root/'run/store.sqlite').resolve())+'?mode=ro',uri=True)) as db:
        nodes = [json.loads(r[0]) for r in db.execute('select payload from ctx_nodes order by seq')]
    assert nodes == d['store_snapshot']['nodes'];nodes = {n['result_id']:n for n in nodes}
    for item in d['store_snapshot']['file_history']:assert sha(root/'run/artifacts/sha256'/item['sha256']) == item['sha256']
    with closing(sqlite3.connect('file:'+str((root/'authority.sqlite').resolve())+'?mode=ro',uri=True)) as db:
        for table,key in (('fr_approvals','feedback_approvals'),('ac_confirmations','approval_confirmations'),('fr_replays','feedback_replays')):
            assert [json.loads(r[0]) for r in db.execute('select body from '+table)] == l[key]
    assert len(l['feedback_approvals']) == 1 and l['feedback_approvals'][0]['consumed'] == 1
    approval = l['feedback_approvals'][0]
    old = {n['result_id']:n for n in f['store_snapshot']['nodes']}
    assert approval['original_feedback'] == old[approval['origin_approval_id']]
    assert l['approval_confirmations'] == d['approval_confirmation_events'] and len(l['approval_confirmations']) <= 1
    for v in l['approval_confirmations']:
        n = v['confirmation_node'];choice = n['payload']['final'];assert n == nodes[n['result_id']]
        assert set(choice) == {'operation','action','approval_id','evidence_id','reason'}
        assert choice['operation'] == 'confirm_existing_approval' and choice['action'] in ('confirm','stop')
        assert choice['approval_id'] == approval['origin_approval_id'] and choice['evidence_id'] in nodes
        assert v['optimization_spent_before'] == v['optimization_spent_after'] == 1 and v['normal_adjustments_consumed'] == 0
        options = next(nodes[p] for p in n['parent_result_ids'] if nodes[p]['kind'] == 'confirmation_options')
        assert options['payload']['allowed_actions'] == ['confirm','stop'] and options['payload']['normal_adjustments_remaining'] == 0
        initial = next(nodes[p] for p in options['parent_result_ids'] if nodes[p]['kind'] == 'contract')
        analyst = next(nodes[p] for p in options['parent_result_ids'] if nodes[p]['role'] == 'Analyst')
        screen = nodes[choice['evidence_id']]
        expected = digest({'operation':'confirm_existing_approval','approval_digest':digest(approval),
            'facts':analyst['payload'],'contract':initial['payload'],'analyst_id':analyst['result_id'],
            'initial_contract_id':initial['result_id'],'screen_result_id':screen['result_id'],
            'screen_producer_id':screen['payload']['producer_id'],'screen_contract':screen['payload']['contract'],
            'metrics':screen['payload']['metrics'],'sources':approval['source_bindings']})
        assert expected == v['input_digest']
        call = next(x for x in d['llm_calls'] if x['node_id'] == n['result_id'])
        wire = next(x for x in calls if x['call_id'] == call['call_id'])['request']['messages'][0]['content']
        assert 'This call ONLY confirms an existing' in wire and 'If no adjustment remains' not in wire
    assert l['feedback_replays'] == d['stage_replays'] and len(l['feedback_replays']) <= 1
    for v in l['feedback_replays']:
        confirm = l['approval_confirmations'][0]
        assert v['confirmation_result_id'] == confirm['confirmation_node']['result_id']
        assert confirm['confirmation_node']['payload']['final']['action'] == 'confirm'
        assert v['input_digest'] == confirm['input_digest'] and v['new_normal_adjustments_consumed'] == 0
        assert v['bound'] == nodes[v['bound']['result_id']]
        assert d['recovery']['equivalent_contracts'] == (v['bound']['payload']['contracts'] == f['active']['contract']['payload']['contracts'])
        assert d['recovery']['duplicate_replay_HTTP_delta'] == 0
    if fake:
        admissions = read(root/'ADMISSIONS.json')
        assert len(admissions) == s['saved_artifact_admissions'] and s['simulated_fit_tasks'] == 0
        for item in admissions:
            assert item['artifact_hashes_checked'] and item['fits'] == item['model_loads'] == item['predict_calls'] == 0
            model = next(n['payload'] for n in old.values() if n['role'] == 'executor' and n['payload'].get('producer_id') == item['producer_id'])
            assert item['contract'] == model['contract']
            campaign = source/'outputs/l_feedback_real_20261031_r3/evidence/real/campaign'
            record = read(campaign/model['record_rel']);origin = Path(read(campaign/'ORIGIN.json')['campaign_root'])
            assert sha(campaign/model['record_rel']) == model['producer_record_sha256']
            folder = campaign/Path(record['spec']['output_dir']).relative_to(origin)
            for artifact in record['response']['artifacts']:
                assert sha(folder/artifact['name']) == artifact['sha256']
                assert (folder/artifact['name']).stat().st_size == artifact['size_bytes']
    else:
        for r in read(root/'CPU_RECORDS.json'):
            value,execution = r['record']['response'],r['record']['execution']
            assert value['passed'] and value['business_correct'] and value['model_fits'] == 0
            assert value['fit_guard']['installed'] and not value['fit_guard']['rejected_calls']
            assert execution['worker_reaped'] and not execution['remaining_processes'] and not execution['inherited_credentials']
    if d['outcome'] == 'completed_execution':
        assert d['quality_goal_met'] and 'publication' in d['active']
        assert len(l['feedback_replays']) == 1 and s['saved_artifact_admissions'] == 3
        assert d['active']['review']['payload']['final']['action'] == 'accept'
        assert d['recovery']['comparison_performed'] and d['recovery']['equivalent_contracts']
        assert d['recovery']['retained_producer_ids'] == ['fit-0005','fit-0006']
        proof['completed_recovery'] = True
    else:assert 'publication' not in d['active']
    return {**proof,'outcome':d['outcome'],'admissions':s['saved_artifact_admissions']}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[1]);a = p.parse_args()
    result = check(a.run,a.source_root)
    with a.output.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(result))


if __name__ == '__main__':main()
