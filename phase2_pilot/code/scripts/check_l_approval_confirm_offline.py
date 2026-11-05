#!/usr/bin/env python3
"""Read-only trace/SQLite/hash audit; imports no agent, recovery or model code."""
import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3


def read(p):return json.loads(Path(p).read_text())
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()


def check_branch(root, source):
    root,source = Path(root),Path(source)
    s,l = read(root/'SUMMARY.json'),read(root/'LEDGER.json')
    h = read(source/'phase2/l_approval_confirm_20261031_v1/HISTORY.json')
    assert h['Bank_calls'] == len(h['receipts']) == 356
    assert h['sha256'] == digest({k:v for k,v in h.items() if k!='sha256'})
    assert all(sha(source/n) == value for n,value in h['source_files'].items())
    b = l['L_budget']
    assert b['Bank_historical_calls'] == 356 and b['project_historical_dispatches'] == 2834
    assert b['historical_known_nano'] == 255512150 and b['historical_held_nano'] == 1003252000
    assert b['first_historical_generations'] == 54 and b['first_generations_used'] == 54+len(l['calls']) <= 64
    assert (b['project_cap_nano'],b['L_cap_nano'],b['first_cap_nano']) == (20000000000,2000000000,1000000000)
    assert [v['amount_nano'] for v in h['holds']] == [503252000,500000000]
    assert not b['old_holds_released'] and not b['old_authority_mutated'] and b['simulated_increment_only']
    assert len(l['calls']) == s['synthetic_HTTP_calls'] <= 10
    assert all(c['simulated'] and c['run_id'] == 'FR03.'+s['method'] for c in l['calls'])
    assert {c['call_id'] for c in l['calls']}.isdisjoint({c['call_id'] for c in h['receipts']})
    assert all(u['body']['duration'] == 192.470543 for u in l['units'])
    assert s['accounting_status'] == l['batch_accounting']['state']
    for key in ('real_API_calls','real_key_reads','real_fits','model_loads','predict_calls','cloud_starts'):
        assert s[key] == 0
    assert not s['actual_recovery_measurement'] and s['real_history_unchanged']
    if not (root/'run/RESULT.json').is_file():
        assert s['outcome'] == 'stopped_before_recovery' and s['error']
        return {'passed':True,'method':s['method'],'case':s['case'],'outcome':s['outcome'],'stage_replayed':False}
    d = read(root/'run/RESULT.json')
    f = read(source/'outputs/l_feedback_real_20261031_r3/evidence/real/campaign/runs/LI01.PREFIX/FREEZE.json')
    assert d['outcome'] == s['outcome'] and d['recovery'] == s['recovery']
    assert d['optimization_spent'] == 1 and d['recovery']['normal_remaining_after'] == 0
    assert d['recovery']['normal_remaining_before'] == 0 and d['recovery']['new_normal_adjustments_consumed'] == 0
    assert d['store_snapshot']['nodes'][:len(f['store_snapshot']['nodes'])] == f['store_snapshot']['nodes']
    with closing(sqlite3.connect('file:'+str((root/'run/store.sqlite').resolve())+'?mode=ro',uri=True)) as db:
        nodes = [json.loads(row[0]) for row in db.execute('SELECT payload FROM ctx_nodes ORDER BY seq')]
    assert nodes == d['store_snapshot']['nodes']
    nodes = {n['result_id']:n for n in nodes}
    assert all(set(n['parent_result_ids']) <= set(nodes) for n in nodes.values())
    for item in d['store_snapshot']['file_history']:
        assert sha(root/'run/artifacts/sha256'/item['sha256']) == item['sha256']
    confirmations = l['approval_confirmations']
    assert len(confirmations) == len(d['approval_confirmation_events']) <= 1
    assert confirmations == d['approval_confirmation_events']
    assert len(l['feedback_approvals']) == 1 and l['feedback_approvals'][0]['consumed'] == 1
    approval = l['feedback_approvals'][0]
    assert approval['source_bindings'] == {k:f['store_snapshot']['files'][k] for k in
        ('inputs/data.json','inputs/code.json','inputs/task.json','inputs/schema.json','inputs/profile.json','inputs/registry.json')}
    assert approval['original_feedback']['payload']['final']['action'] == 'adjust'
    assert approval['adjusted_contract'] == f['active']['contract']
    original_nodes = {n['result_id']:n for n in f['store_snapshot']['nodes']}
    assert approval['original_feedback'] == original_nodes[approval['origin_approval_id']]
    for record in confirmations:
        node = record['confirmation_node'];assert nodes[node['result_id']] == node
        assert record['normal_adjustments_consumed'] == 0
        assert record['optimization_spent_before'] == record['optimization_spent_after'] == 1
        choice = node['payload']['final']
        assert set(choice) == {'operation','action','approval_id','evidence_id','reason'}
        assert choice['operation'] == 'confirm_existing_approval' and choice['action'] in ('confirm','stop')
        assert choice['approval_id'] == approval['origin_approval_id']
        options = next(nodes[p] for p in node['parent_result_ids'] if nodes[p]['kind'] == 'confirmation_options')
        assert options['payload']['allowed_actions'] == ['confirm','stop']
        assert options['payload']['normal_adjustments_remaining'] == 0
        initial = next(nodes[p] for p in options['parent_result_ids'] if nodes[p]['kind'] == 'contract')
        analyst = next(nodes[p] for p in options['parent_result_ids'] if nodes[p]['role'] == 'Analyst')
        screen = nodes[choice['evidence_id']]
        calculated = digest({'operation':'confirm_existing_approval','approval_digest':digest(approval),
            'facts':analyst['payload'],'contract':initial['payload'],'analyst_id':analyst['result_id'],
            'initial_contract_id':initial['result_id'],'screen_result_id':screen['result_id'],
            'screen_producer_id':screen['payload']['producer_id'],'screen_contract':screen['payload']['contract'],
            'metrics':screen['payload']['metrics'],'sources':approval['source_bindings']})
        assert calculated == record['input_digest']
        call = next(c for c in d['llm_calls'] if c['node_id'] == node['result_id'])
        control = json.loads(call['messages'][0]['content'])
        assert control['review_operation'] == 'confirm_existing_approval'
        assert control['confirmation_binding']['input_digest'] == calculated
        wire = next(c for c in l['calls'] if c['call_id'] == call['call_id'])['request']['messages'][0]['content']
        assert 'This call ONLY confirms an existing' in wire and 'If no adjustment remains' not in wire
    assert l['feedback_replays'] == d['stage_replays'] and len(d['stage_replays']) <= 1
    for replay in d['stage_replays']:
        assert confirmations[0]['confirmation_node']['payload']['final']['action'] == 'confirm'
        assert replay['confirmation_result_id'] == confirmations[0]['confirmation_node']['result_id']
        assert replay['input_digest'] == confirmations[0]['input_digest']
        assert replay['new_normal_adjustments_consumed'] == 0 and replay['optimization_spent_after'] == 1
        assert nodes[replay['bound']['result_id']] == replay['bound']
        planner_id = replay['bound']['parent_result_ids'][0]
        planner_call = next(c for c in d['llm_calls'] if c['node_id'] == planner_id)
        assert any(m.get('input_kind') == 'confirmed_approval' and m['producer_result_id'] == replay['confirmation_result_id']
                   for m in planner_call['messages'])
        assert not any(m.get('input_kind') == 'feedback' for m in planner_call['messages'])
        assert d['recovery']['duplicate_replay_HTTP_delta'] == 0 and d['recovery']['comparison_performed']
        assert d['recovery']['equivalent_contracts'] == (replay['bound']['payload']['contracts'] == f['active']['contract']['payload']['contracts'])
    admitted = read(root/'ADMISSIONS.json')
    assert len(admitted) == s['saved_artifact_admissions']
    old_campaign = source/'outputs/l_feedback_real_20261031_r3/evidence/real/campaign'
    origin = Path(read(old_campaign/'ORIGIN.json')['campaign_root'])
    for item in admitted:
        assert item['artifact_hashes_checked'] and item['fits'] == item['model_loads'] == item['predict_calls'] == 0
        old_model = next(n['payload'] for n in original_nodes.values()
                         if n['role'] == 'executor' and n['payload'].get('producer_id') == item['producer_id'])
        assert item['contract'] == old_model['contract'] and sha(old_campaign/old_model['record_rel']) == old_model['producer_record_sha256']
        produced = read(old_campaign/old_model['record_rel'])
        folder = old_campaign/Path(produced['spec']['output_dir']).relative_to(origin)
        for artifact in produced['response']['artifacts']:
            path = folder/artifact['name']
            assert path.stat().st_size == artifact['size_bytes'] and sha(path) == artifact['sha256']
    if s['outcome'] == 'completed_execution':
        assert d['quality_goal_met'] and 'publication' in d['active'] and d['stage_replays']
        assert d['active']['review']['payload']['final']['action'] == 'accept'
        assert json.loads(next(c for c in d['llm_calls'] if c['node_id'] == d['active']['review']['result_id'])['messages'][0]['content'])['review_operation'] == 'normal_review'
    else:
        assert 'publication' not in d['active']
    if s['case'] == 'equivalent' and s['outcome'] == 'completed_execution':
        assert s['simulated_fit_tasks'] == (0 if s['method'] == 'CUTOFF' else 3)
        assert len(admitted) == (3 if s['method'] == 'CUTOFF' else 0)
        assert d['recovery']['retained_producer_ids'] == (['fit-0005','fit-0006'] if s['method'] == 'CUTOFF' else [])
    if s['case'] == 'changed_contract' and s['outcome'] == 'completed_execution':
        assert not d['recovery']['equivalent_contracts'] and not d['recovery']['retained_producer_ids']
        assert s['simulated_fit_tasks'] == (2 if s['method'] == 'CUTOFF' else 3)
    if s['case'] == 'typed_stop':
        assert s['outcome'] == 'safe_stop' and not d['stage_replays']
        assert confirmations[0]['confirmation_node']['payload']['final']['action'] == 'stop'
    if s['case'] == 'saved_real_stop':
        saved = read(source/'outputs/l_replay_cutoff_real_20261031_r2/evidence/real/run/RESULT.json')['llm_calls'][-1]['raw']
        response = read(root/'RESPONSE_SOURCES.json')[-1]
        assert response['response_payload'] == saved and response['payload_unchanged']
        assert s['outcome'] == 'failed_execution' and not confirmations and not d['stage_replays']
    if s['case'] in ('source_version_changed','permission_revoked'):
        assert s['outcome'] == 'safe_stop' and not admitted and not l['calls']
    if s['case'] == 'external_publication':
        assert s['outcome'] == 'safe_stop' and d['store_snapshot']['files']['external/report.json']['writer_id'] == 'external-consumer'
    return {'passed':True,'case':s['case'],'method':s['method'],'outcome':s['outcome'],
            'stage_replayed':bool(d['stage_replays']),'confirmations':len(confirmations),
            'simulated_fits':s['simulated_fit_tasks'],'admissions':len(admitted),
            'new_real_API_calls':0,'new_real_fits':0}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run',type=Path);p.add_argument('--suite',type=Path)
    p.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[1])
    p.add_argument('--output',type=Path,required=True);a = p.parse_args()
    assert bool(a.run) != bool(a.suite)
    rows = [check_branch(a.run,a.source_root)] if a.run else [check_branch(p.parent,a.source_root) for p in sorted(a.suite.glob('*/*/SUMMARY.json'))]
    result = {'passed':True,'offline_branches':len(rows),'rows':rows,'real_API_calls':0,'real_training':0}
    with a.output.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print({'passed':True,'offline_branches':len(rows)})


if __name__ == '__main__':main()
