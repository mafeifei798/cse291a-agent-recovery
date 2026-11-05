#!/usr/bin/env python3
"""Independent accounting, SQLite, binding and numerical-receipt audit."""
from pathlib import Path
import argparse
import hashlib
import json
import sqlite3


def read(p):return json.loads(Path(p).read_text())
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()


def check(root,source):
    root,source=Path(root),Path(source)
    s,c,l=read(root/'SUMMARY.json'),read(root/'CONFIG.json'),read(root/'LEDGER.json')
    assert s['revision']==c['revision']=='l-compare-entry-v1'
    if c['simulated']:
        from check_l_compare_offline import check as offline_check
        proof=offline_check(root,source)
    else:
        # Live results are never relabelled as successful fake experiments.
        h=read(source/'outputs/l_confirm_real_20261031_r1/LEDGER_SUCCESSOR_364.json')
        b=l['comparison_budget'];calls=l['calls']
        assert h['Bank_calls']==364 and all(sha(source/n)==v for n,v in h['source_files'].items())
        assert (b['historical_known_nano'],b['historical_project_held_nano'])==(256624400,1003252000)
        assert (b['sealed_first_used'],b['sealed_first_cap'],b['sealed_first_known_nano'],b['sealed_first_held_nano'])==(
            62,64,6741550,500000000)
        assert not b['old_first_allowance_accessible'] and not b['old_holds_released']
        assert len(calls)==s['real_API_calls']<=c['generation_cap']<=30
        assert len({v['call_id'] for v in calls})==len(calls)
        assert {v['call_id'] for v in calls}.isdisjoint({v['call_id'] for v in h['receipts']})
        assert all(not v['simulated'] for v in calls)
        assert (b['project_cap_nano'],b['L_cap_nano'])==(20000000000,2000000000)
        assert b['batch_cap_nano']==c['batch_cap_nano'] and not b['simulated_increment_only']
        assert sum(v['known_cost_nano_usd']+v['held_cost_nano_usd'] for v in calls)<=c['batch_cap_nano']<=500000000
        assert b['project_known_nano']==256624400+sum(v['known_cost_nano_usd'] for v in calls)
        assert b['project_held_nano']==1003252000+sum(v['held_cost_nano_usd'] for v in calls)
        assert len([v for v in l['http'] if v['kind']=='GET'])<=4
        assert len(s['rows'])==3 and len({r['method'] for r in s['rows']})==3
        for row in s['rows']:
            own=[v for v in calls if v['run_id']==row['unit']]
            assert len(own)==row['calls']<=c['unit_call_cap']<=10
            if row['state']=='not_started':assert not own;continue
            clock=next(v['body'] for v in l['units'] if v['unit']==row['unit'])
            assert clock['duration']==192.470543
            if row['state']=='failed_before_result':assert row['error'];continue
            d=read(root/row['method']/'run/RESULT.json')
            assert d['outcome']==row['state'] and d['optimization_spent']==1
            assert d['recovery']['normal_remaining_after']==0 and d['recovery']['new_normal_adjustments_consumed']==0
            with sqlite3.connect('file:'+str((root/row['method']/'run/store.sqlite').resolve())+'?mode=ro',uri=True) as db:
                nodes=[json.loads(v[0]) for v in db.execute('select payload from ctx_nodes order by seq')]
            assert nodes==d['store_snapshot']['nodes']
            for record in read(root/row['method']/'CPU_RECORDS.json'):
                rec=record['record'];execution=rec['execution'];response=rec['response']
                assert read(root/row['method']/'campaign'/record['record_rel'])==rec
                assert execution['status']=='success' and execution['worker_reaped'] and not execution['remaining_processes']
                assert not execution['inherited_credentials']
                if rec['spec']['schema_version']=='context-cutoff-numeric-v1':
                    assert response['passed'] and response['business_correct'] and response['model_fits']==0
                    assert response['fit_guard']['installed'] and not response['fit_guard']['rejected_calls']
                else:
                    assert response['actual_training']==1 and response['predict_proba_calls']==2
                    assert response['executed_feature_columns']==rec['spec']['contract']['feature_columns']
                    for artifact in response['artifacts']:
                        assert sha(Path(rec['spec']['output_dir'])/artifact['name'])==artifact['sha256']
            records=read(root/row['method']/'CPU_RECORDS.json')
            assert sum(r['record']['spec']['schema_version']=='context-cutoff-cpu-v1' for r in records)==row['real_fits']<=3
            byid={n['result_id']:n for n in nodes}
            for admission in read(root/row['method']/'ADMISSIONS.json'):
                assert admission['fits']==0 and admission['artifact_hashes_checked']
                origin=Path(admission['producer_campaign_root'])
                record_path=origin/admission['record_rel']
                assert sha(record_path)==admission['producer_record_sha256']
                saved=read(record_path);assert saved['spec']['contract']==admission['contract']
                for artifact in saved['response']['artifacts']:
                    assert sha(Path(saved['spec']['output_dir'])/artifact['name'])==artifact['sha256']
            for node in nodes:
                if node['result_id'].startswith(row['unit']+'.') and node['kind'] in ('cpu','admission'):
                    bound=next(byid[p] for p in node['parent_result_ids'] if byid[p]['kind']=='contract')
                    assert node['payload']['contract']==bound['payload']['contracts'][node['payload']['kind']]
            for item in d['store_snapshot']['file_history']:
                assert sha(root/row['method']/'run/artifacts/sha256'/item['sha256'])==item['sha256']
            if row['state']=='completed_execution':
                assert d['quality_goal_met'] and d['active']['review']['payload']['final']['action']=='accept'
                assert 'publication' in d['active']
            else:assert 'publication' not in d['active']
        proof={'passed':True,'actual_recovery_measurement':True,'calls':len(calls)}
    # Same Reviewer/replay audit for either transport. Numeric evidence never
    # substitutes for the semantic approval, quota, source and contract checks.
    with sqlite3.connect('file:'+str((root/'authority.sqlite').resolve())+'?mode=ro',uri=True) as db:
        for table,key in (('fr_approvals','feedback_approvals'),('fr_replays','feedback_replays'),('ac_confirmations','approval_confirmations')):
            assert [json.loads(v[0]) for v in db.execute('select body from '+table)]==l[key]
    frozen=read(source/'outputs/l_feedback_real_20261031_r3/evidence/real/campaign/runs/LI01.PREFIX/FREEZE.json')
    assert frozen['checkpoint_sha256']==digest({k:v for k,v in frozen.items() if k!='checkpoint_sha256'})
    for row in s['rows']:
        if row['state'] in ('not_started','failed_before_result'):continue
        d=read(root/row['method']/'run/RESULT.json');r=d['recovery'];unit=row['unit']
        assert r['checkpoint_sha256']==frozen['checkpoint_sha256']
        assert d['store_snapshot']['nodes'][:len(frozen['store_snapshot']['nodes'])]==frozen['store_snapshot']['nodes']
        byid={n['result_id']:n for n in d['store_snapshot']['nodes']}
        assert all(set(n['parent_result_ids'])<=set(byid) for n in byid.values())
        confirmations=[v for v in l['approval_confirmations'] if v['unit']==unit]
        replays=[v for v in l['feedback_replays'] if v['unit']==unit]
        assert confirmations==d['approval_confirmation_events'] and replays==d['stage_replays']
        assert len(confirmations)<=1 and len(replays)<=1
        for v in confirmations:
            n=v['confirmation_node'];choice=n['payload']['final'];assert byid[n['result_id']]==n
            assert choice['operation']=='confirm_existing_approval' and choice['action'] in ('confirm','stop')
            assert choice['approval_id']=='LI01.PREFIX.node.0012' and choice['evidence_id'] in byid
            assert v['normal_adjustments_consumed']==0 and v['optimization_spent_before']==v['optimization_spent_after']==1
            call=next(x for x in d['llm_calls'] if x['node_id']==n['result_id'])
            wire=next(x for x in l['calls'] if x['call_id']==call['call_id'])['request']['messages'][0]['content']
            assert 'This call ONLY confirms an existing' in wire and 'If no adjustment remains' not in wire
        for v in replays:
            assert confirmations[0]['confirmation_node']['payload']['final']['action']=='confirm'
            assert v['input_digest']==confirmations[0]['input_digest'] and v['new_normal_adjustments_consumed']==0
            assert v['confirmation_result_id']==confirmations[0]['confirmation_node']['result_id']
            assert r['comparison_stage']=='adjustment-1' and r['comparison_performed']
            assert r['equivalent_contracts']==(v['bound']['payload']['contracts']==frozen['active']['contract']['payload']['contracts'])
            assert r['duplicate_replay_HTTP_delta']==0
        if r.get('route')=='new_initial_contract':assert not replays and not confirmations and r['equivalent_contracts'] is None
    for call in l['calls']:
        assert call['sidecar']['wire_request_sha256']==digest(call['request'])
        if call['status']=='settled':
            assert call['known_cost_nano_usd']==call['usage']['prompt_tokens']*150+call['usage']['completion_tokens']*500
    assert not s['automatic_continuation']
    assert s['batch_ready']==(all(r['state']=='completed_execution' for r in s['rows'])
        and s['accounting_status']=='aggregate_reconciled')
    return {**proof,'revision':'l-compare-entry-check-v1','old_first_reopened':False,
        'real_mode':not c['simulated'],'history_calls':364}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',type=Path,required=True)
    p.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[1])
    p.add_argument('--output',type=Path,required=True);a=p.parse_args();v=check(a.run,a.source_root)
    with a.output.open('x') as f:json.dump(v,f,indent=2);f.write('\n')
    print(json.dumps(v))


if __name__=='__main__':main()
