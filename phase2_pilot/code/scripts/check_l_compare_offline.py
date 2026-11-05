#!/usr/bin/env python3
"""Independent JSON/SQLite/hash auditor. No recovery/model imports or inference."""
from contextlib import closing
from decimal import Decimal
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
    s,l,c=read(root/'SUMMARY.json'),read(root/'LEDGER.json'),read(root/'CONFIG.json')
    h=read(source/'outputs/l_confirm_real_20261031_r1/LEDGER_SUCCESSOR_364.json')
    assert h['sha256']==digest({k:v for k,v in h.items() if k!='sha256'})
    assert h['Bank_calls']==len(h['receipts'])==364 and all(sha(source/n)==v for n,v in h['source_files'].items())
    assert c['simulated'] is True and c['generation_cap']<=30 and c['unit_call_cap']<=10 and 0<c['batch_cap_nano']<=500000000
    assert set(c['order'])=={'FULL','CONSERVATIVE','CUTOFF'} and len(c['order'])==3
    b=l['comparison_budget'];calls=l['calls']
    assert b['historical_calls']==364 and b['project_historical_dispatches']==2842
    assert b['historical_known_nano']==256624400 and b['historical_project_held_nano']==1003252000
    assert b['sealed_first_used']==62 and b['sealed_first_cap']==64 and not b['old_first_allowance_accessible']
    assert b['sealed_first_known_nano']==6741550 and b['sealed_first_held_nano']==500000000
    assert b['project_cap_nano']==20000000000 and b['L_cap_nano']==2000000000 and b['batch_cap_nano']==c['batch_cap_nano']
    assert not b['old_holds_released'] and not b['old_authority_mutated'] and b['simulated_increment_only']
    assert len(calls)==s['new_fake_generations']==b['new_generations_used']<=c['generation_cap']
    assert all(v['simulated'] and v['phase']=='replay' for v in calls)
    assert len({v['call_id'] for v in calls})==len(calls)
    assert {v['call_id'] for v in calls}.isdisjoint({v['call_id'] for v in h['receipts']})
    known=sum(v['known_cost_nano_usd'] for v in calls);held=sum(v['held_cost_nano_usd'] for v in calls)
    assert known==b['new_known_nano'] and held==b['new_held_nano'] and known+held<=c['batch_cap_nano']
    assert b['project_known_nano']==256624400+known and b['project_held_nano']==1003252000+held
    assert b['L_known_nano']==6741550+known and b['L_held_nano']==500000000+held
    assert len([v for v in l['http'] if v['kind']=='GET'])==s['new_fake_GETs']<=4
    assert s['accounting_status']==l['batch_accounting']['state']
    for key in ('real_API_calls','real_key_reads','real_fits','model_loads','predict_calls','cloud_starts'):assert s[key]==0
    assert not s['automatic_continuation']
    assert read(root/'TIMING.json')['additive_accounting_passed']
    with closing(sqlite3.connect('file:'+str((root/'authority.sqlite').resolve())+'?mode=ro',uri=True)) as db:
        for table,key in (('fr_approvals','feedback_approvals'),('ac_confirmations','approval_confirmations'),('fr_replays','feedback_replays')):
            assert [json.loads(v[0]) for v in db.execute('select body from '+table)]==l[key]
    frozen=read(source/'outputs/l_feedback_real_20261031_r3/evidence/real/campaign/runs/LI01.PREFIX/FREEZE.json')
    assert digest({k:v for k,v in frozen.items() if k!='checkpoint_sha256'})==frozen['checkpoint_sha256']
    rows={v['method']:v for v in s['rows']};assert set(rows)=={'FULL','CONSERVATIVE','CUTOFF'}
    started=[]
    for method,row in rows.items():
        unit='LCMP01.'+method;assert row['unit']==unit
        own=[v for v in calls if v['run_id']==unit];assert len(own)==row['calls']<=c['unit_call_cap']
        if row['state']=='not_started':
            assert not own and not (root/method/'run/RESULT.json').exists();continue
        started.append(method)
        clock=next(v['body'] for v in l['units'] if v['unit']==unit)
        assert clock['duration']==192.470543
        if row['state']=='failed_before_result':assert row['error'];continue
        d=read(root/method/'run/RESULT.json')
        assert d['outcome']==row['state'] and d['optimization_spent']==1
        r=d['recovery'];assert r['normal_remaining_before']==r['normal_remaining_after']==0
        assert r['new_normal_adjustments_consumed']==0 and r['checkpoint_sha256']==frozen['checkpoint_sha256']
        assert d['store_snapshot']['nodes'][:len(frozen['store_snapshot']['nodes'])]==frozen['store_snapshot']['nodes']
        with closing(sqlite3.connect('file:'+str((root/method/'run/store.sqlite').resolve())+'?mode=ro',uri=True)) as db:
            nodes=[json.loads(v[0]) for v in db.execute('select payload from ctx_nodes order by seq')]
        assert nodes==d['store_snapshot']['nodes'];byid={v['result_id']:v for v in nodes}
        assert all(set(n['parent_result_ids'])<=set(byid) for n in nodes)
        for item in d['store_snapshot']['file_history']:assert sha(root/method/'run/artifacts/sha256'/item['sha256'])==item['sha256']
        fitted=[n for n in nodes if n['kind']=='cpu' and n['result_id'].startswith(unit+'.')]
        assert len(fitted)==row['simulated_fits']==read(root/method/'FIT_TASKS.json')['simulated_fit_tasks']<=3
        assert read(root/method/'FIT_TASKS.json')['actual_fits']==0
        for n in fitted:
            assert n['payload']['fixture_only'] and n['payload']['actual_training']==0
            contract=next(byid[p] for p in n['parent_result_ids'] if byid[p]['kind']=='contract')
            assert n['payload']['contract']==contract['payload']['contracts'][n['payload']['kind']]
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
            wire=next(x for x in own if x['call_id']==call['call_id'])['request']['messages'][0]['content']
            assert 'This call ONLY confirms an existing' in wire and 'If no adjustment remains' not in wire
        for v in replays:
            assert confirmations[0]['confirmation_node']['payload']['final']['action']=='confirm'
            assert v['confirmation_result_id']==confirmations[0]['confirmation_node']['result_id']
            assert v['input_digest']==confirmations[0]['input_digest'] and v['new_normal_adjustments_consumed']==0
            assert r['comparison_performed'] and r['duplicate_replay_HTTP_delta']==0
            assert r['equivalent_contracts']==(v['bound']['payload']['contracts']==frozen['active']['contract']['payload']['contracts'])
        admitted=read(root/method/'ADMISSIONS.json');assert len(admitted)==row['admissions']
        campaign=source/'outputs/l_feedback_real_20261031_r3/evidence/real/campaign'
        origin=Path(read(campaign/'ORIGIN.json')['campaign_root'])
        for item in admitted:
            assert item['artifact_hashes_checked'] and item['model_loads']==item['predict_calls']==item['fits']==0
            model=next(n['payload'] for n in frozen['store_snapshot']['nodes'] if n['role']=='executor' and n['payload'].get('producer_id')==item['producer_id'] and 'contract' in n['payload'])
            assert item['contract']==model['contract'] and sha(campaign/model['record_rel'])==model['producer_record_sha256']
            record=read(campaign/model['record_rel']);folder=campaign/Path(record['spec']['output_dir']).relative_to(origin)
            for art in record['response']['artifacts']:assert sha(folder/art['name'])==art['sha256']
        if row['state']=='completed_execution':
            assert d['quality_goal_met'] and 'publication' in d['active']
            assert d['active']['review']['payload']['final']['action']=='accept'
            if s['case']=='equivalent':assert (row['simulated_fits'],row['admissions'])==((0,3) if method=='CUTOFF' else (3,0))
            if s['case']=='changed_contract':assert (row['simulated_fits'],row['admissions'])==((2,1) if method=='CUTOFF' else (3,0)) and not r['equivalent_contracts']
            if s['case']=='initial_changed':
                assert row['simulated_fits']==2 and row['admissions']==0 and not confirmations and not replays
                assert r['route']=='new_initial_contract' and not r['comparison_performed'] and r['equivalent_contracts'] is None
        else:assert 'publication' not in d['active']
    assert set(started)=={v['unit'].split('.')[-1] for v in l['units']}
    return {'passed':True,'case':s['case'],'started_branches':len(started),'registered_rows':3,
        'fake_generations':len(calls),'simulated_fits':sum(v['simulated_fits'] for v in s['rows']),
        'old_first_used':62,'old_first_reopened':False,'real_API_calls':0,'real_training':0,
        'accounting_status':s['accounting_status'],'performance_measurement':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[1]);a=p.parse_args()
    r=check(a.run,a.source_root)
    with a.output.open('x') as f:json.dump(r,f,indent=2);f.write('\n')
    print(json.dumps(r))


if __name__=='__main__':main()
