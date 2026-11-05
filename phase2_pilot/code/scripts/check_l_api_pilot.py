#!/usr/bin/env python3
"""Independent L pilot wire/ledger/contract and saved-array audit. Never fits."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import sys
sys.dont_write_bytecode=True


def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def digest(v):return hashlib.sha256(json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def compare_probabilities(contract,reference_contract,probabilities,reference):
    # Different legal decisions are checked against their own bound contracts.
    # Equality of probability arrays is meaningful only for the same contract.
    if contract!=reference_contract:
        return {'same_contract':False,'max_probability_error':None}
    import numpy as np
    error=float(np.max(np.abs(probabilities-reference)))
    assert error<1e-10
    return {'same_contract':True,'max_probability_error':error}


def check(campaign,source,require_native=False,*,batch_mode=False,resume_mode=False,feedback_mode=False):
    root=Path(campaign).resolve();s=json.loads((root/'SUMMARY.json').read_text());ledger=json.loads((root/'LEDGER.json').read_text())
    assert not resume_mode or batch_mode
    assert not feedback_mode or batch_mode and not resume_mode
    assert s['status']=='complete' and s['tier']=='L' and len(s['units'])==(7 if resume_mode or feedback_mode else 8) and not s['M_H'] and not s['threshold_tuning']
    simulated=s['HTTP_fixture_only']
    assert s['real_API_calls']==(0 if simulated else len(ledger['calls']))
    if require_native:assert not s['CPU_fixture_only']
    calls=ledger['calls'];assert len(calls)<=(52 if resume_mode or feedback_mode else 61 if batch_mode else 62) and all(c['status']=='settled' for c in calls)
    assert len({c['call_id'] for c in calls})==len({c['provider_request_id'] for c in calls})==len(calls)
    known=0;callmap={c['call_id']:c for c in calls}
    for c in calls:
        u=c['usage'];assert u['total_tokens']==u['prompt_tokens']+u['completion_tokens']
        assert 0<=u['prompt_tokens']<=4000 and 0<=u['completion_tokens']<=768
        expected_risk=min(500000000,ledger['config']['limits']['max_cost_nano_usd']-known) if batch_mode else 500000000
        assert c['reserved_cost_nano_usd']==expected_risk and c['held_cost_nano_usd']==0
        assert c['known_cost_nano_usd']==150*u['prompt_tokens']+500*u['completion_tokens'];known+=c['known_cost_nano_usd']
        req=c['request'];assert req['model']=='api-glm-5.3-flash' and req['reasoning_effort']=='low' and req['temperature']==0 and req['max_tokens']==768
        assert req['response_format']=={'type':'json_object'}
        st=c['sidecar']['local_token_statistics'];assert st['message_count']==len(req['messages']) and st['input_messages_dropped']==0
        if batch_mode and st.get('fixture_only'):
            assert simulated and st['count_scope']=='all-wire-messages-test-double' and s['CPU_fixture_only']
        else:assert st['local_assets_verified']
        assert st['prompt_tokens']<=4000
        if batch_mode:
            assert c['evidence']['billing']['local_usage_priced'] and c['evidence']['billing']['reconciled'] is False
        else:assert c['evidence']['billing']['reconciled']
        assert c['evidence']['usage_is_synthetic']==simulated
    historical_held=1003252000 if batch_mode else 503252000
    historical_known=250726250 if feedback_mode else 250247350 if resume_mode else 249882850
    b=ledger['L_budget'];assert b['historical_known_nano']==historical_known and b['historical_held_nano']==historical_held
    assert b['project_known_nano']==historical_known+known and b['project_held_nano']==historical_held
    assert b['project_cap_nano']==20000000000 and b['L_cap_nano']==2000000000 and b['first_cap_nano']==1000000000
    assert b['old_authority_mutated'] is False and b['old_holds_released'] is False
    http=ledger['http'];assert sum(x['kind']=='GET' for x in http)<=95 and sum(x['kind']=='GEN' for x in http)==len(calls)
    assert all(x['state']=='complete' for x in http)
    assert all(y['body']['mono_started']-x['body']['mono_started']>=2-1e-5 for x,y in zip(http,http[1:]))
    for unit in ledger['units']:
        t=unit['body'];assert unit['state']=='complete' and 0<t['duration']<=240
        assert abs(t['mono_deadline']-t['mono_started']-t['duration'])<1e-5
        assert abs(t['wall_deadline']-t['wall_started']-t['duration'])<1e-5
        for r in http:
            if r['unit']==unit['unit']:assert r['body']['deadline_mono']<=t['mono_deadline'] and r['body']['deadline_wall']<=t['wall_deadline']+1e-5
    prefix=s['units']['LI01.PREFIX']['result'];assert prefix['outcome']=='frozen_before_publish'
    assert digest({k:v for k,v in prefix.items() if k!='checkpoint_sha256'})==prefix['checkpoint_sha256']
    for uid,row in s['units'].items():
        t=row['result']
        timing=json.loads((root/(uid+'.TIMING.json')).read_text())
        assert abs(sum(x['wall_ns'] for x in timing['exclusive_categories'].values())/1e9-timing['whole_wall_seconds'])<1e-9
        if 'active' not in t:continue
        nodes={n['result_id']:n for n in t['store_snapshot']['nodes']}
        assert all(set(n['parent_result_ids'])<=set(nodes) for n in nodes.values())
        for h in t['store_snapshot']['file_history']:assert sha(root/'runs'/uid/'artifacts/sha256'/h['sha256'])==h['sha256']
        for c in t['llm_calls']:
            assert digest(c['messages'])==c['prompt_sha256'] and nodes[c['node_id']]['payload']==c['raw']
            assert callmap[c['call_id']]['result_id']==c['node_id']
            system=json.loads(c['messages'][0]['content'])['task'];assert 'initial_bundle' not in system
            if c['role']=='Reviewer':assert 'outer_metrics' not in json.dumps(c['messages'])
        if uid in ('LI01.FULL','LI01.CONSERVATIVE','LI01.CUTOFF'):
            r=t['recovery'];assert r['checkpoint_sha256']==prefix['checkpoint_sha256']
            assert r['faulty_result_id']==prefix['faults'][-1]['faulty_result_id'] and not r['validation_only_probes_in_timed_path']
            assert r['normal_remaining_before']==1-prefix['optimization_spent'] and not r['FULL_dependency_scan']
            if r['retained_producer_ids']:
                assert uid=='LI01.CUTOFF' and r['equivalent_contracts']
                assert set(r['retained_producer_ids'])=={prefix['active'][k]['payload']['producer_id'] for k in ('screen','final')}
        if row['outcome']=='completed_execution':
            assert t['quality_goal_met'] and t['active']['review']['payload']['final']['action']=='accept'
    for uid,parent in [('LI01.CAL_RAW',prefix),('LI01.CAL_CORRECTED',s['units']['LI01.CUTOFF']['result'])]:
        cal=s['units'][uid]['result'];original=callmap[cal['source_call_id']]
        repeated=next(c for c in calls if c['run_id']==uid)
        assert original['request']==repeated['request'] and cal['same_wire_sha256']==digest(original['request'])
        assert cal['analysis_only'] and not cal['affects_recovery']
    result={'passed':True,'model_loads':0,'fits':0,'predict_calls':0,'real_API_calls':s['real_API_calls'],
        'HTTP_generations':len(calls),'GETs':sum(r['kind']=='GET' for r in http),'history_hold_nano_preserved':historical_held,
        'completed_recoveries':sum(s['units'][u]['outcome']=='completed_execution' for u in ('LI01.FULL','LI01.CONSERVATIVE','LI01.CUTOFF')),
        'calibrations':2,'local_full_message_counter_checked':True,'CPU_fixture_only':s['CPU_fixture_only']}
    if s['CPU_fixture_only']:return result
    origin=json.loads((root/'ORIGIN.json').read_text())
    def mapped(value):
        p=Path(value);remote=Path(origin['campaign_root']);old=Path(origin['source_root'])
        if p.is_relative_to(remote):return root/p.relative_to(remote)
        assert p.is_relative_to(old);return Path(source)/p.relative_to(old)
    sys.path.insert(0,str(Path(source)/'scripts'))
    from check_bank_feature_diagnostics import NoModelImports,metrics
    sys.meta_path.insert(0,NoModelImports())
    import numpy as np
    index=json.loads((root/'CPU_RECORD_INDEX.json').read_text());records={i['record_rel']:json.loads((root/i['record_rel']).read_text()) for i in index}
    raw_cache={};fits={};checks=[];fit_rows=[]
    for item in index:
        rec=records[item['record_rel']];e=rec['execution'];rsp=rec['response'];spec=rec['spec']
        assert e['status']=='success' and e['worker_reaped'] and not e['remaining_processes'] and not e['inherited_credentials']
        assert e['real_process_launched'] and len(e['cpu_affinity'])==1
        if item['schema']=='context-cutoff-numeric-v1':
            assert rsp['passed'] and rsp['business_correct'] and rsp['model_fits']==0 and rsp['fit_guard']['installed'] and not rsp['fit_guard']['rejected_calls']
            checks.append(rec);continue
        assert item['schema']=='context-cutoff-cpu-v1' and rsp['actual_training']==1 and rsp['predict_proba_calls']==2
        contract=spec['contract'];family=contract['recipe']['model_family']
        assert contract['recipe']['parameters']=={'logistic_regression':{'C':1.,'max_iter':200},'random_forest':{'n_estimators':40,'max_depth':8,'n_jobs':1}}[family]
        assert contract['seed']==17 and rsp['executed_feature_columns']==contract['feature_columns'] and not set(contract['feature_columns'])&{'duration','campaign','y'}
        stage=mapped(spec['output_dir'])
        for a in rsp['artifacts']:assert sha(stage/a['name'])==a['sha256'] and (stage/a['name']).stat().st_size==a['size_bytes']
        raw=mapped(spec['raw_path']);assert sha(raw)==contract['data_binding']['file_sha256']
        if str(raw) not in raw_cache:
            with raw.open(newline='') as f:raw_cache[str(raw)]={i:int(r['y']=='yes') for i,r in enumerate(csv.DictReader(f,delimiter=';'),1) if i<=32950}
        for split,field,bind in [('train','train_rows_path','train_rows_sha256'),('validation','validation_rows_path','validation_rows_sha256')]:
            path=mapped(spec[field]);assert sha(path)==contract['data_binding'][bind]
            ids=json.loads(path.read_text())['row_ids'];assert json.loads((stage/(split+'_row_ids.json')).read_text())==ids
            y=np.load(stage/(split+'_labels.npy'),allow_pickle=False);p=np.load(stage/(split+'_probabilities.npy'),allow_pickle=False)
            hard=np.load(stage/(split+'_predictions.npy'),allow_pickle=False)
            assert np.array_equal(y,np.array([raw_cache[str(raw)][int(v.rsplit(':',1)[1])] for v in ids]))
            assert np.array_equal(hard,(p>=.5).astype(np.int8))
            for k,v in metrics(y,p).items():assert abs(v-rsp['metrics'][split][k])<1e-10
        fits[item['job_id']]=np.load(stage/'validation_probabilities.npy',allow_pickle=False)
        fit_rows.append({'job_id':item['job_id'],'family':family,'validation':rsp['metrics']['validation']})
    assert len(fits)==s['training_jobs'] and len(checks)==s['training_jobs']+s['readmissions']
    if simulated:assert sum(r['family']=='random_forest' for r in fit_rows)>=1
    for rec in records.values():
        if rec['spec']['schema_version']=='context-cutoff-cpu-v1':assert any(c['spec']['training_spec']==rec['spec'] for c in checks)
    differences={}
    full=s['units']['LI01.FULL']['result'];reference=fits[full['active']['final']['payload']['producer_id']]
    for uid in ('LI01.FULL','LI01.CONSERVATIVE','LI01.CUTOFF'):
        t=s['units'][uid]['result']
        if t['outcome']=='completed_execution':
            for kind in ('screen','final'):
                model=t['active'][kind]['payload'];assert sha(root/model['record_rel'])==model['producer_record_sha256']
                assert records[model['record_rel']]['response']['contract']==t['active']['contract']['payload']['contracts'][kind]
            if feedback_mode:
                differences[uid]=compare_probabilities(t['active']['final']['payload']['contract'],
                    full['active']['final']['payload']['contract'],fits[t['active']['final']['payload']['producer_id']],reference)
            else:
                error=float(np.max(np.abs(fits[t['active']['final']['payload']['producer_id']]-reference)))
                assert error<1e-10;differences[uid]=error
    result.update(native_fits=len(fits),native_no_fit_checks=len(checks),workers=len(index),
        RF_fits=sum(r['family']=='random_forest' for r in fit_rows),fit_rows=fit_rows,
        final_probability_errors=differences,total_worker_CPU_seconds=sum(r['execution']['cpu_seconds'] for r in records.values()))
    return result


def main():
    p=argparse.ArgumentParser();p.add_argument('--campaign',type=Path,required=True);p.add_argument('--source-root',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--require-native',action='store_true');a=p.parse_args()
    result=check(a.campaign,a.source_root,a.require_native)
    with a.output.open('x') as f:json.dump(result,f,indent=2,sort_keys=True,allow_nan=False);f.write('\n')
    print(json.dumps({'passed':True,'HTTP_generations':result['HTTP_generations'],'RF_fits':result.get('RF_fits',0)}))


if __name__=='__main__':main()
