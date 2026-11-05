"""Recompute Table 3 from saved worker records and prediction arrays."""
from pathlib import Path
import csv
import hashlib
import importlib.util
import json
import sqlite3
import numpy as np


def check(root):
    root=Path(root).resolve();pilot=root/'phase2_pilot';e=pilot/'records/comparison';old=pilot/'records/prefix'
    def physical(value):
        p=Path(value)
        if p.is_relative_to(root):return p
        maps=[('/home/hoding/cse291a-compare-real-20261031-r1/project',pilot/'code'),
              ('/home/hoding/cse291a-compare-real-20261031-r1',e),
              ('/home/hoding/cse291a-l-feedback-20261031-r3/real/campaign',old),
              ('/home/hoding/cse291a-l-feedback-20261031-r3/project',pilot/'code')]
        for source,target in maps:
            if p.is_relative_to(source):return target/p.relative_to(source)
        raise ValueError('Unmapped saved path: '+str(p))
    def read(p):return json.loads(physical(p).read_text())
    def sha(p):return hashlib.sha256(physical(p).read_bytes()).hexdigest()
    def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
    closure=read(pilot/'code/SOURCE_CLOSURE.json')
    assert closure['source_sha256']=='4f693af61c1eebf23d7d4746983bf4fdd4e3f78ea1d1a2385734500c628d9047'
    assert all(sha(pilot/'code'/name)==value for name,value in closure['files'].items())
    spec=importlib.util.spec_from_file_location('pilot_numeric',pilot/'code/src/context_cutoff/numeric_checker.py')
    numeric=importlib.util.module_from_spec(spec);spec.loader.exec_module(numeric)
    ledger=read(e/'real/LEDGER.json');calls=ledger['calls'];frozen=read(old/'runs/LI01.PREFIX/FREEZE.json')
    assert frozen['checkpoint_sha256']==digest({k:v for k,v in frozen.items() if k!='checkpoint_sha256'})
    assert len(calls)==24 and len({c['provider_request_id'] for c in calls})==24
    assert all(c['dispatched'] and c['status']=='settled' and c['simulated'] is False for c in calls)
    for c in calls:
        assert c['known_cost_nano_usd']==c['usage']['prompt_tokens']*150+c['usage']['completion_tokens']*500
    with sqlite3.connect((e/'real/authority.sqlite').as_uri()+'?mode=ro&immutable=1',uri=True) as db:
        saved=[json.loads(v[0]) for v in db.execute('SELECT body FROM p3_calls')]
        assert {v['call_id']:v for v in saved}=={v['call_id']:v for v in calls}
    timing=read(e/'real/TIMING.json');summary=read(e/'real/SUMMARY.json');jobs=[];rows=[]
    for method in ('FULL','CONSERVATIVE','CUTOFF'):
        folder=e/'real'/method;r=read(folder/'run/RESULT.json');rec=read(folder/'CPU_RECORDS.json')
        row=next(v for v in summary['rows'] if v['method']==method)
        assert r['outcome']=='completed_execution' and r['quality_goal_met']
        assert r['optimization_spent']==1 and r['recovery']['normal_remaining_after']==0
        assert r['recovery']['checkpoint_sha256']==frozen['checkpoint_sha256']
        assert r['recovery']['equivalent_contracts'] and r['recovery']['duplicate_replay_HTTP_delta']==0
        with sqlite3.connect((folder/'run/store.sqlite').as_uri()+'?mode=ro&immutable=1',uri=True) as db:
            assert [json.loads(v[0]) for v in db.execute('SELECT payload FROM ctx_nodes ORDER BY seq')]==r['store_snapshot']['nodes']
        train=[];checks=[]
        for item in rec:
            record=item['record'];execution=record['execution']
            assert read(folder/'campaign'/item['record_rel'])==record
            assert execution['worker_reaped'] and not execution['remaining_processes']
            assert not execution['inherited_credentials'] and execution['status']=='success'
            if record['spec']['schema_version']=='context-cutoff-cpu-v1':
                train.append(execution['cpu_seconds']);jobs.append((method,record))
            else:
                assert record['spec']['schema_version']=='context-cutoff-numeric-v1'
                assert record['response']['model_fits']==0 and record['response']['fit_guard']['installed']
                checks.append(execution['cpu_seconds'])
        admitted=read(folder/'ADMISSIONS.json')
        for a in admitted:
            source=Path(a['producer_campaign_root'])/a['record_rel']
            assert a['fits']==0 and a['artifact_hashes_checked'] and sha(source)==a['producer_record_sha256']
            original=read(source);assert original['spec']['contract']==a['contract']
            jobs.append(('CUTOFF_admitted',original))
        assert len(train)==row['real_fits'] and len(admitted)==row['admissions']
        own=[c for c in calls if c['run_id']==row['unit']]
        branch=next(x for x in timing['events'] if x['name']=='branch_'+method)
        rows.append({'method':method,'new_fits':len(train),'reused_artifacts':len(admitted),
                     'training_worker_CPU_seconds':sum(train),'check_worker_CPU_seconds':sum(checks),
                     'total_worker_CPU_seconds':sum(train)+sum(checks),'model_calls':len(own),
                     'local_usage_cost_nano':sum(c['known_cost_nano_usd'] for c in own),
                     'recovery_wall_seconds':branch['wall_ns']/1e9})
    assert [(r['new_fits'],r['reused_artifacts']) for r in rows]==[(3,0),(3,0),(0,3)]
    assert len(jobs)==9
    arrays=[];raw_cache={}
    for method,record in jobs:
        job=record['spec'];response=record['response'];contract=job['contract'];base=Path(job['output_dir'])
        assert sha(job['raw_path'])==contract['data_binding']['file_sha256']
        for a in response['artifacts']:
            p=physical(base/a['name']);assert p.stat().st_size==a['size_bytes'] and sha(p)==a['sha256']
        rawpath=physical(job['raw_path'])
        if rawpath not in raw_cache:
            with rawpath.open(newline='') as f:raw_cache[rawpath]=list(csv.DictReader(f,delimiter=';'))
        original=raw_cache[rawpath];metrics={}
        for split,key in (('train','train_rows_path'),('validation','validation_rows_path')):
            rowfile=read(job[key]);ids=rowfile['row_ids']
            assert read(base/(split+'_row_ids.json'))==ids
            assert sha(job[key])==contract['data_binding'][split+'_rows_sha256']
            y=np.load(physical(base/(split+'_labels.npy')),allow_pickle=False)
            prob=np.load(physical(base/(split+'_probabilities.npy')),allow_pickle=False)
            pred=np.load(physical(base/(split+'_predictions.npy')),allow_pickle=False)
            labels=np.array([int(original[int(v.rsplit(':',1)[-1])-1]['y']=='yes') for v in ids],dtype=np.int8)
            assert np.array_equal(y,labels) and np.array_equal(pred,(prob>=.5).astype(np.int8))
            m=numeric.binary_metrics(y.tolist(),prob.tolist())
            assert all(abs(m[k]-response['metrics'][split][k])<=1e-10 for k in m)
            metrics[split]=m
        arrays.append({'method':method,'job_id':job['job_id'],'metrics':metrics})
    expected=read(pilot/'expected/ANALYSIS.json')
    for row,prior in zip(rows,expected['methods']):
        assert row['method']==prior['method'] and row['model_calls']==8
        for new,oldkey in [('training_worker_CPU_seconds','fit_worker_CPU_seconds'),
                           ('check_worker_CPU_seconds','numeric_worker_CPU_seconds'),
                           ('total_worker_CPU_seconds','worker_CPU_seconds')]:
            assert abs(row[new]-prior[oldkey])<1e-9
    # A failed later source-update attempt remains a failed attempt.
    fail=read(pilot/'records/source_update_incomplete/RESULT.json')
    call=read(pilot/'records/source_update_incomplete/failed_call.json')
    assert fail['outcome']=='failed_execution' and fail['recovery']['new_native_fits']==0
    assert call['status']=='uncertain' and call['usage'] is None
    return {'passed':True,'table3':rows,'saved_array_producers_checked':len(arrays),'array_checks':arrays,
            'pilot_source_closure_files_checked':len(closure['files']),
            'source_update_case_complete':False,'new_training_or_prediction':0,'model_loads':0}
