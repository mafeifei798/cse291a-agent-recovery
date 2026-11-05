#!/usr/bin/env python3
"""Recreate report tables from saved observations in this package."""
from pathlib import Path
from collections import Counter
import argparse
import csv
import gzip
import hashlib
import importlib
import json
import runpy
import statistics
import sys

ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'analysis'))
sys.path.insert(0,str(ROOT/'phase1/evaluation_code/src'))


def read(p):return json.loads(Path(p).read_text())
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for v in iter(lambda:f.read(1024*1024),b''):h.update(v)
    return h.hexdigest()
def save(p,v):p.write_text(json.dumps(v,indent=2,allow_nan=False)+'\n')
def write_csv(p,rows):
    with p.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
def guard(event,args):
    if event.startswith('socket.') or event in ('subprocess.Popen','os.system','os.posix_spawn','pickle.find_class'):
        raise RuntimeError('Saved-result reproduction cannot execute '+event)
    if event=='sqlite3.connect':
        if not (str(args[0]).startswith('file:') and 'mode=ro&immutable=1' in str(args[0])):
            raise RuntimeError('SQLite must be immutable/read-only')


def baseline(out):
    from agent_recovery.p4_checker import audit_records
    from p4_saved import derive_p4
    from p4_depth import classify,check_natural_defect
    with gzip.open(ROOT/'phase1/evidence/p4/records.json.gz','rb') as f:
        original=f.read()
    assert hashlib.sha256(original).hexdigest()=='731f77997898af2c985a5b8f17a35b675cbb35a3279bd469740648c8f2b43da6'
    raw=json.loads(original)
    audit=audit_records(raw,p0_root=ROOT/'phase1/evaluation_code/phase1/p0',expected_processed=168)
    assert audit['passed'];r=derive_p4(raw,audit);trials=r['trials'];groups=r['groups'];pairs=r['recovery_pairs']
    def group(policy,condition):return [x for x in trials if x['policy']==policy and x['condition']==condition and x['executed']]
    table1=[]
    for cond in ('CLEAN','ERR','ADV','TMO','STL'):
        row={'condition':cond}
        for policy in ('BASE','VERIFY_STOP','FULL_RESTART'):
            chosen=group(policy,cond);correct=sum(t['correctness']=='correct' for t in chosen)
            wrong=sum(bool(t['new_wrong_committed_effect_ids']) for t in chosen)
            row.update({policy+'_correct':correct,policy+'_wrong_writes':wrong,
                        policy+'_stopped':len(chosen)-correct-wrong,policy+'_executed':len(chosen)})
        table1.append(row)
    table2=[{'method':policy,'executed_workflows':sum(t['executed'] for t in trials if t['policy']==policy),
             'model_calls':sum(len(t['new_call_ids']) for t in trials if t['policy']==policy),
             'local_usage_cost_nano':sum(t['new_cost_nano_usd'] for t in trials if t['policy']==policy)}
            for policy in ('BASE','VERIFY_STOP','FULL_RESTART')]
    assert [(x['executed_workflows'],x['model_calls']) for x in table2]==[(60,255),(60,167),(36,180)]
    assert sum(x['local_usage_cost_nano'] for x in table2)==32418900
    restarts=[t for t in trials if t['policy']=='FULL_RESTART' and t['executed']]
    assert len(restarts)==36 and sum(t['correctness']=='correct' for t in restarts)==26
    assert sum(bool(t['new_wrong_committed_effect_ids']) for t in restarts)==10
    assert len(group('BASE','CLEAN'))==12 and table1[0]['BASE_wrong_writes']==2
    err=next(g for g in groups if g['policy']=='BASE' and g['condition']=='ERR')
    assert err['wrong_descendants']==18 and err['new_wrong_writes']==12
    stepmap={}
    for step in audit['steps']:stepmap.setdefault(step['trial_key'],[]).append(step)
    categories=Counter();discarded=[]
    for pair in pairs:
        if not pair['restart_executed']:continue
        for step in stepmap[pair['base_trial_key']]:
            for cid in step['call_ids']:
                cat=classify(step);categories[cat]+=1;discarded.append({'call_id':cid,'category':cat,'base_trial':pair['base_trial_key']})
    assert dict(categories)=={'all_four_checks_passed':63,'invalid_on_at_least_one_check':60,'no_fully_judged_result':12}
    slots=raw['artifacts']['execution_manifest.json']['slots'];slotmap={s['trial_key']:s for s in slots}
    focus=[]
    for t in trials:
        if not t['executed'] or t['correctness']=='correct' or not (t['condition']=='CLEAN' or t['policy']=='FULL_RESTART'):continue
        s=slotmap[t['trial_key']];replay=s['phase']=='replay'
        db=raw['databases'][s['trial_dir']+('/restart/branch.sqlite' if replay else '/initial.sqlite')]
        own=set(s['result_ids']);results=[json.loads(v['body']) for v in db['results'] if json.loads(v['body'])['result_id'] in own]
        defect=check_natural_defect(results,raw['artifacts'][s['trial_dir']+'/task.json']['request'])
        assert defect is not None
        focus.append({'trial_key':t['trial_key'],'task_id':t['task_id'],'business_outcome':t['business_outcome'],'first_new_defect':defect})
    assert len(focus)==15 and {x['task_id'] for x in focus}=={'p1-eval-02','p1-eval-08'}
    timings=[]
    describe=lambda v:{'median':statistics.median(v),'minimum':min(v),'maximum':max(v)}
    indexed={t['trial_key']:t for t in trials}
    for cond in ('CLEAN','ERR','TMO','STL'):
        row={'condition':cond}
        for policy in ('BASE','VERIFY_STOP'):
            vals=[t['timing']['wall_execution_ms']/1000 for t in group(policy,cond)]
            for k,v in describe(vals).items():row[policy+'_'+k]=v
        subset=[x for x in pairs if x['condition']==cond and x['restart_executed']]
        if subset:
            for label,vals in [('restart',[x['restart_seconds'] for x in subset]),
                               ('initial_plus_restart',[indexed[x['base_trial_key']]['timing']['wall_execution_ms']/1000+x['restart_seconds'] for x in subset])]:
                for k,v in describe(vals).items():row[label+'_'+k]=v
        timings.append(row)
    write_csv(out/'table1_outcomes.csv',table1);write_csv(out/'table2_calls.csv',table2)
    fields=sorted({k for r in timings for k in r})
    with (out/'tableA1_timing.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(timings)
    write_csv(out/'discarded_calls.csv',discarded)
    save(out/'new_error_cases.json',focus);save(out/'p4_recomputed.json',r)
    verified=[t for t in trials if t['policy']=='VERIFY_STOP' and t['executed']]
    clean_stops=[t for t in verified if t['condition']=='CLEAN' and t['verifier_rejected']]
    assert len(verified)==60 and len(clean_stops)==3
    assert all(t['clean_false_reject'] is False and t['wrong_result_ids'] for t in clean_stops)
    verification={'runs':len(verified),
        'extra_source_reads_mean':statistics.mean(t['extra_verifier_logical_reads'] for t in verified),
        'checking_time_ms_mean':statistics.mean(t['timing']['verifier_elapsed_ms'] for t in verified),
        'clean_run_rejections':len(clean_stops),'observed_clean_false_rejections':0,
        'clean_rejected_trials':[t['trial_key'] for t in clean_stops],
        'timing_scope':'Sum of recorded check_candidate timers; not an end-to-end overhead comparison.'}
    assert verification['extra_source_reads_mean']==3.3
    assert round(verification['checking_time_ms_mean'],1)==2.7
    save(out/'verification_summary.json',verification)
    return {'passed':True,'checks':len(audit['checks']),'registered':len(trials),
            'executed':sum(t['executed'] for t in trials),'model_calls':602,'restart_correct':26,
            'restart_wrong_writes':10,'clean_BASE_wrong_writes':2,'ERR_wrong_descendants':18,
            'discarded_valid_candidates':63,'discarded_total':135,'new_error_cases':15,
            'verification':verification}


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--safety-root',type=Path,help='Optional extracted safety supplement directory')
    a=ap.parse_args();out=a.output.resolve();assert not out.exists(),'Choose a new output directory'
    manifest=read(ROOT/'MANIFEST.json')['files']
    assert all(sha(ROOT/n)==v['sha256'] and (ROOT/n).stat().st_size==v['size_bytes'] for n,v in manifest.items())
    # Import NumPy before applying process/network guards; np.load below uses
    # plain .npy arrays with allow_pickle=False, never serialized estimators.
    import numpy
    sys.addaudithook(guard);out.mkdir(parents=True)
    result=baseline(out)
    for name in list(sys.modules):
        if name=='agent_recovery' or name.startswith('agent_recovery.'):del sys.modules[name]
    safety_root=(a.safety_root.resolve() if a.safety_root else ROOT/'supplements/phase1_safety_supplement')
    safety_status={'status':'not_included','passed':None}
    if a.safety_root or safety_root.exists():
        descriptor=read(ROOT/'supplements/SAFETY_PACKAGE.json')
        assert safety_root.is_dir(),'Extract the safety supplement before using --safety-root'
        assert sha(safety_root/'MANIFEST_SHA256.json')==descriptor['manifest_sha256']
        assert sha(safety_root/'analysis/recompute.py')==descriptor['checker_sha256']
        pins=read(safety_root/'MANIFEST_SHA256.json')
        assert all(sha(safety_root/n)==pin for n,pin in pins.items())
        original_argv=sys.argv[:]
        sys.argv=['recompute.py','--output',str(out/'safety')]
        try:runpy.run_path(str(safety_root/'analysis/recompute.py'),run_name='__main__')
        finally:sys.argv=original_argv
        safety_status={'status':'checked','passed':read(out/'safety/RECOMPUTATION_RECEIPT.json')['passed']}
        safety_checks=read(out/'safety/V1_RECOMPUTED_CHECK.json')
        safety_rows=[r for batch in safety_checks['checks'] for r in batch['checks']]
        proposals=[]
        for enabled in (False,True):
            chosen=[r for r in safety_rows if r['guard_enabled']==enabled]
            dangerous=[r for r in chosen if r['dangerous_proposals']]
            proposals.append({'final_authorization_check':enabled,'runs':len(chosen),
                'unsafe_write_proposals':sum(r['dangerous_proposals'] for r in chosen),
                'unsafe_writes_committed':sum(r['unauthorized_commits'] for r in chosen),
                'unsafe_proposals_rejected_by_guard':sum(r['outcome'] in ('D','B') for r in dangerous) if enabled else 0})
        assert [(x['runs'],x['unsafe_write_proposals'],x['unsafe_writes_committed']) for x in proposals]==[(48,24,13),(48,24,0)]
        assert proposals[1]['unsafe_proposals_rejected_by_guard']==24
        write_csv(out/'safety_proposals.csv',proposals)
        safety_status['unsafe_proposal_comparison']=proposals
    from pilot_check import check
    pilot=check(ROOT);write_csv(out/'table3_pilot.csv',pilot['table3']);save(out/'pilot_numeric_checks.json',pilot)
    assert all(sha(ROOT/n)==v['sha256'] for n,v in manifest.items())
    receipt={'passed':True,'tables':['table1_outcomes.csv','table2_calls.csv','table3_pilot.csv','tableA1_timing.csv'],
             'phase1':result,'safety_saved_recomputation':safety_status['passed'],
             'optional_safety':safety_status,
             'pilot_saved_array_producers':pilot['saved_array_producers_checked'],'input_files_unchanged':len(manifest),
             'new_model_calls':0,'new_training':0,'new_predictions':0,'model_loads':0}
    save(out/'REPRODUCTION_RECEIPT.json',receipt);print(json.dumps(receipt,indent=2))


if __name__=='__main__':main()
