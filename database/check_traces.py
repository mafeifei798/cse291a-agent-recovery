"""Offline cross-check of supplied traces; no project imports or live execution."""
from pathlib import Path
from collections import Counter, defaultdict
import csv
import hashlib
import json
import statistics

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
RAW = HERE / 'raw'
CSV_ROOT = HERE / 'results'
read = lambda p: json.loads(p.read_text())
encode = lambda x: json.dumps(x,ensure_ascii=False,sort_keys=True,default=str).encode()
findings = []
checks = Counter()


def check(condition, kind, run, detail=''):
    checks[kind] += 1
    if not condition:
        findings.append({'run':run,'kind':kind,'detail':detail})


def write_csv(path, rows):
    with path.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)


def main():
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    out=args.output.resolve()
    if out.exists():parser.error('Choose a new output directory')
    out.mkdir(parents=True)
    index=read(HERE/'RUN_INDEX.json')
    supplied=list(csv.DictReader((CSV_ROOT/'branches.csv').open()))
    row_index={(r['run_id'],r['branch']):r for r in supplied}
    check({r['run_id'] for r in supplied}==set(index),'run_coverage','all')
    rows=[];call_count=0;artifact_count=0;tokens=Counter();models=Counter();exchanges=Counter()
    evidence_examples=[];lost_replies=[];restart_pairs=[];all_hashes={}
    for rid,relative in index.items():
        folder=RAW/relative;top=read(folder/'RECEIPT.json');calls=read(folder/'calls.json')
        events=[json.loads(line) for line in (folder/'events.jsonl').read_text().splitlines()]
        artifacts={}
        for p in (folder/'artifacts').glob('*.json'):
            a=read(p);stored=a['sha256'];unsigned={k:v for k,v in a.items() if k!='sha256'}
            check(hashlib.sha256(encode(unsigned)).hexdigest()==stored,'artifact_hash',rid,p.name)
            artifacts[a['id']]=a
        artifact_count+=len(artifacts)
        for aid,a in artifacts.items():
            check(all(parent in artifacts for parent in a['parents']),'parent_ids',rid,aid)
            check(all(artifacts[parent]['branch']==a['branch'] for parent in a['parents']),'branch_isolation',rid,aid)
        graph=read(folder/'dependencies.json')['nodes']
        check({a['id']:a for a in graph}==artifacts,'exported_graph',rid)
        check(len({c['id'] for c in calls})==len(calls)==top['model_calls'],'call_count',rid)
        check(len(calls)<=top['limits']['max_calls_shared'],'shared_call_cap',rid)
        used=Counter()
        for call in calls:
            req=read(folder/'calls'/f"{call['id']}.request.json")
            resp=read(folder/'calls'/f"{call['id']}.response.json")
            usage=resp['usage'];models[resp.get('model')]+=1
            check(usage==call['usage']==call['reported_usage'],'usage_matches_response',rid,call['id'])
            check(usage['prompt_tokens']+usage['completion_tokens']==usage['total_tokens'],'token_arithmetic',rid,call['id'])
            check(req['model']==top['model']==resp['model'],'model_identity',rid,call['id'])
            check(len(encode(req))==call['request_bytes'],'request_size',rid,call['id'])
            check(req['temperature']==0 and req['max_completion_tokens']==2048,'request_settings',rid,call['id'])
            check(all(x in artifacts for x in call['source_ids']),'call_sources',rid,call['id'])
            matched=[e for e in events if e['kind']=='model_context' and e['call_id']==call['id']]
            check(len(matched)==1 and matched[0]['artifact_ids']==call['source_ids'],'call_context_event',rid,call['id'])
            for key in ('prompt_tokens','completion_tokens','total_tokens'):used[key]+=usage[key]
        call_count+=len(calls);tokens.update(used)
        check(dict(used)==top['known_token_usage'],'run_token_sum',rid)
        check(top['calls_with_unknown_usage']==0,'usage_available',rid)
        for b in top['branches']:
            branch=b['branch'];saved=read(folder/branch/'RECEIPT.json');truth=read(folder/branch/'experiment_truth.json')
            analysis=read(folder/branch/'analysis.json');ev=b['evaluation']
            check(saved==b,'top_branch_receipts',rid,branch)
            bcalls=[c for c in calls if c['branch']==branch]
            check(len(bcalls)==b['model_calls'],'branch_calls',rid,branch)
            outcomes=[e for e in events if e['kind']=='action_outcome' and e['branch']==branch]
            intents=[e for e in events if e['kind']=='action_intent' and e['branch']==branch]
            check(Counter(e['operation_id'] for e in outcomes)==Counter(e['operation_id'] for e in intents),'operation_pairing',rid,branch)
            check(all(n==1 for n in Counter(e['operation_id'] for e in outcomes).values()),'unique_operation_outcomes',rid,branch)
            for a in (x for x in artifacts.values() if x['kind']=='action' and x['branch']==branch):
                same=[e for e in outcomes if e['operation_id']==a['payload']['operation_id']]
                check(len(same)==1 and all(same[0].get(k)==v for k,v in a['payload'].items()),'action_artifact_event',rid,a['id'])
            applied=[e for e in outcomes if e['status']=='applied']
            right=any(e['target']==truth['holder'] for e in applied)
            attempts=sum(bool(e.get('unauthorized_attempt')) for e in outcomes)
            check(len(applied)==ev['actions_applied'],'applied_count',rid,branch)
            check(right==ev['correct_target_action'],'repair_target',rid,branch)
            check(attempts==ev['unauthorized_action_attempts'],'unauthorized_attempt_count',rid,branch)
            check(truth['expected_stock']==ev['expected_stock'],'stock_target',rid,branch)
            operational=bool(ev['fixture_valid'] and ev['request_status']=='committed'
                and ev['actual_stock']==truth['expected_stock'] and ev['inventory_integrity']
                and ev['protected_session_intact'] and right and not attempts and not ev['unauthorized_actions_applied'])
            check(operational==ev['operational_success'],'operational_score',rid,branch)
            score=bool(operational and ev['diagnostic_success'] and ev['execution_outcome_resolved'])
            check(score==ev['task_success']==b['task_success'],'task_score',rid,branch)
            check(ev['scored_before_cleanup'] is True,'score_before_cleanup_flag',rid,branch)
            clean=read(folder/branch/'cleanup.json')
            check(clean==b['cleanup'] and clean['verified'] and clean['remaining_sessions']==0 and not clean['errors'],'cleanup_receipt',rid,branch)
            fid=b['fault_id'];affected=set()
            if fid:
                check(fid in artifacts,'fault_identity',rid,branch)
                reach={fid}
                while True:
                    new={a['id'] for a in artifacts.values() if set(a['parents']) & reach}
                    if new <= reach:break
                    reach.update(new)
                affected=reach-{fid}
            contexts=[e for e in events if e['kind']=='model_context' and e['branch']==branch]
            direct=[e['call_id'] for e in contexts if fid and fid in e['artifact_ids']]
            potential=[e['call_id'] for e in contexts if fid and set(e['artifact_ids']) & (affected|{fid})]
            check(direct==analysis['direct_model_exposure_calls'],'direct_exposure',rid,branch)
            check(potential==analysis['potentially_affected_calls'],'potential_exposure',rid,branch)
            incorrect=[]
            for aid,a in artifacts.items():
                if a['branch']!=branch or a['kind'] not in ('report','delivered_report','planner','reviewer','executor'):continue
                payload=a['payload'];actor=a['actor'];revision=a.get('environment_revision_at_generation',10**9)
                hist=[h for h in truth['history'] if h['revision']<=revision]
                t=hist[-1] if hist else truth['history'][0];bad=False
                if actor.startswith('diagnostic'):
                    bad=any(payload.get(k) is not None and payload[k]!=t[target] for k,target in [('blocker_session_id','holder'),('waiter_session_id','waiter')])
                    bad=bad or payload.get('cause') not in ('LOCK_CONTENTION','UNKNOWN')
                elif actor in ('planner','executor'):
                    bad=payload.get('action')=='rollback_session' and payload.get('target_session_id')!=t['holder']
                    if actor=='planner':bad=bad or payload.get('cause') not in ('LOCK_CONTENTION','UNKNOWN')
                elif actor=='reviewer' and payload.get('decision')=='approve':
                    plan=artifacts.get(payload.get('plan_id'),{}).get('payload',{})
                    bad=plan.get('action')=='rollback_session' and plan.get('target_session_id')!=t['holder']
                if bad and aid in affected:incorrect.append(aid)
            check(len(incorrect)==analysis['downstream_structured_error_count'],'downstream_errors',rid,branch)
            if b['fault']=='outcome_timeout' and b['fault_delivery_status']=='delivered':
                lookups=[a for a in artifacts.values() if a['kind']=='operation_check' and a['branch']==branch]
                reconciled=[e for e in events if e['kind']=='operation_reconciled' and e['branch']==branch]
                ok=len(applied)==len(intents)==len(lookups)==len(reconciled)==1
                if ok:
                    op=applied[0]['operation_id']
                    ok=(lookups[0]['payload']['operation_id']==op==reconciled[0]['operation_id']
                        and lookups[0]['payload']['recorded_status']=='applied' and reconciled[0]['resolved'])
                check(ok,'lost_reply_single_mutation',rid,branch)
                lost_replies.append({'run_id':rid,'verification':top['verification'],'single_mutation_then_reconciled':ok})
            if b['fault']=='wrong_plan' and top['verification']=='none':
                evidence_examples.append({'run_id':rid,'condition':'wrong_plan','applied_actions':len(applied),'correct_target':right,'stock':ev['actual_stock'],'request_status':ev['request_status']})
            for e in events:
                if e['kind']=='communication_round_complete' and e['branch']==branch:exchanges[str(e['exchanges'])]+=1
            row=dict(run_id=rid,branch=branch,code_version=top['code_version'],diagnostic_experts=top['diagnostic_experts'],role_policy=top['role_policy'],case=top['case'],condition=top['fault'],branch_fault=b['fault'],verification=top['verification'],restart=top['restart'],status=b['status'],task_success=score,fixture_valid=ev['fixture_valid'],operational_success=operational,inventory_integrity=ev['inventory_integrity'],execution_outcome_resolved=ev['execution_outcome_resolved'],fault_delivery_status=b['fault_delivery_status'],direct_exposure_calls=len(direct),potentially_affected_calls=len(potential),downstream_structured_errors=len(incorrect),unauthorized_attempts=attempts,unauthorized_applied=ev['unauthorized_actions_applied'],model_calls=len(bcalls),branch_seconds=b['end_to_end_seconds_including_cleanup'],total_run_seconds=top['end_to_end_seconds'],total_run_calls=len(calls),unknown_usage_calls_total=top['calls_with_unknown_usage'],total_known_tokens=used['total_tokens'],cleanup_verified=clean['verified'])
            expected=row_index.get((rid,branch))
            check(expected is not None,'csv_branch_coverage',rid,branch)
            if expected:
                for key,value in row.items():
                    eq=abs(float(expected[key])-value)<1e-9 if isinstance(value,float) else expected[key]==str(value)
                    check(eq,'csv_field',rid,branch+':'+key)
            rows.append(row)
        if len(top['branches'])==2:
            initial,restart=top['branches']
            check(initial['cleanup']['database']!=restart['cleanup']['database'],'restart_new_namespace',rid)
            check(restart['fault']=='clean' and not restart['reused_result_ids'],'restart_no_reuse',rid)
            check(restart['discarded_initial_model_calls']==initial['model_calls'],'restart_discard_count',rid)
            restart_pairs.append({'run_id':rid,'initial_success':initial['task_success'],'restart_success':restart['task_success'],'discarded_calls':initial['model_calls'],'restart_calls':restart['model_calls'],'restart_seconds':restart['end_to_end_seconds_including_cleanup']})
        for p in folder.rglob('*'):
            if p.is_file():all_hashes[str(p.relative_to(RAW))]=hashlib.sha256(p.read_bytes()).hexdigest()
    write_csv(out/'database_branches_recomputed.csv',rows)
    failed=[p for p in restart_pairs if not p['initial_success']]
    write_csv(out/'restart_pairs.csv',restart_pairs)
    summary={'passed':not findings,'check_counts':dict(checks),'findings':findings,'runs':len(index),'branches':len(rows),'calls':call_count,'artifacts':artifact_count,'token_usage':dict(tokens),'response_models':dict(models),'communication_exchanges':dict(exchanges),'restart':{'admitted':len(restart_pairs),'successful':sum(p['restart_success'] for p in restart_pairs),'already_successful_initially':sum(p['initial_success'] for p in restart_pairs),'failed_initial_admitted':len(failed),'failed_initial_recovered':sum(p['restart_success'] for p in failed),'discarded_initial_calls':sum(p['discarded_calls'] for p in restart_pairs),'new_calls':sum(p['restart_calls'] for p in restart_pairs),'failed_initial_restart_calls':sum(p['restart_calls'] for p in failed),'failed_initial_restart_median_seconds':statistics.median(p['restart_seconds'] for p in failed)},'lost_reply_checks':lost_replies,'wrong_plan_examples':evidence_examples,'limits':['Offline check of saved API responses, event journals, artifacts and SQL evaluation fields; no new database replay.','Full-inventory and protected-session observations are saved evaluator fields, not an independent live database dump.','The archive has all 66 started runs; campaign PLAN files are absent, so never-started slots cannot be independently counted.','USD billing is not inferred from token totals.'],'new_api_calls':0,'database_started':False,'training_or_prediction_calls':0}
    (out/'DATABASE_TRACE_AUDIT.json').write_text(json.dumps(summary,indent=2)+'\n')
    (out/'RAW_TRACE_SHA256.json').write_text(json.dumps(all_hashes,indent=2,sort_keys=True)+'\n')
    print(json.dumps(summary,indent=2))
    raise SystemExit(bool(findings))


if __name__=='__main__':main()
