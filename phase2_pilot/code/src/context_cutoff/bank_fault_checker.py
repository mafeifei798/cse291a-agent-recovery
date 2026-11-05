"""Independent saved-trace/receipt audit. No runtime or recovery imports."""
from collections import Counter,deque
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
from urllib.parse import quote

from .checker import audit_run,check_contract


def _digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,
                                     allow_nan=False).encode()).hexdigest()


def audit_campaign(output,progress_scene=None):
    try:return _audit_campaign(output,progress_scene)
    except Exception as error:
        return dict(schema_version='bank-fault-independent-audit-v1',passed=False,checks=1,
            failed=[dict(name='MALFORMED_OR_MISSING_EVIDENCE',passed=False,error_type=type(error).__name__)],
            mechanism_fixture_only=None,scientific_benefit_claimed=False,evidence_scope='saved-files-only')


def _audit_campaign(output,progress_scene=None):
    root=Path(output);checks=[]
    def check(name,passed):checks.append(dict(name=name,passed=bool(passed)))
    def read(path):return json.loads(Path(path).read_text())
    def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    result=read(root/(progress_scene+'-PROGRESS.json' if progress_scene else 'RESULTS.json'))
    registry=read(root/'REGISTRY.json')
    ledger=read(root/(progress_scene+'-LEDGER.json' if progress_scene else 'LEDGER.json'))
    check('registry digest',registry['sha256']==_digest({k:v for k,v in registry.items() if k!='sha256'}))
    all_scenes=registry['scenes']
    selected=(all_scenes[:next(i for i,s in enumerate(all_scenes) if s['scene_id']==progress_scene)+1]
              if progress_scene else all_scenes)
    expected_calibrations=sum(s['fault']=='F_INCIDENTAL' for s in selected)
    check('registered scenes and complete branches',len(all_scenes)==4 and len(result['rows'])==4*len(selected))
    check('analysis-only calibrations',len(result['calibrations'])==expected_calibrations and all(
        c['analysis_only'] and not c['affects_recovery'] for c in result['calibrations']))
    check('run completed without hidden failure',result['failure'] is None)
    original_pins=read(root/'PRESERVATION_PINS.json')
    project_root=Path(__file__).resolve().parents[2]
    check('all pinned prior files preserved',all(sha(project_root/name)==pin for name,pin in original_pins.items()))
    calls=ledger['calls'];counts=Counter(c['run_id'] for c in calls)
    check('physical HTTP accounts once',len(calls)==result['physical_http_dispatches']<=162
          and len({c['call_id'] for c in calls})==len(calls))
    for unit in registry['units']:
        check('unit cap '+unit['unit_id'],counts[unit['unit_id']]<=unit['call_cap'])
    roles=Counter((c['run_id'],c['step_id']) for c in calls)
    check('role caps',all(n<=5 for n in roles.values()))
    check('only registered units',set(counts)<=set(u['unit_id'] for u in registry['units']))
    for c in calls:
        u=c['usage'];raw=c['evidence']['wire_audit']['raw_response']['usage']
        check('usage settled '+c['call_id'],c['status']=='settled' and u['raw']==raw
              and u['total_tokens']==u['prompt_tokens']+u['completion_tokens']
              and c['known_cost_nano_usd']==150*u['prompt_tokens']+500*u['completion_tokens'])
    handoff=read(root/'INHERITANCE.json')
    check('eighteen prior receipts charged once',handoff['sha256']==_digest({k:v for k,v in handoff.items() if k!='sha256'})
          and handoff['inherited_generation_calls']==18 and len(handoff['receipts'])==18
          and sum(r['cost_nano'] for r in handoff['receipts'])==3789550)
    new_known=sum(c['known_cost_nano_usd'] for c in calls)
    u=ledger['unified_budget'];b=ledger['bank_budget']
    check('all money caps',b['total_nano']<=1000000000 and u['pilot_total_nano']<=3000000000
          and u['project_total_nano']<=20000000000)
    check('historical hold retained',u['historical_held_nano']==3252000)
    check('history plus new usage',u['pilot_known_nano']==3789550+new_known
          and u['project_known_nano']==183475650+new_known)
    check('authority outside workspaces',Path(read(root/'CONFIG.json')['authority_path']).parent==root.resolve())
    with closing(sqlite3.connect('file:'+quote(str((root/'authority.sqlite').resolve()),safe='/')+'?mode=ro',uri=True)) as db:
        persisted=db.execute('SELECT body FROM bf_handoff WHERE singleton=1').fetchone()
        check('durable inherited authority',json.loads(persisted[0])==handoff)
        units=db.execute('SELECT unit_id,state,started,deadline FROM bf_units').fetchall()
    check('all selected units durably finished',len(units)==4*len(selected)+expected_calibrations and all(r[1]=='finished' for r in units))
    check('single fixed unit deadlines',all(abs(r[3]-r[2]-120)<1e-6 for r in units))
    recovered=[]
    for scene in selected:
        sid=scene['scene_id'];frozen=root/'frozen'/sid;manifest=read(frozen/'MANIFEST.json')
        checkpoint=read(frozen/'CHECKPOINT.json');old=checkpoint['document']
        check('frozen manifest '+sid,manifest['freeze_sha256']==_digest({k:v for k,v in manifest.items() if k!='freeze_sha256'})
              and manifest['checkpoint_sha256']==_digest(checkpoint))
        for name,pin in manifest['files'].items():check('frozen file '+sid+'/'+name,sha(frozen/name)==pin)
        check('freeze before publish '+sid,not checkpoint['publication_executed'] and checkpoint['all_http_settled']
              and 'external/publication.json' not in old['files']
              and checkpoint['pending_publication_request']['payload']=={'tool':'publish','arguments':{}})
        fault=old['faults'][0]
        check('one controlled fault '+sid,len(old['faults'])==1 and fault['type']==scene['fault'])
        truth=json.loads((frozen/'state/artifacts/sha256'/old['files']['inputs/bank-description.json']['sha256']).read_text())
        truth['note']+=' External owner clarified the documentation.'
        expected_source_hash=_digest(truth)
        old_nodes={n['result_id']:n for n in old['nodes']}
        original_contract=old_nodes[checkpoint['planner_result_id']]['payload']
        old_exec={n['result_id'] for n in old['nodes'] if n['role']=='Executor'}
        for method in registry['methods']:
            unit=sid+'.'+method;work=root/'runs'/unit;trace=read(work/'RECOVERY_RESULT.json')
            audit=audit_run(trace);check('independent provenance '+unit,audit['passed'])
            recovery=trace['recovery'];decision=next(d for d in trace['decisions'] if d['method']==method)
            check('same failure scene '+unit,recovery['freeze_sha256']==manifest['freeze_sha256']
                  and decision['old_result_id']==checkpoint['planner_result_id'])
            source=trace['files']['inputs/bank-description.json']
            check('external source update retained '+unit,source['sha256']==expected_source_hash
                  and source['version']==old['files']['inputs/bank-description.json']['version']+1
                  and source['writer_id']=='external-owner' and recovery['source_update_preserved'])
            new_contract=trace['final']['contract'];policy=trace['audit_policy']
            business=check_contract(new_contract,policy['allowed_features'],policy['data_binding'],policy['code_sha256'])
            check('completion separate from safe stop '+unit,trace['final']['outcome'] in
                  ('correct_complete','safe_stop','wrong_complete','infrastructure_failure','external_unresolved'))
            if trace['final']['outcome']=='correct_complete':check('final business correctness '+unit,business['passed'])
            retained=set(recovery['retained_result_ids']);receipts=trace.get('reuse_receipts',[])
            check('retention declaration '+unit,retained==set(trace['final']['retained_result_ids']))
            check('one recheck '+unit,decision['rechecks']==1 and sum(d['method']==method for d in trace['decisions'])==1)
            # Rebuild the conservative closure from actual prompt/tool read
            # edges; never trust a runtime's "other_inputs_valid" boolean.
            edges={(p,n['result_id']) for n in old['nodes'] for p in n['parent_result_ids']}
            cut={(e['parent_result_id'],e['child_result_id']) for e in decision['cut_edges']}
            seeds={checkpoint['faulty_result_id']}
            for n in old['nodes']:
                if any(trace['files'].get(r['file_id'])!=r for r in n.get('file_reads',[])):seeds.add(n['result_id'])
            affected=set(seeds);queue=deque(seeds)
            while queue:
                parent=queue.popleft()
                for p,c in edges-cut:
                    if p==parent and c not in affected:affected.add(c);queue.append(c)
            if retained:
                check('only eligible cutoff retains '+unit,method=='CUTOFF' and len(receipts)==1
                      and new_contract==original_contract and business['passed']
                      and retained==old_exec and not retained.intersection(affected)
                      and cut<=edges and all(p==checkpoint['planner_result_id'] for p,_ in cut))
                check('no retraining on retained path '+unit,recovery['training_requests']==0)
                check('retained computed files current '+unit,all(trace['files'].get(k)==old['files'].get(k)
                    for k in ('work/features.json','work/fixture-model.json','work/report.json')))
                receipt=receipts[0]
                check('reuse receipt hash '+unit,receipt['sha256']==_digest({k:v for k,v in receipt.items() if k!='sha256'})
                    and receipt['freeze_sha256']==manifest['freeze_sha256'] and set(receipt['retained_result_ids'])==retained)
                bundle=read(receipt['bundle_path'])
                check('artifact receipt binding '+unit,sha(receipt['bundle_path'])==receipt['bundle_file_sha256']
                    and bundle['sha256']==_digest({k:v for k,v in bundle.items() if k!='sha256'})
                    and bundle['sha256']==receipt['bundle_sha256'] and bundle['contract']==new_contract
                    and bundle['environment_sha256']==checkpoint['environment_sha256'])
                for item in bundle['files']:check('retained artifact '+unit+'/'+item['name'],sha(item['path'])==item['sha256'])
                with closing(sqlite3.connect('file:'+quote(str((work/'store.sqlite').resolve()),safe='/')+'?mode=ro',uri=True)) as db:
                    stored=db.execute('SELECT body FROM bf_reuse WHERE receipt_id=?',(receipt['receipt_id'],)).fetchone()
                check('reuse receipt durable '+unit,stored is not None and json.loads(stored[0])==receipt)
            else:check('no undeclared artifact reuse '+unit,not receipts and not cut)
            if trace['final']['outcome']=='correct_complete':
                publications=[t for t in trace['tool_calls'] if t['name']=='publish']
                check('publication exactly once '+unit,len(publications)==1)
                pub=publications[0]
                check('publication binds guard sources '+unit,all(any(r==ref for r in pub['reads'])
                    for ref in decision['candidate_guard']['source_refs']))
            recovered.append(dict(unit_id=unit,outcome=trace['final']['outcome'],new_calls=recovery['new_calls'],
                retained_nodes=len(retained),training_requests=recovery['training_requests']))
    return dict(schema_version='bank-fault-independent-audit-v1',passed=all(c['passed'] for c in checks),
        checks=len(checks),failed=[c for c in checks if not c['passed']],branches=recovered,
        mechanism_fixture_only=result['fixture_only'],scientific_benefit_claimed=False,
        real_api_requests=result['real_api_requests'],actual_training=result['actual_training'],
        actual_prediction=result['actual_prediction'],all_checks=checks)
