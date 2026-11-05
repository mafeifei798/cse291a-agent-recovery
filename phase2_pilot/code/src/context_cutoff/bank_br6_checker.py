"""Independent saved-evidence checks, with no recovery/budget execution."""
from collections import Counter
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
from urllib.parse import quote

from agent_recovery.contracts import digest, canonical_json
from .bank_br6_protocol import PLAN, SCENES, UNIT_MAP, REGISTRY_SHA
from .checker import audit_run
from .contracts import contract_digest

HISTORY129_SHA='9ec85927cf554e01787b942e1a7279bc1dcf4a457427e04b9e8574c0a0d5a560'


def read(p):
    return json.loads(Path(p).read_text())


def pin(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def ro(path):
    return closing(sqlite3.connect('file:'+quote(str(Path(path).resolve()),safe='/')+'?mode=ro',uri=True))


def zero_training_acceptance(output,unit,*,fixture_only=True):
    """Independent graph/byte proof; live scope additionally needs no-fit worker proof."""
    out=Path(output); checks=[]
    def check(name,passed):checks.append(dict(name=name,passed=bool(passed)))
    reused=False
    try:
        trace=read(out/'runs'/unit/'RECOVERY_RESULT.json')
        check('independent prompt/file graph',audit_run(trace)['passed'])
        scene=unit.split('.')[0]
        checkpoint=read(out/'frozen'/scene/'CHECKPOINT.json')
        decision=trace['decisions'][-1]
        reused=decision['action']=='retain'
        new_tools=[t for t in trace['tool_calls'] if t['tool_call_id'].startswith(unit+'.tool.')]
        check('explicit execution classification',trace['fixture_only'] is fixture_only
              and (not fixture_only or trace['actual_training']==0))
        if not reused:
            check('fallback does not forge reuse',not trace['reuse_receipts']
                  and not trace['recovery']['retained_result_ids'])
        else:
            receipt=trace['reuse_receipts'][0]
            original=checkpoint['document']
            original_plan=next(n for n in original['nodes'] if n['result_id']==checkpoint['planner_result_id'])
            edges={(p,n['result_id']) for n in original['nodes'] for p in n['parent_result_ids']}
            cuts={(e['parent_result_id'],e['child_result_id']) for e in decision['cut_edges']}
            affected={checkpoint['faulty_result_id']}
            affected.update(n['result_id'] for n in original['nodes']
                if any(trace['files'].get(ref['file_id'])!=ref for ref in n.get('file_reads',[])))
            while True:
                more={child for parent,child in edges-cuts if parent in affected}
                if more<=affected:break
                affected.update(more)
            check('independently rebuilt invalidation closure',cuts<=edges
                  and all(parent==checkpoint['planner_result_id'] for parent,child in cuts)
                  and not set(receipt['retained_result_ids']).intersection(affected))
            check('one persisted reuse',len(trace['reuse_receipts'])==1)
            check('zero new training invocations',trace['training_requests_this_unit']==0
                  and trace['recovery']['training_requests']==0 and not trace.get('cpu_records')
                  and trace['actual_training']==0 and trace['actual_prediction']==0)
            check('no new train tools',not any(t['name']=='train' for t in new_tools))
            check('no new artifact bundle',not list((out/'cpu'/unit).glob('request-*/bundle.json')))
            check('contract strict equality',contract_digest(decision['candidate_contract'])
                  ==receipt['contract_sha256']==contract_digest(trace['final']['contract'])
                  ==contract_digest(original_plan['payload']))
            output_keys=('work/features.json','work/fixture-model.json','work/report.json')
            check('retained output versions unchanged',all(trace['files'][k]==original['files'][k] for k in output_keys)
                  and receipt['retained_output_refs']==[trace['files'][k] for k in output_keys])
            refs=receipt['source_refs']
            required={'inputs/bank-description.json','inputs/data-binding.json','tools/training-entry.txt',
                      'inputs/execution-environment.json','inputs/permission.json'}
            check('acceptance source versions are current',len(refs)==len(required)
                  and {r['file_id'] for r in refs}==required
                  and refs==decision['candidate_guard']['source_refs']
                  and all(trace['files'].get(r['file_id'])==r for r in refs))
            publications=[t for t in new_tools if t['name']=='publish']
            check('publication binds accepted source versions',len(publications)==1
                  and all(ref in publications[0]['reads'] for ref in refs))
            check('one recheck and other dependencies valid',decision['rechecks']==1
                  and decision['equivalent'] is True and decision['other_inputs_valid'] is True
                  and decision['candidate_guard']['passed'] is True)
            check('receipt digest',receipt['sha256']==digest({k:v for k,v in receipt.items() if k!='sha256'}))
            check('same frozen artifact receipt',receipt['bundle_path']==checkpoint['bundle_path']
                  and receipt['bundle_file_sha256']==pin(receipt['bundle_path'])==checkpoint['bundle_file_sha256'])
            bundle=read(receipt['bundle_path'])
            check('bundle content and environment',bundle['sha256']==receipt['bundle_sha256']
                  ==digest({k:v for k,v in bundle.items() if k!='sha256'})
                  and bundle['environment_sha256']==checkpoint['environment_sha256'])
            check('all retained bytes unchanged',bool(bundle['files']) and all(pin(f['path'])==f['sha256'] for f in bundle['files']))
            check('old executor nodes retained',set(receipt['retained_result_ids'])
                  =={n['result_id'] for n in checkpoint['document']['nodes'] if n['role']=='Executor'}
                  ==set(trace['recovery']['retained_result_ids']))
            with ro(out/'runs'/unit/'store.sqlite') as db:
                rows=db.execute('SELECT body FROM bf_reuse').fetchall()
                check('durable SQLite reacceptance',len(rows)==1 and json.loads(rows[0][0])==receipt)
            check('final checks retained',trace['numeric_check']['passed'] is True
                  and trace['final']['outcome']=='correct_complete'
                  and trace['recovery']['source_update_preserved'] is True)
        if not fixture_only:
            numeric=trace.get('numeric_check',{})
            guarded=numeric.get('fit_guard',{})
            check('independent checker actively forbids fitting',guarded.get('installed') is True
                  and bool(guarded.get('protected_methods')) and guarded.get('rejected_calls')==[]
                  and numeric.get('model_fits')==0 and numeric.get('model_loads')==1
                  and numeric.get('model_predictions')==2 and numeric.get('business_correct') is True)
            execution=read(out/'cpu'/unit/'NUMERIC_EXECUTION.json')
            check('independent checker worker was reaped',execution.get('response')==numeric
                  and execution['execution'].get('worker_reaped') is True
                  and execution['execution'].get('remaining_processes')==[])
    except Exception as error:
        check('malformed reuse evidence: '+type(error).__name__,False)
    return dict(schema_version='bank-br6-zero-training-check-v1',unit_id=unit,fixture_only=fixture_only,
        reused=reused,passed=all(c['passed'] for c in checks),checks=checks,
        actual_training=0 if fixture_only or reused else None,actual_prediction=0 if fixture_only else None,
        numeric_quality_verified=(not fixture_only and all(c['passed'] for c in checks)),
        scope=('fixture graph and bytes, not real training reuse' if fixture_only else
               'zero new training on retained branch; independent model loading and prediction still charged'))


def audit_br6(output,*,scene=None,fixture_only=True):
    out=Path(output);checks=[]
    def check(name,passed):checks.append(dict(name=name,passed=bool(passed)))
    try:
        cfg=read(out/'CONFIG.json');h=read(out/'HISTORY129.json');registry=read(out/'REGISTRY.json')
        snap=read(out/(scene+'-LEDGER.json' if scene else 'LEDGER.json'))
        selected=SCENES[:SCENES.index(scene)+1] if scene else SCENES
        expected=[p for p in PLAN if p['scene_id'] in selected]
        units=snap['br6']['units'];calls=snap['calls']
        check('registration digest',registry['sha256']==REGISTRY_SHA==digest({k:v for k,v in registry.items() if k!='sha256'}))
        check('5 scenes 15 recoveries 6 calibrations 206 cap',len(PLAN)==26
              and sum(p['call_cap'] for p in PLAN)==206
              and sum(p['call_cap'] for p in PLAN if p['scene_id']==SCENES[0])==42
              and cfg['total_call_cap']==206 and cfg['first_stage_call_cap']==42)
        check('history 129 digest',h['sha256']==cfg['history129_sha256']==HISTORY129_SHA
              ==digest({k:v for k,v in h.items() if k!='sha256'}))
        old=h['receipts'];old_ids={r['call_id'] for r in old}
        check('all 129 historical IDs and failed hold',len(old)==len(old_ids)==129
              and sum(r['cost_nano'] for r in old)==30_073_000
              and sum(r['hold_nano'] for r in old)==500_000_000
              and h['historical_held_nano']==3_252_000 and h['holds_released_nano']==0)
        check('old and new IDs disjoint',not old_ids.intersection(c['call_id'] for c in calls))
        check('new calls exactly once',len(calls)==len({c['call_id'] for c in calls})<=206)
        check('only registered selected units',len(units)==len(expected)
              and [u['unit_id'] for u in units]==[p['unit_id'] for p in expected]
              and all(u['state']=='finished' for u in units))
        check('fixed 120 second deadlines',all(abs(u['deadline']-u['started']-120)<1e-6 for u in units))
        counts=Counter(c['run_id'] for c in calls);roles=Counter((c['run_id'],c['step_id']) for c in calls)
        check('206 and 42 call limits',sum(counts.values())<=206
              and sum(v for k,v in counts.items() if k.startswith(SCENES[0]+'.'))<=42
              and all(k in UNIT_MAP and v<=UNIT_MAP[k]['call_cap'] for k,v in counts.items())
              and all(v<=5 for v in roles.values()))
        check('matching HTTP scope and settled usage',all(c['simulated'] is fixture_only and c['status']=='settled'
              and c['evidence']['wire_audit']['fixture_only'] is fixture_only for c in calls))
        if scene is None:
            result=read(out/'RESULTS.json')
            check('final result scope and actual resource use',result['fixture_only'] is True
                  and result['failure'] is None and result['all_26_units_finished'] is True
                  and all(result[k]==0 for k in ('real_api_requests','actual_training','actual_prediction',
                      'cloud_starts','actual_new_api_cost_nano','automatic_retries','old_holds_released_nano'))
                  and result['scientific_recovery_benefit_measured'] is False)
            check('result rows match durable unit receipts',result['rows']==[json.loads(u['receipt']) for u in units]
                  and result['total_fake_http_dispatches']==len(calls)
                  and len(result['calibrations'])==6)
        known=sum(c['usage']['prompt_tokens']*150+c['usage']['completion_tokens']*500 for c in calls)
        held=sum(c['held_cost_nano_usd'] for c in calls)+sum(r['extra_held_nano'] for r in snap['bank_budget']['risks'])
        held+=snap['bank_budget']['billing_pending_hold_nano']
        b,u,sub=snap['bank_budget'],snap['unified_budget'],snap['br6_budget']
        check('new subcap accounting',known==sub['known_nano'] and held==sub['held_nano']
              and sub['occupied_nano']==known+held<=1_000_000_000)
        check('same monetary batch retained',b['total_nano']==526_283_450+known+held<=2_000_000_000)
        check('pilot liability retained',u['pilot_total_nano']==530_073_000+known+held<=3_000_000_000)
        check('project liability retained',u['project_total_nano']==713_011_100+known+held<=20_000_000_000
              and u['project_accounted_dispatches']==2607+len(calls))
        check('all old holds retained',u['project_held_nano']==503_252_000+held
              and u['historical_held_nano']==3_252_000)
        with ro(out/'authority.sqlite') as db:
            stored=json.loads(db.execute('SELECT body FROM br6_history WHERE singleton=1').fetchone()[0])
            check('durable history exactly matches',stored==h)
            current=[json.loads(r[0]) for r in db.execute('SELECT body FROM p3_calls')]
            check('snapshot dispatches are durable',all(c in current for c in calls))
            db.row_factory=sqlite3.Row
            persisted=[dict(r) for r in db.execute('SELECT * FROM bf_units ORDER BY rowid')
                       if r['unit_id'].split('.')[0] in selected]
            check('finished units and deadlines are durable',persisted==units)
            gates={s:json.loads(body) for s,body in db.execute('SELECT scene_id,body FROM br6_gates')}
        for s in selected:
            frozen=read(out/'frozen'/s/'MANIFEST.json');cp=read(out/'frozen'/s/'CHECKPOINT.json')
            check('freeze digest '+s,frozen['freeze_sha256']==digest({k:v for k,v in frozen.items() if k!='freeze_sha256'})
                  and frozen['registry_sha256']==REGISTRY_SHA and frozen['checkpoint_sha256']==digest(cp)
                  and all(pin(out/'frozen'/s/name)==hsh for name,hsh in frozen['files'].items()))
            check('same r6 environment '+s,cp['environment_sha256']==digest(read(out/'ENVIRONMENT.json'))
                  and cp['mode']=='SCOPED' and cp['fault']=='F_INCIDENTAL')
            for method in ('FULL','CONSERVATIVE','CUTOFF'):
                uid=s+'.'+method;trace=read(out/'runs'/uid/'RECOVERY_RESULT.json')
                verdict=audit_run(trace)
                check('independent trace '+uid,verdict['passed'])
                check('common freeze '+uid,trace['recovery']['freeze_sha256']==frozen['freeze_sha256'])
                check('external update preserved '+uid,trace['recovery']['source_update_preserved'] is True)
                check('explicit scope and outcome '+uid,trace['fixture_only'] is fixture_only
                      and (not fixture_only or trace['actual_training']==0) and trace['final']['outcome'] in
                      ('correct_complete','safe_stop','wrong_complete','infrastructure_failure','external_unresolved'))
                check('single recheck '+uid,len(trace['decisions'])==1 and trace['decisions'][0]['rechecks']==1)
            uid=s+'.CUTOFF';zero=zero_training_acceptance(out,uid,fixture_only=fixture_only)
            check('independent zero-training/fallback '+uid,zero['passed']
                  and read(out/'runs'/uid/'ZERO_TRAIN_ACCEPTANCE.json')==zero)
            for kind in ('CAL_RAW','CAL_CORRECTED'):
                unit=s+'.'+kind
                if unit not in UNIT_MAP:continue
                cal=read(out/(unit+'.json'))
                parent=s+('.PREFIX' if kind=='CAL_RAW' else '.CUTOFF')
                source_file=out/'runs'/parent/('RUN_STATE.json' if kind=='CAL_RAW' else 'RECOVERY_RESULT.json')
                source=next(c for c in read(source_file)['llm_calls'] if c['call_id']==cal['original_call_id'])
                actual=next(c for c in calls if c['call_id']==cal['call_id'])
                source_body=canonical_json(source['wire_audit']['request']).encode()
                actual_body=canonical_json(actual['request']).encode()
                check('exact calibration wire '+unit,source_body==actual_body
                      and cal['source_wire_sha256']==cal['repeated_wire_sha256']==hashlib.sha256(source_body).hexdigest()
                      and cal['original_context_sha256']==source['prompt_sha256']
                      and actual['sidecar']['original_messages']==source['prompt_messages'])
                check('calibration cannot change main results '+unit,cal['analysis_only'] is True
                      and cal['affects_recovery'] is False and cal['new_calls']==1 and pin(source_file)==cal['main_evidence_sha256']
                      and cal['equivalent']==(contract_digest(source['payload']['final'])
                      ==contract_digest(cal['repeated_payload']['final'])))
            if s != scene:  # Current scene's gate is committed only after this audit.
                saved=read(out/(s+'-INDEPENDENT_AUDIT.json'))
                check('prior scene gate '+s,saved['passed'] and s in gates and digest(saved)==gates[s]['audit_sha256'])
    except Exception as error:
        check('malformed saved evidence: '+type(error).__name__,False)
    return dict(schema_version='bank-br6-independent-audit-v1',scene_id=scene,
        passed=all(c['passed'] for c in checks),checks=len(checks),
        failed=[c for c in checks if not c['passed']],all_checks=checks,
        fixture_only=fixture_only,actual_training=0,actual_prediction=0,real_api_requests=0,
        authority_opened_read_only=True,scientific_recovery_benefit_measured=False)
