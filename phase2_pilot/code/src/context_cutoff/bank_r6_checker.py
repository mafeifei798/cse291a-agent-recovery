"""Independent read-only checks for r6 inheritance, stops and saved traces.

No continuation engine, budget implementation or model client is imported.
"""
from collections import Counter
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
from urllib.parse import quote

from .checker import audit_run


def audit_resume(output,progress_scene=None):
    checks=[]
    def check(name,condition):checks.append(dict(name=name,passed=bool(condition)))
    def read(path):return json.loads(Path(path).read_text())
    def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),
        ensure_ascii=False,allow_nan=False).encode()).hexdigest()
    try:
        out=Path(output);result=read(out/(progress_scene+'-PROGRESS.json' if progress_scene else 'RESULTS.json'));h=read(out/'HISTORY39.json')
        ledger=read(out/(progress_scene+'-LEDGER.json' if progress_scene else 'LEDGER.json'));plan=read(out/'REMAINING_PLAN.json')
        config=read(out/'CONFIG.json')
        cap_by_revision={'bank-budget-20261024-r2':1_000_000_000,'bank-budget-20261024-r3':2_000_000_000}
        cap=cap_by_revision[config['budget_revision']]
        check('budget revision and cap bound',config['batch_cap_nano']==cap)
        if cap==2_000_000_000:
            amendment=read(out/'BUDGET_AMENDMENT.json')
            check('explicit amendment without history rewrite',amendment['original_batch_cap_nano']==1_000_000_000
                  and amendment['amended_batch_cap_nano']==cap and amendment['holds_released_nano']==0
                  and amendment['history39_sha256']==h['sha256']
                  and amendment['historical_registration_unmodified'] is True)
        check('pinned 39-call handoff',h['sha256']==digest({k:v for k,v in h.items() if k!='sha256'})
              =='1bf2ac8b0850639fdccb05bdc32a8e09f44f1a58a697c8f0f36205ffa6296271')
        old=h['receipts'];calls=ledger['calls'];old_ids={r['call_id'] for r in old}
        check('all 39 old IDs distinct',len(old)==len(old_ids)==39)
        check('no inherited dispatch repeated',not old_ids.intersection(c['call_id'] for c in calls))
        check('new calls exactly once',len(calls)==len({c['call_id'] for c in calls})==result['physical_http_dispatches']<=141)
        check('old observed error not double charged',sum(r['cost_nano'] for r in old)==7_443_600
              and sum(r['observed_cost_nano'] for r in old)==7_623_500
              and sum(r['hold_nano'] for r in old)==500_000_000 and h['holds_released_nano']==0)
        known=sum(c['known_cost_nano_usd'] for c in calls)
        held=sum(c['held_cost_nano_usd'] for c in calls)+sum(r['extra_held_nano'] for r in ledger['bank_budget']['risks'])
        held+=ledger['bank_budget'].get('billing_pending_hold_nano',0)
        b,u=ledger['bank_budget'],ledger['unified_budget']
        check('same batch money inherited',b['total_nano']==503_654_050+known+held)
        check('pilot known and held inherited',u['pilot_known_nano']==7_443_600+known
              and u['pilot_held_nano']==500_000_000+held)
        check('project known and held inherited',u['project_known_nano']==187_129_700+known
              and u['project_held_nano']==503_252_000+held)
        check('all 2517 previous project dispatches retained',u['project_accounted_dispatches']==2517+len(calls))
        check('caps match explicit revision',b['batch_cap_nano']==cap
              and u['pilot_cap_nano']==3_000_000_000 and u['project_cap_nano']==20_000_000_000)
        check('historical unknown hold retained',u['historical_held_nano']==3_252_000)
        check('money remains within caps',b['total_nano']<=cap and u['pilot_total_nano']<=3_000_000_000
              and u['project_total_nano']<=20_000_000_000)
        with closing(sqlite3.connect('file:'+quote(str((out/'authority.sqlite').resolve()),safe='/')+'?mode=ro',uri=True)) as db:
            row=db.execute('SELECT body FROM bf_r6_history WHERE singleton=1').fetchone()
            check('durable full handoff',json.loads(row[0])==h)
            units=db.execute('SELECT unit_id,state,started,deadline FROM bf_units').fetchall()
        check('fresh attempts have fixed deadlines',all(abs(r[3]-r[2]-120)<1e-6 for r in units))
        check('old deadlines untouched',ledger['continuation']['history39']['original_units']==h['original_units'])
        old_finished={r['unit_id'] for r in h['original_units'] if r['state']=='finished'}
        check('finished units not rerun',not old_finished.intersection(r[0] for r in units))
        check('remaining plan excludes old completion',len(plan['units'])==13
              and not old_finished.intersection(r['unit_id'] for r in plan['units']))
        counts=Counter(r['run_id'] for r in old if r['source']=='fault-21')+Counter(c['run_id'] for c in calls)
        roles=Counter((r['run_id'],r['step_id']) for r in old if r['source']=='fault-21')
        roles.update((c['run_id'],c['step_id']) for c in calls)
        check('old and new run/role caps',all(v<=(1 if k.endswith('.CAL') else 10) for k,v in counts.items())
              and all(v<=5 for v in roles.values()) and sum(counts.values())<=162)
        if result['failure']:
            check('hard stop persisted',ledger['status']=='quarantined' and result['automatic_retries']==0)
            if result['failure']['error']=='R6_BATCH_MONEY_CAP':
                check('money refusal before transport',not calls and result['physical_http_dispatches']==0
                      and b['remaining_nano']==496_345_950 and b['worstcase_per_call_nano']==500_000_000)
        else:
            branches=[r for r in result['rows'] if r.get('method')]
            selected=['BF02','BF03','BF04']
            if progress_scene:selected=selected[:selected.index(progress_scene)+1]
            skipped=result.get('calibration_skipped',False)
            expected_cal=0 if skipped else 1
            check('only selected unstarted recoveries ran',len(branches)==3*len(selected)
                  and len(result['rows'])==4*len(selected)+expected_cal
                  and all(r['unit_id'].split('.')[0] in selected for r in result['rows']))
            check('no old stop promoted to success',result['old_safe_stop_branches_preserved']==3
                  and result['old_failures_reclassified'] is False)
            check('no extra calibration probe' if skipped else 'cross-revision comparison not self-consistency',
                  len(result['calibrations'])==expected_cal and (skipped or (
                  result['calibrations'][0].get('eligible_for_self_consistency') is False
                  and result['calibrations'][0].get('same_wire_as_original') is False)))
            for row in branches:
                trace=read(out/'runs'/row['unit_id']/'RECOVERY_RESULT.json')
                audited=audit_run(trace)
                check('independent trace '+row['unit_id'],audited['passed'])
                check('source update preserved '+row['unit_id'],trace['recovery']['source_update_preserved'])
                check('explicit result classification '+row['unit_id'],row['outcome'] in
                    ('correct_complete','safe_stop','wrong_complete','infrastructure_failure','external_unresolved'))
            resumed=read(out/'runs/BF02.PREFIX/RUN_STATE.json')
            check('accepted prefix alone replayed',len(resumed['llm_calls'])==7
                  and all(c['call_id']!='BF02.PREFIX.llm.0003' for c in resumed['llm_calls'])
                  and resumed['r6_resume_attempt']['accepted_prior_model_responses']==3
                  and resumed['r6_resume_attempt']['original_deadline_mutated'] is False)
        check('fixture is not scientific evidence',result['scientific_recovery_benefit_measured'] is False)
        if result['fixture_only']:
            check('no real resource use',result['real_api_requests']==result['actual_training']
                  ==result['actual_prediction']==result['cloud_starts']==result['actual_new_api_cost_nano']==0)
    except Exception as error:
        check('malformed saved evidence: '+type(error).__name__,False)
    return dict(schema_version='bank-r6-independent-audit-v1',passed=all(c['passed'] for c in checks),
        checks=len(checks),failed=[c for c in checks if not c['passed']],all_checks=checks,
        authority_opened_read_only=True)
