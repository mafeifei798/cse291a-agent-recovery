"""Read-only first-grant/worker audit; no budget/recovery/model execution."""
from pathlib import Path
from agent_recovery.contracts import digest
from .bank_br6_checker import audit_br6,ro,read
from .bank_br6_first import FIRST_IDS,GRANT,GRANT_SHA


def audit_first(output,*,fixture_only=True):
    out=Path(output);base=audit_br6(out,scene='BR6-01',fixture_only=fixture_only)
    checks=list(base['all_checks'])
    def check(name,passed):checks.append(dict(name=name,passed=bool(passed)))
    try:
        config=read(out/'CONFIG.json');grant=read(out/'FIRST_GRANT.json');snap=read(out/'BR6-01-LEDGER.json')
        check('separate immutable first-only grant',grant=={**GRANT,'sha256':GRANT_SHA}
              and config['first_grant_sha256']==GRANT_SHA)
        check('all new calls and units inside first grant',len(snap['calls'])<=42
              and [u['unit_id'] for u in snap['br6']['units']]==list(FIRST_IDS)
              and all(c['run_id'] in FIRST_IDS for c in snap['calls']))
        check('new source pin digest',digest(read(out/'SOURCE_PINS.json'))==config['controller_sources_sha256'])
        policy=digest(dict(grant=GRANT,config_sha256=digest(config)))
        with ro(out/'authority.sqlite') as db:
            check('durable grant binds exact launch',db.execute('SELECT body FROM br6_first_grant').fetchall()==[(policy,)])
        for method in ('FULL','CONSERVATIVE','CUTOFF'):
            unit='BR6-01.'+method;trace=read(out/'runs'/unit/'RECOVERY_RESULT.json')
            report=read(out/(unit+'-BILLING.json'))
            check('billing closed before advancing '+unit,report.get('reconciled') is True)
            if fixture_only:continue
            worker=read(out/'cpu'/unit/'NUMERIC_EXECUTION.json');value=worker.get('response') or {}
            guard=value.get('fit_guard',{})
            check('common numeric worker no-fit proof '+unit,value==trace.get('numeric_check')
                and value.get('passed') is True and value.get('business_correct') is True
                and value.get('model_fits')==0 and value.get('model_loads')==1
                and value.get('model_predictions')==2 and guard.get('installed') is True
                and bool(guard.get('protected_methods')) and guard.get('rejected_calls')==[]
                and worker['execution'].get('worker_reaped') is True
                and not worker['execution'].get('remaining_processes'))
    except Exception as error:
        check('malformed first-only evidence: '+type(error).__name__,False)
    return dict(schema_version='bank-br6-first-independent-audit-v1',scene_id='BR6-01',
        passed=all(c['passed'] for c in checks),checks=len(checks),all_checks=checks,
        failed=[c for c in checks if not c['passed']],fixture_only=fixture_only,
        actual_training=0,actual_prediction=0,real_api_requests=0,authority_opened_read_only=True,
        scientific_recovery_benefit_measured=False,next_scene_authorized=False)
