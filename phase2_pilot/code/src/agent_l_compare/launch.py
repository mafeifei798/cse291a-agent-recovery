from contextlib import ExitStack
from dataclasses import asdict
from pathlib import Path
import json
import socket
import sys
from unittest.mock import patch

from agent_l_api.acceptance import SyntheticCounter
from agent_l_api.model import bound_counter
from agent_l_replay_live.gateway import Gateway
from agent_l_replay_live.evidence import verify_saved_source
from agent_l_batch.billing import Billing
from agent_l_v3.timing import Timing
from agent_l_v1.core import DATA,PERMISSION,PUBLICATION
from agent_l_approval_confirm.runner import NoEstimators
from agent_recovery.p3_transport import FakeHTTPSender
from agent_recovery.contracts import require,canonical_json
from .protocol import Config,UNITS,METHODS,history
from .budget import Budget
from .runtime import Model
from .fixtures import CPU,Service,Spend
from .recovery import recover

CASES=('equivalent','changed_contract','initial_changed','typed_stop','saved_real_stop','legacy_adjust',
       'wrong_approval','second_adjustment','source_version_changed','permission_revoked','external_publication')


def write(p,v):
    with Path(p).open('x') as f:json.dump(v,f,indent=2,sort_keys=True);f.write('\n')


def launch(output,*,source_root,config=None,case='equivalent',post_responses=None,metadata_responses=None,clock=None,
           local_counter=None,live=False):
    require(live is False,'This batch has no live/key/training permission','CMP_OFFLINE_ONLY')
    c=config or Config();require(type(c) is Config and case in CASES,'Exact offline config/case','CMP_CONFIG')
    output,source=Path(output).resolve(),Path(source_root).resolve()
    require(not output.exists(),'Never overwrite/reopen output','CMP_OUTPUT')
    h=history(source);frozen,campaign=verify_saved_source(source)
    require(frozen['remaining_seconds']==192.470543,'Fixed freeze budget','CMP_FREEZE')
    output.mkdir(parents=True)
    ledger=Budget(output/'authority.sqlite',config=c,historical=h,clock=clock)
    local=local_counter or SyntheticCounter();counter,stats=bound_counter(local,simulated=True)
    spend=Spend(h);getter=FakeHTTPSender(metadata_responses if metadata_responses is not None else [spend.get]*4)
    billing=Billing(ledger,fake_sender=getter);timing=Timing();error=None;active=None
    rows={m:{'method':m,'unit':UNITS[m],'state':'not_started','calls':0,'simulated_fits':0,'admissions':0} for m in METHODS}
    guard=NoEstimators();sys.meta_path.insert(0,guard)
    def mutate(store):
        key=DATA if case=='source_version_changed' else PERMISSION
        old=store.read(key)
        content=old['content'] if key==DATA else canonical_json({'publish_allowed':False})
        store.write(key,content,{k:old[k] for k in store.REF_FIELDS},'external-update')
    def external(store):
        old=store.read(PUBLICATION)
        store.write(PUBLICATION,canonical_json({'owner':'external','retain':True}),
            {k:old[k] for k in store.REF_FIELDS},'external-consumer')
    try:
        with timing.span('whole_comparison_with_accounting'),ExitStack() as stack:
            stack.enter_context(patch.object(socket,'socket',side_effect=AssertionError('CMP_NO_NETWORK')))
            stack.enter_context(patch('agent_l_v1.cpu.ActualCPU.fit',side_effect=AssertionError('CMP_NO_REAL_FIT')))
            try:
                billing.begin()
                for method in c.order:
                    active=None
                    unit=UNITS[method];folder=output/method;folder.mkdir()
                    cpu=CPU(campaign,source,forbid_fake_fit=False)
                    service=Service(local,frozen,source,case,unit,spend)
                    post=FakeHTTPSender(post_responses if post_responses is not None else [service.post]*10)
                    model=Model(post,token_counter=counter,token_statistics=stats)
                    before=len(ledger.calls())
                    ledger.start_unit(unit,192.470543)
                    active=method
                    with timing.span('branch_'+method):
                        result=recover(campaign/'runs/LI01.PREFIX',frozen,folder/'run',method,cpu,ledger,
                            Gateway(model,ledger,billing),timing,
                            mutate=mutate if case in ('source_version_changed','permission_revoked') else None,
                            before_publish=external if case=='external_publication' else None)
                    rows[method].update(state=result['outcome'],calls=len(ledger.calls())-before,
                        simulated_fits=cpu.fit_count,admissions=cpu.admissions,
                        equivalent_contracts=result['recovery']['equivalent_contracts'],
                        comparison_performed=result['recovery']['comparison_performed'],
                        route=result['recovery'].get('route'),error=result['recovery'].get('error'))
                    write(folder/'ADMISSIONS.json',cpu.admission_evidence)
                    write(folder/'RESPONSE_SOURCES.json',service.audit)
                    write(folder/'FIT_TASKS.json',{'simulated_fit_tasks':cpu.fit_count,'actual_fits':0})
                    if result['outcome']=='completed_execution':
                        ledger.finish_unit(unit);active=None
                    else:
                        error=result['recovery'].get('error',{'code':'CMP_REVIEW_STOP'})
                        ledger.quarantine(None,error['code']);break
            except Exception as exc:
                error={'code':getattr(exc,'code',type(exc).__name__),'message':str(exc)}
                if active is not None and rows[active]['state']=='not_started':
                    rows[active].update(state='failed_before_result',error=error,calls=len(ledger.calls())-before,
                        simulated_fits=cpu.fit_count,admissions=cpu.admissions)
                if ledger.batch_state()=='running':ledger.quarantine(None,error['code'])
            finally:
                if ledger.batch_state()=='running':billing.finish()
                elif ledger.batch_state()=='initial':ledger.batch_transition('preflight_failed',{'error':error})
        summary={'revision':'l-compare-offline-v1','case':case,'rows':[rows[m] for m in METHODS],
            'order':c.order,'error':error,'accounting_status':ledger.batch_state(),
            'new_fake_generations':len(ledger.calls()),'new_fake_GETs':getter.request_count,
            'historical_real_calls':364,'sealed_first_used':62,'sealed_first_cap':64,
            'real_API_calls':0,'real_key_reads':0,'real_fits':0,'model_loads':0,'predict_calls':0,'cloud_starts':0,
            'old_results_unchanged':True,'automatic_continuation':False,
            'batch_ready':all(r['state']=='completed_execution' for r in rows.values()) and ledger.batch_state()=='aggregate_reconciled',
            'scope':'Offline control-flow verification; simulated fits/metrics and usage are not real measurements'}
        write(output/'SUMMARY.json',summary);write(output/'LEDGER.json',ledger.snapshot())
        write(output/'BATCH_ACCOUNTING.json',billing.snapshot());write(output/'CONFIG.json',asdict(c))
        write(output/'TIMING.json',timing.document())
        return summary
    finally:ledger.close();sys.meta_path.remove(guard)
