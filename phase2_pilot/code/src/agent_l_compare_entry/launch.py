"""One new authority, three methods. No credentials before all permission checks."""
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
from agent_l_compare.fixtures import CPU,Service,Spend
from agent_l_compare.launch import CASES
from agent_recovery.p3_transport import FakeHTTPSender,P3Binding,LiveRuntimePermit
from agent_recovery.p3_deadline import BoundedHTTPSender
from agent_recovery.contracts import require,canonical_json
from context_cutoff.token_counter import MultiMessageGLM53TokenCounter
from .protocol import Config,Permit,UNITS,METHODS,history,SECONDS,MODEL
from .budget import Budget
from .runtime import Model
from .cpu import NativeCPU,verify_native_origin
from .recovery import recover


def write(p,v):
    with Path(p).open('x') as f:json.dump(v,f,indent=2,sort_keys=True,allow_nan=False);f.write('\n')


def launch(output,*,source_root,config=None,live=False,authorized=False,permit=None,
           acceptance=None,catalog=None,models=None,fixture_counter=False,case='equivalent',
           post_responses=None,metadata_responses=None,clock=None):
    c=config or Config();output,source=Path(output).resolve(),Path(source_root).resolve()
    require(type(c) is Config and c.simulated is (not live) and case in CASES,'Wrong entry mode','CMPE_CONFIG')
    require(not output.exists(),'Never reopen or overwrite output','CMPE_OUTPUT')
    require(not live or (post_responses is None and metadata_responses is None and clock is None
        and fixture_counter is False and case=='equivalent'),'No fake hooks in live mode','CMPE_TEST_HOOK')
    if live:
        require(authorized is True and type(permit) is Permit and c.output_root==str(output),
            'Fresh complete authorization required','CMPE_PERMISSION')
        permit.validate_live(c,source,acceptance,catalog,models)
    h=history(source);frozen,campaign=verify_saved_source(source)
    require(frozen['remaining_seconds']==SECONDS,'Frozen deadline changed','CMPE_FREEZE')
    native_saved=verify_native_origin(campaign,frozen) if live else None
    local=SyntheticCounter() if fixture_counter else MultiMessageGLM53TokenCounter.from_directory(
        source/'sr_v2/v0/environment/tokenizer_files')
    counter,stats=bound_counter(local,simulated=not live)
    output.mkdir(parents=True)
    ledger=Budget(output/'authority.sqlite',config=c,historical=h,clock=clock)
    timing=Timing();error=None;active=None;billing=None;getter=None;guard=None;provider=None
    rows={m:{'method':m,'unit':UNITS[m],'state':'not_started','calls':0,
        'simulated_fits':0,'real_fits':0,'admissions':0} for m in METHODS}
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
            if live:
                from br7_live.credentials import DataHubCredentialProvider
                provider=DataHubCredentialProvider(str(output/'CREDENTIAL_ACCESS.jsonl'))
                binding=P3Binding(binding_ref='compare-entry-'+c.sha256,model=MODEL,
                    allowed_response_models=(MODEL,),simulated=False,real_requests_authorized=True,
                    input_nano_usd_per_token=150,output_nano_usd_per_token=500,
                    price_evidence='compare-entry:'+c.catalog_sha256,
                    capability_evidence='compare-entry:'+c.acceptance_sha256,
                    token_admission_evidence=counter.evidence_ref,reasoning_effort='low',temperature=0,
                    output_token_parameter='max_tokens',supported_parameters=('model','messages','n','stream',
                        'response_format','max_tokens','temperature','reasoning_effort'))
                model=Model(BoundedHTTPSender(),token_counter=counter,token_statistics=stats,live_binding=binding,
                    runtime_permit=LiveRuntimePermit(True,binding.binding_digest,permit.authorization_reference),
                    credential_provider=provider,timeout_s=120)
                billing=Billing(ledger,credential_provider=provider)
            else:
                stack.enter_context(patch.object(socket,'socket',side_effect=AssertionError('CMPE_NO_NETWORK')))
                stack.enter_context(patch('agent_l_v1.cpu.ActualCPU.fit',side_effect=AssertionError('CMPE_NO_FIT')))
                guard=NoEstimators();sys.meta_path.insert(0,guard)
                stack.callback(lambda:sys.meta_path.remove(guard))
                spend=Spend(h)
                getter=FakeHTTPSender(metadata_responses if metadata_responses is not None else [spend.get]*4)
                billing=Billing(ledger,fake_sender=getter)
            try:
                billing.begin()
                for method in c.order:
                    active=None;unit=UNITS[method];folder=output/method;folder.mkdir()
                    service=None
                    if live:
                        cpu=NativeCPU(folder/'campaign',native_saved,authorized=True,training_authorized=True)
                        cpu.timing=timing
                    else:
                        cpu=CPU(campaign,source,forbid_fake_fit=False)
                        service=Service(local,frozen,source,case,unit,spend)
                        post=FakeHTTPSender(post_responses if post_responses is not None else [service.post]*10)
                        model=Model(post,token_counter=counter,token_statistics=stats)
                    before=len(ledger.calls());ledger.start_unit(unit,SECONDS);active=method
                    with timing.span('branch_'+method):
                        result=recover(campaign/'runs/LI01.PREFIX',frozen,folder/'run',method,cpu,ledger,
                            Gateway(model,ledger,billing),timing,native_authorized=live,
                            mutate=mutate if case in ('source_version_changed','permission_revoked') else None,
                            before_publish=external if case=='external_publication' else None)
                    rows[method].update(state=result['outcome'],calls=len(ledger.calls())-before,
                        simulated_fits=0 if live else cpu.fit_count,real_fits=cpu.fit_count if live else 0,
                        admissions=cpu.admissions,equivalent_contracts=result['recovery']['equivalent_contracts'],
                        comparison_performed=result['recovery']['comparison_performed'],route=result['recovery'].get('route'),
                        error=result['recovery'].get('error'))
                    write(folder/'ADMISSIONS.json',cpu.admission_evidence)
                    write(folder/'CPU_RECORDS.json',cpu.records)
                    if service:write(folder/'RESPONSE_SOURCES.json',service.audit)
                    write(folder/'FIT_TASKS.json',{'simulated_fit_tasks':0 if live else cpu.fit_count,
                        'actual_fits':cpu.fit_count if live else 0})
                    if result['outcome']=='completed_execution':ledger.finish_unit(unit);active=None
                    else:
                        error=result['recovery'].get('error',{'code':'CMPE_REVIEW_STOP'})
                        ledger.quarantine(None,error['code']);break
            except Exception as exc:
                error={'code':getattr(exc,'code',type(exc).__name__),'message':str(exc)}
                if active is not None and rows[active]['state']=='not_started':
                    rows[active].update(state='failed_before_result',error=error,calls=len(ledger.calls())-before,
                        simulated_fits=0 if live else cpu.fit_count,real_fits=cpu.fit_count if live else 0,
                        admissions=cpu.admissions)
                    write(output/active/'CPU_RECORDS.json',cpu.records)
                if ledger.batch_state()=='running':ledger.quarantine(None,error['code'])
            finally:
                if ledger.batch_state()=='running':billing.finish()
                elif ledger.batch_state()=='initial':ledger.batch_transition('preflight_failed',{'error':error})
    except Exception as exc:
        error={'code':getattr(exc,'code',type(exc).__name__),'message':str(exc)}
        if ledger.batch_state()=='initial':ledger.batch_transition('preflight_failed',{'error':error})
        elif ledger.batch_state()=='running':
            ledger.quarantine(None,error['code'])
            if billing:billing.finish()
    finally:
        try:
            snapshot=ledger.snapshot()
            summary={'revision':'l-compare-entry-v1','case':case,'rows':[rows[m] for m in METHODS],
                'order':c.order,'error':error,'accounting_status':ledger.batch_state(),
                'new_fake_generations':0 if live else len(ledger.calls()),
                'new_fake_GETs':getter.request_count if getter else 0,
                'historical_real_calls':364,'sealed_first_used':62,'sealed_first_cap':64,
                'real_API_calls':len(ledger.calls()) if live else 0,'real_key_reads':None if live else 0,
                'real_fits':sum(r['real_fits'] for r in rows.values()),
                'cloud_starts':0,'old_results_unchanged':True,'automatic_continuation':False,
                'batch_ready':all(r['state']=='completed_execution' for r in rows.values())
                    and ledger.batch_state()=='aggregate_reconciled',
                'scope':'Actual comparison' if live else 'Offline control flow; simulated CPU and usage, not performance results'}
            if not live:summary.update(model_loads=0,predict_calls=0)
            write(output/'SUMMARY.json',summary);write(output/'LEDGER.json',snapshot)
            write(output/'BATCH_ACCOUNTING.json',billing.snapshot() if billing else {'error':error})
            write(output/'CONFIG.json',asdict(c));write(output/'TIMING.json',timing.document())
        finally:ledger.close()
    return summary
