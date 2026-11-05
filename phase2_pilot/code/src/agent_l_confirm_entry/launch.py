"""A single fresh CUTOFF authority. All permission checks precede credentials."""
from contextlib import ExitStack
from dataclasses import asdict
from decimal import Decimal
from pathlib import Path
import json
import socket
from unittest.mock import patch

from agent_recovery.contracts import require
from agent_recovery.p3_transport import FakeHTTPSender, P3Binding, LiveRuntimePermit
from agent_recovery.p3_deadline import BoundedHTTPSender
from agent_l_api.acceptance import SyntheticCounter
from agent_l_api.budget import FakeClock
from agent_l_api.model import bound_counter
from agent_l_replay_live.gateway import Gateway
from agent_l_replay_live.evidence import verify_saved_source
from agent_l_batch.billing import Billing
from agent_l_v3.timing import Timing
from agent_l_approval_confirm.fixtures import SavedService
from context_cutoff.token_counter import MultiMessageGLM53TokenCounter
from .protocol import Config, Permit, UNIT, MODEL, HISTORY_REL, history
from .budget import Budget
from .runtime import Model
from .cpu import NoFitCPU, NoFitSavedCPU
from .recovery import recover


def write(path,value):
    with Path(path).open('x') as f:
        json.dump(value,f,sort_keys=True,indent=2);f.write('\n')


def launch(output,*,source_root,config=None,live=False,authorized=False,permit=None,
           acceptance=None,catalog=None,models=None,fixture_counter=False,fixture_mode='equivalent',
           post_responses=None,metadata_responses=None,clock=None):
    output,source = Path(output).resolve(),Path(source_root).resolve()
    config = config or Config()
    require(not output.exists(),'Never overwrite or reopen an authority','ACE_OUTPUT')
    require(type(config) is Config and config.simulated is (not live),'Wrong entry mode','ACE_CONFIG')
    require(not live or (post_responses is None and metadata_responses is None and clock is None
            and not fixture_counter and fixture_mode == 'equivalent'),'Fake hooks cannot authorize live work','ACE_TEST_HOOK')
    if live:
        require(authorized and config.output_root == str(output) and type(permit) is Permit,
                'Explicit CPU permission, config and permit required','ACE_PERMISSION')
        permit.validate_live(config,source,acceptance,catalog,models)
    h = history(source/HISTORY_REL,source)
    frozen,campaign = verify_saved_source(source)
    require(frozen['remaining_seconds'] == 192.470543,'Frozen remaining time changed','ACE_FREEZE')
    native_saved = None
    if live:
        native_saved = Path(json.loads((campaign/'ORIGIN.json').read_text())['campaign_root']).resolve()
        require(native_saved.is_dir(),'Original native producer directory required','ACE_NATIVE_ORIGIN')
    local = SyntheticCounter() if fixture_counter else MultiMessageGLM53TokenCounter.from_directory(
        source/'sr_v2/v0/environment/tokenizer_files')
    counter,stats = bound_counter(local,simulated=not live)
    output.mkdir(parents=True)
    ledger = Budget(output/'authority.sqlite',config=config,historical=h,clock=clock or (None if live else FakeClock()))
    timing,result,error,billing,cpu,model,service = Timing(),None,None,None,None,None,None
    try:
        with timing.span('entry_with_accounting'),ExitStack() as stack:
            if live:
                # No provider is constructed until permission, source, history,
                # target and the complete pinned tokenizer have all passed.
                from br7_live.credentials import DataHubCredentialProvider
                provider = DataHubCredentialProvider(str(output/'CREDENTIAL_ACCESS.jsonl'))
                binding = P3Binding(binding_ref='confirm-entry-'+config.sha256,model=MODEL,
                    allowed_response_models=(MODEL,),simulated=False,real_requests_authorized=True,
                    input_nano_usd_per_token=150,output_nano_usd_per_token=500,
                    price_evidence='confirm-entry:'+config.catalog_sha256,
                    capability_evidence='confirm-entry:'+config.acceptance_sha256,
                    token_admission_evidence=counter.evidence_ref,reasoning_effort='low',temperature=0,
                    output_token_parameter='max_tokens',supported_parameters=('model','messages','n','stream',
                        'response_format','max_tokens','temperature','reasoning_effort'))
                model = Model(BoundedHTTPSender(),token_counter=counter,token_statistics=stats,live_binding=binding,
                    runtime_permit=LiveRuntimePermit(True,binding.binding_digest,permit.authorization_reference),
                    credential_provider=provider,timeout_s=120)
                billing = Billing(ledger,credential_provider=provider)
                cpu = NoFitCPU(output/'campaign',native_saved,authorized=True,training_authorized=False)
                cpu.timing = timing
            else:
                stack.enter_context(patch.object(socket,'socket',side_effect=AssertionError('ACE_NETWORK_DISABLED')))
                stack.enter_context(patch('agent_l_v1.cpu.ActualCPU.fit',side_effect=AssertionError('ACE_FIT_DISABLED')))
                service = SavedService(local,frozen,source,fixture_mode)
                service.spend = Decimal(h['expected_key_spend_nano'])
                model = Model(FakeHTTPSender(post_responses if post_responses is not None else [service.post]*10),
                    token_counter=counter,token_statistics=stats)
                billing = Billing(ledger,fake_sender=FakeHTTPSender(
                    metadata_responses if metadata_responses is not None else [service.get]*4))
                cpu = NoFitSavedCPU(campaign,source,forbid_fake_fit=True)
            try:
                billing.begin()
                ledger.start_unit(UNIT,min(240.,frozen['remaining_seconds']))
                with timing.span('recovery'):
                    result = recover(campaign/'runs/LI01.PREFIX',frozen,output/'run','CUTOFF',cpu,
                        ledger,Gateway(model,ledger,billing),timing,native_authorized=live and authorized)
                if result['outcome'] == 'completed_execution':ledger.finish_unit(UNIT)
                else:
                    error = result['recovery'].get('error',{'code':'ACE_STOPPED'})
                    ledger.quarantine(None,error['code'])
            except Exception as exc:
                error = {'code':getattr(exc,'code',type(exc).__name__),'message':str(exc)}
                if ledger.batch_state() == 'running':ledger.quarantine(None,error['code'])
            finally:
                if ledger.batch_state() == 'running':billing.finish()
                elif ledger.batch_state() == 'initial':ledger.batch_transition('preflight_failed',{'error':error})
    except Exception as exc:
        error = {'code':getattr(exc,'code',type(exc).__name__),'message':str(exc)}
        if ledger.batch_state() == 'running':
            ledger.quarantine(None,error['code'])
            if billing is not None:billing.finish()
        elif ledger.batch_state() == 'initial':ledger.batch_transition('preflight_failed',{'error':error})
    finally:
        try:
            snapshot = ledger.snapshot()
            entry = {'revision':'confirm-entry-v1','method':'CUTOFF','unit':UNIT,
                'business_status':result['outcome'] if result else 'stopped_before_recovery','error':error,
                'accounting_status':ledger.batch_state(),'HTTP_fixture_only':not live,'CPU_fixture_only':not live,
                'history_real_calls':356,'inherited_first_generations':54,'new_generation_cap':config.new_generation_cap,
                'first_total_generation_cap':64,'actual_training_this_entry':cpu.fit_count if cpu else 0,
                'normal_adjustment_consumed':1,'normal_adjustment_remaining':0,
                'old_holds_released':False,'automatic_continuation':False,'new_live_permission_granted':False,
                'next_live_invocation_requires_latest_history':True}
            write(output/'ENTRY_RESULT.json',entry)
            write(output/'LEDGER.json',snapshot)
            write(output/'BATCH_ACCOUNTING.json',billing.snapshot() if billing else {'error':error})
            write(output/'TIMING.json',timing.document())
            write(output/'CONFIG.json',asdict(config))
            if service is not None:
                write(output/'RESPONSE_SOURCES.json',service.audit)
                write(output/'ADMISSIONS.json',cpu.admission_evidence)
            if cpu is not None:write(output/'CPU_RECORDS.json',cpu.records)
            if result is not None:
                write(output/'SUMMARY.json',{'revision':'confirm-entry-v1','case':fixture_mode,'method':'CUTOFF',
                    'outcome':result['outcome'],'error':error,'recovery':result['recovery'],
                    'stage_replays':result['stage_replays'],'saved_artifact_admissions':cpu.admissions,
                    'synthetic_HTTP_calls':len(ledger.calls()) if not live else 0,
                    'simulated_fit_tasks':0,'real_API_calls':len(ledger.calls()) if live else 0,
                    'real_fits':cpu.fit_count,'real_key_reads':None if live else 0,
                    'model_loads':sum(r['record']['response'].get('model_loads',0) for r in cpu.records) if live else 0,
                    'predict_calls':sum(r['record']['response'].get('model_predictions',0) for r in cpu.records) if live else 0,
                    'real_history_unchanged':not live,'cloud_starts':0,'actual_recovery_measurement':live})
        finally:ledger.close()
    return entry
