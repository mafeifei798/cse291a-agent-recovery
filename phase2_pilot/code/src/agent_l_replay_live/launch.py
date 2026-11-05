"""One method per fresh authority. No credential construction before permission."""
from dataclasses import asdict
from decimal import Decimal
from pathlib import Path
import json

from agent_recovery.contracts import require
from agent_recovery.p3_transport import FakeHTTPSender, P3Binding, LiveRuntimePermit
from agent_recovery.p3_deadline import BoundedHTTPSender
from agent_l_api.acceptance import SyntheticCounter
from agent_l_api.budget import FakeClock
from agent_l_api.model import bound_counter
from .gateway import Gateway
from agent_l_batch.billing import Billing
from agent_l_v3.timing import Timing
from agent_l_feedback_replay.runner import ORIGIN_REL
from agent_l_feedback_replay.fixtures import SavedCPU, SavedService
from context_cutoff.token_counter import MultiMessageGLM53TokenCounter
from .protocol import Config, Permit, history, MODEL, source_sha
from .budget import Budget
from .runtime import Model
from .cpu import NativeCPU
from .recovery import recover


def launch(output, *, source_root, config=None, live=False, authorized=False, permit=None,
           acceptance=None, catalog=None, models=None, fixture_counter=False, fixture_mode='saved',
           post_responses=None, metadata_responses=None, clock=None):
    root, source = Path(output).resolve(), Path(source_root).resolve()
    config = config or Config()
    require(not root.exists(), 'Never overwrite/reopen an output', 'FRL_OUTPUT')
    require(type(config) is Config and config.simulated is (not live), 'Wrong entry mode', 'FRL_CONFIG')
    require(not live or (post_responses is None and metadata_responses is None and clock is None
                        and not fixture_counter and fixture_mode == 'saved'),
            'Test hooks cannot authorize live work', 'FRL_TEST_HOOK')
    if live:
        require(authorized and config.output_root == str(root), 'Explicit CPU/output permission required', 'FRL_PERMISSION')
        require(type(permit) is Permit, 'Default-denied real entry', 'FRL_PERMISSION')
        permit.validate_live(config, source, acceptance, catalog, models)
    h = history(source/'phase2/l_feedback_replay_20261031_v2/HISTORY.json', source)
    from .evidence import verify_saved_source
    frozen, saved_campaign = verify_saved_source(source)
    if live:
        origin = json.loads((saved_campaign/'ORIGIN.json').read_text())
        native_saved = Path(origin['campaign_root']).resolve()
        require(native_saved.is_dir(), 'Original native producer directory is required', 'FRL_NATIVE_ORIGIN')
    if fixture_counter:
        require(not live, 'Synthetic counter cannot be used live', 'FRL_COUNTER')
        local = SyntheticCounter()
    else:
        local = MultiMessageGLM53TokenCounter.from_directory(source/'sr_v2/v0/environment/tokenizer_files')
    counter, stats = bound_counter(local, simulated=not live)
    root.mkdir(parents=True)
    ledger = Budget(root/'authority.sqlite', config=config, historical=h, clock=clock or (None if live else FakeClock()))
    billing, result, error, cpu, model, service = None, None, None, None, None, None
    try:
        if live:
            from br7_live.credentials import DataHubCredentialProvider
            provider = DataHubCredentialProvider(str(root/'CREDENTIAL_ACCESS.jsonl'))
            binding = P3Binding(binding_ref='stage-replay-'+config.sha256, model=MODEL, allowed_response_models=(MODEL,),
                simulated=False, real_requests_authorized=True, input_nano_usd_per_token=150,
                output_nano_usd_per_token=500, price_evidence='stage-replay:'+config.catalog_sha256,
                capability_evidence='stage-replay:'+config.acceptance_sha256,
                token_admission_evidence=counter.evidence_ref, reasoning_effort='low', temperature=0,
                output_token_parameter='max_tokens', supported_parameters=('model','messages','n','stream',
                    'response_format','max_tokens','temperature','reasoning_effort'))
            model = Model(BoundedHTTPSender(), token_counter=counter, token_statistics=stats, live_binding=binding,
                runtime_permit=LiveRuntimePermit(True, binding.binding_digest, permit.authorization_reference),
                credential_provider=provider, timeout_s=120)
            billing = Billing(ledger, credential_provider=provider)
            cpu = NativeCPU(root/'campaign', native_saved, authorized=True,
                            training_authorized=config.allow_training and permit.training_authorized)
        else:
            service = SavedService(local, frozen, fixture_mode)
            service.spend = Decimal(h['expected_key_spend_nano'])
            model = Model(FakeHTTPSender(post_responses if post_responses is not None else [service.post]*10),
                          token_counter=counter, token_statistics=stats)
            billing = Billing(ledger, fake_sender=FakeHTTPSender(metadata_responses if metadata_responses is not None else [service.get]*4))
            cpu = SavedCPU(saved_campaign, source, forbid_fake_fit=config.method == 'CUTOFF' and fixture_mode == 'saved')
        billing.begin()
        uid = 'FR02.'+config.method
        ledger.start_unit(uid, min(240., frozen['remaining_seconds']))
        timing = Timing()
        if live:
            cpu.timing = timing
        with timing.span('whole_unit'):
            result = recover(saved_campaign/'runs/LI01.PREFIX', frozen, root/'run', config.method,
                             cpu, ledger, Gateway(model, ledger, billing), timing, native_authorized=live and authorized)
        if result['outcome'] != 'completed_execution':
            error = result['recovery'].get('error', {'code': 'FRL_NOT_COMPLETED'})
            ledger.quarantine(None, error['code'])
        else:
            ledger.finish_unit(uid)
        write(root/'TIMING.json', timing.document())
    except Exception as exc:
        error = {'code': getattr(exc, 'code', type(exc).__name__), 'message': str(exc)}
        try:
            ledger.quarantine(None, error['code'])
        except Exception:
            pass
    finally:
        if billing is not None and ledger.batch_state() == 'running':
            billing.finish()
        elif ledger.batch_state() == 'initial':
            ledger.batch_transition('preflight_failed', {'error': error})
        write(root/'LEDGER.json', ledger.snapshot())
        write(root/'BATCH_ACCOUNTING.json', billing.snapshot() if billing else {'error': error})
        if service is not None:
            write(root/'RESPONSE_SOURCES.json', service.audit)
            write(root/'ADMISSIONS.json', cpu.admission_evidence)
        if result is not None:
            write(root/'SUMMARY.json', {'case': 'saved_adjusted' if fixture_mode == 'saved' else fixture_mode,
                'method': config.method, 'outcome': result['outcome'], 'recovery': result['recovery'],
                'stage_replays': result['stage_replays'], 'simulated_fit_tasks': cpu.fit_count if not live else 0,
                'saved_artifact_admissions': cpu.admissions, 'real_API_calls': 0 if not live else len(ledger.calls()),
                'real_fits': cpu.fit_count if live else 0, 'model_loads': 0, 'predict_calls': 0, 'cloud_starts': 0,
                'actual_recovery_measurement': live})
        if live and cpu is not None:
            write(root/'CPU_RECORDS.json', cpu.records)
        entry = {'revision': 'stage-replay-entry-v1', 'method': config.method,
                 'business_status': result['outcome'] if result else 'stopped', 'error': error,
                 'accounting_status': ledger.batch_state(), 'HTTP_fixture_only': not live,
                 'CPU_fixture_only': not live, 'actual_training_this_entry': cpu.fit_count if live and cpu else 0,
                 'history_real_calls': 350, 'old_holds_released': False, 'automatic_continuation': False,
                 'new_generation_cap': config.new_generation_cap, 'first_total_generation_cap': 64,
                 'next_live_invocation_requires_latest_history': True}
        write(root/'ENTRY_RESULT.json', entry)
        write(root/'CONFIG.json', asdict(config))
        ledger.close()
    return entry


def write(path, value):
    with Path(path).open('x') as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write('\n')
