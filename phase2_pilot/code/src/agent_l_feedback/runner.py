"""Four offline cases using the original L loop, gateway and durable accounting."""
from copy import deepcopy
from decimal import Decimal
from pathlib import Path
import json

from agent_recovery.contracts import require
from agent_recovery.p3_transport import FakeHTTPSender
from agent_l_api.acceptance import SyntheticCounter
from agent_l_api.budget import FakeClock
from agent_l_api.gateway import Gateway
from agent_l_api.model import bound_counter
from agent_l_batch.billing import Billing
from agent_l_v1.core import prepare_inputs, save
from agent_l_v3.timing import Timing
from context_cutoff.store import FileProvenanceStore
from .budget import Budget
from .fixtures import ScenarioCPU, Service
from .model import Model
from .protocol import Config, history
from .runtime import FeedbackLoop


def run_case(output, source, inputs, mode, *, initial=None, feature_cap=11, saved_replay=False):
    root, source = Path(output).resolve(), Path(source).resolve()
    require(not root.exists(), 'Use a fresh offline case directory', 'LF_OUTPUT')
    h = history(source/'phase2/l_feedback_20261031_v1/HISTORY.json', source)
    root.mkdir(parents=True)
    ledger = Budget(root/'authority.sqlite', config=Config(), historical=h, clock=FakeClock())
    local = SyntheticCounter()
    saved = None
    document = None
    if saved_replay:
        origin = source/'outputs/l_resume_real_20261031_r1/raw/real/campaign/runs/LC02'
        document = json.loads((origin/'RESULT.json').read_text())
        saved = deepcopy(document['llm_calls'][-1]['raw'])
        with FileProvenanceStore(origin/'store.sqlite', origin/'artifacts') as store:
            store.save_to(root/'run')
    service = Service(local, mode, initial, saved)
    service.spend = Decimal(h['expected_key_spend_nano'])
    sender = FakeHTTPSender([service.post]*10)
    counter, stats = bound_counter(local, simulated=True)
    model = Model(sender, token_counter=counter, token_statistics=stats)
    billing = Billing(ledger, fake_sender=FakeHTTPSender([service.get]*4))
    gateway = Gateway(model, ledger, billing)
    cpu, timing = ScenarioCPU(mode), Timing()
    engine = None
    result = None
    failure = None
    try:
        billing.begin()
        ledger.start_unit('FBC01')
        with timing.span('whole_unit'):
            engine = FeedbackLoop(root/'run', 'FBC01', cpu, ledger, gateway=gateway, unit='FBC01',
                                  timing=timing, document=document)
            try:
                if saved_replay:
                    engine.review(engine.doc['active']['contract'], engine.doc['active']['screen'])
                    raise AssertionError('Saved invalid adjustment was accepted')
                engine.initialize(inputs, feature_cap)
                accepted = engine.run()
                if accepted:
                    engine.publish()
                result = engine.export('completed_execution' if accepted else 'review_stop')
                ledger.finish_unit('FBC01')
            except Exception as exc:
                failure = {'code': getattr(exc, 'code', type(exc).__name__), 'message': str(exc)}
                ledger.quarantine(None, failure['code'])
                result = engine.export('failed_execution', error=failure)
            finally:
                engine.close()
    finally:
        if ledger.batch_state() == 'running':
            billing.finish()
        save(root/'LEDGER.json', ledger.snapshot())
        save(root/'BATCH_ACCOUNTING.json', billing.snapshot())
        ledger.close()
    summary = {'mode': mode, 'saved_response_replay_only': saved_replay,
               'outcome': result['outcome'], 'error': failure, 'synthetic_generations': sender.request_count,
               'synthetic_fit_tasks': cpu.fit_count, 'optimization_spent': result['optimization_spent'],
               'published': 'publication' in result['active'], 'CPU_fixture_only': True,
               'HTTP_fixture_only': True, 'real_API_calls': 0, 'real_fits': 0, 'model_loads': 0,
               'history_attempts': 314, 'workflow_result': 'run/RESULT.json'}
    save(root/'SUMMARY.json', summary)
    save(root/'TIMING.json', timing.document())
    return summary


def run_suite(output, source):
    root, source = Path(output).resolve(), Path(source).resolve()
    require(not root.exists(), 'Output already exists', 'LF_OUTPUT')
    root.mkdir(parents=True)
    inputs = prepare_inputs(source, root/'inputs')
    cases = {}
    for name, mode, replay in [('accept', 'accept', False), ('adjust_accept', 'adjust_accept', False),
                               ('adjust_stop', 'adjust_stop', False), ('saved_rejection', 'reviewer_repeat', True)]:
        cases[name] = run_case(root/name, source, inputs, mode, saved_replay=replay)
    result = {'revision': 'l-feedback-offline-v1', 'cases': cases,
              'history_attempts': 314, 'synthetic_not_real_results': True,
              'real_API_calls': 0, 'real_fits': 0, 'model_loads': 0, 'cloud_starts': 0}
    save(root/'SUMMARY.json', result)
    return result
