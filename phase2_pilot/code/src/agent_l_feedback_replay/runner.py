"""Bounded saved-response integration; no live clients, training or cloud use."""
from copy import deepcopy
from decimal import Decimal
import importlib.abc
import json
from pathlib import Path
import socket
import sys
import hashlib
import zipfile
from unittest.mock import patch

from agent_l_api.acceptance import SyntheticCounter
from agent_l_api.budget import FakeClock
from agent_l_api.gateway import Gateway
from agent_l_api.model import bound_counter
from agent_l_batch.billing import Billing
from agent_recovery.p3_transport import FakeHTTPSender
from agent_recovery.contracts import require
from agent_l_v1.core import DATA, PUBLICATION, PERMISSION, save
from agent_l_v3.timing import Timing
from sr_recovery_v2.common import canonical
from .budget import Budget
from .protocol import Config, history
from .fixtures import SavedCPU, SavedService
from .recovery import recover
from .runtime import Model

ORIGIN_REL = 'outputs/l_feedback_real_20261031_r3/evidence/real/campaign'
CASES = ('saved_adjusted', 'zero_fit_guard', 'changed_contract', 'data_version_changed',
         'external_publication', 'permission_revoked', 'revalidation_stop', 'second_adjustment',
         'substitute_approval', 'initial_changed')


class NoEstimators(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in ('sklearn', 'joblib'):
            raise RuntimeError('FR_ESTIMATOR_IMPORT_FORBIDDEN')


def run_branch(output, source, case, method):
    output, source = Path(output).resolve(), Path(source).resolve()
    require(case in CASES and not output.exists(), 'Invalid offline case/output', 'FR_CASE')
    output.mkdir(parents=True)
    h = history(source/'phase2/l_feedback_replay_20261031_v2/HISTORY.json', source)
    campaign = source/ORIGIN_REL
    prefix = campaign/'runs/LI01.PREFIX'
    with zipfile.ZipFile(source/'outputs/l_feedback_real_20261031_r3/feedback-evidence.zip') as z:
        manifest = json.loads(z.read('EXPORT_MANIFEST.json'))
    evidence = campaign.parent.parent
    protected = [prefix/'FREEZE.json', prefix/'store.sqlite', campaign/'ORIGIN.json',
                 *(prefix/'artifacts').rglob('*'), *(campaign/'jobs').glob('fit-*.record.json')]
    require(all(hashlib.sha256(p.read_bytes()).hexdigest() == manifest[str(p.relative_to(evidence))]
                for p in protected if p.is_file()), 'Saved evidence changed', 'FR_SAVED_EVIDENCE')
    frozen = json.loads((prefix/'FREEZE.json').read_text())
    ledger = Budget(output/'authority.sqlite', config=Config(), historical=h, clock=FakeClock())
    local = SyntheticCounter()
    service = SavedService(local, frozen, case)
    service.spend = Decimal(h['expected_key_spend_nano'])
    sender = FakeHTTPSender([service.post]*10)
    counter, stats = bound_counter(local, simulated=True)
    model = Model(sender, token_counter=counter, token_statistics=stats)
    billing = Billing(ledger, fake_sender=FakeHTTPSender([service.get]*4))
    gateway = Gateway(model, ledger, billing)
    cpu = SavedCPU(campaign, source, forbid_fake_fit=case == 'zero_fit_guard' and method == 'CUTOFF')
    timing = Timing()
    uid = 'FR02.'+method
    def change_data(store):
        before = store.read(DATA)
        store.write(DATA, before['content'], {k: before[k] for k in store.REF_FIELDS}, 'external-data-update')
    def external_publish(store):
        before = store.read(PUBLICATION)
        store.write(PUBLICATION, canonical({'owner': 'external', 'retain': True}),
                    {k: before[k] for k in store.REF_FIELDS}, 'external-consumer')
    def deny_publish(store):
        before = store.read(PERMISSION)
        store.write(PERMISSION, canonical({'publish_allowed': False}),
                    {k: before[k] for k in store.REF_FIELDS}, 'external-permission')
    guard = NoEstimators()
    sys.meta_path.insert(0, guard)
    try:
        with patch.object(socket, 'socket', side_effect=AssertionError('FR_NETWORK_FORBIDDEN')), \
             patch('agent_l_v1.cpu.ActualCPU.fit', side_effect=AssertionError('FR_REAL_FIT_FORBIDDEN')):
            billing.begin()
            ledger.start_unit(uid, min(240., frozen['remaining_seconds']))
            with timing.span('whole_unit'):
                result = recover(prefix, frozen, output/'run', method, cpu, ledger, gateway, timing,
                    mutate=change_data if case == 'data_version_changed' else deny_publish if case == 'permission_revoked' else None,
                    before_publish=external_publish if case == 'external_publication' else None)
            ledger.finish_unit(uid)
            billing.finish()
        summary = {'case': case, 'method': method, 'outcome': result['outcome'],
                   'recovery': result['recovery'], 'simulated_fit_tasks': cpu.fit_count,
                   'saved_artifact_admissions': cpu.admissions, 'synthetic_HTTP_calls': sender.request_count,
                   'real_API_calls': 0, 'real_fits': 0, 'model_loads': 0, 'predict_calls': 0,
                   'cloud_starts': 0, 'historical_real_calls': 350, 'real_history_unchanged': True,
                   'stage_replays': result['stage_replays'], 'actual_recovery_measurement': False,
                   'billing_scope': 'synthetic per-branch simulation; does not increment real totals'}
        save(output/'SUMMARY.json', summary)
        save(output/'LEDGER.json', ledger.snapshot())
        save(output/'ADMISSIONS.json', cpu.admission_evidence)
        save(output/'RESPONSE_SOURCES.json', service.audit)
        save(output/'TIMING.json', timing.document())
        return summary
    finally:
        ledger.close()
        sys.meta_path.remove(guard)


def run_suite(output, source):
    output = Path(output)
    require(not output.exists(), 'Fresh suite only', 'FR_OUTPUT')
    output.mkdir(parents=True)
    rows = [run_branch(output/case/method, source, case, method)
            for case in CASES for method in ('FULL', 'CONSERVATIVE', 'CUTOFF')]
    save(output/'SUMMARY.json', {'revision': 'feedback-replay-offline-v2', 'branches': rows,
        'real_API_calls': 0, 'real_fits': 0, 'historical_real_calls': 350,
        'scope': 'offline correctness checks, not real completion rates or savings'})
    return rows
