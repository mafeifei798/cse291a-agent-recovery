"""Fresh per-branch fake HTTP only; original results and true ledger are read-only."""
from copy import deepcopy
from dataclasses import asdict
from decimal import Decimal
import importlib.abc
import json
from pathlib import Path
import socket
import sys
from unittest.mock import patch

from agent_l_api.acceptance import SyntheticCounter
from agent_l_api.budget import FakeClock
from agent_l_api.model import bound_counter
from agent_l_replay_live.gateway import Gateway
from agent_l_replay_live.evidence import verify_saved_source
from agent_l_feedback_replay.fixtures import SavedCPU
from agent_l_batch.billing import Billing
from agent_l_v3.timing import Timing
from agent_l_v1.core import DATA, PERMISSION, PUBLICATION, save
from agent_recovery.contracts import require
from agent_recovery.p3_transport import FakeHTTPSender
from sr_recovery_v2.common import canonical
from .protocol import Config, HISTORY_REL, history
from .model import Model
from .budget import Budget
from .fixtures import SavedService
from .recovery import recover

CASES = ('equivalent','changed_contract','typed_stop','saved_real_stop','legacy_adjust',
         'wrong_approval','second_adjustment','source_version_changed','permission_revoked',
         'external_publication','initial_changed')


class NoEstimators(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in ('sklearn','joblib'):
            raise RuntimeError('AC_ESTIMATORS_DISABLED')


def run_branch(output, source, case='equivalent', method='CUTOFF', *, config=None,
               post_responses=None, metadata_responses=None, clock=None, local_counter=None):
    output,source = Path(output).resolve(),Path(source).resolve()
    require(not output.exists() and case in CASES,'Fresh offline branch required','AC_OUTPUT')
    config = config or Config(method=method)
    require(type(config) is Config and config.method == method and config.simulated,
            'Offline config/method mismatch','AC_OFFLINE_ONLY')
    h = history(source/HISTORY_REL,source)
    frozen,campaign = verify_saved_source(source)
    output.mkdir(parents=True)
    ledger = Budget(output/'authority.sqlite',config=config,historical=h,clock=clock or FakeClock())
    local = local_counter or SyntheticCounter()
    counter,stats = bound_counter(local,simulated=True)
    service = SavedService(local,frozen,source,case)
    service.spend = Decimal(h['expected_key_spend_nano'])
    post = FakeHTTPSender(post_responses if post_responses is not None else [service.post]*10)
    get = FakeHTTPSender(metadata_responses if metadata_responses is not None else [service.get]*4)
    model = Model(post,token_counter=counter,token_statistics=stats)
    cpu = SavedCPU(campaign,source,forbid_fake_fit=(case == 'equivalent' and method == 'CUTOFF'))
    billing = Billing(ledger,fake_sender=get)
    timing,result,error = Timing(),None,None
    def change_data(store):
        before = store.read(DATA)
        store.write(DATA,before['content'],{k:before[k] for k in store.REF_FIELDS},'external-data-update')
    def deny(store):
        before = store.read(PERMISSION)
        store.write(PERMISSION,canonical({'publish_allowed':False}),
                    {k:before[k] for k in store.REF_FIELDS},'external-permission')
    def external(store):
        before = store.read(PUBLICATION)
        store.write(PUBLICATION,canonical({'owner':'external','retain':True}),
                    {k:before[k] for k in store.REF_FIELDS},'external-consumer')
    guard = NoEstimators();sys.meta_path.insert(0,guard)
    try:
        with timing.span('offline_branch'), \
             patch.object(socket,'socket',side_effect=AssertionError('AC_NETWORK_DISABLED')), \
             patch('agent_l_v1.cpu.ActualCPU.fit',side_effect=AssertionError('AC_REAL_FIT_DISABLED')):
            try:
                billing.begin()
                ledger.start_unit('FR03.'+method,min(240.,frozen['remaining_seconds']))
                with timing.span('whole_unit'):
                    result = recover(campaign/'runs/LI01.PREFIX',frozen,output/'run',method,cpu,
                        ledger,Gateway(model,ledger,billing),timing,
                        mutate=change_data if case == 'source_version_changed' else deny if case == 'permission_revoked' else None,
                        before_publish=external if case == 'external_publication' else None)
                if result['outcome'] == 'completed_execution':ledger.finish_unit('FR03.'+method)
                else:
                    error = result['recovery'].get('error',{'code':'AC_STOPPED'})
                    ledger.quarantine(None,error['code'])
            except Exception as exc:
                error = {'code':getattr(exc,'code',type(exc).__name__),'message':str(exc)}
                if ledger.batch_state() == 'running':ledger.quarantine(None,error['code'])
            finally:
                if ledger.batch_state() == 'running':billing.finish()
                elif ledger.batch_state() == 'initial':ledger.batch_transition('preflight_failed',{'error':error})
        summary = {'revision':'approval-confirm-offline-v1','case':case,'method':method,
            'outcome':result['outcome'] if result else 'stopped_before_recovery','error':error,
            'comparison_performed':result['recovery']['comparison_performed'] if result else False,
            'recovery':result['recovery'] if result else None,'stage_replays':result['stage_replays'] if result else [],
            'synthetic_HTTP_calls':post.request_count,'synthetic_GETs':get.request_count,
            'simulated_fit_tasks':cpu.fit_count,'saved_artifact_admissions':cpu.admissions,
            'real_API_calls':0,'real_key_reads':0,'real_fits':0,'model_loads':0,'predict_calls':0,'cloud_starts':0,
            'historical_real_calls':356,'real_history_unchanged':True,'actual_recovery_measurement':False,
            'automatic_continuation':False,
            'accounting_status':ledger.batch_state(),'scope':'Fake-HTTP correctness only; confirmation positives are synthetic'}
        save(output/'SUMMARY.json',summary)
        save(output/'LEDGER.json',ledger.snapshot())
        save(output/'ADMISSIONS.json',cpu.admission_evidence)
        save(output/'RESPONSE_SOURCES.json',service.audit)
        save(output/'BATCH_ACCOUNTING.json',billing.snapshot())
        save(output/'TIMING.json',timing.document())
        save(output/'CONFIG.json',asdict(config))
        return summary
    finally:
        ledger.close();sys.meta_path.remove(guard)


def run_suite(output, source):
    output = Path(output)
    require(not output.exists(),'Fresh suite required','AC_OUTPUT')
    output.mkdir(parents=True)
    rows = [run_branch(output/case/method,source,case,method)
            for case in CASES for method in ('FULL','CONSERVATIVE','CUTOFF')]
    save(output/'SUMMARY.json',{'branches':rows,'real_API_calls':0,'real_training':0,
         'historical_real_calls':356,'claims':'Offline protocol correctness only; not real model success rates'})
    return rows
