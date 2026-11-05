"""Stage-aligned replay; legacy recovery and all frozen artifacts stay intact."""
from copy import deepcopy
from pathlib import Path
import shutil

from agent_l_v1.core import DATA, CODE, PUBLICATION, PERMISSION
from context_cutoff.store import FileProvenanceStore
from agent_recovery.contracts import require
from sr_recovery_v2.common import digest, closure_ids
from .runtime import ReplayLoop, approved_stage


def recover(prefix, frozen, dest, method, cpu, ledger, gateway, timing, *, mutate=None,
            before_publish=None, check_duplicate=True):
    require(cpu.fixture_only and gateway.model.fixture_only, 'Offline CPU and fake HTTP only', 'FR_OFFLINE_ONLY')
    require(method in ('FULL', 'CONSERVATIVE', 'CUTOFF'), 'Unknown method', 'FR_METHOD')
    require(digest({k: v for k, v in frozen.items() if k != 'checkpoint_sha256'}) == frozen['checkpoint_sha256'],
            'Freeze changed', 'FR_FREEZE')
    dest = Path(dest)
    require(not dest.exists(), 'Fresh recovery only', 'FR_OUTPUT')
    # Never open the preserved source SQLite database for writing.
    dest.mkdir(parents=True)
    shutil.copyfile(Path(prefix)/'store.sqlite', dest/'store.sqlite')
    shutil.copytree(Path(prefix)/'artifacts', dest/'artifacts')
    approval = approved_stage(frozen)
    ledger.inherit_approval(approval)
    unit = 'FR02.'+method
    with FileProvenanceStore(dest/'store.sqlite', dest/'artifacts') as store:
        require(store.snapshot() == frozen['store_snapshot'], 'Cloned freeze changed', 'FR_FREEZE')
        if mutate:
            mutate(store)
    e = ReplayLoop(dest, unit, cpu, ledger, gateway=gateway, unit=unit, timing=timing,
                   document=deepcopy(frozen), approval=approval)
    decision = {'method': method, 'checkpoint_sha256': frozen['checkpoint_sha256'],
                'logical_adjustment_id': approval['logical_adjustment_id'],
                'comparison_stage': 'adjustment-1', 'normal_remaining_before': 0,
                'original_adjusted_planner_id': approval['adjusted_planner_id'],
                'new_normal_adjustments_consumed': 0, 'equivalent_contracts': False,
                'retained_producer_ids': [], 'duplicate_replay_HTTP_delta': None}
    try:
        e.check_approval_sources()
        require(e.read(PERMISSION)[1]['publish_allowed'], 'Publication denied', 'L_PUBLISH_PERMISSION')
        require(not e.read(PUBLICATION)[0]['writer_id'].startswith('external'),
                'External publication owner', 'L_EXTERNAL_OWNER')
        if method != 'FULL':
            roots = {n['result_id'] for n in frozen['store_snapshot']['nodes'] if n['role'] == 'Analyst'}
            decision['invalidated_result_ids'] = closure_ids(roots, frozen['store_snapshot']['nodes'])
        else:
            decision['invalidated_result_ids'] = []
        analyst = e.role('Analyst')
        e.doc['active']['analyst'] = analyst
        initial = e.bind(e.role('Planner', [('facts', analyst, analyst['payload']['final'])]))
        require(initial['payload']['contracts'] == approval['initial_contract']['payload']['contracts'],
                'Initial stage changed; cannot replay old approval', 'FR_INITIAL_CONTRACT_CHANGED')
        data_ref, data = e.read(DATA)
        code_ref, _ = e.read(CODE)
        if method == 'CUTOFF':
            old = approval['initial_screen']
            value = cpu.admit(old['payload'], initial['payload']['contracts']['screen'], 'screen', data, e.deadline)
            screen = e.node('admission', 'executor', value, [initial['result_id']], [data_ref, code_ref],
                            origin_result_id=old['result_id'])
            e.doc['active']['screen'] = screen
        else:
            screen = e.train(initial, 'screen')
        bound = e.replay_approved(analyst, initial, screen)
        decision['replayed_adjusted_planner_id'] = bound['parent_result_ids'][0]
        if check_duplicate:
            before = len(ledger.calls())
            again = e.replay_approved(analyst, initial, screen)
            require(again == bound, 'Duplicate replay changed output', 'FR_REPLAY_IDEMPOTENCE')
            decision['duplicate_replay_HTTP_delta'] = len(ledger.calls())-before
        old_bound = approval['adjusted_contract']
        equal = bound['payload']['contracts'] == old_bound['payload']['contracts']
        decision['equivalent_contracts'] = equal
        retained_screen, supplier = None, None
        if method == 'CUTOFF' and equal:
            e.check_approval_sources()
            for key in ('screen', 'final'):
                origin = frozen['active'][key]
                require(set(origin['parent_result_ids']) <= {old_bound['result_id'], frozen['active']['review']['result_id']},
                        'Bypass dependency', 'FR_OTHER_INPUT')
                require(all(e.read(r['file_id'])[0] == r for r in origin['file_reads']),
                        'Other source changed', 'FR_OTHER_INPUT')
            old = frozen['active']['screen']
            value = cpu.admit(old['payload'], bound['payload']['contracts']['screen'], 'screen', data, e.deadline)
            retained_screen = e.node('admission', 'executor', value, [bound['result_id']], [data_ref, code_ref],
                                     origin_result_id=old['result_id'])
            def supplier(current, reviewed):
                e.check_approval_sources()
                old = frozen['active']['final']
                value = cpu.admit(old['payload'], current['payload']['contracts']['final'], 'final', data, e.deadline)
                return e.node('admission', 'executor', value, [current['result_id'], reviewed['result_id']],
                              [data_ref, code_ref], origin_result_id=old['result_id'])
        accepted = e.finish(analyst, bound, retained_screen=retained_screen, retained_final=supplier)
        if accepted:
            if before_publish:
                before_publish(e.store)
            e.publish()
            decision['retained_producer_ids'] = [e.doc['active'][k]['payload']['producer_id'] for k in ('screen', 'final')
                if e.doc['active'][k]['payload']['producer_id'] == frozen['active'][k]['payload']['producer_id']]
        outcome = 'completed_execution' if accepted else 'review_stop'
    except Exception as exc:
        decision['error'] = {'code': getattr(exc, 'code', type(exc).__name__), 'message': str(exc)}
        outcome = 'safe_stop' if decision['error']['code'] in (
            'FR_APPROVAL_SOURCE_STALE', 'FR_INITIAL_CONTRACT_CHANGED', 'FR_APPROVAL_REJECTED',
            'L_EXTERNAL_OWNER', 'L_PUBLISH_PERMISSION', 'FILE_VERSION_CONFLICT') else 'failed_execution'
    try:
        decision.update(normal_remaining_after=1-e.doc['optimization_spent'],
                        new_fit_count=cpu.fit_count, readmissions=cpu.admissions)
        return e.export(outcome, recovery=decision)
    finally:
        e.close()
