"""One known fault, shared freeze and equal remaining quotas; never reset prefix."""
from copy import deepcopy
import json
from pathlib import Path

from context_cutoff.contracts import require
from context_cutoff.store import FileProvenanceStore
from sr_recovery_v2.common import canonical, closure_ids, digest
from .core import DATA, CODE, TASK, MODEL, CHOICE, PUBLICATION, ScriptedLLM, ref, save
from .runtime import AgentLoop


def clone(prefix, frozen, destination, run_id, cpu, ledger, model=None):
    require(digest({k: v for k, v in frozen.items() if k != 'checkpoint_sha256'}) == frozen['checkpoint_sha256'], 'L_FREEZE_CHANGED')
    with FileProvenanceStore(Path(prefix) / 'store.sqlite', Path(prefix) / 'artifacts') as source:
        require(source.snapshot() == frozen['store_snapshot'], 'L_FREEZE_STORE_CHANGED')
        source.save_to(destination)
    return AgentLoop(destination, run_id, cpu, ledger, model=model, document=frozen,
                     remaining_seconds=frozen['remaining_seconds'])


def recover(prefix, frozen, destination, method, cpu, ledger, *, forced_bundle=None):
    require(method in ('FULL', 'CONSERVATIVE', 'CUTOFF'), 'L_RECOVERY_METHOD')
    engine = clone(prefix, frozen, destination, frozen['run_id'] + '.' + method, cpu, ledger,
                   ScriptedLLM(force_recovery_bundle=forced_bundle))
    try:
        before_fits = cpu.fit_count
        old = frozen['active']['contract']
        fault = frozen['faults'][-1]['faulty_result_id']
        # The replay unit is a whole Analyst turn; keep its exact observed call graph.
        roots = {n['result_id'] for n in frozen['store_snapshot']['nodes'] if n['role'] == 'Analyst'}
        require(fault in roots, 'L_FAULT_ID')
        invalid = closure_ids(roots, frozen['store_snapshot']['nodes'])
        analyst = engine.role('Analyst')
        engine.doc['active']['analyst'] = analyst
        planner = engine.role('Planner', [('facts', analyst, analyst['payload']['final'])])
        bound = engine.bind(planner)
        equal = digest(old['payload']['contracts']) == digest(bound['payload']['contracts'])
        decision = {'method': method, 'faulty_result_id': fault, 'checkpoint_sha256': frozen['checkpoint_sha256'],
            'normal_adjustments_remaining_before': 1 - frozen['optimization_spent'], 'fault_recovery_round': 1,
            'cutoff_rechecks': int(method == 'CUTOFF'), 'equivalent_contracts': equal,
            'old_contract_id': old['result_id'], 'new_contract_id': bound['result_id'],
            'old_contracts_sha256': digest(old['payload']['contracts']),
            'new_contracts_sha256': digest(bound['payload']['contracts']),
            'invalidated_result_ids': invalid, 'retained_producer_ids': [],
            'conservative_granularity': 'whole-agent-turn plus observed downstream closure'}
        dataref, data = engine.read(DATA); coderef, _ = engine.read(CODE)
        if method == 'CUTOFF' and equal:
            # Historical origin remains immutable. Rebind only after equivalence,
            # all current data/code checks and independent no-fit numerical audit.
            origin = frozen['active']['screen']
            retained = cpu.admit(origin['payload'], bound['payload']['contracts']['screen'], 'screen', data, engine.deadline)
            screening = engine.node('admission', 'executor', retained, [bound['result_id']], [dataref, coderef],
                origin_result_id=origin['result_id'], equivalent_input_contracts=True)
            engine.doc['active']['screen'] = screening
            reviewed = engine.review(bound, screening)
            require(reviewed['payload']['final']['action'] == 'accept', 'L_REVIEW_NOT_ACCEPTED')
            origin = frozen['active']['final']
            retained = cpu.admit(origin['payload'], bound['payload']['contracts']['final'], 'final', data, engine.deadline)
            final = engine.node('admission', 'executor', retained,
                [bound['result_id'], reviewed['result_id']], [dataref, coderef],
                origin_result_id=origin['result_id'], equivalent_input_contracts=True)
            engine.doc['active']['final'] = final
            decision['retained_producer_ids'] = [frozen['active'][k]['payload']['producer_id'] for k in ('screen', 'final')]
            decision['cut_edges'] = [{'old_parent': old['result_id'], 'old_child': frozen['active'][k]['result_id'],
                                      'new_parent': bound['result_id']} for k in ('screen', 'final')]
        else:
            screening = engine.train(bound, 'screen')
            reviewed = engine.review(bound, screening)
            require(reviewed['payload']['final']['action'] == 'accept', 'L_REVIEW_NOT_ACCEPTED')
            engine.train(bound, 'final')
            decision['cut_edges'] = []
        engine.capture_guard_refs()
        engine.publish()
        decision['new_fit_count'] = cpu.fit_count - before_fits
        decision['normal_adjustments_remaining_after'] = 1 - engine.doc['optimization_spent']
        engine.doc['decisions'].append(decision)
        result = engine.export('completed_execution', recovery=decision)
        require(engine.doc['optimization_spent'] == frozen['optimization_spent'], 'L_NORMAL_QUOTA_RESET')
        return result
    finally:
        engine.close()


def data_update_refusal(prefix, frozen, destination, cpu, ledger, changed_data):
    engine = clone(prefix, frozen, destination, frozen['run_id'] + '.DATA_UPDATE', cpu, ledger)
    try:
        oldref, old_data = engine.read(DATA)
        newref = engine.store.write(DATA, canonical(changed_data), oldref, 'external-data-owner')['after']
        old = frozen['active']['contract']['payload']
        from .core import contract_pair
        _, code = engine.read(CODE); _, task = engine.read(TASK)
        desired = contract_pair(old['selection'], changed_data, code, task)
        fit_before, admissions_before = cpu.fit_count, cpu.admissions
        try:
            cpu.admit(frozen['active']['final']['payload'], desired['final'], 'final', changed_data, engine.deadline)
        except Exception as exc:
            require(getattr(exc, 'code', str(exc)) == 'L_ADMISSION_CONTRACT_STALE', 'L_WRONG_STALE_REJECTION')
            refusal = {'code': str(exc), 'old_binding': old['contracts']['final']['data_binding'],
                'new_binding': desired['final']['data_binding'], 'selection_unchanged': True,
                'external_source_ref': newref, 'new_fit_count': cpu.fit_count - fit_before,
                'new_admissions': cpu.admissions - admissions_before, 'recovery_completed': False}
        else:
            raise RuntimeError('L_STALE_MODEL_ACCEPTED')
        require(ref(engine.store.read(DATA)) == newref and cpu.fit_count == fit_before, 'L_DATA_UPDATE_OVERWRITTEN')
        return engine.export('safe_stop', refusal=refusal)
    finally:
        engine.close()


def external_write_refusal(prefix, frozen, destination, cpu, ledger):
    engine = clone(prefix, frozen, destination, frozen['run_id'] + '.EXTERNAL_WRITE', cpu, ledger)
    try:
        original = ref(engine.store.read(PUBLICATION))
        external = engine.store.write(PUBLICATION, canonical({'status': 'external-valid-new-report'}),
                                       original, 'external-reporter')['after']
        engine.capture_guard_refs()
        try:
            engine.publish()
        except Exception as exc:
            require(str(exc) == 'L_EXTERNAL_OWNER', 'L_WRONG_EXTERNAL_REJECTION')
            owner_code = str(exc)
        else:
            raise RuntimeError('L_EXTERNAL_REPORT_OVERWRITTEN')
        try:
            engine.store.write_checked(PUBLICATION, canonical({'bad': 'stale write'}), original,
                                        'recovery', engine.guard_refs)
        except Exception as exc:
            require(str(exc) == 'FILE_VERSION_CONFLICT', 'L_WRONG_CAS_REJECTION')
            cas_code = str(exc)
        else:
            raise RuntimeError('L_CAS_DID_NOT_REJECT')
        try:
            engine.store.restore(PUBLICATION, external, original, 'recovery')
        except Exception as exc:
            require(str(exc) == 'FILE_EXTERNAL_OWNER', 'L_WRONG_RESTORE_REJECTION')
            restore_code = str(exc)
        else:
            raise RuntimeError('L_EXTERNAL_RESTORE_OVERWROTE')
        require(ref(engine.store.read(PUBLICATION)) == external, 'L_EXTERNAL_CHANGED')
        return engine.export('safe_stop', refusal={'owner': owner_code, 'cas': cas_code,
            'restore': restore_code, 'external_ref_unchanged': True, 'recovery_completed': False})
    finally:
        engine.close()
