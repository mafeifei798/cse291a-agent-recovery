"""One recovery path: recheck once, cut only equivalent and still-valid edges."""
from pathlib import Path

from agent_l_v1.core import DATA, CODE, PUBLICATION, ref
from context_cutoff.contracts import require
from context_cutoff.store import FileProvenanceStore
from sr_recovery_v2.common import canonical, closure_ids, digest
from .runtime import UnifiedLoop


METHODS = ('FULL', 'CONSERVATIVE', 'CUTOFF')


def clone(prefix, frozen, destination, method, cpu, ledger, timing):
    require(digest({k: v for k, v in frozen.items() if k != 'checkpoint_sha256'}) == frozen['checkpoint_sha256'], 'L3_FREEZE_CHANGED')
    with timing.span('freeze_validation_and_clone'):
        with FileProvenanceStore(Path(prefix) / 'store.sqlite', Path(prefix) / 'artifacts') as source:
            require(source.snapshot() == frozen['store_snapshot'], 'L3_FREEZE_STORE_CHANGED')
            source.save_to(destination)
    return UnifiedLoop(destination, frozen['run_id'] + '.' + method, cpu, ledger, timing=timing,
                       document=frozen, remaining_seconds=frozen['remaining_seconds'])


def recover(prefix, frozen, destination, method, cpu, ledger, timing, *, protect_external=False):
    require(method in METHODS, 'L3_METHOD')
    engine = clone(prefix, frozen, destination, ('protected.' if protect_external else '') + method, cpu, ledger, timing)
    try:
        old = frozen['active']['contract']; nodes = frozen['store_snapshot']['nodes']
        files = frozen['store_snapshot']['files']; old_producers = {frozen['active'][k]['payload']['producer_id'] for k in ('screen', 'final')}
        before_fits, before_admit = cpu.fit_count, cpu.admissions
        roots = {n['result_id'] for n in nodes if n['role'] == 'Analyst'}
        stale = [n['result_id'] for n in nodes if any(files.get(r['file_id']) != r for r in n.get('file_reads', []))]
        roots.update(stale)
        with timing.span('dependency_invalidation'):
            invalidated = closure_ids(roots, nodes)
        analyst = engine.role('Analyst'); engine.doc['active']['analyst'] = analyst
        planner = engine.role('Planner', [('facts', analyst, analyst['payload']['final'])]); bound = engine.bind(planner)
        with timing.span('contract_equivalence'):
            equal = old['payload']['contracts'] == bound['payload']['contracts']
        data_ref, data = engine.read(DATA); code_ref, _ = engine.read(CODE)
        probes = []
        for kind in ('screen', 'final'):
            try:
                cpu.validate(frozen['active'][kind]['payload'], bound['payload']['contracts'][kind], kind, data)
            except Exception as exc:
                require(str(exc) == 'L_ADMISSION_CONTRACT_STALE', 'L3_UNEXPECTED_PROBE_FAILURE')
                probes.append({'kind': kind, 'rejected': True, 'code': str(exc)})
            else: probes.append({'kind': kind, 'rejected': False, 'code': 'current-contract'})
        require(equal == all(not p['rejected'] for p in probes), 'L3_PROBE_CONTRACT_DISAGREEMENT')
        decision = {'method': method, 'checkpoint_sha256': frozen['checkpoint_sha256'],
            'faulty_result_id': frozen['faults'][-1]['faulty_result_id'],
            'equivalent_contracts': equal, 'old_selection': old['payload']['selection'],
            'new_selection': bound['payload']['selection'], 'old_model_probes': probes,
            'invalidated_result_ids': invalidated, 'stale_source_roots': stale,
            'normal_remaining_before': 1-frozen['optimization_spent'], 'cutoff_rechecks': int(method == 'CUTOFF'),
            'retained_producer_ids': [], 'cut_edges': [], 'recovery_round': 1,
            'conservative_granularity': 'whole Analyst turn plus observed downstream closure'}
        can_cut = method == 'CUTOFF' and equal
        screen = None; final_supplier = None
        if can_cut:
            # Equality is not enough: every non-cut producer dependency must still hold.
            for kind in ('screen', 'final'):
                origin = frozen['active'][kind]
                require(set(origin['parent_result_ids']) <= {old['result_id'], frozen['active']['review']['result_id']}, 'L3_BYPASS_DEPENDENCY')
                require(all(files.get(r['file_id']) == r for r in origin['file_reads']), 'L3_OTHER_SOURCE_STALE')
            origin = frozen['active']['screen']
            retained = cpu.admit(origin['payload'], bound['payload']['contracts']['screen'], 'screen', data, engine.deadline)
            screen = engine.node('admission', 'executor', retained, [bound['result_id']], [data_ref, code_ref],
                origin_result_id=origin['result_id'], equivalent_input_contracts=True)
            def final_supplier(current_bound, reviewed):
                origin = frozen['active']['final']
                retained = cpu.admit(origin['payload'], current_bound['payload']['contracts']['final'], 'final', data, engine.deadline)
                return engine.node('admission', 'executor', retained, [current_bound['result_id'], reviewed['result_id']],
                    [data_ref, code_ref], origin_result_id=origin['result_id'], equivalent_input_contracts=True)
        accepted = engine.finish(analyst, bound, retained_screen=screen, retained_final=final_supplier)
        final_active = engine.doc['active']
        if accepted:
            decision['retained_producer_ids'] = [final_active[k]['payload']['producer_id'] for k in ('screen','final')
                                                   if final_active[k]['payload']['producer_id'] in old_producers]
            decision['cut_edges'] = [{'old_parent': old['result_id'], 'old_child': frozen['active'][k]['result_id'],
                'new_parent': final_active['contract']['result_id']} for k in ('screen','final')
                if final_active[k]['payload']['producer_id'] in old_producers]
        refusal = None; outcome = 'review_stop'
        if accepted:
            if protect_external:
                prior = ref(engine.store.read(PUBLICATION))
                after = engine.store.write(PUBLICATION, canonical({'status': 'external-valid-new-report', 'revision': 'L3'}), prior, 'external-reporter')['after']
                engine.doc['external_publication_update'] = {'before': prior, 'after': after,
                    'barrier': 'after_training_and_checks_before_publish'}
            try: engine.publish()
            except Exception as exc:
                require(protect_external and str(exc) == 'L_EXTERNAL_OWNER', 'L3_UNEXPECTED_COMMIT_FAILURE')
                require(ref(engine.store.read(PUBLICATION)) == after, 'L3_EXTERNAL_OVERWRITTEN')
                refusal = {'code': str(exc), 'external_ref': after, 'preserved': True, 'recovery_completed': False}
                outcome = 'safe_stop'
            else:
                require(not protect_external, 'L3_EXTERNAL_PROTECTION_FAILED')
                outcome = 'completed_execution'
        require(ref(engine.store.read(DATA)) == files[DATA], 'L3_EXTERNAL_DATA_OVERWRITTEN')
        require(engine.doc['optimization_spent'] >= frozen['optimization_spent'], 'L3_QUOTA_RESET')
        decision.update(new_fit_count=cpu.fit_count-before_fits, new_admissions=cpu.admissions-before_admit,
            normal_remaining_after=1-engine.doc['optimization_spent'], external_data_ref_preserved=True,
            publication_refusal=refusal)
        engine.doc['decisions'].append(decision)
        return engine.export(outcome, recovery=decision)
    finally: engine.close()
