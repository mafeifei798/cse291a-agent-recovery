"""Bounded L-tier acceptance cases, all model replies explicitly scripted."""
from copy import deepcopy
import json
from pathlib import Path

from context_cutoff.runtime import new_fixture_ledger
from context_cutoff.contracts import require
from sr_recovery_v2.common import digest
from .core import prepare_inputs, save, sha
from .cpu import FakeCPU, ActualCPU
from .runtime import AgentLoop
from .recovery import recover, data_update_refusal, external_write_refusal


def changed_inputs(data, directory):
    directory = Path(directory)
    directory.mkdir(exist_ok=False)
    lines = Path(data['raw']['path']).read_bytes().splitlines(keepends=True)
    fields = lines[1].split(b';')
    quoted = fields[0].startswith(b'"')
    value = str(int(fields[0].strip(b'"')) + 1).encode()
    fields[0] = b'"' + value + b'"' if quoted else value
    lines[1] = b';'.join(fields)
    path = directory / 'bank-updated.csv'
    with path.open('xb') as f: f.write(b''.join(lines))
    result = deepcopy(data)
    result['raw'] = {'path': str(path.resolve()), 'sha256': sha(path)}
    for key in ('screen_train', 'screen_validation', 'final_train', 'final_validation'):
        original = json.loads(Path(data[key]['path']).read_text())
        ids = [r.replace(data['raw']['sha256'], result['raw']['sha256'], 1) for r in original['row_ids']]
        updated = {**original, 'row_ids': ids, 'row_ids_digest': digest(ids)}
        target = directory / (key + '.json')
        save(target, updated)
        result[key] = {'path': str(target.resolve()), 'sha256': sha(target)}
    save(directory / 'CHANGE_RECEIPT.json', {'selected_training_row': 1, 'field': 'age',
        'old_raw_sha256': data['raw']['sha256'], 'new_raw_sha256': result['raw']['sha256'],
        'old_input_modified': False, 'labels_changed': False, 'real_fit_count': 0})
    return result


def execute_suite(directory, source_root, *, native=False, authorized=False):
    root = Path(directory).resolve()
    root.mkdir(parents=True, exist_ok=False)
    save(root / 'ORIGIN.json', {'campaign_root': str(root), 'source_root': str(Path(source_root).resolve())})
    inputs = prepare_inputs(source_root, root / 'inputs')
    save(root / 'INPUTS.json', inputs)
    (root / 'cases').mkdir()
    cpu = ActualCPU(root, authorized=authorized, fit_limit=10) if native else FakeCPU()
    ledger = new_fixture_ledger(root / 'fixture-ledger.sqlite', 'agent-l-offline-only')
    summary = {'revision': 'agent-l-v1', 'tier': 'L', 'llm_fixture_only': True, 'cpu_fixture_only': not native,
        'status': 'running', 'real_API_calls': 0, 'key_reads': 0, 'cloud_starts': 0, 'GPU': False,
        'threshold': .5, 'threshold_tuning': False, 'old_default_client_modified': False, 'cases': {}}
    try:
        clean = AgentLoop(root / 'cases/clean', 'clean', cpu, ledger)
        try:
            clean.initialize(inputs); clean.run(); clean.publish()
            result = clean.export('completed_execution')
            require(result['optimization_spent'] == 1 and result['new_fit_count'] == 3, 'L_CLEAN_FEEDBACK')
            summary['cases']['clean'] = {'outcome': result['outcome'], 'fits': result['new_fit_count'],
                'quality_goal_met': result['quality_goal_met'], 'normal_adjustments': result['optimization_spent']}
        finally: clean.close()
        prefix_dir = root / 'cases/prefix'
        prefix = AgentLoop(prefix_dir, 'prefix', cpu, ledger)
        try:
            prefix.initialize(inputs); prefix.run(fault=True)
            frozen = prefix.freeze()
            require(frozen['optimization_spent'] == 1 and frozen['new_fit_count'] == 3, 'L_PREFIX_FEEDBACK')
            summary['cases']['prefix'] = {'outcome': frozen['outcome'], 'fits': frozen['new_fit_count'],
                'checkpoint_sha256': frozen['checkpoint_sha256'], 'normal_adjustments': 1}
        finally: prefix.close()
        for method in ('FULL', 'CONSERVATIVE', 'CUTOFF'):
            result = recover(prefix_dir, frozen, root / 'cases' / method, method, cpu, ledger)
            summary['cases'][method] = {'outcome': result['outcome'], 'fits': result['new_fit_count'],
                'scripted_calls': result['new_scripted_calls'], 'normal_adjustments_remaining': 1 - result['optimization_spent'],
                'retained_producer_ids': result['recovery']['retained_producer_ids'],
                'equivalent_contracts': result['recovery']['equivalent_contracts'],
                'quality_goal_met': result['quality_goal_met'], 'checkpoint_sha256': frozen['checkpoint_sha256']}
        require([summary['cases'][m]['fits'] for m in ('FULL', 'CONSERVATIVE', 'CUTOFF')] == [2, 2, 0], 'L_RECOVERY_FIT_COUNTS')
        require(len(summary['cases']['CUTOFF']['retained_producer_ids']) == 2, 'L_CUTOFF_RETAINED')
        changed = changed_inputs(inputs['data'], root / 'updated-data')
        result = data_update_refusal(prefix_dir, frozen, root / 'cases/data-update', cpu, ledger, changed)
        summary['cases']['data-update'] = {'outcome': result['outcome'], **result['refusal']}
        result = external_write_refusal(prefix_dir, frozen, root / 'cases/external-write', cpu, ledger)
        summary['cases']['external-write'] = {'outcome': result['outcome'], **result['refusal']}
        require(cpu.fit_count == 10, 'L_SUITE_TOTAL_FITS')
        summary.update(status='complete', training_jobs=cpu.fit_count, numerical_readmissions=cpu.admissions,
            simulated_llm_calls=len(ledger.calls()), fixture_token_usage='synthetic-not-measured',
            actual_model_API_cost=0, scientific_recovery_benefit_claimed=False)
        save(root / 'FIXTURE_LEDGER_SNAPSHOT.json', ledger.snapshot())
        if native:
            save(root / 'CPU_RECORD_INDEX.json', [{'record_rel': item['record_rel'],
                'schema': item['record']['spec']['schema_version'], 'job_id': item['record']['spec']['job_id']}
                for item in cpu.records])
        return summary
    except BaseException as exc:
        summary.update(status='failed', error={'type': type(exc).__name__, 'message': str(exc)},
                       training_launches=cpu.fit_count)
        raise
    finally:
        save(root / 'SUMMARY.json', summary)
        ledger.close()
