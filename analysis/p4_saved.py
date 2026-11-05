#!/usr/bin/env python3
"""Recompute Phase 1 measurements from saved SQL/HTTP exports, offline only.

P4 business checks run again against raw rows. With --real-cohorts, static
Phase 2 records are independently recomputed from the portable raw package;
without it, the retained-audit summary mode remains explicitly labelled.
Dynamic traces are rechecked against immutable SQLite. No execution modules,
model clients, credentials, fitting, or prediction are needed.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import csv
import hashlib
import io
import json
import math
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'src'))
P4_SHA = '731f77997898af2c985a5b8f17a35b675cbb35a3279bd469740648c8f2b43da6'
POLICIES = ('BASE', 'VERIFY_STOP', 'FULL_RESTART')
CONDITIONS = ('CLEAN', 'ERR', 'ADV', 'TMO', 'STL')


def require(value, reason):
    if not value:
        raise ValueError(reason)


def offline_only(event, args):
    if event.startswith('socket.') or event in ('subprocess.Popen', 'os.system',
            'os.posix_spawn', 'pickle.find_class'):
        raise RuntimeError('OFFLINE_EVALUATION_FORBIDS:' + event)
    if event == 'sqlite3.connect':
        require(str(args[0]).startswith('file:') and 'mode=ro&immutable=1' in str(args[0]),
                'SQL_REQUIRES_IMMUTABLE_READ_ONLY_MODE')


def read(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'DUPLICATE_JSON_KEY:' + key)
            result[key] = value
        return result
    return json.loads(Path(path).read_text(), object_pairs_hook=unique,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError('NONFINITE:' + value)))


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def verify_manifest(bundle):
    bundle = Path(bundle).resolve()
    manifest = read(bundle / 'MANIFEST.json')
    for relative, pin in manifest['files'].items():
        path = (bundle / relative).resolve()
        require(path.is_relative_to(bundle) and path.is_file(), 'MANIFEST_PATH:' + relative)
        require(path.stat().st_size == pin['size_bytes'] and sha(path) == pin['sha256'],
                'MANIFEST_CHANGED:' + relative)
    return len(manifest['files'])


def describe(values):
    require(all(isinstance(x, (int, float)) and not isinstance(x, bool)
                and math.isfinite(x) and x >= 0 for x in values), 'INVALID_MEASUREMENT')
    return {'n': len(values), 'values': values, 'median': statistics.median(values) if values else None,
            'min': min(values) if values else None, 'max': max(values) if values else None}


def timing_for(slot, trial, artifacts, callmap, standard):
    """Check saved timing against the original run summary and HTTP receipts."""
    prefix = slot['trial_dir'].rstrip('/') + '/'
    summary = artifacts[prefix + 'summary.json']
    replay = slot['phase'] == 'replay'
    receipts = [] if replay else artifacts.get(prefix + 'verifier_receipts.json', [])
    expected = {
        'wall_execution_ms': summary['replay_elapsed_ms' if replay else 'initial_elapsed_ms'],
        'wall_recovery_total_ms': summary.get('restart_total_elapsed_ms') if replay else None,
        'wall_recovery_control_ms': summary.get('recovery_control_elapsed_ms') if replay else None,
        'verifier_elapsed_ms': sum(r['elapsed_ms'] for r in receipts),
        'real_api_latency_ms': sum(callmap[c]['evidence']['http_trace']['elapsed_s'] * 1000
                                   for c in trial['new_call_ids']),
    }
    require(standard['trial_key'] == trial['trial_key'], 'TIMING_IDENTITY')
    for key, value in expected.items():
        if value is None:
            require(standard[key] is None, 'TIMING_NULL:' + key)
        else:
            describe([value])
            require(isinstance(standard[key], (int, float)) and math.isclose(
                standard[key], value, rel_tol=1e-12, abs_tol=1e-8), 'TIMING_DIFF:' + key)
    if replay:
        require(math.isclose(expected['wall_recovery_total_ms'], expected['wall_execution_ms'] +
            expected['wall_recovery_control_ms'], rel_tol=1e-12, abs_tol=1e-6), 'RECOVERY_TIME_SUM')
    return expected


def derive_p4(records, audit):
    require(audit['passed'], 'P4_INDEPENDENT_AUDIT_FAILED:' + str(audit['findings'][:3]))
    artifacts = records['artifacts']
    raw = next(d for d in records['databases'].values() if 'p3_campaign' in d)
    calls = [json.loads(r['body']) for r in raw['p3_calls']]
    callmap = {c['call_id']: c for c in calls}
    require(len(callmap) == len(calls), 'DUPLICATE_CALL')
    slots = artifacts['execution_manifest.json']['slots']
    standard = {s['trial_key']: s for s in map(json.loads,
        artifacts['standard/trial_summaries.jsonl'].splitlines())}
    rows = []
    for slot, trial in zip(slots, audit['trials']):
        require(slot['trial_key'] == trial['trial_key'], 'TRIAL_ORDER')
        row = dict(trial)
        wrong = set(trial['wrong_result_ids'])
        descendants = set(trial['observed_wrong_result_ids'])
        own = [callmap[c] for c in trial['new_call_ids']]
        row['invalid_result_calls'] = sum(c['result_id'] in wrong for c in own)
        row['invalid_result_cost_nano_usd'] = sum(c['known_cost_nano_usd'] for c in own if c['result_id'] in wrong)
        row['fault_wrong_descendant_calls'] = sum(c['result_id'] in descendants for c in own)
        row['fault_wrong_descendant_cost_nano_usd'] = sum(c['known_cost_nano_usd'] for c in own if c['result_id'] in descendants)
        row['non_successful_steps'] = sum(s['execution_status'] != 'success' for s in audit['steps'] if s['trial_key'] == trial['trial_key'])
        row['timing'] = timing_for(slot, trial, artifacts, callmap,
            artifacts[standard[trial['trial_key']]['timing_record_ref']]) if trial['executed'] else None
        rows.append(row)
    groups = []
    for policy in POLICIES:
        for condition in CONDITIONS:
            selected = [r for r in rows if r['policy'] == policy and r['condition'] == condition]
            if not selected:
                continue
            executed = [r for r in selected if r['executed']]
            groups.append({'policy': policy, 'condition': condition, 'planned': len(selected),
                'executed': len(executed), 'correct': sum(r['correctness'] == 'correct' for r in executed),
                'safe_unfinished': sum(r.get('safe_stop') is True for r in executed),
                'delivered': sum(r['fault_event_delivered'] is True for r in executed),
                'model_exposed': sum(r['model_exposed'] is True for r in executed),
                'attack_goal_observed': sum(r.get('attack_goal_observed') is True for r in executed),
                'wrong_descendants': sum(len(r['observed_wrong_result_ids']) for r in executed),
                'new_wrong_writes': sum(len(r.get('new_wrong_committed_effect_ids', [])) for r in executed),
                'new_calls': sum(len(r['new_call_ids']) for r in executed),
                'known_cost_nano_usd': sum(r['new_cost_nano_usd'] for r in executed),
                **{key: sum(r[key] for r in executed) for key in ('actual_steps', 'invalid_result_calls',
                    'invalid_result_cost_nano_usd', 'fault_wrong_descendant_calls',
                    'fault_wrong_descendant_cost_nano_usd', 'non_successful_steps')},
                'execution_seconds': describe([r['timing']['wall_execution_ms'] / 1000 for r in executed]),
                'api_seconds': describe([r['timing']['real_api_latency_ms'] / 1000 for r in executed]),
                'verifier_ms': describe([r['timing']['verifier_elapsed_ms'] for r in executed])})
    repeats = []
    for policy in POLICIES:
        for condition in CONDITIONS:
            for task in sorted({r['task_id'] for r in rows}):
                selected = sorted((r for r in rows if r['policy'] == policy and r['condition'] == condition
                    and r['task_id'] == task), key=lambda r: r['repeat'])
                if not selected:
                    continue
                observed = [r for r in selected if r['executed']]
                repeats.append({'task_id': task, 'policy': policy, 'condition': condition,
                    'planned': len(selected), 'executed': len(observed),
                    'repeat_numbers': [r['repeat'] for r in observed],
                    'correct': [int(r['correctness'] == 'correct') for r in observed],
                    'execution_seconds': describe([r['timing']['wall_execution_ms'] / 1000 for r in observed]),
                    'cost_nano_usd': describe([r['new_cost_nano_usd'] for r in observed])})
    indexed = {r['trial_key']: r for r in rows}
    recovery = []
    for slot in slots:
        if slot['policy'] != 'FULL_RESTART':
            continue
        restart = indexed[slot['trial_key']]
        base = indexed[slot['parent_trial_key']]
        recovery.append({'task_id': slot['task_id'], 'condition': slot['condition'], 'repeat': slot['repeat'],
            'base_trial_key': base['trial_key'], 'restart_trial_key': restart['trial_key'],
            'restart_executed': restart['executed'], 'restart_status': restart['status'],
            'base_correct': base['correctness'] == 'correct',
            'final_correct': (restart if restart['executed'] else base)['correctness'] == 'correct',
            'discarded_base_calls': len(base['new_call_ids']) if restart['executed'] else 0,
            'discarded_base_cost_nano_usd': base['new_cost_nano_usd'] if restart['executed'] else 0,
            'restart_calls': len(restart['new_call_ids']), 'restart_steps': restart['actual_steps'],
            'logical_cost_nano_usd': base['new_cost_nano_usd'] + restart['new_cost_nano_usd'],
            'restart_seconds': restart['timing']['wall_recovery_total_ms'] / 1000 if restart['executed'] else None})
    unique_wrong = {e for r in rows for e in r.get('new_wrong_committed_effect_ids', [])}
    require(sum(g['new_wrong_writes'] for g in groups) == len(unique_wrong), 'WRONG_WRITE_DOUBLE_COUNT')
    require(sum(g['new_calls'] for g in groups) == len(calls), 'PHYSICAL_CALL_PARTITION')
    require(sum(g['known_cost_nano_usd'] for g in groups) == sum(c['known_cost_nano_usd'] for c in calls), 'PHYSICAL_COST_PARTITION')
    return {'schema_version': 'phase1-offline-p4-v1', 'audit_checks': len(audit['checks']),
        'aggregate': audit['aggregate'], 'groups': groups, 'per_task_repeats': repeats,
        'recovery_pairs': recovery, 'trials': rows,
        'conditional_restart_summary': {'fault_tasks': len(recovery),
            'actual_restarts': sum(r['restart_executed'] for r in recovery),
            'correct_after_restart': sum(r['final_correct'] and r['restart_executed'] for r in recovery),
            'correct_with_optional_restart': sum(r['final_correct'] for r in recovery),
            'discarded_base_calls': sum(r['discarded_base_calls'] for r in recovery),
            'discarded_base_cost_nano_usd': sum(r['discarded_base_cost_nano_usd'] for r in recovery)},
        'measurement_limits': [
            'Four evaluation tasks; three repeats per task, not 12 independent task instances.',
            'All repeat values and median/range are retained; no significance or general reliability claim.',
            'Execution time is observed wall time, affected by provider load, output length, and early stopping.',
            'BASE and VERIFY use separate model draws; their difference is not isolated verification overhead.',
            'Invalid-result calls include naturally wrong and injected-invalid delivered artifacts; non-success statuses are separate.',
            'Fault wrong-descendant cost is a lower-bound attribution using actual parent links, not total causal waste.',
            'Discarded BASE work counts all physical calls replaced by an actual full restart, including correct prefixes.',
            'Safe unfinished trials are not successful recoveries; skipped restart rows are not executions.',
            'The adversarial goal metric is separate from general business-invalid writes.',
            'TMO is a controlled local zero-output tool timeout, not a provider timeout measurement.',
            'Raw SQL exports and HTTP receipts are rechecked; original P4 binary SQLite remains outside this package.']}


def save(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + '\n')


def evaluate(bundle, output, real_cohorts=None):
    bundle, output = Path(bundle).resolve(), Path(output).resolve()
    require(not output.exists(), 'FRESH_OUTPUT_REQUIRED')
    require(not output.is_relative_to(bundle / 'evidence'), 'OUTPUT_MUST_NOT_REWRITE_EVIDENCE')
    manifest_files = verify_manifest(bundle)
    raw_path = bundle / 'evidence/p4/records.json'
    require(sha(raw_path) == P4_SHA, 'ORIGINAL_P4_EXPORT_CHANGED')
    from agent_recovery.p4_checker import audit_records
    records = read(raw_path)
    audit = audit_records(records, p0_root=bundle / 'phase1/p0', expected_processed=168)
    result = derive_p4(records, audit)
    require(result['aggregate'] == read(bundle / 'evidence/p4/aggregate.json'), 'ORIGINAL_AGGREGATE_DIFFERS')
    # Reuse the existing independent read-only SQL checker for Phase 2 context.
    sys.path.insert(0, str(bundle / 'scripts'))
    from replay_sr_dynamic_demo import replay
    with redirect_stdout(io.StringIO()):
        dynamic = replay(bundle / 'evidence/dynamic/raw', all_cases=True)
    cohort = read(bundle / 'evidence/REAL_COHORT_AUDIT.json')
    require(cohort['passed'] and not cohort['issues'], 'SAVED_PHASE2_AUDIT_FAILED')
    preliminary = {'scope': 'Retained independent-audit summaries, not a fresh raw API-cohort audit.',
        'cohorts_pooled': False, 'domains': {domain: value['policy_branch_aggregates']
            for domain, value in cohort['cohorts'].items()}}
    budget = read(bundle / 'evidence/FINAL_REAL_BUDGET.json')
    cumulative = budget['cumulative']
    require(cumulative['known_cost_nano_usd'] + cumulative['held_cost_nano_usd'] ==
        cumulative['known_plus_held_nano_usd'] <= cumulative['max_cost_nano_usd'], 'BUDGET_ARITHMETIC')
    require(cumulative['remaining_after_risk_nano_usd'] == cumulative['max_cost_nano_usd'] -
        cumulative['risk_adjusted_known_plus_held_nano_usd'], 'BUDGET_REMAINDER')
    raw_result = None
    if real_cohorts is not None:
        from sr_saved_audit.core import recompute, write_outputs
        raw_result = recompute(real_cohorts)
        require(raw_result['passed'] and not raw_result['differences'], 'RAW_REAL_COHORT_RECOMPUTATION_FAILED')
        require(raw_result['budget']['known_plus_held_nano_usd'] == cumulative['known_plus_held_nano_usd'],
                'REAL_COHORT_AND_PHASE1_BUDGET_DIFFERS')
        preliminary = {'scope': 'Raw micro/macro records recomputed; saved macro numerical receipts linked, not rerun.',
            'cohorts_pooled': False, 'domains': {domain: value['policy_branch_aggregates']
                for domain, value in raw_result['cohorts'].items()}}
    output.mkdir(parents=True)
    save(output / 'p4_recomputed.json', result)
    save(output / 'p4_independent_audit.json', audit)
    save(output / 'dynamic_rechecked.json', dynamic)
    save(output / ('phase2_raw_recomputed_summary.json' if raw_result is not None
                   else 'phase2_retained_audit_summary.json'), preliminary)
    raw_receipt = write_outputs(raw_result, output / 'real_cohorts') if raw_result is not None else None
    # Flat data include repeat-level observations, not only a printed main table.
    flat = [{**{k: v for k, v in r.items() if k != 'timing'}, **(r['timing'] or {})} for r in result['trials']]
    columns = ['source_trial_key', 'task_id', 'condition', 'policy', 'repeat', 'executed', 'correctness',
        'status', 'business_outcome', 'terminal_certain', 'fault_event_delivered', 'model_exposed',
        'safe_stop', 'attack_goal_observed', 'actual_steps', 'invalid_result_calls', 'fault_wrong_descendant_calls',
        'new_cost_nano_usd', 'held_cost_nano_usd', 'extra_verifier_logical_reads', 'wall_execution_ms',
        'wall_recovery_control_ms', 'wall_recovery_total_ms', 'verifier_elapsed_ms', 'real_api_latency_ms']
    with (output / 'p4_trials.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction='ignore')
        writer.writeheader(); writer.writerows(flat)
    receipt = {'passed': True, 'manifest_files_verified': manifest_files,
        'p4_checks': result['audit_checks'], 'p4_processed': 168,
        'p4_executed': result['aggregate']['executed'], 'p4_real_calls_historical': result['aggregate']['real_api_requests'],
        'dynamic_saved_branches_rechecked': len(dynamic['branches']),
        'p4_aggregate_matches_original': True, 'p4_records_sha256': sha(raw_path),
        'new_real_api_requests': 0, 'new_training_or_prediction': 0, 'new_cost_nano_usd': 0,
        'cumulative_known_plus_held_nano_usd': cumulative['known_plus_held_nano_usd'],
        'provider_account_debit_verified': budget['provider_account_debit_verified'],
        'static_phase2_scope': preliminary['scope'],
        'real_cohort_raw_receipt': raw_receipt,
        'output_files': {p.name: sha(p) for p in sorted(output.iterdir()) if p.is_file()}}
    save(output / 'EVALUATION_RECEIPT.json', receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, default=ROOT)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--real-cohorts', type=Path, help='Optional saved raw micro/macro evidence package.')
    args = parser.parse_args()
    sys.addaudithook(offline_only)
    if args.real_cohorts is not None:
        from sr_saved_audit.core import offline_only as raw_offline_only
        sys.addaudithook(raw_offline_only)
    print(json.dumps(evaluate(args.bundle, args.output, args.real_cohorts), ensure_ascii=False))


if __name__ == '__main__':
    main()
