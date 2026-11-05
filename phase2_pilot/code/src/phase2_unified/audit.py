"""Read-only independent audit of the shared durable admission protocol.

The SQLite document, ordered transaction journal and dispatch table are read
directly. Runtime policy, guard, fake executor and estimators are never used as
oracles. Existing independent lineage/business checks inspect artifact bytes.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from contextlib import closing
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sqlite3

from phase2_offline.artifacts import verify_artifacts
from phase2_offline.audit import Audit, _initial_audit, _work
from phase2_supplement.audit import (_artifacts, _consumer, _faults, _audit_ledger,
    HISTORICAL_KNOWN, HISTORICAL_HELD, RESERVATION)
from sr_recovery_timing.core import summarize


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode()


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _read(path):
    return json.loads(Path(path).read_text())


def _rows(value):
    return list(value.values()) if isinstance(value, dict) else value if isinstance(value, list) else []


def _time(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def _safe(directory, relative):
    rel = Path(relative)
    if rel.is_absolute() or not rel.parts or '..' in rel.parts:
        raise ValueError('UNSAFE_EVIDENCE_PATH')
    path = directory / rel
    if any(p.is_symlink() for p in (path, *path.parents)
           if p == directory or directory in p.parents):
        raise ValueError('EVIDENCE_SYMLINK')
    if not path.resolve().is_relative_to(directory.resolve()):
        raise ValueError('EVIDENCE_PATH_ESCAPE')
    return path


def _decode(record):
    value = dict(record)
    for key in ('payload', 'response', 'intent', 'settlement'):
        if key in value and isinstance(value[key], str):
            value[key] = json.loads(value[key])
    return value


def _database(directory, export, a):
    """Inspect the actual SQLite tables; a wrapper final snapshot is inadequate."""
    path = _safe(directory, 'workflow.sqlite')
    a.expect(path.is_file(), 'SHARED_AUTHORITATIVE_WORKFLOW_DATABASE_REQUIRED')
    if not path.is_file():
        return {}, [], []
    a.expect(not (directory / 'initial.sqlite').exists() and not (directory / 'branch.sqlite').exists(),
             'NO_METHOD_SPECIFIC_SHADOW_DATABASE')
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro&immutable=1', uri=True)) as db:
        db.row_factory = sqlite3.Row
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        a.expect({'document', 'commands', 'dispatches'} <= tables, 'COMMON_DURABLE_TABLES')
        a.expect(db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok', 'WORKFLOW_SQLITE_INTEGRITY')
        a.expect(db.execute('PRAGMA journal_mode').fetchone()[0].lower() == 'delete', 'COMMON_DELETE_JOURNAL_MODE')
        native = json.loads(db.execute('SELECT payload FROM document WHERE id=1').fetchone()[0])
        commands = [_decode(r) for r in db.execute('SELECT * FROM commands ORDER BY seq')]
        dispatches = [_decode(r) for r in db.execute('SELECT * FROM dispatches ORDER BY rowid')]
    for key in ('state', 'results', 'calls', 'tool_receipts', 'artifacts', 'guards', 'plans',
                'attempts', 'sources', 'source_history', 'objects', 'effects', 'task', 'dag',
                'cpu_gateway_receipts', 'transport_receipts', 'supplement_evidence'):
        a.expect(native.get(key) == export.get(key), 'SQLITE_CORE_EQUALS_EXPORT', key)
    evidence = export.get('kernel_evidence', {})
    a.expect(bool(evidence), 'RAW_KERNEL_EVIDENCE_REQUIRED')
    a.expect(evidence.get('commands') == commands and evidence.get('dispatches') == dispatches,
             'KERNEL_EXPORT_EQUALS_RAW_SQLITE_TABLES')
    a.expect(export.get('events') == commands, 'EXPORTED_EVENTS_FROM_RAW_COMMANDS')
    a.expect(evidence.get('protocol') == 'phase2-unified-durable-kernel-v1' and
             evidence.get('database_path') == 'workflow.sqlite' and
             evidence.get('synchronous') == 'FULL' and evidence.get('journal_mode') == 'DELETE' and
             evidence.get('single_authoritative_document') is True,
             'COMMON_DURABLE_PROTOCOL_CONFIGURATION')
    a.expect(evidence.get('transaction_count') == len(commands) and
             evidence.get('document_digest') == _digest(native) and
             evidence.get('state_digest') == _digest(native['state']), 'KERNEL_DIGESTS_FROM_AUTHORITY')
    return native, commands, dispatches


def _shared_protocol(native, commands, dispatches, export, a):
    """Rebuild admission and rejection from durable raw rows, not metadata."""
    state = native.get('state', {})
    results = {r['result_id']: r for r in _rows(native.get('results', []))}
    attempts = {r['attempt_id']: r for r in _rows(native.get('attempts', []))}
    calls = {r['call_id']: r for r in _rows(native.get('calls', []))}
    guards = {r['guard_id']: r for r in _rows(native.get('guards', []))}
    a.expect(len(commands) > 0, 'RAW_TRANSACTION_JOURNAL_REQUIRED')
    a.expect([r.get('seq') for r in commands] == list(range(1, len(commands) + 1)), 'CONTIGUOUS_TRANSACTION_SEQUENCE')
    a.expect(len({r.get('event_id') for r in commands}) == len(commands), 'IDEMPOTENT_EVENT_IDS_UNIQUE')
    a.expect(len({r.get('attempt_id') for r in dispatches}) == len(dispatches), 'ONE_DURABLE_INTENT_PER_ATTEMPT')
    for command in commands:
        for field in ('before_digest', 'after_digest', 'command_digest', 'previous_hash', 'command_hash'):
            value = command.get(field)
            a.expect(isinstance(value, str) and len(value) == 64,
                     'RAW_TRANSACTION_DIGEST_PRESENT', str(command.get('seq')) + ':' + field)
    previous_hash = '0' * 64; previous_after = None
    keys = ('event_id', 'kind', 'command_digest', 'payload', 'before_digest',
            'after_digest', 'previous_hash', 'response')
    for command in commands:
        seq = command['seq']
        a.expect(command.get('command_digest') == _digest({'kind': command['kind'], 'payload': command['payload']}),
                 'TRANSACTION_COMMAND_DIGEST', seq)
        a.expect(command.get('previous_hash') == previous_hash and
                 command.get('command_hash') == _digest({key: command[key] for key in keys}),
                 'TRANSACTION_HASH_CHAIN', seq)
        if previous_after is not None:
            a.expect(command.get('before_digest') == previous_after, 'TRANSACTION_STATE_CHAIN', seq)
        previous_hash, previous_after = command['command_hash'], command['after_digest']
    a.expect(not commands or commands[-1]['after_digest'] == _digest(native), 'FINAL_TRANSACTION_EQUALS_DURABLE_DOCUMENT')
    a.expect(not commands or commands[0]['kind'] == 'create', 'KERNEL_CREATED_BEFORE_ANY_EXECUTION')
    by_attempt = {r.get('attempt_id'): r for r in dispatches}
    intent_commands = {r['response'].get('attempt_id'): r for r in commands if r['kind'] == 'dispatch_intent'}
    sent_commands = {r['payload'].get('attempt_id'): r for r in commands if r['kind'] == 'dispatch_started'}
    settle_commands = {r['payload'].get('attempt_id'): r for r in commands if r['kind'] == 'settle'}
    inherited = {r['result_id'] for r in export.get('initial_snapshot', {}).get('results', [])
                 if r.get('attempt_id') not in by_attempt}
    new_results = [r for rid, r in results.items() if rid not in inherited]
    for result in new_results:
        a.expect(result.get('attempt_id') in by_attempt, 'EVERY_NEW_CANDIDATE_HAS_DURABLE_DISPATCH', result['result_id'])
    for dispatch in dispatches:
        aid = dispatch['attempt_id']; intent = dispatch.get('intent') or {}
        attempt = attempts.get(aid, {})
        intent_command = intent_commands.get(aid, {})
        sent_command = sent_commands.get(aid, {})
        settle_command = settle_commands.get(aid, {})
        a.expect(bool(intent_command), 'RAW_DISPATCH_INTENT_COMMAND_REQUIRED', aid)
        if intent_command:
            a.expect(all(intent_command['response'].get(key) == value for key, value in intent.items()),
                     'RAW_INTENT_TABLE_EQUALS_TRANSACTION_RESPONSE', aid)
        a.expect(intent.get('attempt_id', aid) == aid and
                 dispatch.get('node_id') == intent.get('node_id', dispatch.get('node_id')) and
                 dispatch.get('input_digest') == intent.get('input_digest', dispatch.get('input_digest')),
                 'DURABLE_INTENT_IDENTITY', aid)
        if attempt:
            a.expect(attempt.get('node_id') == dispatch.get('node_id'), 'ATTEMPT_NODE_FROM_RAW_INTENT', aid)
            a.expect(attempt.get('input_digest') == intent.get('input_digest') and
                     attempt.get('input_snapshot') == intent.get('input_snapshot') and
                     attempt.get('expected_parent_result_ids') == intent.get('expected_parent_result_ids'),
                     'ATTEMPT_SNAPSHOT_IMMUTABLE_FROM_INTENT', aid)
        a.expect(_digest(intent.get('input_snapshot')) == dispatch.get('input_digest'), 'INTENT_SNAPSHOT_DIGEST', aid)
        if intent.get('started_at_utc') and intent.get('deadline_utc'):
            a.expect(_time(intent['started_at_utc']) < _time(intent['deadline_utc']) <= _time(state['deadline_utc']),
                     'ATTEMPT_DEADLINE_BOUNDED_BY_FIXED_ROW_DEADLINE', aid)
        if sent_command:
            a.expect(intent_command and intent_command['seq'] < sent_command['seq'], 'PERSISTED_INTENT_PRECEDES_DISPATCH', aid)
            if intent.get('expected_llm'):
                reservation = sent_command['payload'].get('reservation') or {}
                a.expect(reservation.get('stage') == 'before' and reservation.get('attempt_id') == aid and
                         reservation.get('call_id') == aid + '.call' and reservation.get('input_digest') == intent.get('input_digest'),
                         'BUDGET_RESERVATION_BEFORE_LLM_DISPATCH', aid)
        relevant = [r for r in new_results if r.get('attempt_id') == aid]
        a.expect(len(relevant) <= 1, 'IMMUTABLE_ONE_CANDIDATE_PER_ATTEMPT', aid)
        for result in relevant:
            a.expect(result.get('input_digest') == dispatch.get('input_digest'), 'CANDIDATE_INTENT_INPUT_BINDING', aid)
            a.expect(result.get('input_snapshot') == intent.get('input_snapshot') and
                     result.get('parent_result_ids') == intent.get('expected_parent_result_ids'),
                     'RAW_CANDIDATE_FROM_EXACT_INTENT_PARENTS', aid)
        settlement = dispatch.get('settlement') or {}
        if settlement:
            a.expect(sent_command and settle_command and sent_command['seq'] < settle_command['seq'],
                     'DISPATCH_PRECEDES_ATOMIC_SETTLEMENT', aid)
            raw_package = settlement.get('raw_package', {})
            a.expect(settle_command.get('payload', {}).get('package') == raw_package,
                     'IMMUTABLE_RAW_PACKAGE_FROM_SETTLEMENT_TRANSACTION', aid)
            raw_result = raw_package.get('result', {})
            a.expect(len(relevant) == 1 and all(all(result.get(key) == value for key, value in raw_result.items()
                       if key != 'execution_status') for result in relevant), 'RAW_CANDIDATE_IMMUTABLE_EXCEPT_ACCEPTANCE_STATUS', aid)
            a.expect(settle_command.get('response', {}).get('accepted') is bool(dispatch.get('selected')) and
                     settlement.get('accepted') is bool(dispatch.get('selected')),
                     'SELECTION_ATOMIC_WITH_SETTLEMENT', aid)
            a.expect(settlement.get('guard') == settle_command.get('response', {}).get('guard'), 'GUARD_ATOMIC_WITH_SETTLEMENT', aid)
            guard = settlement.get('guard')
            if guard:
                a.expect(guards.get(guard.get('guard_id')) == guard, 'RAW_SETTLEMENT_GUARD_IN_DURABLE_DOCUMENT', aid)
            if intent.get('expected_llm'):
                budget = settlement.get('budget_settlement') or {}
                a.expect(budget == settle_command.get('payload', {}).get('budget_settlement') and
                         budget.get('stage') == 'after' and budget.get('call_id') == aid + '.call',
                         'BUDGET_SETTLEMENT_ATOMIC_WITH_ACCEPTANCE', aid)
            if settlement.get('unknown_usage') or settlement.get('late'):
                a.expect(not dispatch.get('selected'), 'UNKNOWN_OR_LATE_NEVER_ACCEPTED', aid)
                if settle_command:
                    a.expect(not any(c['kind'] in ('dispatch_intent', 'dispatch_started') and c['seq'] > settle_command['seq']
                                     for c in commands), 'NO_NEW_DISPATCH_AFTER_UNKNOWN_OR_LATE', aid)
        if dispatch.get('selected'):
            a.expect(len(relevant) == 1, 'SELECTED_DISPATCH_HAS_CANDIDATE', aid)
            a.expect(dispatch.get('status') not in ('uncertain', 'late', 'abandoned', 'rejected', 'intent', 'dispatched'),
                     'UNKNOWN_OR_REJECTED_DISPATCH_NOT_SELECTED', aid)
            a.expect(bool(settlement), 'SELECTED_HAS_DURABLE_SETTLEMENT', aid)
            if relevant:
                candidate = relevant[0]
                accepted_guards = [g for g in guards.values()
                    if g.get('candidate_result_id') == candidate['result_id']]
                a.expect(any(g.get('classification') == 'passed' for g in accepted_guards),
                         'SELECTED_CANDIDATE_HAS_PASSED_GUARD', aid)
                a.expect(candidate.get('execution_status') not in ('uncertain', 'validation_rejected', 'late'),
                         'REJECTED_RAW_CANDIDATE_NOT_ACCEPTED', aid)
                for cid in candidate.get('call_ids', []):
                    call = calls.get(cid, {})
                    budget = settlement.get('budget_settlement') or {}
                    usage = budget.get('usage') or {}
                    p, c, total = (usage.get(k) for k in ('prompt_tokens', 'completion_tokens', 'total_tokens'))
                    a.expect(call.get('status') not in ('uncertain', 'reserved') and
                             budget.get('status') == 'completed' and
                             all(type(v) is int and v >= 0 for v in (p, c, total)) and p + c == total,
                             'ACCEPTED_LLM_CALL_SETTLED_WITH_KNOWN_USAGE', cid)
    # Nothing marked selected in current business state may be a refused raw
    # candidate, including a previous candidate retained for negative evidence.
    for rid in set(state.get('selected_by_node', {}).values()) - {None}:
        result = results.get(rid, {})
        a.expect(bool(result), 'SELECTED_RESULT_EXISTS', rid)
        a.expect(result.get('execution_status') not in ('uncertain', 'validation_rejected', 'late'),
                 'CURRENT_SELECTION_NEVER_UNCERTAIN_OR_REFUSED', rid)
        if rid not in inherited:
            a.expect(bool(by_attempt.get(result.get('attempt_id'), {}).get('selected')),
                     'CURRENT_SELECTION_FROM_ATOMIC_ACCEPTANCE', rid)


def _correction_limits(native, commands, a):
    state = native['state']; start = state.get('started_at_utc'); deadline = state.get('deadline_utc')
    a.expect(bool(start) and bool(deadline), 'FIXED_DEADLINE_REQUIRED')
    if start and deadline:
        a.expect((_time(deadline) - _time(start)).total_seconds() == 1800, 'FIXED_1800_SECOND_DEADLINE')
    for kind in ('semantic', 'stale'):
        count = state.get('counters', {}).get(kind + '_used', 0)
        a.expect(type(count) is int and 0 <= count <= 1, 'FINITE_CORRECTION_ALLOWANCE', kind)
        corrections = [c for c in commands if c['kind'] == 'invalidation_and_compensation' and
                       c['payload'].get('correction_class') == kind]
        a.expect(len(corrections) == count, 'CORRECTION_COUNT_FROM_ACCEPTED_SQL_TRANSACTIONS', kind)
    a.expect(state.get('state_version') == len(commands), 'STATE_VERSION_FROM_COMMITTED_COMMAND_COUNT')


def _cpu_bridge(export, directory, row, pack, new_tools, a):
    """Cross-check fake CPU contracts against exact persisted node inputs.

    The immutable evaluation row manifests are a data oracle. The production
    CPU spec builder and worker are deliberately not imported by this audit.
    """
    records = _read(directory / 'cpu_gateway_receipts.json')
    a.expect(records == export.get('cpu_gateway_receipts'), 'CPU_RAW_GATEWAY_RECEIPTS_EQUAL_EXPORT')
    a.expect(len(records) == len(new_tools), 'EVERY_NEW_CPU_JOB_HAS_GATEWAY_RECEIPT')
    results = {r['attempt_id']: r for r in export.get('results', [])}
    tools = {r['attempt_id']: r for r in new_tools}
    seen = set()
    settled_commands = {c['payload'].get('attempt_id'): c for c in export.get('kernel_evidence', {}).get('commands', [])
                        if c['kind'] == 'settle'}
    for record in records:
        spec = record['spec']; receipt = record['receipt']; aid = spec['attempt_id']
        a.expect(aid not in seen, 'CPU_ONE_RECEIPT_PER_ATTEMPT', aid); seen.add(aid)
        a.expect(settled_commands.get(aid, {}).get('payload', {}).get('cpu_evidence') == record,
                 'CPU_GATEWAY_EVIDENCE_COMMITTED_WITH_NODE_ACCEPTANCE', aid)
        result = results.get(aid, {}); tool = tools.get(aid, {})
        a.expect(spec.get('spec_sha256') == _digest({k: v for k, v in spec.items() if k != 'spec_sha256'}),
                 'CPU_SERIALIZED_SPEC_DIGEST', aid)
        a.expect(result and tool and spec.get('input_digest') == result.get('input_digest') == tool.get('input_digest') and
                 spec.get('projection') == result.get('input_snapshot') and spec.get('node_id') == result.get('node_id'),
                 'CPU_EXECUTED_EXACT_DURABLE_NODE_PROJECTION', aid)
        a.expect(spec.get('task_id') == row['task_id'] and spec.get('dataset_id') == row['dataset_id'],
                 'CPU_EXACT_REGISTERED_TASK', aid)
        a.expect(spec.get('selected_parent_ids') == result.get('parent_result_ids'), 'CPU_EXACT_SELECTED_PARENTS', aid)
        a.expect(spec.get('artifacts') == result.get('input_snapshot', {}).get('artifact_bindings'),
                 'CPU_EXACT_INPUT_ARTIFACT_BINDINGS', aid)
        a.expect(receipt.get('fixture_only') is True and receipt.get('actual_training') == 0 and
                 receipt.get('actual_model_prediction') == 0 and receipt.get('model_loads') == 0 and
                 receipt.get('worker_started') is False, 'CPU_BRIDGE_NO_SCIENTIFIC_EXECUTION', aid)
        for key in ('attempt_id', 'node_id', 'task_id', 'dataset_id', 'evaluation_pack_sha256', 'protocol_sha256',
                    'data_manifest_sha256', 'train_version', 'train_row_ids_digest', 'validation_row_ids_digest',
                    'input_digest', 'selected_parent_ids', 'spec_sha256'):
            a.expect(receipt.get(key) == spec.get(key), 'CPU_RECEIPT_EXACT_SPEC_IDENTITY', aid + ':' + key)
        a.expect(receipt.get('status') == 'success' and receipt.get('settled') is True and
                 _time(receipt['finished_utc']) < _time(spec['deadline_utc']), 'CPU_RECEIPT_SETTLED_BEFORE_DEADLINE', aid)
        a.expect(receipt.get('payload') == result.get('payload'), 'CPU_RESPONSE_PAYLOAD_ACTUALLY_DELIVERED', aid)
        a.expect(receipt.get('parameters') == tool.get('parameters'), 'CPU_PARAMETERS_MATCH_RAW_TOOL_RECEIPT', aid)
        a.expect(receipt.get('produced_artifact_sha256') == {art['artifact_id']: art['sha256'] for art in receipt.get('artifacts', [])},
                 'CPU_OUTPUT_ARTIFACT_DIGESTS', aid)
        reads = result.get('effective_reads', [])
        versions = {ref['version'] for ref in reads if ref['object_key'] == 'data:train'}
        a.expect(versions == {spec.get('train_version')}, 'CPU_TRAIN_VERSION_FROM_REAL_NODE_READS', aid)
        if spec['node_id'].startswith('fit_'):
            family = spec['node_id'][-2:]
            plan = next((p for p in result.get('input_snapshot', {}).get('parent_inputs', [])
                         if p.get('node_id') == 'plan_' + family), {})
            parameters = plan.get('payload', {}).get('parameters', plan.get('payload', {}).get('model_parameters'))
            a.expect(spec.get('inputs', {}).get('parameters') == parameters == receipt.get('actual_parameters_from_projection'),
                     'PLANNER_DELIVERED_RECIPE_REALLY_USED_BY_CPU_CLIENT', aid)
        a.expect(Path(spec.get('artifact_root', '')).resolve() == (directory / 'files').resolve(),
                 'CPU_ARTIFACT_ROOT_IS_ROW_ARTIFACTS', aid)
        if pack:
            base = Path(pack['eval_pack_path']).resolve()
            a.expect(Path(spec.get('evaluation_pack_root', '')).resolve() == base and
                     spec.get('evaluation_pack_sha256') == pack['eval_pack_sha256'] and
                     spec.get('protocol_sha256') == pack['freeze_sha256'], 'CPU_EVAL_AND_PROTOCOL_PINS', aid)
            train = _read(base / 'data' / 'splits' / row['dataset_id'] / f"train_v{spec['train_version']}.json")
            val = _read(base / 'data' / 'splits' / row['dataset_id'] / 'validation.json')
            a.expect(spec.get('train_row_ids_digest') == _digest(train['row_ids']) == train['row_ids_digest'] and
                     spec.get('validation_row_ids_digest') == _digest(val['row_ids']) == val['row_ids_digest'],
                     'CPU_NEW_ROW_MANIFESTS_INDEPENDENTLY_BOUND', aid)
            names = {e['relative_path'] for e in spec.get('input_files', [])}
            raw = 'adult.data' if row['dataset_id'] == 'adult' else 'bank-additional-full.csv'
            expected_names = {'data/schema_and_preprocessing.json', f"data/raw/{row['dataset_id']}/{raw}"} | {
                f"data/splits/{row['dataset_id']}/{name}.json" for name in ('train_v1', 'train_v2', 'validation')}
            a.expect(names == expected_names and len(spec.get('input_files', [])) == len(expected_names),
                     'CPU_COMPLETE_PUBLIC_RAW_AND_ROW_INPUT_SET', aid)
            a.expect(spec.get('data_manifest_sha256') == pack['tasks'][row['task_id']]['data_binding']['manifest_sha256'],
                     'CPU_EXPECTED_TASK_DATA_MANIFEST', aid)
            for entry in spec.get('input_files', []):
                path = _safe(base, entry['relative_path'])
                a.expect(path.is_file() and path.stat().st_size == entry['size_bytes'] and
                         hashlib.sha256(path.read_bytes()).hexdigest() == entry['sha256'], 'CPU_RAW_INPUT_FILE_BYTES', aid)
    return records


def _numeric_bridge(export, directory, row, pack, loaded, timing, a):
    status = export['state']['terminal_status']
    receipt = export.get('independent_numeric_check')
    if status not in ('completed_correct', 'completed_local_unresolved_external', 'consumed_prefix_frozen'):
        a.expect(receipt is None, 'NO_SUCCESSFUL_NUMERIC_CLAIM_FOR_INCOMPLETE_ROW')
        return
    a.expect(isinstance(receipt, dict), 'COMPLETED_LOCAL_STATE_REQUIRES_NUMERIC_CHECKER')
    if not isinstance(receipt, dict):
        return
    from .numeric import validate_checker_spec, fixture_metrics
    spec = receipt['spec']
    try:
        checked = validate_checker_spec(spec)
    except (KeyError, TypeError, ValueError, OSError) as exc:
        a.expect(False, 'INDEPENDENT_NUMERIC_SPEC_VALIDATION', detail=str(exc))
        return
    selected = export['state']['selected_by_node']; results = {r['result_id']: r for r in export['results']}
    payloads = {node: results[rid]['payload'] for node, rid in selected.items() if rid}
    a.expect(spec.get('task_id') == row['task_id'] and spec.get('dataset_id') == row['dataset_id'],
             'NUMERIC_EXACT_REGISTERED_TASK')
    a.expect(spec.get('selected_result_ids') == selected and
             spec.get('inputs', {}).get('selected_payloads') == payloads,
             'NUMERIC_CHECKER_USES_ACTUAL_SELECTED_OUTPUTS')
    a.expect(spec.get('deadline_utc') == export['state']['deadline_utc'] == receipt.get('deadline_utc'),
             'NUMERIC_CHECKER_SHARES_ORIGINAL_FIXED_DEADLINE')
    current_train = next(s['version'] for s in export['sources'] if s['object_key'] == 'data:train')
    a.expect(spec.get('train_version') == current_train, 'NUMERIC_CHECKER_CURRENT_TRAIN_SOURCE')
    if pack:
        a.expect(spec.get('protocol_sha256') == pack['freeze_sha256'] and
                 spec.get('evaluation_pack_sha256') == pack['eval_pack_sha256'], 'NUMERIC_BOTH_NEW_EVAL_AND_PROTOCOL_PINS')
    a.expect(receipt.get('fixture_only') is True and receipt.get('passed') is True and
             receipt.get('actual_training') == receipt.get('actual_model_prediction') == receipt.get('model_loads') == 0 and
             receipt.get('workflow_cpu_jobs_added') == receipt.get('model_calls_added') == 0 and
             receipt.get('evaluation_dataset_rows_executed') is False, 'NUMERIC_FIXTURE_NOT_REAL_DATA_OR_MODEL_EVIDENCE')
    a.expect(type(receipt.get('wall_ns')) is int and receipt['wall_ns'] >= 0 and
             type(receipt.get('controller_cpu_ns')) is int and receipt['controller_cpu_ns'] >= 0,
             'NUMERIC_CHECKER_COST_RECORDED')
    spans = [s for s in timing.get('spans', []) if s.get('stage') == 'independent_numeric_checker']
    a.expect(len(spans) == 1, 'NUMERIC_CHECKER_INSIDE_COMPLETE_CONTROLLER_WINDOW')
    for family in ('lr', 'rf'):
        matrix = loaded.get(payloads['prepare']['families'][family]['matrix_artifact_id'], {})
        predictions = loaded.get(payloads['predict_' + family]['prediction_artifact_id'], {})
        labels, probabilities = matrix.get('val_y'), predictions.get('positive_probabilities')
        a.expect(predictions.get('row_ids') == matrix.get('val_row_ids') and
                 predictions.get('model_artifact_id') == payloads['fit_' + family]['model_artifact_id'],
                 'NUMERIC_FIXTURE_ARRAY_ROW_AND_MODEL_BINDINGS', family)
        expected = fixture_metrics(labels, probabilities); reported = payloads['summary_' + family]['metrics']
        a.expect(set(expected) == set(reported) and all(abs(reported[k] - v) <= 1e-8 for k, v in expected.items()),
                 'NUMERIC_METRICS_RECOMPUTED_FROM_SAVED_FIXTURE_ARRAYS', family)
        result = receipt.get('families', {}).get(family, {})
        a.expect(result.get('metrics') == expected and result.get('array_rows') == len(labels) and
                 result.get('train_rows_bound') == checked['train']['row_count'] and
                 result.get('validation_rows_bound') == checked['validation']['row_count'] and
                 result.get('fixture_only') is True and result.get('passed') is True,
                 'NUMERIC_RECEIPT_SEPARATES_FIXTURE_ARRAYS_FROM_NEW_DATA_BINDING', family)


def audit_row(row, row_dir, pack=None):
    a = Audit(); directory = Path(row_dir).resolve(); stats = {}
    try:
        item, export, timing = (_read(_safe(directory, name)) for name in ('item.json', 'export.json', 'timing.json'))
        a.expect(item.get('row_id') == row['row_id'], 'EXACT_REGISTERED_ROW_ID')
        for field in ('kind', 'strategy', 'scenario'):
            a.expect(item.get(field) == row[field], 'EXACT_REGISTERED_ROW_FIELDS', field)
        a.expect(item.get('fixture_only') is True and item.get('mode') == 'offline_fixture', 'OFFLINE_FIXTURE_ONLY')
        if pack:
            a.expect(export.get('phase2_row') == row, 'EXPORT_EXACT_REGISTRY_ROW')
            a.expect(export.get('dag') == pack['dag'], 'WORKFLOW_DAG_UNCHANGED')
            binding = export.get('metadata', {}).get('evaluation_binding', {})
            a.expect(binding.get('task_id') == row['task_id'] and binding.get('pack_sha256') == pack['freeze_sha256'],
                     'EXPLICIT_NEW_TASK_AND_PACK_BINDING')
        pins = item.get('evidence_sha256', {})
        a.expect({'workflow.sqlite', 'export.json', 'timing.json', 'terminal.json',
                  'transport_events.json', 'artifact_manifest.json'} <= set(pins), 'COMPLETE_EVIDENCE_PINS')
        for name, expected in pins.items():
            path = _safe(directory, name)
            a.expect(path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                     'PINNED_EVIDENCE_BYTES', name)
        a.extend(verify_artifacts(directory, export), 'artifacts')
        artifact_root, loaded = _artifacts(export, directory)
        native, commands, dispatches = _database(directory, export, a)
        _shared_protocol(native, commands, dispatches, export, a)
        _correction_limits(native, commands, a)
        local_status = export['state'].get('terminal_status')
        business_view = export
        if local_status == 'completed_local_unresolved_external':
            business_view = {**export, 'state': {**export['state'], 'terminal_status': 'completed_correct'}}
        before = len(a.issues)
        business_correct = _initial_audit(business_view, artifact_root, {**row, 'kind': 'supplement'}, a)
        business_correct = business_correct and len(a.issues) == before
        calls, tools, results, attempts, prefix_ids = _work(export, row['kind'] in ('recovery', 'consumption_recovery'))
        cpu_records = _cpu_bridge(export, directory, row, pack, tools, a)
        for call in calls:
            a.expect(call.get('request_sent') is False and call.get('cost_nano_usd', 0) == 0,
                     'NO_REAL_API_OR_PROVIDER_COST', call['call_id'])
        for tool in tools:
            params = tool.get('parameters', {})
            a.expect(params.get('training_performed') is False and params.get('actual_model_prediction_performed') is False,
                     'NO_TRAINING_OR_PREDICTION', tool['receipt_id'])
        a.expect(len(calls) <= row['call_cap'], 'REGISTERED_CALL_CAP')
        a.expect(len(tools) <= row.get('cpu_job_cap', 60), 'REGISTERED_CPU_CAP')
        a.expect(item.get('call_count') == len(calls) and item.get('cpu_jobs') == len(tools), 'WORK_COUNTS_FROM_RAW')
        dispatched_attempts = [r for r in attempts if r.get('status') != 'not_dispatched']
        a.expect(item.get('recomputed_nodes') == [r['node_id'] for r in dispatched_attempts], 'REDO_FROM_RAW_ATTEMPTS')
        if row['kind'] == 'e2e':
            invalidations = [c['seq'] for c in commands if c['kind'] == 'invalidation_and_compensation']
            first_correction = min(invalidations) if invalidations else 0
            prefix_ids = {c['payload']['package']['result']['result_id'] for c in commands
                          if c['kind'] == 'settle' and c['seq'] < first_correction}
        selected = set(export['state']['selected_by_node'].values()) - {None}
        reused = sorted(prefix_ids & selected) if local_status in ('completed_correct', 'completed_local_unresolved_external') else []
        a.expect(item.get('reused_result_ids', []) == reused, 'REUSE_FROM_ACTUAL_SELECTED_IDS')
        _faults(export, loaded, row, a, pack)
        consumer = _consumer(export, item, row, directory, a)
        _numeric_bridge(export, directory, row, pack, loaded, timing, a)
        a.expect(item.get('status') == item.get('terminal_status') == local_status, 'TERMINAL_CLASSIFICATION_FROM_SQLITE')
        a.expect(item.get('completed_correct') is (local_status == 'completed_correct'), 'SUCCESS_EXCLUDES_SAFE_STOP_AND_EXTERNAL_EFFECT')
        a.expect(not item.get('completed_correct') or business_correct, 'COMPLETION_REQUIRES_INDEPENDENT_BUSINESS')
        a.expect(not (item.get('completed_correct') and item.get('safe_stop')), 'SAFE_STOP_NOT_SUCCESS')
        checks = export.get('supplement_evidence', {}).get('verification_checks', [])
        raw_guards = {g['guard_id']: g for g in native.get('guards', [])}
        for check in checks:
            guard = raw_guards.get(check.get('guard_id'), {})
            a.expect(bool(guard) and check.get('node_id') == guard.get('node_id') and
                     check.get('classification') == guard.get('classification'), 'TIMED_CHECK_FROM_DURABLE_GUARD', check.get('guard_id'))
            a.expect(type(check.get('wall_ns')) is int and check['wall_ns'] >= 0 and
                     type(check.get('controller_cpu_ns')) is int and check['controller_cpu_ns'] >= 0,
                     'GUARD_MEASUREMENTS_NONNEGATIVE', check.get('guard_id'))
        a.expect(item.get('verification_check_count') == len(checks) and
                 item.get('verification_wall_ns') == sum(c['wall_ns'] for c in checks) and
                 item.get('verification_controller_cpu_ns') == sum(c['controller_cpu_ns'] for c in checks),
                 'GUARD_COST_FROM_ALL_DURABLE_CHECKS')
        a.expect(item.get('verification_checks_scope') == 'whole_row_current_kernel', 'GUARD_SCOPE_INCLUDES_ALL_EXECUTION')
        transport = _read(directory / 'transport_events.json')
        a.expect(transport == export.get('transport_receipts'), 'RAW_TRANSPORT_EQUALS_EXPORT')
        by_call = defaultdict(list)
        for event in transport:
            a.expect(event.get('fixture_only') is True and event.get('request_sent') is False, 'SYNTHETIC_TRANSPORT_ONLY')
            by_call[event.get('call_id')].append(event)
        for call in calls:
            events = by_call[call['call_id']]
            a.expect(Counter(e.get('stage') for e in events) == Counter(before=1, after=1), 'ONE_CALL_ONE_RAW_EXCHANGE', call['call_id'])
            for event in events:
                a.expect(event.get('row_id') == row['row_id'] and event.get('node_id') == call['node_id'] and
                         event.get('attempt_id') == call['attempt_id'] and event.get('input_digest') == call['input_digest'],
                         'RAW_CALL_IDENTITY', call['call_id'])
        summary = summarize(timing); closure = timing.get('closure', {})
        a.expect(timing.get('closed') is True and timing.get('summary') == summary and summary['complete_window_recorded'],
                 'COMPLETE_RECOMPUTED_TIMING')
        a.expect(timing.get('item_id') == row['row_id'], 'TIMING_EXACT_ROW')
        a.expect(closure.get('durable_database_probe') is True and closure.get('database_relative_path') == 'workflow.sqlite',
                 'COMMON_WORKFLOW_DATABASE_INSIDE_TIMING')
        a.expect(closure.get('database_state_digest') == _digest(native['state']), 'TIMED_AUTHORITATIVE_STATE_DIGEST')
        a.expect(closure.get('database_sha256') == hashlib.sha256((directory / 'workflow.sqlite').read_bytes()).hexdigest(),
                 'TIMED_CLOSED_DATABASE_BYTES_HASH')
        a.expect(closure.get('active_attempt_ids') == [] and closure.get('terminal_status') == local_status,
                 'CLOSED_TERMINAL_NO_ACTIVE_ATTEMPTS')
        a.expect(native['state'].get('status') == 'terminal' and native['state'].get('active_attempt_ids') == [],
                 'AUTHORITATIVE_TERMINAL_HAS_NO_ACTIVE_ATTEMPTS')
        unknown = native['state'].get('unsettled_call_ids', [])
        a.expect(closure.get('unsettled_call_ids') == unknown and closure.get('held_cost_nano_usd') == len(unknown) * RESERVATION,
                 'UNKNOWN_USAGE_AND_HOLD_SURVIVE_CLOSURE')
        a.expect(local_status != 'completed_correct' or not unknown, 'UNSETTLED_CALLS_NEVER_SUCCESS')
        terminal = _read(directory / 'terminal.json')
        a.expect(terminal.get('terminal_status') == local_status and terminal.get('row_id') == row['row_id'] and
                 terminal.get('worker_launches') == 0 and terminal.get('worker_pids') == [],
                 'RAW_TERMINAL_RECEIPT_AND_NO_WORKER_CLAIM')
        stats = {'terminal_status': local_status, 'completed_correct': bool(item.get('completed_correct') and business_correct),
                 'safe_stop': bool(item.get('safe_stop')), 'new_llm_calls': len(calls), 'new_cpu_jobs': len(tools),
                 'new_call_ids': [c['call_id'] for c in calls], 'recomputed_nodes': [r['node_id'] for r in dispatched_attempts],
                 'reused_result_ids': reused, 'window_wall_ns': summary['recovery_wall_ns'],
                 'consumer': consumer, 'durable_commands': len(commands), 'durable_dispatches': len(dispatches),
                 'cpu_gateway_jobs': len(cpu_records),
                 'fixture_only': True, 'real_training': 0, 'real_prediction': 0, 'real_api_calls': 0}
    except (KeyError, ValueError, TypeError, OSError, IndexError, sqlite3.Error, AttributeError) as exc:
        a.expect(False, 'MALFORMED_UNIFIED_ROW', detail=f'{type(exc).__name__}: {exc}')
    return {'passed': not a.issues, 'checks': a.checks, 'issues': a.issues,
            'row_id': row.get('row_id'), 'fixture_only': True, 'statistics': stats}


def audit_campaign(root, pack=None, require_complete=False):
    try:
        return _campaign(root, pack, require_complete)
    except (KeyError, ValueError, TypeError, OSError, IndexError, sqlite3.Error, AttributeError) as exc:
        return {'passed': False, 'checks': 1, 'issues': [{'code': 'MALFORMED_UNIFIED_CAMPAIGN',
                'detail': f'{type(exc).__name__}: {exc}'}], 'row_audits': [], 'fixture_only': True}


def _campaign(root, pack, require_complete):
    if pack is None:
        from .pack import load_pack
        pack = load_pack()
    root = Path(root).resolve(); a = Audit(); rows = pack['rows']; by_id = {r['row_id']: r for r in rows}
    a.expect(len(rows) == len(by_id) == 74, 'FIXED_74_INDEPENDENT_UNIFIED_ROWS')
    a.expect(sum(r['call_cap'] for r in rows) == 1180, 'REGISTERED_1180_CALL_UPPER_BOUND')
    items = {}; exports = {}; audits = []; physical = set(); raw_after = {}; rows_dir = root / 'rows'
    if rows_dir.is_dir():
        a.expect({p.name for p in rows_dir.iterdir() if p.is_dir()} <= set(by_id), 'NO_UNREGISTERED_OUTPUT_ROWS')
    for row in rows:
        directory = rows_dir / row['row_id']
        if not (directory / 'item.json').is_file():
            continue
        item = _read(directory / 'item.json'); items[row['row_id']] = item
        if item.get('status') == 'not_run_blocked_prefix':
            prefix = rows_dir / row['prefix_row_id'] / 'item.json'
            a.expect(prefix.is_file() and not _read(prefix).get('qualified'), 'BLOCKED_BRANCH_REQUIRES_FAILED_PREFIX')
            a.expect(not (directory / 'workflow.sqlite').exists(), 'BLOCKED_BRANCH_NEVER_DISPATCHED')
            continue
        result = audit_row(row, directory, pack); audits.append(result); a.extend(result, row['row_id'])
        export = _read(directory / 'export.json'); exports[row['row_id']] = export
        calls = _work(export, row['kind'] in ('recovery', 'consumption_recovery'))[0]
        ids = {c['call_id'] for c in calls}
        a.expect(not physical & ids, 'NO_DUPLICATE_PHYSICAL_CALLS'); physical |= ids
        for event in export.get('transport_receipts', []):
            if event.get('stage') == 'after':
                a.expect(event['call_id'] not in raw_after, 'NO_DUPLICATE_RAW_RESPONSE', event['call_id'])
                raw_after[event['call_id']] = event
    for row in rows:
        if row['kind'] in ('recovery', 'consumption_recovery') and row['row_id'] in exports:
            scene_path = rows_dir / row['prefix_row_id'] / 'scene.json'
            a.expect(scene_path.is_file(), 'SHARED_FROZEN_SCENE_PRESENT', row['row_id'])
            if scene_path.is_file():
                scene = _read(scene_path); export = exports[row['row_id']]
                a.expect(export.get('initial_snapshot') == scene and export.get('prefix_digest') == _digest(scene),
                         'IDENTICAL_FROZEN_SCENE_FOR_RECOVERY', row['row_id'])
    database = root / 'budget' / 'ledger.sqlite'
    if database.is_file():
        with closing(sqlite3.connect(database.as_uri() + '?mode=ro&immutable=1', uri=True)) as db:
            state = json.loads(db.execute('SELECT body FROM document WHERE id=1').fetchone()[0])
        known = sum(c['known_nano'] for c in state.get('calls', [])); held = sum(c['held_nano'] for c in state.get('calls', []))
        ledger = {**state, 'campaign_known_nano': known, 'campaign_held_nano': held,
            'historical_known_nano': HISTORICAL_KNOWN, 'historical_held_nano': HISTORICAL_HELD,
            'project_total_nano': HISTORICAL_KNOWN + HISTORICAL_HELD + known + held,
            'simulated_dispatches': len(state.get('calls', [])), 'actual_new_api_cost_nano': 0,
            'pacing_clock': 'virtual_offline_only', 'other_planned_cap_nano': 1_500_000_000,
            'planning_envelope_nano': HISTORICAL_KNOWN + HISTORICAL_HELD + 1_500_000_000 + state['limits']['campaign_nano'],
            'actual_new_api_cost_nano_usd': 0}
        if (root / 'ledger.json').is_file():
            a.expect(_read(root / 'ledger.json') == ledger, 'LEDGER_SIDECAR_EQUALS_RAW_SQLITE')
        _audit_ledger(ledger, by_id, items, physical, raw_after, rows_dir, a, require_complete)
        for call in ledger.get('calls', []):
            response = raw_after.get(call['call_id'], {})
            for key in ('row_id', 'node_id', 'attempt_id', 'input_digest'):
                a.expect(bool(call.get(key)) and call.get(key) == response.get(key),
                         'BUDGET_FULL_DISPATCH_IDENTITY_FROM_RAW_RESPONSE', call['call_id'] + ':' + key)
    elif require_complete:
        a.expect(False, 'DURABLE_CAMPAIGN_LEDGER_REQUIRED')
    if require_complete:
        a.expect(set(items) == set(by_id), 'ALL_74_ROWS_ACCOUNTED')
    return {'passed': not a.issues, 'checks': a.checks, 'issues': a.issues, 'registry_count': len(rows),
            'executed_row_count': len(items), 'row_audits': audits, 'fixture_only': True,
            'physical_llm_calls': len(physical), 'outcomes': dict(Counter(i.get('status') for i in items.values()))}
