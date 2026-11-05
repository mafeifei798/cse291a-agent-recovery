"""Runtime evidence checks shared by all V1 policies, without private oracles.

V1 checks JSON fake-artifact bindings. It does not load an estimator, fit a model,
recompute real-data metrics or claim model-to-prediction execution (V2 work).
"""
import hashlib
import json
import math
from pathlib import Path

from .common import REV, digest, source_fingerprint, selected_graph_digest, read_refs, node_map


_PRIORITY = {'uncertain': 0, 'integrity_error': 0, 'conflict': 1,
             'permission_denied': 1, 'source_drift': 2, 'stale': 3,
             'semantic': 4, 'passed': 5}


def diagnose(view, node_id, checkpoint='pre_dispatch', candidate=None, full=False, artifact_root=None):
    # Identity must use the persisted checkpoint, including full diagnoses.
    if full and checkpoint != 'precommit':
        checkpoint = 'post_refusal_full_diagnosis'
    state, dag = view['state'], view['dag']
    results = list(view['results'])
    if candidate and candidate['result_id'] not in {r['result_id'] for r in results}:
        results.append(candidate)
    by_id = {r['result_id']: r for r in results}
    sources = list(view['sources'])
    current = {s['object_key']: s for s in sources}
    history_rows = view.get('source_history', [])
    if isinstance(history_rows, dict):
        history_rows = history_rows.get('sources', [])
    authority_versions = {}
    for source in list(history_rows) + sources:
        identity = (source['object_key'], source['version'])
        authority_versions.setdefault(identity, []).append(source)
    selected = state['selected_by_node']
    nodes = node_map(dag)
    receipts = {r['receipt_id']: r for r in view.get('tool_receipts', [])}
    calls = {r['call_id']: r for r in view.get('calls', [])}
    artifacts_list = view.get('artifacts', [])
    if isinstance(artifacts_list, dict):
        artifacts_list = artifacts_list.get('artifacts', list(artifacts_list.values()))
    artifacts = {r['artifact_id']: r for r in artifacts_list}
    root = Path(artifact_root).resolve() if artifact_root is not None else None
    issues, classes, checked_artifacts = [], [], set()
    artifact_values = {}

    def issue(cls, code, field, related=(), refs=(), **extra):
        value = {'code': code, 'field_path': field,
                 'related_result_ids': sorted(set(r for r in related if r)),
                 'evidence_refs': list(dict.fromkeys(str(r) for r in refs if r))}
        value.update(extra)
        if value not in issues:
            issues.append(value)
            classes.append(cls)

    def artifact_value(aid, result_id=None):
        if aid in checked_artifacts:
            return artifact_values.get(aid)
        checked_artifacts.add(aid)
        art = artifacts.get(aid)
        if art is None:
            issue('integrity_error', 'MISSING_ARTIFACT', 'artifacts.' + aid, [result_id], [aid])
            return None
        if root is None:
            issue('integrity_error', 'ARTIFACT_ROOT_REQUIRED', 'artifacts.' + aid, [result_id], [aid])
            return None
        path = (root / art['uri']).resolve()
        if not path.is_relative_to(root):
            issue('integrity_error', 'ARTIFACT_PATH_ESCAPE', 'artifacts.' + aid, [result_id], [aid])
            return None
        try:
            raw = path.read_bytes()
        except OSError:
            issue('integrity_error', 'MISSING_ARTIFACT_BYTES', 'artifacts.' + aid, [result_id], [aid])
            return None
        if len(raw) != art['size_bytes'] or hashlib.sha256(raw).hexdigest() != art['sha256']:
            issue('integrity_error', 'ARTIFACT_HASH_MISMATCH', 'artifacts.' + aid, [result_id], [aid])
            return None
        if art.get('media_type') == 'application/json':
            try:
                artifact_values[aid] = json.loads(raw)
            except (ValueError, UnicodeDecodeError):
                issue('integrity_error', 'INVALID_JSON_ARTIFACT', 'artifacts.' + aid, [result_id], [aid])
        return artifact_values.get(aid)

    fp = source_fingerprint(sources)
    if fp != state['source_fingerprint']:
        issue('source_drift', 'SOURCE_DRIFT_AFTER_FREEZE', 'state.source_fingerprint', refs=[fp, state['source_fingerprint']])
    if len(current) != len(sources):
        issue('integrity_error', 'DUPLICATE_AUTHORITY_KEY', 'sources')
    for source in sources:
        if digest(source['payload']) != source['payload_digest']:
            issue('integrity_error', 'SOURCE_PAYLOAD_DIGEST_MISMATCH', 'sources.' + source['object_key'], refs=[source['object_key']])
        if source['object_key'].startswith('permission') and source['payload'].get('allowed') is not True:
            issue('permission_denied', 'PERMISSION_DENIED', 'sources.' + source['object_key'], refs=[source['object_key']])
    request = view.get('task', {}).get('request', view.get('task', {}).get('public_request', {}))
    if request.get('publish_allowed') is False:
        issue('permission_denied', 'PUBLISH_PERMISSION_DENIED', 'request.publish_allowed')
    if len(by_id) != len(results):
        issue('integrity_error', 'DUPLICATE_RESULT_ID', 'results')

    visited, visiting, actual = set(), set(), []
    invalid = set(state['invalidated_result_ids'])

    def walk(rid, allow_rejected=False):
        if rid in visiting:
            issue('integrity_error', 'ANCESTRY_CYCLE', 'results.' + rid, [rid], [rid])
            return []
        if rid in visited:
            return by_id.get(rid, {}).get('effective_reads', [])
        r = by_id.get(rid)
        if r is None:
            issue('integrity_error', 'MISSING_ACTUAL_ANCESTOR', 'results.' + str(rid), [rid], [rid])
            return []
        visiting.add(rid)
        actual.append(r)
        if rid in invalid:
            issue('integrity_error', 'INVALIDATED_RESULT_CONSUMED', r['node_id'], [rid], [rid])
        if r['execution_status'] != 'success' and not (allow_rejected and r['execution_status'] == 'validation_rejected'):
            issue('uncertain' if r['execution_status'] == 'uncertain' else 'integrity_error',
                  'NON_SUCCESS_ANCESTOR', r['node_id'], [rid], [rid])
        node = nodes.get(r['node_id'])
        if node is None:
            issue('integrity_error', 'UNKNOWN_NODE', r['node_id'], [rid], [rid])
            node = {'parents': [], 'llm_calls_per_execution': 0, 'cpu_jobs_per_execution': 0}
        parent_rows = [by_id[p] for p in r['parent_result_ids'] if p in by_id]
        if sorted(p['node_id'] for p in parent_rows) != sorted(node['parents']):
            issue('integrity_error', 'ACTUAL_PARENT_SET_MISMATCH', r['node_id'] + '.parent_result_ids', [rid], r['parent_result_ids'])
        inherited = []
        for parent in r['parent_result_ids']:
            inherited.extend(walk(parent))
        aliases = view.get('source_aliases', view.get('task', {}).get('resolved_source_aliases', {}))
        expected_direct = {aliases.get(key, key) for key in node.get('direct_source_keys', [])}
        if {ref['object_key'] for ref in r['direct_reads']} != expected_direct:
            issue('integrity_error', 'DIRECT_SOURCE_SET_MISMATCH', r['node_id'] + '.direct_reads', [rid], [rid])
        all_reads = inherited + r['direct_reads']
        versions = {}
        for ref in all_reads:
            versions.setdefault(ref['object_key'], set()).add(ref['version'])
        mixed = {key: vals for key, vals in versions.items() if len(vals) > 1}
        if mixed:
            issue('stale', 'PROVABLE_MIXED_READ_VERSIONS', r['node_id'] + '.effective_reads', [rid], [rid] + sorted(mixed))
        derived = sorted((k, v) for k, versions_set in versions.items() for v in versions_set)
        declared = sorted((v['object_key'], v['version']) for v in r['effective_reads'])
        if not mixed and derived != declared:
            issue('integrity_error', 'EFFECTIVE_READ_SET_MISMATCH', r['node_id'] + '.effective_reads', [rid], [rid])
        for ref in r['effective_reads'] + r['direct_reads']:
            key = ref['object_key']
            if key not in current:
                issue('integrity_error', 'UNKNOWN_SOURCE_KEY', r['node_id'] + '.effective_reads', [rid], [rid, key])
            elif ref['version'] != current[key]['version']:
                issue('stale', 'STALE_EFFECTIVE_READ', r['node_id'] + '.effective_reads.' + key,
                      [rid], [rid, key + '@' + str(ref['version']), key + '@' + str(current[key]['version'])],
                      object_key=key, observed_version=ref['version'], current_version=current[key]['version'])
        snapshot = r.get('input_snapshot')
        if snapshot is None or digest(snapshot) != r['input_digest']:
            issue('integrity_error', 'INPUT_DIGEST_MISMATCH', r['node_id'] + '.input_digest', [rid], [rid])
        else:
            input_bindings = snapshot.get('artifact_bindings', [])
            ancestry_ids, source_artifact_ids = set(), set()
            todo = list(r['parent_result_ids'])
            while todo:
                parent_id = todo.pop()
                if parent_id in ancestry_ids:
                    continue
                ancestry_ids.add(parent_id)
                parent = by_id.get(parent_id)
                if parent:
                    todo.extend(parent['parent_result_ids'])
                    for direct in parent.get('input_snapshot', {}).get('direct_source_inputs', []):
                        source_artifact_ids.update(direct.get('artifact_refs', []))
            for direct in snapshot.get('direct_source_inputs', []):
                source_artifact_ids.update(direct.get('artifact_refs', []))
            allowed_artifacts = source_artifact_ids | {aid for aid, binding in artifacts.items()
                                                       if binding['producer_result_id'] in ancestry_ids}
            for binding in input_bindings:
                if binding['artifact_id'] not in allowed_artifacts:
                    issue('integrity_error', 'INPUT_ARTIFACT_OUTSIDE_ACTUAL_ANCESTRY', r['node_id'] + '.input_snapshot.artifact_bindings', [rid], [rid, binding['artifact_id']])
            if len({binding['artifact_id'] for binding in input_bindings}) != len(input_bindings):
                issue('integrity_error', 'DUPLICATE_INPUT_ARTIFACT_BINDING', r['node_id'] + '.input_snapshot.artifact_bindings', [rid], [rid])
            for binding in input_bindings:
                aid = binding['artifact_id']
                if artifacts.get(aid) != binding:
                    issue('integrity_error', 'INPUT_ARTIFACT_MANIFEST_MISMATCH', r['node_id'] + '.input_snapshot.artifact_bindings', [rid], [rid, aid])
                value = artifact_value(aid, rid)
                if 'artifact_values' in snapshot and snapshot['artifact_values'].get(aid) != value:
                    issue('integrity_error', 'INPUT_ARTIFACT_VALUE_MISMATCH', r['node_id'] + '.input_snapshot.artifact_values', [rid], [rid, aid])
            if 'artifact_values' in snapshot and set(snapshot['artifact_values']) != {binding['artifact_id'] for binding in input_bindings}:
                issue('integrity_error', 'INPUT_ARTIFACT_VALUE_SET_MISMATCH', r['node_id'] + '.input_snapshot.artifact_values', [rid], [rid])
            # The fake adapter consumes the serialized user message, so it
            # must represent this same bound input, not a second hidden context.
            # Old CPU-only V0 snapshots have neither optional field.
            if 'artifact_values' in snapshot and 'rendered_messages' not in snapshot:
                issue('integrity_error', 'INPUT_RENDERED_MESSAGE_REQUIRED', r['node_id'] + '.input_snapshot.rendered_messages', [rid], [rid])
            if 'rendered_messages' in snapshot:
                messages = snapshot['rendered_messages']
                users = [message for message in messages if isinstance(message, dict) and message.get('role') == 'user'] if isinstance(messages, list) else []
                core = {key: value for key, value in snapshot.items() if key != 'rendered_messages'}
                try:
                    rendered = json.loads(users[0]['content']) if len(users) == 1 else None
                except (KeyError, TypeError, ValueError):
                    rendered = None
                if rendered != core:
                    issue('integrity_error', 'INPUT_RENDERED_MESSAGE_MISMATCH', r['node_id'] + '.input_snapshot.rendered_messages', [rid], [rid])
            recorded_sources = snapshot.get('direct_source_inputs', [])
            recorded_refs = sorted((item['object_key'], item['version']) for item in recorded_sources)
            if recorded_refs != sorted((ref['object_key'], ref['version']) for ref in r['direct_reads']):
                issue('integrity_error', 'INPUT_DIRECT_READ_BINDING_MISMATCH', r['node_id'] + '.input_snapshot.direct_source_inputs', [rid], [rid])
            for item in recorded_sources:
                authority = current.get(item['object_key'])
                known_bindings = authority_versions.get((item['object_key'], item['version']), [])
                if not known_bindings or not any(
                        known['payload_digest'] == item['payload_digest'] and
                        known.get('artifact_refs', []) == item.get('artifact_refs', []) and
                        known['payload'] == item['payload'] for known in known_bindings):
                    issue('integrity_error', 'UNVERIFIED_SOURCE_HISTORY_BINDING', r['node_id'] + '.input_snapshot.direct_source_inputs', [rid], [rid, item['object_key'] + '@' + str(item['version'])])
                if digest(item['payload']) != item['payload_digest'] or (authority and item['version'] == authority['version'] and item['payload_digest'] != authority['payload_digest']):
                    issue('integrity_error', 'INPUT_SOURCE_PAYLOAD_MISMATCH', r['node_id'] + '.input_snapshot.direct_source_inputs', [rid], [rid, item['object_key']])
                for aid in item.get('artifact_refs', []):
                    artifact_value(aid, rid)
            actual_parents = {p['result_id']: p for p in snapshot.get('parent_inputs', [])}
            if set(actual_parents) != set(r['parent_result_ids']):
                issue('integrity_error', 'INPUT_PARENT_ID_MISMATCH', r['node_id'] + '.input_snapshot.parent_inputs', [rid], [rid])
            for prid, parent_input in actual_parents.items():
                parent = by_id.get(prid)
                if parent and (parent_input.get('payload_digest') != digest(parent['payload']) or parent_input.get('payload') != parent['payload'] or parent_input.get('effective_reads') != parent['effective_reads']):
                    issue('integrity_error', 'ACTUAL_PARENT_PAYLOAD_MISMATCH', r['node_id'] + '.input_snapshot', [rid], [rid, prid])
        for aid in r['artifact_refs']:
            artifact_value(aid, rid)
            if aid in artifacts and artifacts[aid]['producer_result_id'] != rid:
                issue('integrity_error', 'ARTIFACT_PRODUCER_MISMATCH', r['node_id'] + '.artifact_refs', [rid], [aid, rid])
        if node['llm_calls_per_execution'] and not r['call_ids']:
            issue('integrity_error', 'MISSING_CALL_EVIDENCE', r['node_id'] + '.call_ids', [rid], [rid])
        if node['cpu_jobs_per_execution'] and not r['tool_receipt_ids']:
            issue('integrity_error', 'MISSING_TOOL_RECEIPT', r['node_id'] + '.tool_receipt_ids', [rid], [rid])
        for key, ids, evidence in [('call_ids', r['call_ids'], calls), ('tool_receipt_ids', r['tool_receipt_ids'], receipts)]:
            for identity in ids:
                receipt = evidence.get(identity)
                if receipt is None or any(receipt.get(f) != r.get(f) for f in ['run_id', 'node_id', 'attempt_id', 'input_digest']):
                    issue('integrity_error', 'RECEIPT_IDENTITY_MISMATCH', r['node_id'] + '.' + key, [rid], [rid, identity])
                elif key == 'tool_receipt_ids' and receipt['producer_result_id'] != rid:
                    issue('integrity_error', 'TOOL_PRODUCER_MISMATCH', r['node_id'] + '.' + key, [rid], [rid, identity])
        visiting.remove(rid)
        visited.add(rid)
        return r['effective_reads']

    if full:
        roots = [rid for rid in selected.values() if rid]
    elif candidate:
        roots = [candidate['result_id']]
    else:
        if node_id not in nodes:
            issue('integrity_error', 'UNKNOWN_DISPATCH_NODE', 'node_id', refs=[node_id])
            roots = []
        else:
            roots = []
            for parent_node in nodes[node_id]['parents']:
                rid = selected.get(parent_node)
                if rid:
                    roots.append(rid)
                else:
                    issue('integrity_error', 'MISSING_SELECTED_PARENT', node_id + '.parents', refs=[parent_node])
    for rid in roots:
        walk(rid, allow_rejected=bool(candidate and rid == candidate['result_id']))
    if checkpoint in ('precommit', 'post_tool'):
        for source in sources:
            for aid in source['artifact_refs']:
                artifact_value(aid)
    if checkpoint == 'precommit' and candidate:
        attempts = view.get('attempts', [])
        attempt = next((a for a in attempts if a['attempt_id'] == candidate['attempt_id']), None)
        if attempt is not None and 'target_before' in attempt:
            before = attempt['target_before']
            expected_keys = {'config', 'draft'} if candidate['node_id'] == 'execute' else {'manifest', 'report_index'}
            if set(before) != expected_keys:
                issue('integrity_error', 'OUTPUT_GROUP_EXPECTATION_MISSING', 'attempt.target_before',
                      [candidate['result_id']], [candidate['attempt_id']])
            for key, expected in before.items():
                if view.get('objects', {}).get(key) != expected:
                    issue('conflict', 'OUTPUT_GROUP_PRECONDITION_CONFLICT', 'objects.' + key,
                          [candidate['result_id']], [candidate['attempt_id'], key])
    # Semantic checks apply only at the common final business gate, not as an
    # oracle at every intermediate node. Post-tool checks retain raw corruption.
    if checkpoint == 'precommit':
        if dag['workflow_id'].startswith('sr-v2.micro'):
            _micro_business(current, selected, by_id, request, candidate, issue, artifact_value)
        else:
            _macro_business(current, selected, by_id, receipts, artifact_value, request, candidate, issue)
    classification = min(classes, key=lambda c: _PRIORITY[c]) if classes else 'passed'
    graph_hash = selected_graph_digest(selected, results)
    evidence = {
        'record_type': 'GuardEvidence', 'revision': REV,
        'guard_id': 'v1.guard.' + digest({'branch_id': state['branch_id'], 'state_version': state['state_version'],
            'node_id': node_id, 'checkpoint': checkpoint, 'full': full,
            'candidate': candidate['result_id'] if candidate else None, 'issues': issues, 'graph': graph_hash, 'sources': fp})[:24],
        'run_id': state['run_id'], 'node_id': node_id,
        'candidate_result_id': candidate['result_id'] if candidate else None,
        'checkpoint': checkpoint,
        'classification': classification, 'issues': issues,
        'selected_graph_digest': graph_hash, 'source_fingerprint': fp,
        'current_sources': read_refs(sources), 'full_version_diagnosis': bool(full),
        'source_drift_after_freeze': fp != state['source_fingerprint'],
        'feedback': {'failed_constraints': sorted(set(i['code'] for i in issues)),
                     'field_paths': sorted(set(i['field_path'] for i in issues)),
                     'evidence_refs': sorted(set(r for i in issues for r in i['evidence_refs']))},
        'fixture_only': True,
    }
    evidence['diagnostic_digest'] = digest(evidence)
    return evidence


def _micro_business(current, selected, by_id, request, candidate, issue, artifact_value):
    def source(prefix):
        return next((s['payload'] for k, s in current.items() if k.startswith(prefix)), {})
    metadata, permission, resources = source('metadata'), source('permission'), source('resource')
    expected = dict(request)
    n = metadata.get('num_examples', metadata.get('n'))
    if not isinstance(n, int) or n < 0 or not isinstance(request.get('batch_size'), int) or request['batch_size'] <= 0:
        issue('integrity_error', 'INVALID_AUTHORITATIVE_BUSINESS_INPUT', 'sources.metadata')
        return
    expected.update(num_examples=n, steps=((n + request['batch_size'] - 1) // request['batch_size']) * request['epochs'],
                    workers=min(request['requested_workers'], resources.get('max_workers', 0)))
    expected['policy_revision'] = permission.get('policy_revision')
    expected['allowed'] = permission.get('allowed')
    rows = {node: by_id.get(rid) for node, rid in selected.items()}
    if candidate:
        rows[candidate['node_id']] = candidate
    for node in ['read_metadata', 'read_permission', 'read_resources', 'plan', 'execute']:
        result = rows.get(node)
        if not result:
            continue
        payload = result.get('payload') or {}
        if node == 'read_metadata':
            fields = ['dataset_id', 'num_examples']
        elif node == 'read_permission':
            fields = ['dataset_id', 'purpose', 'policy_revision']
            if payload.get('allowed') is not True:
                issue('semantic', 'COPIED_PERMISSION_MISMATCH', node + '.allowed', [result['result_id']], [result['result_id']])
        elif node == 'read_resources':
            fields = []
            if payload.get('max_workers') != resources.get('max_workers'):
                issue('semantic', 'COPIED_RESOURCE_MISMATCH', node + '.max_workers', [result['result_id']], [result['result_id']])
        else:
            fields = ['dataset_id', 'purpose', 'batch_size', 'epochs', 'requested_workers', 'num_examples', 'steps', 'workers', 'policy_revision', 'allowed']
        body = payload.get('config', payload)
        for field in fields:
            actual = body.get(field, body.get('n') if field == 'num_examples' else None)
            if actual != expected.get(field):
                issue('semantic', 'BUSINESS_FIELD_MISMATCH', node + '.' + field, [result['result_id']], [result['result_id']])
    plan, execute = rows.get('plan'), rows.get('execute')
    if plan and execute:
        command = (execute['payload'] or {}).get('command')
        planned = plan['payload'].get('command', plan['payload'].get('config', plan['payload']))
        if command != planned:
            issue('semantic', 'COMMAND_DIFFERS_FROM_PLAN', 'execute.command', [execute['result_id']], [execute['result_id'], plan['result_id']])
        for aid in execute['artifact_refs']:
            stored = artifact_value(aid, execute['result_id'])
            if stored is not None:
                stored_command = stored.get('command', stored)
                if stored_command != command:
                    issue('semantic', 'EXECUTE_ARTIFACT_COMMAND_MISMATCH', 'execute.artifacts', [execute['result_id']], [aid, execute['result_id']])


def _macro_business(current, selected, by_id, receipts, artifact_value, request, candidate, issue):
    rows = {node: by_id.get(rid) for node, rid in selected.items()}
    if candidate:
        rows[candidate['node_id']] = candidate
    train_ids = current.get('data:train', {}).get('payload', {}).get('row_ids')
    prepare = rows.get('prepare')
    if prepare and train_ids is not None and prepare['payload'].get('training_row_ids') != train_ids:
        issue('semantic', 'PREPARE_TRAINING_ROWS_MISMATCH', 'prepare.training_row_ids', [prepare['result_id']], [prepare['result_id'], 'data:train'])
    ap = {}
    for family in ['lr', 'rf']:
        plan, fit, prediction, summary = [rows.get(n + '_' + family) for n in ['plan', 'fit', 'predict', 'summary']]
        recipe = current.get('recipe:' + family, {}).get('payload', {})
        prepared_family = prepare['payload'].get('families', {}).get(family, {}) if prepare else {}
        expected_matrix = prepared_family.get('matrix_artifact_id')
        expected_preprocessor = prepared_family.get('preprocessor_artifact_id')
        if prepare:
            for field, aid in [('matrix_artifact_id', expected_matrix), ('preprocessor_artifact_id', expected_preprocessor)]:
                if not aid or aid not in prepare['artifact_refs']:
                    issue('semantic', 'PREPARE_ARTIFACT_BINDING_MISMATCH', 'prepare.' + family + '.' + field, [prepare['result_id']], [prepare['result_id']])
                elif aid:
                    prepared_artifact = artifact_value(aid, prepare['result_id'])
                    if prepared_artifact:
                        row_key = 'train_row_ids' if field == 'matrix_artifact_id' else 'training_row_ids'
                        if train_ids is not None and prepared_artifact.get(row_key) != train_ids:
                            issue('semantic', 'PREPROCESS_TRAINING_ROWS_MISMATCH', 'prepare.' + family + '.' + row_key, [prepare['result_id']], [aid])
                        if field == 'matrix_artifact_id' and prepared_artifact.get('val_row_ids') != prepare['payload'].get('validation_row_ids'):
                            issue('semantic', 'MATRIX_VALIDATION_ROWS_MISMATCH', 'prepare.' + family + '.val_row_ids', [prepare['result_id']], [aid])
        if plan:
            planned = plan['payload'].get('parameters', plan['payload'].get('model_parameters'))
            if planned != recipe.get('parameters'):
                issue('semantic', 'PLAN_RECIPE_MISMATCH', 'plan_' + family + '.parameters', [plan['result_id']], [plan['result_id'], 'recipe:' + family])
        if fit:
            for receipt_id in fit['tool_receipt_ids']:
                receipt = receipts.get(receipt_id, {})
                if receipt.get('parameters', {}).get('model_parameters') != recipe.get('parameters'):
                    issue('semantic', 'FIT_RECIPE_MISMATCH', 'fit_' + family + '.parameters', [fit['result_id']], [fit['result_id'], receipt_id])
            for aid in fit['artifact_refs']:
                model = artifact_value(aid, fit['result_id'])
                if model:
                    if model.get('matrix_artifact_id') != expected_matrix:
                        issue('semantic', 'MODEL_MATRIX_BINDING_MISMATCH', 'fit_' + family + '.matrix_artifact_id', [fit['result_id']], [aid])
                    if model.get('parameters') != recipe.get('parameters'):
                        issue('semantic', 'MODEL_RECIPE_MISMATCH', 'fit_' + family + '.artifact.parameters', [fit['result_id']], [aid])
                    if train_ids is not None and model.get('training_row_ids') != train_ids:
                        issue('semantic', 'MODEL_TRAINING_ROWS_MISMATCH', 'fit_' + family + '.artifact.training_row_ids', [fit['result_id']], [aid])
        if prediction:
            for aid in prediction['artifact_refs']:
                pred = artifact_value(aid, prediction['result_id'])
                if pred and pred.get('preprocessor_artifact_id') != expected_preprocessor:
                    issue('semantic', 'PREDICTION_PREPROCESSOR_BINDING_MISMATCH', 'predict_' + family + '.preprocessor_artifact_id', [prediction['result_id']], [aid])
                if pred and fit and pred.get('model_artifact_id') not in fit['artifact_refs']:
                    issue('semantic', 'PREDICTION_MODEL_BINDING_MISMATCH', 'predict_' + family + '.model_artifact_id', [prediction['result_id']], [aid, fit['result_id']])
                if pred and prepare and pred.get('row_ids') != prepare['payload'].get('validation_row_ids'):
                    issue('semantic', 'PREDICTION_VALIDATION_ROWS_MISMATCH', 'predict_' + family + '.row_ids', [prediction['result_id']], [aid, prepare['result_id']])
        if summary:
            metrics = summary['payload'].get('metrics', {})
            raw_receipts = [receipts[r] for r in summary['tool_receipt_ids'] if r in receipts]
            raw = next((r['parameters']['unmodified_metrics'] for r in raw_receipts if 'unmodified_metrics' in r.get('parameters', {})), None)
            if raw is None:
                issue('integrity_error', 'MISSING_RAW_METRIC_RECEIPT', 'summary_' + family, [summary['result_id']], summary['tool_receipt_ids'])
            elif metrics != raw:
                issue('semantic', 'SUMMARY_DIFFERS_FROM_TOOL_METRICS', 'summary_' + family + '.metrics', [summary['result_id']], [summary['result_id']] + summary['tool_receipt_ids'])
            if raw is not None:
                ap[family.upper()] = raw.get('average_precision')
                if any(not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or not 0 <= value <= 1 for value in raw.values()):
                    issue('integrity_error', 'INVALID_RAW_METRIC_VALUE', 'summary_' + family + '.metrics', [summary['result_id']], summary['tool_receipt_ids'])
            for aid in summary['artifact_refs']:
                metric_art = artifact_value(aid, summary['result_id'])
                if metric_art and metric_art.get('metrics') != raw:
                    issue('semantic', 'METRICS_ARTIFACT_DIFFERS_FROM_RECEIPT', 'summary_' + family + '.artifact.metrics', [summary['result_id']], [aid])
                if metric_art and prediction and metric_art.get('prediction_artifact_id') not in prediction['artifact_refs']:
                    issue('semantic', 'METRIC_PREDICTION_BINDING_MISMATCH', 'summary_' + family + '.prediction_artifact_id', [summary['result_id']], [aid])
    report = rows.get('report')
    if report and set(ap) == {'LR', 'RF'} and all(isinstance(x, (int, float)) for x in ap.values()):
        payload = report['payload']
        chosen = 'LR' if ap['LR'] + request.get('tie_break', {}).get('epsilon', 1e-6) >= ap['RF'] else 'RF'
        if payload.get('validation_average_precision') != ap or payload.get('chosen_family') != chosen:
            issue('semantic', 'REPORT_SELECTION_MISMATCH', 'report.validation_average_precision', [report['result_id']], [report['result_id']])
        for field, parent_node in [('model_artifact_id', 'fit_' + chosen.lower()), ('prediction_artifact_id', 'predict_' + chosen.lower())]:
            parent = rows.get(parent_node)
            if parent and payload.get(field) not in parent['artifact_refs']:
                issue('semantic', 'REPORT_ARTIFACT_BINDING_MISMATCH', 'report.' + field, [report['result_id']], [report['result_id'], parent['result_id']])

    publish = rows.get('publish')
    if publish:
        payload = publish['payload']
        if payload.get('action') != 'publish_manifest':
            issue('semantic', 'PUBLISH_ACTION_MISMATCH', 'publish.action', [publish['result_id']], [publish['result_id']])
        candidate_id = payload.get('candidate_artifact_id')
        if candidate_id not in publish['artifact_refs']:
            issue('semantic', 'PUBLISH_CANDIDATE_BINDING_MISMATCH', 'publish.candidate_artifact_id', [publish['result_id']], [publish['result_id']])
        manifest = artifact_value(candidate_id, publish['result_id']) if candidate_id else None
        if report:
            if manifest:
                for field in ['model_artifact_id', 'prediction_artifact_id']:
                    if field in manifest and manifest[field] != report['payload'].get(field):
                        issue('semantic', 'PUBLISH_MANIFEST_REPORT_MISMATCH', 'publish.manifest.' + field, [publish['result_id']], [candidate_id, report['result_id']])
                report_id = manifest.get('report_artifact_id')
                report_document = artifact_value(report_id, report['result_id']) if report_id else None
                if not report_document:
                    issue('semantic', 'PUBLISH_REPORT_DOCUMENT_MISSING', 'publish.manifest.report_artifact_id', [publish['result_id']], [candidate_id])
                else:
                    for field in ['chosen_family', 'validation_average_precision', 'model_artifact_id', 'prediction_artifact_id', 'report_text']:
                        if report_document.get(field) != report['payload'].get(field):
                            issue('semantic', 'REPORT_DOCUMENT_PAYLOAD_MISMATCH', 'report.artifact.' + field, [report['result_id']], [report_id, report['result_id']])
            for field in ['chosen_family', 'model_artifact_id', 'prediction_artifact_id']:
                if field in payload and payload[field] != report['payload'].get(field):
                    issue('semantic', 'PUBLISH_REPORT_BINDING_MISMATCH', 'publish.' + field, [publish['result_id']], [publish['result_id'], report['result_id']])
            if 'report_result_id' in payload and payload['report_result_id'] != report['result_id']:
                issue('semantic', 'PUBLISH_REPORT_ID_MISMATCH', 'publish.report_result_id', [publish['result_id']], [publish['result_id'], report['result_id']])
