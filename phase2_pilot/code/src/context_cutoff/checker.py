"""Read-only audit of saved pilot evidence, independent of runtime/recovery.

Passing this audit establishes record consistency, not model quality. In
particular, fixture outputs are not evidence of real inference or CPU work.
The hidden task policy is supplied outside the messages sent to the model.
"""
from copy import deepcopy

from .contracts import REVISION, normalize_contract
from sr_recovery_v2.common import digest


OUTCOMES = {
    'correct_complete', 'safe_stop', 'wrong_complete',
    'infrastructure_failure', 'not_reached', 'external_unresolved',
}


def _hash(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in '0123456789abcdef' for c in value))


def check_contract(contract, allowed_features, data_binding, code_sha256,
                   prediction_time='pre_call'):
    """Validate execution fields against independently supplied task truth.

    ``duration`` is forbidden for prediction before a call. This is a task
    restriction, not a claim that the column is invalid for every Bank task.
    Feature order is execution-significant and must never be sorted away.
    """
    issues = []
    try:
        normalized = normalize_contract(contract)
    except (TypeError, KeyError, ValueError, RuntimeError) as exc:
        return {'passed': False, 'issues': [getattr(exc, 'code', 'CONTRACT_FORMAT')]}
    if not isinstance(allowed_features, (list, tuple, set)):
        issues.append('TASK_FEATURE_POLICY_MISSING')
        allowed_features = []
    features = normalized['feature_columns']
    if not set(features).issubset(set(allowed_features)) or 'y' in features:
        issues.append('CONTRACT_FEATURE_POLICY')
    if prediction_time == 'pre_call' and 'duration' in features:
        issues.append('PRE_CALL_DURATION_FORBIDDEN')
    if normalized['data_binding'] != data_binding:
        issues.append('CONTRACT_DATA_BINDING')
    if not all(_hash(v) for v in normalized['data_binding'].values()):
        issues.append('CONTRACT_BINDING_HASH')
    if normalized['code_sha256'] != code_sha256 or not _hash(code_sha256):
        issues.append('CONTRACT_CODE_BINDING')
    return {'passed': not issues, 'issues': issues}


def _producer_ids(message):
    result = set()
    for key in ('producer_result_id', 'source_result_id', 'result_id'):
        if message.get(key):
            result.add(message[key])
    for key in ('producer_result_ids', 'source_result_ids'):
        result.update(message.get(key, []))
    return result


def _file_key(ref):
    return (ref['file_id'], ref['version'])


def _same_file(left, right):
    return all(left.get(k) == right.get(k)
               for k in ('file_id', 'version', 'sha256', 'writer_id'))


def audit_run(document):
    """Rebuild observed edges and audit one saved run without executing it.

    The audit intentionally accepts a valid ``wrong_complete`` result: record
    validity and task correctness are separate axes. No runtime/recovery
    implementation is imported here.
    """
    issues, checks = [], {}

    def check(name, passed, detail=''):
        checks[name] = checks.get(name, True) and bool(passed)
        if not passed:
            issues.append(name + (':' + str(detail) if detail else ''))

    if not isinstance(document, dict):
        return {'passed': False, 'checks': {'DOCUMENT': False}, 'issues': ['DOCUMENT']}
    check('REVISION', document.get('revision') == REVISION)
    check('RUN_ID', isinstance(document.get('run_id'), str) and bool(document['run_id']))
    check('MODE', document.get('mode') in ('FULL_HISTORY', 'SCOPED'))
    check('EVIDENCE_SCOPE', type(document.get('fixture_only')) is bool)
    fixture_only = document.get('fixture_only') is True

    def indexed(items, key, name):
        result = {}
        if not isinstance(items, list):
            check(name, False, 'not-list')
            return result
        for item in items:
            good = isinstance(item, dict) and isinstance(item.get(key), str) and bool(item[key])
            check(name, good)
            if good:
                check(name + '_UNIQUE', item[key] not in result, item[key])
                result[item[key]] = item
        return result

    messages = indexed(document.get('messages', []), 'message_id', 'MESSAGES')
    calls = indexed(document.get('llm_calls', []), 'call_id', 'LLM_CALLS')
    tools = indexed(document.get('tool_calls', []), 'tool_call_id', 'TOOL_CALLS')
    nodes = indexed(document.get('nodes', []), 'result_id', 'NODES')
    history = {}
    for ref in document.get('file_history', []):
        good = (isinstance(ref, dict) and all(k in ref for k in
                ('file_id', 'version', 'sha256', 'writer_id')))
        check('FILE_REF_FORMAT', good)
        if not good:
            continue
        key = _file_key(ref)
        check('FILE_HASH', _hash(ref['sha256']), key)
        check('FILE_VERSION', type(ref['version']) is int and ref['version'] > 0, key)
        check('FILE_HISTORY_UNIQUE', key not in history, key)
        history[key] = ref
    current = document.get('files', [])
    if isinstance(current, dict):
        check('CURRENT_FILE_KEYS', all(k == v.get('file_id') for k, v in current.items()))
        current = list(current.values())
    current_map = {}
    for ref in current:
        try:
            check('CURRENT_FILE_HISTORY', _file_key(ref) in history
                  and _same_file(ref, history[_file_key(ref)]), ref.get('file_id'))
            check('CURRENT_FILE_UNIQUE', ref['file_id'] not in current_map, ref['file_id'])
            versions = [v for (f, v) in history if f == ref['file_id'] and type(v) is int]
            check('CURRENT_FILE_LATEST', bool(versions) and ref['version'] == max(versions), ref['file_id'])
            current_map[ref['file_id']] = ref
        except (KeyError, TypeError):
            check('CURRENT_FILE_HISTORY', False, 'invalid-ref')

    def known_ref(ref, name):
        try:
            good = _file_key(ref) in history and _same_file(ref, history[_file_key(ref)])
        except (TypeError, KeyError):
            good = False
        check(name, good)
        return good

    observed = {}
    faults_by_call = {}
    for fault in document.get('faults', []):
        call_id = fault.get('call_id')
        check('FAULT_CALL_UNIQUE', call_id not in faults_by_call, call_id)
        check('FAULT_CALL_EXISTS', call_id in calls, call_id)
        faults_by_call[call_id] = fault
        if call_id not in calls:
            continue
        call = calls[call_id]
        check('FAULT_RAW_BINDING', fault.get('raw_payload') == call.get('payload'), call_id)
        check('FAULT_DELIVERY_BINDING', fault.get('delivered_payload') == call.get('delivered_payload'), call_id)
        expected = deepcopy(call.get('payload'))
        try:
            if fault.get('type') == 'F_DECISION':
                expected['final']['unavailable_before_call'] = []
            elif fault.get('type') == 'F_INCIDENTAL':
                expected['final']['row_count'] += 1
            else:
                raise ValueError('unknown-fault')
            check('FAULT_EXACT_DELTA', call.get('role') == 'Analyst'
                  and fault.get('delivered_payload') == expected, call_id)
        except (KeyError, TypeError, ValueError):
            check('FAULT_EXACT_DELTA', False, call_id)
        if fixture_only:
            check('FAULT_FIXTURE_LABEL', fault.get('fixture_only') is True, call_id)
    for call_id, call in calls.items():
        if call.get('delivered_payload', call.get('payload')) != call.get('payload'):
            check('ALTERED_DELIVERY_RECEIPT', call_id in faults_by_call, call_id)
        prompt = call.get('prompt_messages', [])
        good_prompt = isinstance(prompt, list) and all(isinstance(m, dict) for m in prompt)
        check('PROMPT_FORMAT', good_prompt, call_id)
        if not good_prompt:
            continue
        check('PROMPT_HASH', call.get('prompt_sha256') == digest(prompt), call_id)
        refs = [{'message_id': m.get('message_id'), 'sha256': digest(m)} for m in prompt]
        check('PROMPT_REFS', call.get('prompt_refs') == refs, call_id)
        exposed = set()
        for message in prompt:
            mid = message.get('message_id')
            check('PROMPT_MESSAGE_BINDING', mid in messages and messages[mid] == message, call_id)
            exposed.update(_producer_ids(message))
        observed[call_id] = exposed
        if fixture_only:
            check('CALL_FIXTURE_LABEL', call.get('fixture_only') is True, call_id)

    for tool_id, tool in tools.items():
        if fixture_only:
            check('TOOL_FIXTURE_LABEL', tool.get('fixture_only') is True, tool_id)
        for ref in tool.get('reads', []):
            known_ref(ref, 'TOOL_READ_BINDING')
        for write in tool.get('writes', []):
            before, after = write.get('before'), write.get('after')
            if before is not None:
                known_ref(before, 'WRITE_BEFORE_BINDING')
            if not known_ref(after, 'WRITE_AFTER_BINDING'):
                continue
            if before is not None:
                check('WRITE_VERSION_ADVANCE', before['file_id'] == after['file_id']
                      and type(before['version']) is int
                      and after['version'] == before['version'] + 1, tool_id)

    event_current = {}
    saw_file_event = False
    for event in document.get('events', []):
        kind = event.get('kind')
        if kind not in ('file_write', 'file_restore', 'file_write_conflict',
                        'file_restore_conflict', 'file_restore_external_owner'):
            continue
        saw_file_event = True
        file_id = event.get('file_id')
        if kind == 'file_restore_external_owner':
            actual = event.get('actual') or {}
            writer = actual.get('writer_id', '')
            check('FILE_EXTERNAL_OWNER_REFUSAL',
                  event.get('expected') == actual
                  and actual == event_current.get(file_id)
                  and (writer == 'external' or writer.startswith('external-'))
                  and event.get('refusal_code') == 'FILE_EXTERNAL_OWNER', file_id)
            continue
        if kind.endswith('_conflict'):
            check('FILE_CONFLICT_REFUSAL', event.get('expected') != event.get('actual'), file_id)
            check('FILE_CONFLICT_CURRENT', event.get('actual') == event_current.get(file_id), file_id)
            continue
        before, after = event.get('before'), event.get('after')
        check('FILE_EVENT_CAS', before == event_current.get(file_id), file_id)
        if not known_ref(after, 'FILE_EVENT_AFTER'):
            continue
        check('FILE_EVENT_VERSION', after['file_id'] == file_id
              and type(after['version']) is int
              and after['version'] == (before['version'] + 1 if before else 1), file_id)
        if kind == 'file_restore':
            owner = before.get('writer_id', '') if before else ''
            check('FILE_RESTORE_OWNERSHIP', not (owner == 'external' or owner.startswith('external-')), file_id)
            restore_ref = event.get('restore_ref')
            if known_ref(restore_ref, 'FILE_RESTORE_SOURCE'):
                check('FILE_RESTORE_CONTENT', restore_ref['file_id'] == file_id
                      and after['sha256'] == restore_ref['sha256'], file_id)
        event_current[file_id] = after
    if saw_file_event:
        check('FILE_EVENT_FINAL_STATE', event_current == current_map)

    seen, observed_edges = set(), set()
    used_calls, used_tools = set(), set()
    for result_id, node in nodes.items():
        parents = node.get('parent_result_ids', [])
        check('PARENTS_FORMAT', isinstance(parents, list) and len(parents) == len(set(parents)), result_id)
        check('TOPOLOGICAL_PARENTS', all(p in seen for p in parents), result_id)
        observed_edges.update((p, result_id) for p in parents)
        for ref in node.get('file_reads', []):
            known_ref(ref, 'NODE_FILE_BINDING')
        llm_id = node.get('llm_call_id')
        if llm_id:
            good = llm_id in calls
            check('NODE_LLM_BINDING', good, result_id)
            if good:
                call = calls[llm_id]
                delivered = call.get('delivered_payload', call.get('payload'))
                expected_payload = delivered.get('final', delivered) if isinstance(delivered, dict) else delivered
                check('LLM_DELIVERY_NODE_PAYLOAD', node.get('payload') == expected_payload, result_id)
                check('LLM_NODE_ID', call.get('node_id') == result_id, result_id)
                check('LLM_ROLE', node.get('role') == call.get('role'), result_id)
                check('EXPOSED_PARENT_COVERAGE', observed.get(llm_id, set()).issubset(set(parents)), result_id)
                check('LLM_SINGLE_NODE', llm_id not in used_calls, llm_id)
                used_calls.add(llm_id)
        tool_id = node.get('tool_call_id')
        if tool_id:
            good = tool_id in tools
            check('NODE_TOOL_BINDING', good, result_id)
            if good:
                tool = tools[tool_id]
                check('TOOL_NODE_ID', tool.get('node_id') == result_id, result_id)
                check('TOOL_NODE_READS', node.get('file_reads', []) == tool.get('reads', []), result_id)
                check('TOOL_SINGLE_NODE', tool_id not in used_tools, tool_id)
                used_tools.add(tool_id)
        seen.add(result_id)
    check('ALL_LLM_CALLS_BOUND', used_calls == set(calls))
    check('ALL_TOOL_CALLS_BOUND', used_tools == set(tools))

    def current_dependencies_valid(result_id, excluded, visiting=None):
        """Walk other observed edges; a cutoff never validates unrelated inputs."""
        visiting = set() if visiting is None else visiting
        if result_id not in nodes or result_id in visiting:
            return False
        visiting = visiting | {result_id}
        node = nodes[result_id]
        if any(ref.get('file_id') not in current_map
               or not _same_file(ref, current_map[ref['file_id']])
               for ref in node.get('file_reads', [])):
            return False
        return all((p, result_id) in excluded or
                   current_dependencies_valid(p, excluded, visiting)
                   for p in node.get('parent_result_ids', []))

    attempts = set()
    for decision in document.get('decisions', []):
        if decision.get('method') != 'CUTOFF' or not decision.get('new_result_id'):
            continue
        key = (decision.get('round'), decision.get('node_id'))
        check('CUTOFF_ONCE_PER_ROUND', key not in attempts, key)
        attempts.add(key)
        old_id, new_id = decision.get('old_result_id'), decision.get('new_result_id')
        check('CUTOFF_NODE_BINDING', old_id in nodes and new_id in nodes, key)
        equivalent = False
        if old_id in nodes and new_id in nodes:
            try:
                equivalent = normalize_contract(nodes[old_id]['payload']) == normalize_contract(nodes[new_id]['payload'])
            except (TypeError, KeyError, ValueError, RuntimeError):
                pass
        check('CUTOFF_EQUIVALENCE', decision.get('equivalent') is equivalent, key)
        edges = {(e.get('parent_result_id'), e.get('child_result_id'))
                 for e in decision.get('cut_edges', [])}
        check('CUTOFF_OBSERVED_EDGES', edges.issubset(observed_edges)
              and all(p == old_id for p, _ in edges), key)
        if edges or decision.get('action') in ('retain', 'cutoff', 'cut'):
            check('CUTOFF_VALIDITY_GATE', equivalent and decision.get('other_inputs_valid') is True, key)
            policy = document.get('audit_policy', {})
            eligibility = check_contract(nodes[new_id]['payload'], policy.get('allowed_features'),
                policy.get('data_binding'), policy.get('code_sha256'), policy.get('prediction_time', 'pre_call'))
            check('CUTOFF_CANDIDATE_ELIGIBLE', eligibility['passed'], key)
            check('CUTOFF_OTHER_INPUTS', all(current_dependencies_valid(child, edges)
                                           for _, child in edges), key)

    final = document.get('final', {})
    outcome = final.get('outcome')
    check('OUTCOME', outcome in OUTCOMES)
    policy = document.get('audit_policy', {})
    contract_result = None
    if outcome in ('correct_complete', 'wrong_complete'):
        contract_result = check_contract(final.get('contract'),
            policy.get('allowed_features'), policy.get('data_binding'),
            policy.get('code_sha256'), policy.get('prediction_time', 'pre_call'))
        check('COMPLETION_CLASSIFICATION', contract_result['passed'] == (outcome == 'correct_complete'))
    if outcome == 'external_unresolved':
        check('EXTERNAL_UNRESOLVED_EVIDENCE', bool(final.get('external_receipts')
              or final.get('external_unresolved') or document.get('external_receipts')))
    return {'passed': not issues, 'checks': checks, 'issues': issues,
            'fixture_only': fixture_only,
            'evidence_scope': 'mechanism_fixture_only' if fixture_only else 'saved_evidence_audit_only',
            'scientific_success_claimed': False, 'outcome': outcome,
            'contract_check': contract_result, 'observed_edge_count': len(observed_edges)}
