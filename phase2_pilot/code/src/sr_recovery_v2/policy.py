"""Pure V1 next-action policy; never performs work or accepts a decision."""
from datetime import timedelta

from .common import REV, ProtocolError, digest, closure_ids, node_map, utc_parse, selected_graph_digest


def advance(advance_input, dag):
    """Return exactly one frozen AdvanceOutput from already-begun durable state.

    Execution, CAS, idempotent acceptance and correction counters belong to Store.
    No input dictionary is mutated. A complete guard carries authoritative versions;
    the policy never obtains changed keys or a private correctness oracle.
    """
    value = advance_input
    state = value['state']
    start, deadline = state.get('started_at_utc'), state.get('deadline_utc')
    if not start or not deadline:
        raise ProtocolError('BRANCH_NOT_BEGUN')
    began, expires, now = utc_parse(start), utc_parse(deadline), utc_parse(value['now_utc'])
    if expires != began + timedelta(seconds=1800) or now < began:
        raise ProtocolError('INVALID_CLOCK_OR_DEADLINE')
    if value['workflow_id'] != dag['workflow_id']:
        raise ProtocolError('WORKFLOW_BINDING_MISMATCH')
    order = dag['topological_order']
    nodes = node_map(dag)
    results = value['results']
    by_id = {r['result_id']: r for r in results}
    selected = state['selected_by_node']
    guard = value.get('guard_evidence')
    fp = guard['source_fingerprint'] if guard else state['source_fingerprint']
    output = {
        'record_type': 'AdvanceOutput', 'revision': REV,
        'decision_id': 'v1.decision.' + digest({'branch_id': state['branch_id'], 'event_id': value['event_id']})[:24],
        'event_id': value['event_id'], 'branch_id': state['branch_id'],
        'expected_state_version': state['state_version'], 'kind': 'execute_node',
        'node_id': None, 'parent_result_ids': [], 'ordered_node_ids': [],
        'carried_pending_node_ids': [], 'guard_id': guard['guard_id'] if guard else None,
        'correction_kind': None, 'source_fingerprint': fp, 'reason_codes': [],
        'terminal_status': None, 'fixture_only': True,
    }

    def terminal(status, reason):
        output.update(kind='terminal', terminal_status=status, reason_codes=[reason])
        return output

    if state['status'] == 'terminal':
        output.update(kind='return_existing', terminal_status=state['terminal_status'],
                      reason_codes=['TERMINAL_ALREADY_DURABLE'])
        return output
    if now >= expires:
        return terminal('budget_or_time_stopped', 'FIXED_DEADLINE_EXPIRED')
    if state['active_attempt_ids'] or state['unsettled_call_ids']:
        raise ProtocolError('ACTIVE_OR_UNSETTLED_WORK')
    if guard and guard['selected_graph_digest'] != selected_graph_digest(selected, results):
        raise ProtocolError('GUARD_GRAPH_BINDING_MISMATCH')
    if guard and guard['source_fingerprint'] != state['source_fingerprint']:
        return terminal('uncertain', 'SOURCE_DRIFT_AFTER_FREEZE')
    if guard:
        cls = guard['classification']
        if cls in ('integrity_error', 'uncertain', 'source_drift'):
            return terminal('uncertain', cls.upper())
        if cls == 'permission_denied':
            return terminal('permission_denied_safe', 'PERMISSION_DENIED')
        if cls == 'conflict':
            return terminal('conflict_safe', 'COMPENSATION_CONFLICT')
    else:
        cls = 'passed'

    # First admission has its own durable identity. Proactive invalidation is first
    # stage work and must never spend the LAZY stale correction allowance.
    if state['active_plan_id'] is None and not state['invalidated_result_ids']:
        if state['policy'] == 'EAGER' and not (guard and guard['full_version_diagnosis']):
            output.update(kind='need_version_scan', reason_codes=['INITIAL_EAGER_VERSION_SCAN'])
            return output
        seeds = [value['notice']['faulty_result_id']]
        if state['policy'] == 'FULL':
            wanted = set(order)
        else:
            if state['policy'] == 'EAGER':
                if guard:
                    seeds += [rid for issue in guard['issues']
                              if issue['code'] in ('STALE_EFFECTIVE_READ', 'PROVABLE_MIXED_READ_VERSIONS')
                              for rid in issue.get('related_result_ids', [])]
            invalidated = set(closure_ids(seeds, results))
            wanted = {r['node_id'] for r in results if r['result_id'] in invalidated}
            wanted |= set(state['pending_node_ids'])
            wanted |= {node for node in order if not selected.get(node)}
        output.update(kind='compensate', ordered_node_ids=[n for n in order if n in wanted],
                      reason_codes=['INITIAL_' + ('NOTICE' if state['policy'] == 'LAZY' else state['policy'])])
        return output

    if cls == 'stale' and not guard['full_version_diagnosis']:
        output.update(kind='need_version_scan', reason_codes=['LOCAL_STALE_REQUIRES_COMPLETE_DIAGNOSIS'])
        return output
    if cls in ('stale', 'semantic'):
        if state['counters'][cls + '_used']:
            return terminal('validation_rejected', 'SAME_KIND_ALLOWANCE_ALREADY_USED_' + cls.upper())
        diagnostic_issues = guard['issues']
        if cls == 'stale':
            diagnostic_issues = [issue for issue in diagnostic_issues if issue['code'] in
                                 ('STALE_EFFECTIVE_READ', 'PROVABLE_MIXED_READ_VERSIONS')]
        seeds = [rid for issue in diagnostic_issues for rid in issue.get('related_result_ids', [])]
        if not seeds and guard.get('candidate_result_id'):
            seeds.append(guard['candidate_result_id'])
        invalidated = set(closure_ids(seeds, results))
        wanted = {r['node_id'] for r in results if r['result_id'] in invalidated}
        pending = set(state['pending_node_ids'])
        wanted |= pending
        # Missing valid selections and interrupted notice work must survive a
        # stage switch; they do not become an uncharged later fourth stage.
        wanted |= {n for n in order if not selected.get(n)}
        if not wanted:
            return terminal('validation_rejected', 'DIAGNOSIS_WITHOUT_REPAIRABLE_NODES')
        output.update(kind='admit_correction', correction_kind=cls,
                      ordered_node_ids=[n for n in order if n in wanted],
                      carried_pending_node_ids=[n for n in order if n in pending],
                      reason_codes=['FULL_STALE_DIAGNOSIS' if cls == 'stale' else 'SEMANTIC_DIAGNOSIS',
                                    'UNION_UNFINISHED_NOTICE_WORK'])
        return output

    pending = set(state['pending_node_ids'])
    if not pending:
        final = order[-1]
        result = by_id.get(selected.get(final))
        if not result or result['execution_status'] != 'success':
            return terminal('validation_rejected', 'FINAL_SELECTION_NOT_SUCCESS')
        if not guard or guard['checkpoint'] != 'precommit':
            output.update(kind='commit', node_id=final, reason_codes=['PRECOMMIT_GUARD_REQUIRED'])
        else:
            output.update(kind='commit', node_id=final, reason_codes=['GUARDED_FINAL_PUBLICATION'])
        return output
    next_node = next((n for n in order if n in pending), None)
    if next_node is None or next_node in state['stage_completed_node_ids']:
        return terminal('uncertain', 'INVALID_OR_REPEATED_STAGE_NODE')
    node = nodes[next_node]
    counters = state['counters']
    if counters['physical_calls'] + node['llm_calls_per_execution'] > 15 or counters['cpu_jobs'] + node['cpu_jobs_per_execution'] > 30:
        return terminal('budget_or_time_stopped', 'BRANCH_CALL_OR_JOB_CAP')
    parents = [selected.get(parent) for parent in node['parents']]
    if any(not rid or rid not in by_id or by_id[rid]['execution_status'] != 'success' for rid in parents):
        return terminal('uncertain', 'MISSING_VALID_SELECTED_PARENT')
    output.update(node_id=next_node, parent_result_ids=parents,
                  ordered_node_ids=[n for n in order if n in pending],
                  reason_codes=['NEXT_TOPOLOGICAL_REQUIRED_NODE'])
    return output
