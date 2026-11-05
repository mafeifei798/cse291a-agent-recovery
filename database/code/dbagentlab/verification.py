"""Always-verify comparison: current public evidence, not experiment truth."""
import time
from .graphs import root_blockers


class VerificationRejected(RuntimeError):
    pass


def check_claim(role, payload, evidence, plan=None):
    """Focused checks for supported lock facts, capability summaries and action preconditions.

    This is NOT a general verifier for arbitrary database diagnoses or malicious text.
    """
    rows = evidence['activity']['rows']
    policy = evidence['policy']['rows']
    eligible = {row['session_id'] for row in policy
                if 'rollback_session' in row['allowed_actions'] and not row['released']}
    business = evidence['business']['rows']
    roots = root_blockers(rows, business['request_session_id'])
    errors = []
    if role.startswith('diagnostic'):
        blocker, waiter = payload['blocker_session_id'], payload['waiter_session_id']
        if blocker is not None or waiter is not None:
            if waiter != business['request_session_id'] or blocker not in roots:
                errors.append('blocking_claim_not_supported_by_current_activity')
        if payload['cause'] == 'LOCK_CONTENTION' and (waiter != business['request_session_id'] or blocker not in roots):
            errors.append('lock_diagnosis_missing_supported_pair')
    elif role == 'state':
        if set(payload['eligible_sessions']) != eligible:
            errors.append('capability_summary_mismatch')
    else:
        candidate = plan if role == 'reviewer' else payload
        if role == 'reviewer' and payload['decision'] != 'approve':
            return []
        target = candidate['target_session_id']
        if candidate['action'] == 'rollback_session':
            if target not in eligible:
                errors.append('target_not_currently_eligible')
            if target not in roots:
                errors.append('target_not_blocking_business_request')
        elif business['request_status'] != 'committed':
            errors.append('no_op_does_not_resolve_pending_request')
    return errors


def verify(ledger, env, artifact, branch, plan=None):
    started = time.monotonic()
    evidence = env.read(['activity', 'policy', 'business'])
    observation = ledger.artifact('verification_evidence', 'verifier', evidence, branch=branch,
        parents=[env.state_ref] if getattr(env, 'state_ref', None) else [])
    errors = check_claim(artifact['actor'], artifact['payload'], evidence, plan)
    result = ledger.artifact('verification', 'verifier',
        {'accepted': not errors, 'reason_codes': errors, 'logical_reads': 3,
         'latency_seconds': time.monotonic()-started,
         'scope': 'focused current lock/capability checks; no semantic attack detector'},
        parents=[artifact['id'], observation['id']], branch=branch)
    if errors:
        raise VerificationRejected(', '.join(errors))
    return result
