"""Offline multi-run integration: one reservation owns one fake HTTP request.

This entry is deliberately fixture-only. It cannot turn a local tokenizer
estimate or an accounting budget into authorization to use a real credential.
The durable budget lives outside each workflow's rollback/snapshot directory.
"""
from copy import deepcopy
import math
from time import monotonic

from agent_recovery.contracts import require
from .triton import TritonAgentModel
from .unified_budget import UnifiedPilotBudget


class AccountedFixtureGateway:
    def __init__(self, model, ledger):
        require(isinstance(model, TritonAgentModel) and model.fixture_only is True,
                "This entry only accepts fake HTTP", "CTX_OFFLINE_ONLY")
        require(isinstance(ledger, UnifiedPilotBudget) and ledger.binding['simulated'] is True,
                "A simulated shared authority is required", "CTX_OFFLINE_ONLY")
        self.model, self.ledger = model, ledger

    def call(self, role, messages, *, run_id, call_id, deadline_monotonic,
             logical_run_key=None, trial_key=None):
        """Use an absolute caller deadline; never retry, reset or extend it.

        An exact duplicate of a settled successful call returns the saved
        validated payload. Pending, failed and conflicting duplicates cannot
        send. This is request idempotency, not model-output determinism.
        """
        require(type(deadline_monotonic) in (int, float)
                and math.isfinite(deadline_monotonic)
                and monotonic() < deadline_monotonic <= monotonic() + 120,
                "An unexpired absolute deadline of at most 120 seconds is required",
                "CTX_DEADLINE")
        deadline_monotonic = min(deadline_monotonic, monotonic() + self.model.timeout_s)
        prepared = self.model.prepare(role, deepcopy(messages))
        record = dict(call_id=call_id, attempt_id=call_id + '.attempt',
            trial_key=trial_key or run_id + '.' + role,
            logical_run_key=logical_run_key or run_id, branch_id=run_id,
            run_id=run_id, result_id=call_id + '.result', step_id=role,
            phase='initial', input_token_upper_bound=prepared.input_token_upper_bound,
            request=prepared.request, sidecar=prepared.sidecar)
        admission = self.ledger.reserve(record)
        if not admission['admission']['dispatch_allowed']:
            evidence = admission.get('evidence') or {}
            require(admission['status'] == 'settled'
                    and evidence.get('kind') == 'ctx-successful-fake-exchange-v1'
                    and 'payload' in evidence,
                    "Repeated pending or failed call cannot dispatch", "CTX_DUPLICATE_BLOCKED")
            return dict(call_id=call_id, replayed=True, payload=deepcopy(evidence['payload']),
                        usage=deepcopy(admission['usage']), sidecar=deepcopy(prepared.sidecar))
        try:
            exchange = self.model.exchange(prepared,
                before_send=lambda: self.ledger.mark_dispatched(call_id),
                deadline_monotonic=deadline_monotonic)
            usage = exchange.usage
            self.ledger.settle(call_id, provider_request_id=exchange.provider_request_id,
                raw_usage=usage['raw'], normalized_usage=usage,
                evidence=dict(kind='ctx-successful-fake-exchange-v1',
                    payload=exchange.payload, wire_audit=exchange.audit,
                    fixture_only=True))
        except Exception as exc:
            row = next(c for c in self.ledger.calls() if c['call_id'] == call_id)
            code = getattr(exc, 'code', type(exc).__name__)
            try:
                if row['status'] == 'dispatched':
                    usage, receipt = getattr(exc, 'usage', None), getattr(exc, 'request_id', None)
                    if usage and receipt:
                        self.ledger.settle(call_id, provider_request_id=receipt,
                            raw_usage=usage['raw'], normalized_usage=usage,
                            evidence=dict(kind='ctx-failed-fake-exchange-v1',
                                          error=code, fixture_only=True))
                    else:
                        self.ledger.quarantine(call_id, code)
            finally:
                # In particular, a 429 remains a global stop even when its
                # response included enough usage to release the reservation.
                self.ledger.stop(code)
            raise
        return dict(call_id=call_id, replayed=False, payload=deepcopy(exchange.payload),
                    usage=deepcopy(usage), sidecar=deepcopy(prepared.sidecar))
