"""V1 offline orchestration: pure policy -> durable Store -> fake adapter.

The driver never selects invalidation sets, changes correction allowances or
edits durable branch state. Guards are shared by FULL/LAZY/EAGER. All acceptance,
quota and final publication decisions remain in Store transactions.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .common import REV, ProtocolError, digest, read_refs
from .fake import execute_fake
from .guard import diagnose
from .policy import advance


class FakeClock:
    """Injectable monotonically advanced UTC clock for deadline/replay tests."""
    def __init__(self, start="2026-10-21T00:00:00Z"):
        self.value = datetime.fromisoformat(start.replace("Z", "+00:00"))

    def __call__(self):
        return self.value.isoformat(timespec="microseconds").replace("+00:00", "Z")

    def advance(self, seconds=1):
        self.value += timedelta(seconds=seconds)
        return self()


def real_clock():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def advance_input(view, now_utc, guard_evidence=None, event_id=None):
    """Public frozen AdvanceInput assembled from a Store snapshot, not an oracle."""
    state = view["state"]
    identity = {"branch": state["branch_id"], "version": state["state_version"],
                "guard_id": guard_evidence["guard_id"] if guard_evidence else None}
    return {"record_type": "AdvanceInput", "revision": REV, "fixture_only": True,
        "event_id": event_id or "v1.advance." + digest(identity)[:24], "state": state,
        "workflow_id": view["dag"]["workflow_id"], "notice": view["notice"],
        "results": view["results"], "source_versions": read_refs(view["sources"]),
        "guard_evidence": guard_evidence,
        "settled_receipt_ids": [r["receipt_id"] for r in view.get("tool_receipts", [])],
        "workflow_binding_digest": digest(view["dag"]), "now_utc": now_utc}


def _persist_guard(store, view, guard, clock, scan_decision=None):
    if scan_decision is not None:
        store.record_scan(scan_decision, guard, "v1.scan." + guard["guard_id"], clock())
    else:
        store.record_guard(guard, "v1.record." + guard["guard_id"], clock())
    return store.snapshot()


def run_branch(store, clock=None, faults=None, after_step=None, max_steps=200):
    """Run one already-created offline branch, then return its full Store export.

    ``faults={(stage, node_id): 'steps_plus_one'}`` is an offline harness-only
    delivery fault. Each key is used at most once; a changed node/round never
    supplies a free retry. ``after_step`` may advance a fake clock or reopen a
    Store in tests; it is not visible to policy/model input.
    """
    clock = clock or real_clock
    faults = dict(faults or {})
    start_view = store.snapshot()
    store.begin_branch("v1.begin." + start_view["state"]["branch_id"], clock())
    for step in range(max_steps):
        view = store.snapshot()
        state = view["state"]
        if state["status"] == "terminal":
            return store.export()
        if state["active_attempt_ids"] or state["unsettled_call_ids"]:
            # An interrupted active attempt has an unknown dispatch/outcome.
            # Returning a new fake response would be an unlicensed retry.
            raise ProtocolError("ACTIVE_OR_UNSETTLED_WORK")
        pending_decision = view.get("pending_decision")
        if pending_decision and pending_decision["kind"] == "execute_node":
            attempt = store.start_node(pending_decision, "v1.start." + pending_decision["decision_id"], clock())
            execution_view = store.snapshot()
            key = (execution_view["state"]["stage"], pending_decision["node_id"])
            package = execute_fake(execution_view, pending_decision["node_id"], attempt,
                store.artifact_root, fault=faults.pop(key, None))
            store.finish_node(attempt["attempt_id"], package, clock())
            if after_step:
                after_step(store, step, pending_decision)
            continue
        guard = view.get("last_guard", view.get("guard_evidence"))
        # A successful old checkpoint is not a license for a later dispatch.
        if guard and guard["classification"] == "passed":
            guard = None
        decision = advance(advance_input(view, clock(), guard), view["dag"])
        if decision["kind"] == "need_version_scan":
            guard = diagnose(view, view["dag"]["topological_order"][-1],
                checkpoint="pre_dispatch", full=True, artifact_root=store.artifact_root)
            view = _persist_guard(store, view, guard, clock, scan_decision=decision)
            decision = advance(advance_input(view, clock(), guard), view["dag"])
        elif decision["kind"] == "execute_node":
            guard = diagnose(view, decision["node_id"], checkpoint="pre_dispatch", artifact_root=store.artifact_root)
            view = _persist_guard(store, view, guard, clock)
            decision = advance(advance_input(view, clock(), guard), view["dag"])
            if decision["kind"] == "need_version_scan":
                guard = diagnose(view, decision["node_id"] or view["dag"]["topological_order"][-1],
                    checkpoint="pre_dispatch", full=True, artifact_root=store.artifact_root)
                view = _persist_guard(store, view, guard, clock, scan_decision=decision)
                decision = advance(advance_input(view, clock(), guard), view["dag"])
        elif decision["kind"] == "commit":
            node = view["dag"]["topological_order"][-1]
            result_id = state["selected_by_node"].get(node)
            candidate = next((r for r in view["results"] if r["result_id"] == result_id), None)
            guard = diagnose(view, node, checkpoint="precommit", candidate=candidate,
                full=True, artifact_root=store.artifact_root)
            view = _persist_guard(store, view, guard, clock)
            decision = advance(advance_input(view, clock(), guard), view["dag"])
        if decision["kind"] == "need_version_scan":
            raise ProtocolError("UNRESOLVED_FULL_VERSION_DIAGNOSIS")
        if decision["kind"] == "return_existing":
            return store.export()
        store.admit_decision(decision, clock(), guard_evidence=guard)
        if decision["kind"] == "execute_node":
            attempt = store.start_node(decision, "v1.start." + decision["decision_id"], clock())
            execution_view = store.snapshot()
            key = (execution_view["state"]["stage"], decision["node_id"])
            package = execute_fake(execution_view, decision["node_id"], attempt,
                store.artifact_root, fault=faults.pop(key, None))
            store.finish_node(attempt["attempt_id"], package, clock())
        if after_step:
            after_step(store, step, decision)
    raise ProtocolError("OFFLINE_DRIVER_STEP_CAP")
