"""Independent V1 export auditor.

Only the Python standard library is used.  In particular, this module must never
import Store, policy, guard, graph closure helpers, or the fake executor as an
oracle.  It reconstructs evidence from exported durable records and file bytes.
V1 is synthetic: these checks do not establish real model training correctness.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


def _json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_json(value)).hexdigest()


def _rows(value: Any, member: str | None = None) -> list[dict]:
    if isinstance(value, dict):
        if member and member in value:
            return _rows(value[member])
        return list(value.values())
    return value if isinstance(value, list) else []


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _ref_map(reads: list[dict]) -> dict[str, int]:
    return {x["object_key"]: x["version"] for x in reads}


def _close(nodes: set[str], dag: dict) -> list[str]:
    """Deliberately independent, small fixed-DAG descendant reconstruction."""
    changed = True
    while changed:
        changed = False
        for node in dag["nodes"]:
            if node["node_id"] not in nodes and any(p in nodes for p in node["parents"]):
                nodes.add(node["node_id"])
                changed = True
    return [n for n in dag["topological_order"] if n in nodes]


class _Audit:
    def __init__(self):
        self.checks = 0
        self.issues: list[dict] = []

    def expect(self, condition: Any, code: str, ref: str = "", detail: Any = None) -> bool:
        self.checks += 1
        if not condition:
            self.issues.append({"code": code, "ref": ref, "detail": detail})
            return False
        return True


def check_export(export: dict, artifact_root: str | Path, dag: dict | None = None) -> dict:
    """Audit a persisted branch export, without consulting runtime decisions.

    ``artifact_root`` is a filesystem allow-root; manifests may name subpaths or
    absolute paths inside it. Missing fields fail checks rather than being
    inferred from the terminal label.  The returned ``passed`` means the records
    are internally auditable, including a safely failed branch, not that the
    workflow succeeded. ``business_correct`` is separate.
    """
    audit = _Audit()
    try:
        return _check(export, Path(artifact_root), dag or export["dag"], audit)
    except (KeyError, TypeError, ValueError, OSError, OverflowError, AttributeError, IndexError) as exc:
        audit.expect(False, "MALFORMED_EXPORT", detail=f"{type(exc).__name__}: {exc}")
        return {"passed": False, "business_correct": False, "checks": audit.checks,
                "issues": audit.issues, "statistics": {}}


def _check(view: dict, root: Path, dag: dict, a: _Audit) -> dict:
    state = view["state"]
    results = _rows(view["results"])
    result_map = {r["result_id"]: r for r in results}
    artifacts = _rows(view.get("artifacts", []), "artifacts")
    artifact_map = {r["artifact_id"]: r for r in artifacts}
    calls = _rows(view.get("calls", []))
    tools = _rows(view.get("tool_receipts", []))
    attempts = _rows(view.get("attempts", []))
    plans = _rows(view.get("plans", []))
    events = _rows(view.get("events", []))
    sources = _rows(view.get("sources", []))
    selected = state["selected_by_node"]
    node_map = {n["node_id"]: n for n in dag["nodes"]}
    order = dag["topological_order"]
    original = view.get("initial_snapshot", {})
    if "state" in original:
        original_selected = original["state"].get("selected_by_node", {})
    else:
        original_selected = original.get("selected_by_node", {})
    original_ids = {x for x in original_selected.values() if x}
    original_ids.update(r["result_id"] for r in _rows(original.get("results", [])))
    original_ids.update(view.get("metadata", {}).get("initial_result_ids", []))
    if not original_ids:
        original_ids = set(view.get("prefix_result_ids", []))
    branch = state["branch_id"]
    a.expect(len(result_map) == len(results), "DUPLICATE_RESULT_ID", branch)
    a.expect(len(artifact_map) == len(artifacts), "DUPLICATE_ARTIFACT_ID", branch)
    a.expect(set(selected) == set(order), "SELECTED_FIXED_DAG", branch)
    a.expect(state["policy"] in ("FULL", "LAZY", "EAGER"), "POLICY_ID", branch)
    current = {s["object_key"]: s for s in sources}
    for source in sources:
        a.expect(_digest(source["payload"]) == source["payload_digest"],
                 "SOURCE_PAYLOAD_DIGEST", source["object_key"])
    source_history = _rows(view.get("source_history", []))
    history_map = {(s["object_key"], s["version"]): s for s in source_history}
    a.expect(len(history_map) == len(source_history), "UNIQUE_SOURCE_HISTORY_VERSION", branch)
    for source in source_history:
        a.expect(_digest(source["payload"]) == source["payload_digest"],
                 "HISTORICAL_SOURCE_PAYLOAD_DIGEST", source["object_key"])
    for source in sources:
        a.expect(history_map.get((source["object_key"], source["version"])) == source,
                 "CURRENT_SOURCE_RESOLVES_HISTORY", source["object_key"])
    fingerprint = _digest([{"object_key": s["object_key"], "version": s["version"],
                            "payload_digest": s["payload_digest"]}
                           for s in sorted(sources, key=lambda s: s["object_key"])])
    if state.get("terminal_status") != "uncertain":
        a.expect(state["source_fingerprint"] == fingerprint, "CURRENT_SOURCE_FINGERPRINT", branch)
    a.expect(state["counters"]["stale_used"] in (0, 1), "STALE_ALLOWANCE", branch)
    a.expect(state["counters"]["semantic_used"] in (0, 1), "SEMANTIC_ALLOWANCE", branch)
    start, deadline = state.get("started_at_utc"), state.get("deadline_utc")
    a.expect(bool(start) == bool(deadline), "START_DEADLINE_PAIR", branch)
    if start:
        a.expect((_time(deadline) - _time(start)).total_seconds() == 1800,
                 "FIXED_1800_SECOND_DEADLINE", branch)
    if state["status"] == "terminal":
        a.expect(not state["active_attempt_ids"] and not state["unsettled_call_ids"],
                 "TERMINAL_QUIESCENT", branch)

    # Every exported raw record remains immutable; known bad delivered values
    # may remain in the prefix, but may never become successful final ancestry.
    initial_results = _rows(original.get("results", []))
    for old in initial_results:
        a.expect(result_map.get(old["result_id"]) == old, "PREFIX_RESULT_UNMODIFIED", old["result_id"])
    initial_digest = view.get("prefix_digest") or view.get("branch_metadata", {}).get("prefix_digest")
    if initial_digest and original:
        a.expect(initial_digest == _digest(original), "PREFIX_SNAPSHOT_DIGEST", branch)
    target_id = view["notice"]["faulty_result_id"]
    a.expect(target_id in result_map and target_id in original_ids, "NOTICE_TARGET_IN_FROZEN_PREFIX", branch)
    descendants = set([target_id])
    changed = True
    while changed:
        expanded = descendants | {r["result_id"] for r in initial_results if descendants.intersection(r["parent_result_ids"])}
        changed = expanded != descendants
        descendants = expanded
    actual_exposure = [r for r in initial_results if r["result_id"] != target_id and r["result_id"] in descendants
                       and (r["call_ids"] or r["tool_receipt_ids"])]
    a.expect(bool(actual_exposure), "FAULT_HAS_DOWNSTREAM_INPUT_RECEIPT", branch)
    a.expect(original.get("prefix_refusal", {}).get("classification") == "semantic",
             "FIRST_PREFIX_REFUSAL_RETAINED", branch)
    call_map = {x["call_id"]: x for x in calls}
    receipt_map = {x["receipt_id"]: x for x in tools}
    a.expect(len(call_map) == len(calls), "UNIQUE_CALL_ID", branch)
    a.expect(len(receipt_map) == len(tools), "UNIQUE_TOOL_RECEIPT", branch)

    # Secure byte-level manifest checks, not a manifest self-certification.
    loaded: dict[str, Any] = {}
    root = root.resolve()
    input_producers = {x.get("producer_result_id", x.get("producer_id", x.get("input_producer_id", x.get("result_id"))))
                       for x in _rows(view.get("input_producers", []))}
    for art in artifacts:
        aid = art["artifact_id"]
        path = Path(art["uri"])
        path = (root / path).resolve() if not path.is_absolute() else path.resolve()
        if not a.expect(path == root or root in path.parents, "ARTIFACT_PATH_ESCAPE", aid):
            continue
        if not a.expect(path.is_file(), "ARTIFACT_FILE_MISSING", aid):
            continue
        data = path.read_bytes()
        a.expect(len(data) == art["size_bytes"], "ARTIFACT_SIZE", aid)
        a.expect(hashlib.sha256(data).hexdigest() == art["sha256"], "ARTIFACT_SHA256", aid)
        producer = art["producer_result_id"]
        a.expect(producer in result_map or producer in input_producers,
                 "ARTIFACT_PRODUCER", aid, producer)
        if producer in result_map:
            a.expect(aid in result_map[producer]["artifact_refs"], "PRODUCER_BACKLINK", aid)
        if art.get("media_type") == "application/json" or path.suffix == ".json":
            loaded[aid] = json.loads(data)

    for r in results:
        rid = r["result_id"]
        node_id = r["node_id"]
        if not a.expect(node_id in node_map, "RESULT_NODE_IN_FIXED_DAG", rid):
            continue
        parents = r["parent_result_ids"]
        a.expect(len(set(parents)) == len(parents), "NO_DUPLICATE_PARENT", rid)
        resolved = [result_map.get(p) for p in parents]
        a.expect(all(x is not None for x in resolved), "PARENT_RESOLVES", rid)
        if not all(x is not None for x in resolved):
            continue
        a.expect([x["node_id"] for x in resolved] == node_map[node_id]["parents"],
                 "EXACT_ORDERED_DAG_PARENTS", rid)
        a.expect(all(x["execution_status"] == "success" for x in resolved),
                 "PARENT_SUCCESS", rid)
        for field in ("direct_reads", "effective_reads"):
            keys = [x["object_key"] for x in r[field]]
            a.expect(len(keys) == len(set(keys)), "UNIQUE_READS", rid + ":" + field)
            if rid not in original_ids:
                a.expect(keys == sorted(keys), "NEW_READS_SORTED", rid + ":" + field)
        union: dict[str, int] = {}
        mixed = False
        for ref in r["direct_reads"] + [ref for p in resolved for ref in p["effective_reads"]]:
            k, v = ref["object_key"], ref["version"]
            if k in union and union[k] != v:
                mixed = True
            union[k] = v
        if r["execution_status"] == "success":
            a.expect(not mixed, "NO_SUCCESS_WITH_MIXED_READS", rid)
            a.expect(union == _ref_map(r["effective_reads"]), "EFFECTIVE_READ_UNION", rid)
        snapshot = r.get("input_snapshot")
        if a.expect(isinstance(snapshot, dict), "INPUT_SNAPSHOT_PRESENT", rid):
            a.expect(_digest(snapshot) == r["input_digest"], "INPUT_DIGEST", rid)
            request = view["task"].get("request", view["task"].get("public_request"))
            a.expect(snapshot.get("request") == request, "INPUT_FROZEN_REQUEST", rid)
            bindings = snapshot.get("artifact_bindings", [])
            for binding in bindings:
                aid = binding["artifact_id"]
                a.expect(artifact_map.get(aid) == binding, "INPUT_ARTIFACT_BINDING", rid + ":" + aid)
            if rid not in original_ids:
                values = snapshot.get("artifact_values", {})
                a.expect(set(values) == {b["artifact_id"] for b in bindings}, "INPUT_ARTIFACT_VALUE_SET", rid)
                for aid, value in values.items():
                    a.expect(aid in loaded and loaded[aid] == value, "INPUT_ARTIFACT_ACTUAL_BYTES", rid + ":" + aid)
                users = [m["content"] for m in snapshot.get("rendered_messages", []) if m.get("role") == "user"]
                core = {k: value for k, value in snapshot.items() if k != "rendered_messages"}
                a.expect(len(users) == 1 and json.loads(users[0]) == core,
                         "ACTUAL_RENDERED_INPUT_EQUALS_SNAPSHOT", rid)
            parent_inputs = snapshot.get("parent_inputs", [])
            a.expect([p["result_id"] for p in parent_inputs] == parents,
                     "INPUT_ACTUAL_PARENT_ORDER", rid)
            for saved, parent in zip(parent_inputs, resolved):
                a.expect(saved.get("payload") == parent["payload"], "INPUT_PARENT_PAYLOAD", rid)
                if "payload_digest" in saved:
                    a.expect(saved["payload_digest"] == _digest(parent["payload"]),
                             "INPUT_PARENT_PAYLOAD_DIGEST", rid)
                a.expect(saved.get("effective_reads") == parent["effective_reads"],
                         "INPUT_PARENT_READS", rid)
            source_inputs = snapshot.get("direct_source_inputs", [])
            a.expect(_ref_map(source_inputs) == _ref_map(r["direct_reads"]),
                     "INPUT_DIRECT_SOURCES", rid)
            for source in source_inputs:
                a.expect(_digest(source["payload"]) == source["payload_digest"],
                         "INPUT_SOURCE_PAYLOAD_DIGEST", rid)
                a.expect(history_map.get((source["object_key"], source["version"])) == source,
                         "INPUT_SOURCE_RESOLVES_HISTORY", rid)
        for aid in r["artifact_refs"]:
            a.expect(aid in artifact_map and artifact_map[aid]["producer_result_id"] == rid,
                     "RESULT_ARTIFACT_BINDING", rid, aid)
        for cid in r["call_ids"]:
            c = call_map.get(cid)
            a.expect(c is not None and c["attempt_id"] == r["attempt_id"] and
                     c["node_id"] == node_id and c["input_digest"] == r["input_digest"],
                     "RESULT_CALL_BINDING", rid, cid)
        for tid in r["tool_receipt_ids"]:
            t = receipt_map.get(tid)
            a.expect(t is not None and t["producer_result_id"] == rid and
                     t["input_digest"] == r["input_digest"] and t["node_id"] == node_id,
                     "RESULT_TOOL_BINDING", rid, tid)
        if rid not in original_ids and r["execution_status"] == "success":
            a.expect(all(key in current and current[key]["version"] == version for key, version in union.items()),
                     "NO_DISPATCH_OF_STALE_INHERITED_INPUT", rid)
        if "recipe:rf" in union and node_id in ("profile", "inspect", "prepare", "plan_lr", "fit_lr", "predict_lr", "summary_lr"):
            a.expect(False, "RF_DEPENDENCY_LEAK_IN_LR", rid)

    # Count actual durable dispatch identities, never copies of shared prefix.
    new_results = [r for r in results if r["result_id"] not in original_ids]
    prefix_calls = {c for r in results if r["result_id"] in original_ids for c in r["call_ids"]}
    prefix_calls.update(view.get("metadata", {}).get("initial_call_ids", []))
    prefix_tools = {c for r in results if r["result_id"] in original_ids for c in r["tool_receipt_ids"]}
    prefix_tools.update(view.get("metadata", {}).get("initial_receipt_ids", []))
    new_calls = [c for c in calls if c["call_id"] not in prefix_calls]
    new_tools = [t for t in tools if t["receipt_id"] not in prefix_tools]
    a.expect(len(new_calls) <= 15, "LLM_CALL_CAP", branch)
    a.expect(len(new_tools) <= 30, "CPU_JOB_CAP", branch)
    for c in calls:
        a.expect(c.get("mode", "fixture" if c.get("fixture_only") and c["call_id"] in prefix_calls else None) in ("fixture", "fake_http"), "NO_REAL_CALL", c["call_id"])
        a.expect(c.get("request_sent") is False, "NO_NETWORK_SENT", c["call_id"])
        a.expect(c.get("cost_nano_usd", 0) == 0, "FAKE_ZERO_COST", c["call_id"])
        a.expect(not c.get("endpoint") or c["endpoint"].startswith("fake"),
                 "FAKE_ENDPOINT_ONLY", c["call_id"])
    for key, actual in (("physical_calls", len(new_calls)), ("cpu_jobs", len(new_tools))):
        # V0 explicitly fixes these counter names; no inference from results.
        a.expect(state["counters"].get(key) == actual, "ACTUAL_COUNTER_MATCH", key,
                 {"actual": actual, "declared": state["counters"].get(key)})
    attempt_map = {att["attempt_id"]: att for att in attempts}
    a.expect(len(attempt_map) == len(attempts), "UNIQUE_ATTEMPT_ID", branch)
    new_attempts = [att for att in attempts if att.get("attempt_id") not in
                    {r["attempt_id"] for r in results if r["result_id"] in original_ids}]
    dispatch_ids = [att.get("dispatch_id") for att in new_attempts]
    a.expect(all(dispatch_ids) and len(dispatch_ids) == len(set(dispatch_ids)), "UNIQUE_PHYSICAL_DISPATCH", branch)
    for c in new_calls:
        a.expect(c["attempt_id"] in attempt_map, "CALL_HAS_DURABLE_ATTEMPT", c["call_id"])
    for t in new_tools:
        a.expect(t["attempt_id"] in attempt_map, "TOOL_HAS_DURABLE_ATTEMPT", t["receipt_id"])
        a.expect(t["parameters"].get("training_performed") is False and
                 t["parameters"].get("actual_model_prediction_performed") is False,
                 "NO_ACTUAL_TRAINING_OR_PREDICTION", t["receipt_id"])
    stage_calls = Counter(attempt_map[c["attempt_id"]].get("plan_id") for c in new_calls if c["attempt_id"] in attempt_map)
    for plan_id, count in stage_calls.items():
        a.expect(count <= 5, "FIVE_CALLS_PER_ACCEPTED_STAGE", str(plan_id))
    for att in attempts:
        if att.get("attempt_id") in {r["attempt_id"] for r in results if r["result_id"] in original_ids}:
            continue
        at = att.get("started_at_utc", att.get("dispatch_started_at_utc"))
        if at and deadline:
            a.expect(_time(start) <= _time(at) < _time(deadline), "DISPATCH_WITHIN_FIXED_DEADLINE",
                     att["attempt_id"])
        if att.get("status") in ("completed", "success", "cancelled", "failed", "timeout") and "worker_reaped" in att:
            a.expect(att["worker_reaped"], "WORKER_REAPED", att["attempt_id"])
    _check_events(view, dag, a)

    adopted: set[str] = set()
    stack = [selected.get(order[-1])] if state.get("terminal_status") == "completed_correct" else []
    while stack:
        rid = stack.pop()
        if not rid or rid in adopted:
            continue
        if not a.expect(rid in result_map, "ADOPTED_RESULT_EXISTS", rid):
            continue
        adopted.add(rid)
        r = result_map[rid]
        a.expect(r["execution_status"] == "success", "ADOPTED_SUCCESS", rid)
        for receipt_id in r["tool_receipt_ids"]:
            a.expect(receipt_id in receipt_map and receipt_map[receipt_id]["exit_code"] == 0,
                     "ADOPTED_TOOL_EXIT_SUCCESS", rid)
        a.expect(rid not in state["invalidated_result_ids"], "ADOPTED_NOT_INVALIDATED", rid)
        a.expect(selected.get(r["node_id"]) == rid, "ADOPTED_IS_SELECTED", rid)
        a.expect(all(k in current and current[k]["version"] == v
                     for k, v in _ref_map(r["effective_reads"]).items()),
                 "ADOPTED_CURRENT", rid)
        stack.extend(r["parent_result_ids"])
    business_correct = False
    if state.get("terminal_status") == "completed_correct":
        a.expect(len(adopted) == len(order), "COMPLETE_FINAL_ANCESTRY", branch)
        a.expect(not state["pending_node_ids"], "COMPLETED_NO_PENDING", branch)
        before = len(a.issues)
        _business(view, result_map, loaded, current, a)
        business_correct = not a.issues
    else:
        a.expect(not view.get("effects") or state.get("terminal_status") in ("permission_denied_safe", "conflict_safe"),
                 "FAILED_BRANCH_NO_NEW_EFFECT", branch)
    reused = sorted(adopted.intersection(original_ids))
    return {"passed": not a.issues, "business_correct": business_correct,
            "checks": a.checks, "issues": a.issues,
            "statistics": {"new_llm_calls": len(new_calls), "new_cpu_jobs": len(new_tools),
                           "real_requests": sum(bool(c.get("request_sent")) for c in calls),
                           "api_cost_nano_usd": sum(c.get("cost_nano_usd", 0) for c in calls),
                           "adopted_original_result_ids": reused,
                           "adopted_original_nodes": sorted(result_map[x]["node_id"] for x in reused),
                           "new_result_count": len(new_results),
                           "actual_training": 0,
                           "prefix_evidence_mode": "executed_fake_adapter_prefix" if original.get("prefix_mode") else "constructed_V0_fixture",
                           "scope": "V1 synthetic workflow evidence only"}}


def _check_events(view: dict, dag: dict, a: _Audit) -> None:
    state = view["state"]
    events = _rows(view.get("events", []))
    plans = _rows(view.get("plans", []))
    branch = state["branch_id"]
    a.expect(len({x["event_id"] for x in events}) == len(events), "EVENT_ID_UNIQUE", branch)
    a.expect(len({x["plan_id"] for x in plans}) == len(plans), "PLAN_ID_UNIQUE", branch)
    kinds = Counter(p["kind"] for p in plans if p.get("kind") in ("stale", "semantic"))
    for kind in ("stale", "semantic"):
        a.expect(kinds[kind] == state["counters"][kind + "_used"], "DURABLE_PLAN_COUNTER", kind)
    by_id = {r["result_id"]: r for r in _rows(view["results"])}
    authority = {s["object_key"]: s["version"] for s in _rows(view["sources"])}
    guards = {g["guard_id"]: g for g in _rows(view.get("guards", []))}
    for plan in plans:
        kind = plan.get("kind")
        if kind not in ("stale", "semantic"):
            continue
        pid = plan["plan_id"]
        before, after = plan["counters_before"], plan["counters_after"]
        a.expect(before[kind + "_used"] == 0 and after[kind + "_used"] == 1,
                 "PLAN_CONSUMED_AT_ACCEPTANCE", pid)
        other = "semantic" if kind == "stale" else "stale"
        a.expect(before[other + "_used"] == after[other + "_used"], "ONE_COUNTER_ONLY", pid)
        pending = set(plan["pending_before"])
        carried = set(plan["carried_pending_node_ids"])
        ordered = plan["ordered_node_ids"]
        a.expect(pending <= carried and carried <= set(ordered), "INTERRUPTED_PENDING_UNION", pid)
        a.expect(ordered == [n for n in dag["topological_order"] if n in set(ordered)],
                 "PLAN_TOPOLOGICAL_UNIQUE", pid)
        a.expect(plan["admission_event_id"] in {e["event_id"] for e in events},
                 "PLAN_HAS_ADMISSION_EVENT", pid)
        guard = guards.get(plan["guard_id"])
        a.expect(guard is not None and guard["classification"] == kind,
                 "CORRECTION_SUPPORTED_BY_PERSISTED_DIAGNOSIS", pid)
        if kind == "stale" and guard:
            a.expect(guard["full_version_diagnosis"], "FULL_DIAGNOSIS_BEFORE_STALE_ACCEPT", pid)
            selected_ids = {x for x in plan["selected_before"].values() if x}
            observed = set()
            stack = list(selected_ids)
            while stack:
                rid = stack.pop()
                if rid in observed or rid not in by_id:
                    continue
                observed.add(rid)
                stack.extend(by_id[rid]["parent_result_ids"])
            stale_ids = {rid for rid in observed if any(authority.get(ref["object_key"]) != ref["version"]
                         for ref in by_id[rid]["effective_reads"])}
            diagnosed = {rid for issue in guard["issues"] for rid in issue["related_result_ids"]}
            a.expect(stale_ids <= diagnosed, "ALL_OBSERVED_STALE_IN_SINGLE_DIAGNOSIS", pid,
                     sorted(stale_ids - diagnosed))
            seeds = {by_id[rid]["node_id"] for rid in stale_ids}
            expected = set(_close(seeds, dag)) | pending | {n for n, r in plan["selected_before"].items() if not r}
            a.expect(set(ordered) == expected, "STALE_PLAN_EXACT_REQUIRED_UNION", pid)
    executions = Counter()
    stage_calls = Counter()
    for att in _rows(view.get("attempts", [])):
        if att.get("stage") is None or att.get("plan_id") is None:
            continue
        # One attempt identity may have multiple call/tool receipts; one job
        # acceptance is not a second DAG node execution.
        executions[(att["plan_id"], att["node_id"])] += 1
    for key, count in executions.items():
        a.expect(count <= 1, "ONE_NODE_PER_ACCEPTED_STAGE", str(key))
    previous_after = None
    calls = {c["call_id"]: c for c in _rows(view.get("calls", []))}
    tools = {t["receipt_id"]: t for t in _rows(view.get("tool_receipts", []))}
    artifacts = {t["artifact_id"]: t for t in _rows(view.get("artifacts", []))}
    for e in events:
        before_state, after_state = e.get("before"), e.get("after")
        if before_state and after_state:
            if previous_after is not None:
                a.expect(before_state == previous_after, "EVENT_STATE_CHAIN", e["event_id"])
            a.expect(after_state["state_version"] == before_state["state_version"] + 1,
                     "EVENT_STATE_VERSION_CAS", e["event_id"])
            previous_after = after_state
            for field in ("physical_calls", "cpu_jobs", "stale_used", "semantic_used"):
                a.expect(after_state["counters"][field] >= before_state["counters"][field],
                         "COUNTER_NEVER_RESETS", e["event_id"] + ":" + field)
            if e["kind"] != "dispatch":
                for field in ("physical_calls", "cpu_jobs"):
                    a.expect(after_state["counters"][field] == before_state["counters"][field],
                             "ONLY_DISPATCH_CONSUMES_WORK_QUOTA", e["event_id"])
        decision = e.get("decision") or {}
        detail = e.get("details", {})
        command = None
        if e["kind"] == "begin_branch":
            command = {}
        elif e["kind"] == "admit":
            command = {"decision": decision, "guard": guards.get(decision.get("guard_id"))}
        elif e["kind"] == "dispatch":
            command = {"decision": decision}
        elif e["kind"] in ("guard", "version_scan"):
            command = {"guard": guards.get(detail.get("guard_id"))}
            if e["kind"] == "version_scan":
                command["decision"] = decision
        elif e["kind"] == "settle" and "raw_candidate" in detail:
            raw = detail["raw_candidate"]
            command = {"attempt_id": raw["attempt_id"], "package": {
                "result": raw, "artifacts": [artifacts[x] for x in raw["artifact_refs"]],
                "calls": [calls[x] for x in raw["call_ids"]],
                "tool_receipts": [tools[x] for x in raw["tool_receipt_ids"]]}}
        if command is not None:
            a.expect(e["command_digest"] == _digest({"kind": e["kind"], "command": command}),
                     "DURABLE_COMMAND_DIGEST", e["event_id"])
        if decision.get("kind") == "compensate" and before_state and after_state and after_state.get("terminal_status") != "conflict_safe":
            initial = view["initial_snapshot"]
            initial_results = initial["results"]
            target = view["notice"]["faulty_result_id"]
            wanted = {target}
            if state["policy"] == "FULL":
                wanted = {r["result_id"] for r in initial_results}
            elif state["policy"] == "EAGER":
                wanted |= {r["result_id"] for r in initial_results if any(
                    authority.get(ref["object_key"]) != ref["version"] for ref in r["effective_reads"])}
            while True:
                expanded = wanted | {r["result_id"] for r in initial_results if wanted.intersection(r["parent_result_ids"])}
                if expanded == wanted:
                    break
                wanted = expanded
            required = {r["node_id"] for r in initial_results if r["result_id"] in wanted}
            required |= {n for n, rid in before_state["selected_by_node"].items() if not rid}
            required |= set(before_state["pending_node_ids"])
            a.expect(set(decision["ordered_node_ids"]) == required, "POLICY_INITIAL_REQUIRED_NODES", e["event_id"])
            a.expect(set(after_state["invalidated_result_ids"]) == wanted, "POLICY_INITIAL_RESULT_INVALIDATION", e["event_id"])
            a.expect(after_state["counters"]["stale_used"] == 0 and after_state["counters"]["semantic_used"] == 0,
                     "INITIAL_STRATEGY_USES_NO_CORRECTION_ALLOWANCE", e["event_id"])
        for image in (e.get("before"), e.get("after"), e.get("state_before"), e.get("state_after")):
            if isinstance(image, dict) and image.get("started_at_utc"):
                a.expect(image["started_at_utc"] == state["started_at_utc"] and
                         image["deadline_utc"] == state["deadline_utc"],
                         "NO_DEADLINE_RESET", e["event_id"])
        at = e.get("accepted_at_utc", e.get("now_utc"))
        decision = e.get("decision") or {}
        if at and state.get("deadline_utc") and decision.get("kind") in ("execute_node", "admit_correction", "need_version_scan"):
            a.expect(_time(at) < _time(state["deadline_utc"]), "ADMISSION_WITHIN_DEADLINE", e["event_id"])
    if previous_after is not None:
        a.expect(previous_after == state, "FINAL_STATE_EQUALS_EVENT_TAIL", branch)


def _business(view: dict, results: dict, loaded: dict, sources: dict, a: _Audit) -> None:
    state = view["state"]
    selected = state["selected_by_node"]
    payloads = {n: results[r]["payload"] for n, r in selected.items() if r in results}
    task = view["task"]
    request = task.get("public_request", task.get("request", {}))
    if "read_metadata" in selected:
        aliases = task["resolved_source_aliases"]
        meta = sources[aliases["metadata"]]["payload"]
        permission = sources[aliases["permission"]]["payload"]
        resources = sources[aliases["resources"]]["payload"]
        expected = {"dataset_id": request["dataset_id"], "purpose": request["purpose"],
                    "num_examples": meta["num_examples"], "batch_size": request["batch_size"],
                    "epochs": request["epochs"],
                    "steps": math.ceil(meta["num_examples"] / request["batch_size"]) * request["epochs"],
                    "workers": min(request["requested_workers"], resources["max_workers"]),
                    "requested_workers": request["requested_workers"],
                    "allowed": permission["allowed"], "policy_revision": permission["policy_revision"]}
        a.expect(permission["allowed"] and permission["policy_revision"] >= 1, "MICRO_PERMISSION", state["branch_id"])
        a.expect(payloads["execute"].get("config") == payloads["plan"] and
                 payloads["execute"].get("command") == payloads["plan"],
                 "MICRO_COMMAND_CONFIG_EQUAL_PLAN", state["branch_id"])
        for node in ("plan", "execute"):
            p = payloads[node]
            p = p.get("config", p.get("command", p))
            for k, v in expected.items():
                a.expect(p.get(k) == v, "MICRO_BUSINESS_FIELD", node + "." + k,
                         {"expected": v, "actual": p.get(k)})
    else:
        scores = {}
        for family in ("lr", "rf"):
            summary = payloads["summary_" + family]
            metrics = summary["metrics"]
            scores[family.upper()] = metrics["average_precision"]
            rid = selected["summary_" + family]
            receipts = [r for r in _rows(view["tool_receipts"]) if r["producer_result_id"] == rid]
            authority = next((r["parameters"].get("unmodified_metrics", r["parameters"].get("metrics")) for r in receipts
                              if r["parameters"].get("unmodified_metrics", r["parameters"].get("metrics")) is not None), None)
            if authority is not None:
                a.expect(metrics == authority, "MACRO_DELIVERED_SUMMARY_EQUALS_RAW", rid)
            # Fixture predictions can be independently evaluated, though they
            # are emphatically not outputs of actual fitted estimators in V1.
            pred = next((loaded[aid] for aid in results[selected["predict_" + family]]["artifact_refs"]
                         if aid in loaded and "positive_probabilities" in loaded[aid]), None)
            if pred:
                matrix_id = payloads["prepare"]["families"][family]["matrix_artifact_id"]
                matrix = loaded[matrix_id]
                a.expect(matrix["val_row_ids"] == pred["row_ids"], "MACRO_PREDICTION_ROW_BINDING", rid)
                ap = _average_precision(matrix["val_y"], pred["positive_probabilities"])
                a.expect(abs(metrics["average_precision"] - ap) <= 1e-12, "MACRO_AP_FROM_PREDICTIONS", rid)
                fit_artifacts = results[selected["fit_" + family]]["artifact_refs"]
                a.expect(pred.get("model_artifact_id") in fit_artifacts, "MACRO_PREDICTION_MODEL_BINDING", rid)
                model = loaded[pred["model_artifact_id"]]
                recipe = sources["recipe:" + family]["payload"]["parameters"]
                a.expect(model["parameters"] == recipe, "MACRO_MODEL_RECIPE", rid)
                train_ids = sources["data:train"]["payload"]["row_ids"]
                a.expect(model.get("training_row_ids", model.get("train_row_ids")) == train_ids,
                         "MACRO_MODEL_TRAINING_ROWS", rid)
        report = payloads["report"]
        chosen = "LR" if scores["LR"] >= scores["RF"] - 1e-6 else "RF"
        a.expect(report["chosen_family"] == chosen, "MACRO_SELECTION_TIE_BREAK", state["branch_id"])
        a.expect(report["validation_average_precision"] == scores, "MACRO_REPORT_SCORES", state["branch_id"])
        family = chosen.lower()
        pred_id = payloads["predict_" + family]["prediction_artifact_id"]
        model_id = payloads["fit_" + family]["model_artifact_id"]
        a.expect(report["prediction_artifact_id"] == pred_id and report["model_artifact_id"] == model_id,
                 "MACRO_REPORT_CHOSEN_ARTIFACTS", state["branch_id"])
        candidate_id = payloads["publish"]["candidate_artifact_id"]
        candidate = loaded[candidate_id]
        a.expect(candidate["model_artifact_id"] == model_id and candidate["prediction_artifact_id"] == pred_id,
                 "MACRO_MANIFEST_CHOSEN_ARTIFACTS", state["branch_id"])
        report_artifact = report.get("report_artifact_id") or results[selected["report"]]["artifact_refs"][0]
        a.expect(candidate["report_artifact_id"] == report_artifact,
                 "MACRO_MANIFEST_REPORT_BINDING", state["branch_id"])


def _average_precision(labels: list[int], scores: list[float]) -> float:
    if len(labels) != len(scores) or not labels or any(not math.isfinite(x) for x in scores):
        raise ValueError("invalid probability fixture")
    positives = sum(int(y == 1) for y in labels)
    if not positives:
        return 0.0
    pairs = sorted(zip(scores, labels), reverse=True)
    numerator = 0.0
    hits = 0
    i = 0
    while i < len(pairs):
        j = i
        newly_positive = 0
        while j < len(pairs) and pairs[j][0] == pairs[i][0]:
            newly_positive += int(pairs[j][1] == 1)
            j += 1
        hits += newly_positive
        numerator += newly_positive * hits / j
        i = j
    return numerator / positives


def check_campaign(exports: list[dict], artifact_root: str | Path,
                   offline_registry: list[dict] | None = None) -> dict:
    """Independently reconcile a V1 registry batch and same-freeze triplets.

    ``exports`` are raw Store exports, not precomputed runner summaries.
    A supplied registry makes exact coverage mandatory; missing failed branches
    cannot disappear from the denominator. This never mutates frozen registration.
    """
    a = _Audit()
    audits = [check_export(x, artifact_root) for x in exports]
    ids = [x.get("metadata", {}).get("item_id", x["state"]["branch_id"]) for x in exports]
    a.expect(len(ids) == len(set(ids)), "UNIQUE_CAMPAIGN_ITEM_ID")
    expected = {x["item_id"]: x for x in (offline_registry or [])}
    if offline_registry is not None:
        a.expect(set(ids) == set(expected), "EXACT_FROZEN_OFFLINE_REGISTRY_COVERAGE",
                 detail={"missing": sorted(set(expected) - set(ids)), "extra": sorted(set(ids) - set(expected))})
    groups: dict[str, list[dict]] = {}
    for item_id, view, audit in zip(ids, exports, audits):
        state = view["state"]
        a.expect(audit["passed"], "BRANCH_INDEPENDENT_AUDIT", item_id,
                 [i["code"] for i in audit["issues"]])
        a.expect(state["status"] == "terminal", "ALL_REGISTERED_BRANCHES_TERMINAL", item_id)
        if expected:
            registration = expected.get(item_id, {})
            a.expect(registration.get("policy") == state["policy"] and
                     registration.get("workflow_id") == view["dag"]["workflow_id"],
                     "ITEM_POLICY_WORKFLOW_BINDING", item_id)
            scene = registration.get("scene_id", state["scene_id"])
        else:
            scene = state["scene_id"]
        groups.setdefault(scene, []).append(view)
    for scene, views in groups.items():
        a.expect(sorted(x["state"]["policy"] for x in views) == ["EAGER", "FULL", "LAZY"],
                 "ONE_OF_EACH_POLICY_PER_SCENE", scene)
        for field in ("initial_snapshot", "dag", "task", "notice", "sources"):
            values = {_digest(x.get(field)) for x in views}
            a.expect(len(values) == 1, "SHARED_FROZEN_" + field.upper(), scene)
        # No policy may silently get different node/branch caps or schemas.
        caps = [x["dag"]["branch_caps"] for x in views]
        a.expect(all(c == {"physical_llm_calls": 15, "cpu_jobs": 30, "wall_seconds": 1800}
                     for c in caps), "COMMON_BRANCH_CAPS", scene)
    real = sum(r["statistics"].get("real_requests", 0) for r in audits)
    fee = sum(r["statistics"].get("api_cost_nano_usd", 0) for r in audits)
    a.expect(real == 0 and fee == 0, "OFFLINE_NO_REAL_REQUEST_OR_API_FEE")
    return {"passed": not a.issues, "checks": a.checks, "issues": a.issues,
            "branch_audits": audits, "item_count": len(exports), "scene_count": len(groups),
            "business_correct_count": sum(x["business_correct"] for x in audits),
            "real_requests": real, "api_cost_nano_usd": fee,
            "scope": "V1 deterministic fake-client execution; no model training"}
