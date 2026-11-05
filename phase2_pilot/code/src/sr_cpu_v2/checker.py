"""Read-only durable-evidence audit for V2 CPU workflows.

No imports from the production tools, Store, guard or policy. Numerical checks
run separately in check_worker, under the same supervised resource boundary.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode()


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _rows(value):
    return list(value.values()) if isinstance(value, dict) else value or []


def _time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class _Audit:
    def __init__(self):
        self.checks = 0
        self.issues = []

    def expect(self, condition, code, ref="", detail=None):
        self.checks += 1
        if not condition:
            self.issues.append({"code": code, "ref": ref, "detail": detail})
        return bool(condition)


def audit_export(view, artifact_root, v0_root):
    """Audit source/data ancestry, immutable files, counters and actual reuse.

    A safe failure can pass the evidence audit with business_correct false.
    A completed_correct label alone never establishes either property.
    """
    audit = _Audit()
    try:
        return _audit(view, Path(artifact_root).resolve(), Path(v0_root).resolve(), audit)
    except (KeyError, TypeError, ValueError, OSError, OverflowError, AttributeError, IndexError) as exc:
        audit.expect(False, "MALFORMED_EXPORT", detail=f"{type(exc).__name__}: {exc}")
        return {"passed": False, "business_correct": False, "checks": audit.checks,
                "issues": audit.issues, "statistics": {}}


def _audit(view, root, v0, a):
    import jsonschema
    state = view["state"]
    branch = state["branch_id"]
    dag = view["dag"]
    nodes = {n["node_id"]: n for n in dag["nodes"]}
    results = _rows(view["results"])
    result_map = {r["result_id"]: r for r in results}
    artifacts = _rows(view.get("artifacts"))
    art_map = {r["artifact_id"]: r for r in artifacts}
    calls = _rows(view.get("calls"))
    receipts = _rows(view.get("tool_receipts"))
    call_map = {c["call_id"]: c for c in calls}
    receipt_map = {r["receipt_id"]: r for r in receipts}
    attempts = _rows(view.get("attempts"))
    attempt_map = {r["attempt_id"]: r for r in attempts}
    events = _rows(view.get("events"))
    plans = _rows(view.get("plans"))
    sources = _rows(view.get("sources"))
    current = {s["object_key"]: s for s in sources}
    initial = view.get("initial_snapshot", {})
    initial_results = _rows(initial.get("results"))
    initial_ids = {r["result_id"] for r in initial_results}
    initial_ids.update(view.get("metadata", {}).get("initial_result_ids", []))
    initial_calls = {c for r in initial_results for c in r["call_ids"]}
    initial_receipts = {c for r in initial_results for c in r["tool_receipt_ids"]}
    schema = json.loads((v0 / "contracts/records.schema.json").read_text())
    for collection in [results, artifacts, calls, receipts, sources, plans, [state], _rows(view.get("guards"))]:
        for record in collection:
            errors = list(jsonschema.Draft202012Validator({**schema, "oneOf": [{"$ref": "#/$defs/" + record["record_type"]}]}).iter_errors(record))
            a.expect(not errors, "FROZEN_RECORD_SCHEMA", record.get("result_id", record.get("record_type", "")),
                     [e.message for e in errors[:2]])
    a.expect(len(result_map) == len(results), "UNIQUE_RESULT_ID", branch)
    a.expect(len(art_map) == len(artifacts), "UNIQUE_ARTIFACT_ID", branch)
    a.expect(len(call_map) == len(calls), "UNIQUE_CALL_ID", branch)
    a.expect(len(receipt_map) == len(receipts), "UNIQUE_RECEIPT_ID", branch)
    a.expect(len(attempt_map) == len(attempts), "UNIQUE_ATTEMPT_ID", branch)
    a.expect(state["policy"] in ("FULL", "LAZY", "EAGER"), "KNOWN_POLICY", branch)
    a.expect(set(state["selected_by_node"]) == set(nodes), "FIXED_DAG_SELECTION", branch)
    for old in initial_results:
        a.expect(result_map.get(old["result_id"]) == old, "PREFIX_RESULT_UNMODIFIED", old["result_id"])
    if initial and view.get("prefix_digest"):
        a.expect(_digest(initial) == view["prefix_digest"], "PREFIX_SNAPSHOT_DIGEST", branch)
    histories = {(x["object_key"], x["version"]): x for x in _rows(view.get("source_history"))}
    for source in list(histories.values()) + sources:
        a.expect(source["payload_digest"] == _digest(source["payload"]), "SOURCE_PAYLOAD_DIGEST", source["object_key"])
    for source in sources:
        a.expect(histories.get((source["object_key"], source["version"])) == source, "CURRENT_SOURCE_IN_HISTORY", source["object_key"])
    fingerprint = _digest([{"object_key": s["object_key"], "version": s["version"], "payload_digest": s["payload_digest"]}
                           for s in sorted(sources, key=lambda x: x["object_key"])])
    if state.get("terminal_status") != "uncertain":
        a.expect(state["source_fingerprint"] == fingerprint, "SOURCE_FINGERPRINT", branch)
    input_producers = {r.get("producer_result_id", r.get("producer_id", r.get("result_id")))
                       for r in _rows(view.get("input_producers"))}
    loaded = {}
    for artifact in artifacts:
        aid = artifact["artifact_id"]
        path = Path(artifact["uri"])
        path = (root / path).resolve() if not path.is_absolute() else path.resolve()
        if not a.expect(path != root and root in path.parents, "ARTIFACT_PATH_ROOT", aid):
            continue
        if not a.expect(path.is_file(), "ARTIFACT_EXISTS", aid):
            continue
        stat = path.stat()
        raw = path.read_bytes()
        a.expect(not (stat.st_mode & 0o222), "ARTIFACT_IMMUTABLE", aid)
        a.expect(stat.st_size <= 128 * 1024 ** 2, "ARTIFACT_128MIB_CAP", aid)
        a.expect(len(raw) == artifact["size_bytes"] and hashlib.sha256(raw).hexdigest() == artifact["sha256"], "ARTIFACT_BYTES", aid)
        producer = artifact["producer_result_id"]
        a.expect(producer in result_map or producer in input_producers, "ARTIFACT_PRODUCER_RESOLVES", aid)
        if producer in result_map:
            a.expect(aid in result_map[producer]["artifact_refs"], "ARTIFACT_PRODUCER_BACKLINK", aid)
        if artifact["media_type"] == "application/json":
            loaded[aid] = json.loads(raw)
    for result in results:
        rid = result["result_id"]
        if not a.expect(result["node_id"] in nodes, "RESULT_FIXED_DAG_NODE", rid):
            continue
        parent_ids = result["parent_result_ids"]
        parents = [result_map.get(p) for p in parent_ids]
        if not a.expect(all(parents), "PARENTS_EXIST", rid):
            continue
        a.expect([p["node_id"] for p in parents] == nodes[result["node_id"]]["parents"], "EXACT_DAG_PARENTS", rid)
        a.expect(all(p["execution_status"] == "success" for p in parents), "SUCCESSFUL_PARENTS", rid)
        union = {}
        mixed = False
        for ref in result["direct_reads"] + [x for p in parents for x in p["effective_reads"]]:
            mixed |= ref["object_key"] in union and union[ref["object_key"]] != ref["version"]
            union[ref["object_key"]] = ref["version"]
        effective = {r["object_key"]: r["version"] for r in result["effective_reads"]}
        if result["execution_status"] == "success":
            a.expect(not mixed and union == effective, "EFFECTIVE_READ_UNION", rid)
        snapshot = result.get("input_snapshot")
        if a.expect(isinstance(snapshot, dict), "INPUT_SNAPSHOT_PRESENT", rid):
            a.expect(_digest(snapshot) == result["input_digest"], "INPUT_SNAPSHOT_DIGEST", rid)
            if "parent_inputs" in snapshot:
                a.expect([p["result_id"] for p in snapshot["parent_inputs"]] == parent_ids, "INPUT_PARENT_IDENTITIES", rid)
                for saved, parent in zip(snapshot["parent_inputs"], parents):
                    a.expect(saved.get("payload") == parent["payload"], "INPUT_PARENT_ACTUAL_PAYLOAD", rid)
            for binding in snapshot.get("artifact_bindings", []):
                a.expect(art_map.get(binding["artifact_id"]) == binding, "INPUT_ARTIFACT_BINDING", rid)
            for source in snapshot.get("direct_source_inputs", []):
                a.expect(histories.get((source["object_key"], source["version"])) == source, "INPUT_SOURCE_HISTORY_BINDING", rid)
        for aid in result["artifact_refs"]:
            a.expect(aid in art_map and art_map[aid]["producer_result_id"] == rid, "RESULT_ARTIFACT_OWNERSHIP", rid, aid)
        for cid in result["call_ids"]:
            call = call_map.get(cid)
            a.expect(call is not None and call["attempt_id"] == result["attempt_id"] and
                     call["input_digest"] == result["input_digest"], "RESULT_CALL_BINDING", rid, cid)
        for tid in result["tool_receipt_ids"]:
            receipt = receipt_map.get(tid)
            a.expect(receipt is not None and receipt["producer_result_id"] == rid and
                     receipt["input_digest"] == result["input_digest"], "RESULT_TOOL_BINDING", rid, tid)
        if result["node_id"] in ("profile", "inspect", "prepare", "plan_lr", "fit_lr", "predict_lr", "summary_lr"):
            a.expect("recipe:rf" not in effective, "NO_RF_DEPENDENCY_IN_SHARED_OR_LR", rid)
    for receipt in receipts:
        tid = receipt["receipt_id"]
        parameters = receipt.get("parameters", {})
        execution = parameters.get("execution")
        a.expect(receipt.get("fixture_only") is False, "REAL_CPU_RECEIPT", tid)
        if not a.expect(isinstance(execution, dict), "CPU_EXECUTION_EVIDENCE", tid):
            continue
        a.expect(execution.get("tool") == receipt["node_id"] and execution.get("worker_reaped") is True and
                 not execution.get("remaining_processes"), "CPU_WORKER_IDENTITY_REAPED", tid)
        limits = execution.get("limits", {})
        a.expect(limits.get("address_space_bytes", 2 ** 63) <= 8 * 1024 ** 3 and
                 limits.get("rss_monitor_bytes", 2 ** 63) <= 8 * 1024 ** 3 and
                 limits.get("max_artifact_bytes", 2 ** 63) <= 128 * 1024 ** 2 and
                 limits.get("total_disk_bytes", 2 ** 63) <= 4 * 1024 ** 3, "CPU_RESOURCE_LIMITS_CONFIGURED", tid)
        a.expect(0 < execution.get("effective_timeout_seconds", 121) <= 120, "CPU_120S_DEADLINE", tid)
        if execution.get("status") == "success":
            a.expect(execution.get("returncode") == 0 and not execution.get("timed_out") and
                     execution.get("peak_rss_bytes", 2 ** 63) <= 8 * 1024 ** 3 and
                     execution.get("wall_seconds", 121) <= execution.get("effective_timeout_seconds", 0),
                     "SUCCESS_WITHIN_RESOURCE_BOUNDARY", tid)
        if receipt["node_id"] in ("fit_lr", "fit_rf"):
            a.expect(parameters.get("actual_model_fit") is True, "REAL_FIT_RECEIPT", tid)
        if receipt["node_id"] in ("predict_lr", "predict_rf"):
            a.expect(parameters.get("actual_model_predict") is True, "REAL_PREDICT_RECEIPT", tid)
    for call in calls:
        a.expect(call.get("mode") in ("fake_http", "fixture") and call.get("request_sent") is False and
                 call.get("cost_nano_usd") == 0, "FAKE_CLIENT_ZERO_NETWORK_COST", call["call_id"])
    new_calls = [c for c in calls if c["call_id"] not in initial_calls]
    new_receipts = [r for r in receipts if r["receipt_id"] not in initial_receipts]
    a.expect(state["counters"]["physical_calls"] == len(new_calls), "ACTUAL_LLM_COUNTER", branch)
    a.expect(state["counters"]["cpu_jobs"] == len(new_receipts), "ACTUAL_CPU_COUNTER", branch)
    a.expect(len(new_calls) <= 15 and len(new_receipts) <= 30, "BRANCH_DISPATCH_CAPS", branch)
    new_attempts = [r for r in attempts if r["attempt_id"] not in {x["attempt_id"] for x in initial_results}]
    identities = [r.get("dispatch_id") for r in new_attempts]
    a.expect(all(identities) and len(identities) == len(set(identities)), "UNIQUE_DURABLE_DISPATCH", branch)
    pairs = [(r["node_id"], r["stage"]) for r in new_attempts]
    a.expect(len(set(pairs)) == len(pairs), "ONCE_PER_NODE_STAGE", branch)
    by_stage = Counter(attempt_map[c["attempt_id"]]["stage"] for c in new_calls if c["attempt_id"] in attempt_map)
    a.expect(all(n <= 5 for n in by_stage.values()), "FIVE_LLM_PER_STAGE", branch)
    start, deadline = state.get("started_at_utc"), state.get("deadline_utc")
    a.expect(bool(start) == bool(deadline), "DEADLINE_PAIR", branch)
    if start:
        a.expect((_time(deadline) - _time(start)).total_seconds() == 1800, "FIXED_BRANCH_1800S", branch)
    for attempt in new_attempts:
        at = attempt.get("started_at_utc")
        if at and deadline:
            a.expect(_time(start) <= _time(at) < _time(deadline), "DISPATCH_BEFORE_DEADLINE", attempt["attempt_id"])
        if attempt.get("status") in ("completed", "success", "failed", "timeout", "cancelled"):
            a.expect(attempt.get("worker_reaped") is True, "DISPATCH_WORKER_REAPED", attempt["attempt_id"])
    accepted_ids = [e["event_id"] for e in events]
    a.expect(len(accepted_ids) == len(set(accepted_ids)), "IDEMPOTENT_EVENT_IDS", branch)
    last_state = None
    for event in events:
        before, after = event.get("before"), event.get("after")
        if before and after:
            a.expect(after["state_version"] == before["state_version"] + 1, "EVENT_STATE_VERSION_CAS", event["event_id"])
            if last_state is not None:
                a.expect(before == last_state, "EVENT_STATE_CHAIN", event["event_id"])
            last_state = after
            if before.get("started_at_utc"):
                a.expect(after["started_at_utc"] == before["started_at_utc"] and after["deadline_utc"] == before["deadline_utc"], "EVENT_FIXED_DEADLINE", event["event_id"])
            for counter in ("physical_calls", "cpu_jobs", "stale_used", "semantic_used"):
                a.expect(after["counters"][counter] >= before["counters"][counter], "COUNTER_MONOTONIC", event["event_id"] + ":" + counter)
    if last_state is not None:
        a.expect(last_state == state, "EVENT_FINAL_STATE", branch)
    for kind in ("stale", "semantic"):
        matching = [p for p in plans if p["kind"] == kind]
        a.expect(len(matching) == state["counters"][kind + "_used"] and len(matching) <= 1, "CORRECTION_CREDIT_ADMISSION", kind)
        for plan in matching:
            a.expect(plan["admission_event_id"] in accepted_ids, "CORRECTION_HAS_ADMISSION", plan["plan_id"])
            a.expect(plan["counters_after"][kind + "_used"] == plan["counters_before"][kind + "_used"] + 1,
                     "CORRECTION_DEDUCTED_ON_ACCEPT", plan["plan_id"])
            a.expect(set(plan["carried_pending_node_ids"]).issubset(plan["ordered_node_ids"]), "PENDING_UNION_CARRIED", plan["plan_id"])
    selected = state["selected_by_node"]
    adopted = set()
    completed = state.get("terminal_status") == "completed_correct"
    pending = [selected.get("publish")] if completed else []
    while pending:
        rid = pending.pop()
        if not rid or rid in adopted:
            continue
        if not a.expect(rid in result_map, "FINAL_ANCESTRY_RESOLVES", str(rid)):
            continue
        adopted.add(rid)
        result = result_map[rid]
        a.expect(result["execution_status"] == "success" and rid not in state["invalidated_result_ids"], "FINAL_RESULT_SUCCESS_VALID", rid)
        a.expect(selected[result["node_id"]] == rid, "FINAL_ANCESTRY_IS_SELECTED", rid)
        for ref in result["effective_reads"]:
            a.expect(ref["object_key"] in current and current[ref["object_key"]]["version"] == ref["version"], "FINAL_ANCESTRY_CURRENT", rid)
        pending.extend(result["parent_result_ids"])
    if completed:
        a.expect(len(adopted) == len(nodes) and not state["pending_node_ids"] and not state["active_attempt_ids"] and not state["unsettled_call_ids"], "COMPLETE_QUIESCENT_ANCESTRY", branch)
        publish = result_map.get(selected.get("publish"), {}).get("payload", {})
        manifest_id = publish.get("candidate_artifact_id")
        a.expect(manifest_id in loaded, "PUBLISH_MANIFEST_ACTUAL_BYTES", branch)
        if manifest_id in loaded:
            a.expect(loaded[manifest_id] == publish.get("publish_manifest"), "PUBLISH_MANIFEST_PAYLOAD_EQUALS_BYTES", branch)
        for key in ("model_artifact_id", "prediction_artifact_id", "report_artifact_id"):
            a.expect(publish.get(key) in art_map, "PUBLISH_REFERENCE_RESOLVES", key)
    # Reuse requires the original identity/file bindings in final ancestry AND
    # no dispatch of that node in this branch; a terminal flag cannot prove it.
    reused = sorted(adopted & initial_ids)
    new_dispatched_nodes = {r["node_id"] for r in new_attempts}
    proven_reuse = []
    for rid in reused:
        result = result_map[rid]
        a.expect(result["node_id"] not in new_dispatched_nodes, "REUSED_NODE_NOT_REDISPATCHED", rid)
        if result["node_id"] not in new_dispatched_nodes:
            proven_reuse.append(rid)
    training_jobs = [r for r in new_receipts if r["node_id"] in ("fit_lr", "fit_rf")]
    predicted_jobs = [r for r in new_receipts if r["node_id"] in ("predict_lr", "predict_rf")]
    return {"passed": not a.issues, "business_correct": completed and not a.issues,
            "checks": a.checks, "issues": a.issues,
            "statistics": {"branch_id": branch, "policy": state["policy"], "new_fake_llm_calls": len(new_calls),
                           "new_cpu_jobs": len(new_receipts), "real_training_jobs": len(training_jobs),
                           "real_prediction_jobs": len(predicted_jobs),
                           "fit_tool_dispatches": len(training_jobs),
                           "successful_model_fits": sum(r["parameters"].get("execution", {}).get("status") == "success" and r["exit_code"] == 0 for r in training_jobs),
                           "workflow_cpu_seconds": sum(float(r.get("cpu_seconds", 0)) for r in new_receipts),
                           "training_cpu_seconds": sum(float(r.get("cpu_seconds", 0)) for r in training_jobs),
                           "summed_worker_wall_seconds": sum(float(r.get("wall_seconds", 0)) for r in new_receipts),
                           "branch_elapsed_seconds": ((_time(events[-1]["accepted_at_utc"]) - _time(start)).total_seconds() if events and start else None),
                           "peak_workflow_rss_bytes": max((r["parameters"].get("execution", {}).get("peak_rss_bytes", 0) for r in new_receipts), default=0),
                           "actual_reused_result_ids": proven_reuse,
                           "actual_reused_nodes": sorted(result_map[r]["node_id"] for r in proven_reuse),
                           "final_ancestry_result_ids": sorted(adopted), "real_api_requests": 0, "actual_cost_nano_usd": 0}}
