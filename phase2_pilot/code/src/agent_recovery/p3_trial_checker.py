"""Read-only P3 workflow/HTTP linkage checks, separate from execution."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sqlite3

from .contracts import STEPS, source_keys, validate_result
from .oracle import BasicOracle
from .p1_checker import _label_result, _effect_analysis, _fault_state, verify_p1_text_protocol
from .p1_runner import legacy_task
from .p3_checker import _usage


def read(path):
    return json.loads(Path(path).read_text())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def same(left, right):
    # Python object equality would equate booleans with integer token counts.
    return canonical(left) == canonical(right)


def raw_snapshot(connection):
    """Reconstruct persisted business state through read-only SQL, not Store."""
    connection.row_factory = sqlite3.Row
    run = connection.execute("SELECT public_view,mode FROM runs").fetchone()
    public = json.loads(run["public_view"])
    objects = [json.loads(r[0]) for r in connection.execute("SELECT body FROM objects ORDER BY object_key")]
    keys = source_keys(public["request"])
    effects = []
    for row in connection.execute("SELECT * FROM effects ORDER BY rowid"):
        compensations = [json.loads(r[0]) for r in connection.execute(
            "SELECT body FROM compensation_attempts WHERE effect_id=? ORDER BY rowid", (row["effect_id"],))]
        effects.append({**json.loads(row["body"]), "state": row["state"], "compensation_attempts": compensations})
    return {"request": public["request"], "run_state": run["mode"],
            "source_objects": [o for o in objects if o["object_key"] in keys],
            "output_objects": [o for o in objects if o["object_key"] not in keys],
            "attempts": [{k: r[k] for k in ("run_id", "step_id", "attempt_no", "result_id", "status", "started_at")}
                         for r in connection.execute("SELECT * FROM attempts ORDER BY rowid")],
            "results": [json.loads(r[0]) for r in connection.execute("SELECT body FROM results ORDER BY rowid")],
            "result_status_events": [json.loads(r[0]) for r in connection.execute("SELECT body FROM result_status_events ORDER BY event_seq,result_id")],
            "effects": effects,
            "event_log": [json.loads(r[0]) for r in connection.execute("SELECT body FROM event_log ORDER BY event_seq")],
            "notices": [json.loads(r[0]) for r in connection.execute("SELECT body FROM notices ORDER BY rowid")]}


def evaluate_trial_snapshot(task, snapshot, selected, audits, identity, *, policy, terminal_known=True):
    byid = {r["result_id"]: r for r in snapshot["results"]}
    labels = [_label_result(task, snapshot, r, byid, {}, None) for r in snapshot["results"]]
    effects, unsafe = _effect_analysis(task, snapshot, byid, {}, None)
    business = BasicOracle().check("initial", legacy_task(task), snapshot)
    chosen = [r for r in labels if r["result_id"] == selected.get("execute")]
    correct = (business["passed"] and set(selected) == set(STEPS) and len(chosen) == 1
               and all(chosen[0].get(k) is True for k in
                       ("schema_valid", "stage_semantic_valid", "fresh_at_consume", "authority_consistent_at_decision")))
    delivered, reasons, _ = _fault_state(identity or {}, audits, snapshot)
    certain = terminal_known and snapshot["run_state"] == "terminal" and not any(
        r["status"] == "active" for r in snapshot["attempts"])
    return {"correctness": "unknown" if not certain else "correct" if correct else "incorrect", "terminal_certain": bool(certain),
            "restart_eligible": bool(certain and not correct and policy == "BASE" and delivered and not reasons),
            "fault_identity": deepcopy(identity), "fault_delivered": delivered, "business": business,
            "step_labels": labels, "effects": effects, "unsafe_effect_ids": unsafe, "fault_reasons": reasons}


def audit_offline_trial(path, campaign_db):
    path, campaign_db = Path(path), Path(campaign_db)
    checks = []

    def need(ok, message):
        if not ok:
            raise ValueError(message)

    try:
        summary, task = read(path / "summary.json"), read(path / "task.json")
        p0 = Path(__file__).resolve().parents[2] / "phase1/p0"
        frozen_tasks = read(p0 / "manifests/tasks.json")["tasks"]
        need(task in frozen_tasks and task["split"] == "dev", "P3_TASK_DIFFERS_FROM_FROZEN_DEVELOPMENT_MANIFEST")
        audits = read(path / "delivery_audit.json")
        need((path / "initial.sqlite").is_file(), "P3_INITIAL_DATABASE_MISSING")
        initial_saved = read(path / "initial_snapshot.json")
        controlled_tmo = any(r["execution_status"] == "timeout" and (r.get("error") or {}).get("code") == "TOOL_TIMEOUT"
                             for r in initial_saved["results"])
        if controlled_tmo:
            need(summary["condition"] == "TMO" and isinstance(summary.get("freeze"), dict)
                 and isinstance(summary.get("drain"), dict), "P3_CONTROLLED_TMO_CLEANUP_MISSING")
        replay_expected = summary.get("admission") is not None and summary["admission"]["status"] == "ready"
        need((path / "restart/branch.sqlite").is_file() == replay_expected
             and (summary.get("replay") is not None) == replay_expected, "P3_REPLAY_DATABASE_MISSING_OR_UNEXPECTED")
        with sqlite3.connect(campaign_db.resolve().as_uri() + "?mode=ro", uri=True) as connection:
            external = {r[0]: json.loads(r[1]) for r in connection.execute("SELECT call_id,body FROM p3_calls")}
            restarts = {r[0]: json.loads(r[1]) for r in connection.execute("SELECT logical_run_key,body FROM p3_restarts")}
        for prefix, database, report_key in (("initial", path / "initial.sqlite", "initial"),
                                              ("replay", path / "restart/branch.sqlite", "replay")):
            if not database.exists():
                continue
            with sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True) as connection:
                actual_snapshot = raw_snapshot(connection)
                results = [json.loads(r[0]) for r in connection.execute("SELECT body FROM results ORDER BY rowid")]
                local = {r[0]: (r[1], json.loads(r[2])) for r in connection.execute(
                    "SELECT call_id,attempt_id,body FROM p3_local_calls")}
                active = connection.execute("SELECT COUNT(*) FROM attempts WHERE status='active'").fetchone()[0]
                attempts = {r[0]: r[1] for r in connection.execute("SELECT result_id,token FROM attempts")}
                actual_run_id = connection.execute("SELECT run_id FROM runs").fetchone()[0]
            snapshot = read(path / (prefix + "_snapshot.json"))
            need(snapshot == actual_snapshot, "P3_SAVED_SNAPSHOT_DIFFERS_FROM_DATABASE")
            need(not active or summary[report_key]["log_complete"] is False, "P3_ACTIVE_TERMINAL_ATTEMPT")
            published_ids = []
            for result in results:
                validate_result(result)
                calls = result["model_calls"]
                if result["execution_status"] == "success":
                    need(len(calls) == 1, "P3_SUCCESS_WITHOUT_CALL")
                for call in calls:
                    cid = call["call_id"]
                    need(cid in local and cid in external, "P3_MISSING_CALL_LINK")
                    token, stored = local[cid]
                    need(stored == call and token == attempts[result["result_id"]], "P3_LOCAL_CALL_CHANGED")
                    budget_call = external[cid]
                    for key in ("run_id", "result_id", "step_id", "attempt_no"):
                        need(call[key] == result[key] == budget_call[key], "P3_CALL_RESULT_IDENTITY_MISMATCH")
                    evidence = budget_call["evidence"]
                    outcome = evidence["outcome"]
                    need(call["status"] == outcome["status"]
                         and call.get("error_code") == outcome.get("error_code"), "P3_LOCAL_OUTCOME_CHANGED")
                    need(same(call["usage"], _usage(evidence.get("raw_response"))), "P3_LOCAL_USAGE_CHANGED")
                    if budget_call["usage"] is not None:
                        need(same(call["usage"], budget_call["usage"]), "P3_LOCAL_USAGE_CHANGED")
                    need(evidence["sidecar"]["attempt_id"] == token, "P3_ATTEMPT_LINK_MISMATCH")
                    need(evidence["sidecar"]["input_bundle"] == {k: result["input_snapshot"][k]
                         for k in ("request", "parents", "tool_snapshots")}, "P3_CAPTURED_INPUT_CHANGED")
                    need(same(result["input_snapshot"]["rendered_messages"], evidence["sidecar"]["rendered_messages"])
                         and result["input_snapshot"]["prompt_revision"] == evidence["sidecar"]["prompt_revision"],
                         "P3_CAPTURED_MESSAGES_CHANGED")
                    need(call["prompt_digest"] == hashlib.sha256(canonical(result["input_snapshot"]["rendered_messages"]).encode()).hexdigest(),
                         "P3_LOCAL_PROMPT_DIGEST_CHANGED")
                    need(result["execution_status"] != "success" or call["status"] == "success",
                         "P3_FAILED_HTTP_PUBLISHED_AS_SUCCESS")
                    raw_payload = outcome["payload"]
                    if call["status"] != "success":
                        need(call["delivered_output"] is None, "P3_FAILED_HTTP_DELIVERED_OUTPUT")
                    elif result["step_id"] == "execute":
                        need(same(call["delivered_output"], raw_payload), "P3_RAW_EXECUTOR_ACTION_CHANGED")
                    elif result["execution_status"] == "success":
                        need(same(call["delivered_output"], result["payload"]), "P3_DELIVERED_OUTPUT_CHANGED")
                        if not same(raw_payload, result["payload"]):
                            fault = read(p0 / "manifests/faults.private.json")["fault_specs"].get(task["task_id"] + "__ERR")
                            need(budget_call["phase"] == "initial" and summary["condition"] == "ERR" and fault is not None
                                 and result["step_id"] == fault["target_step"]
                                 and result["attempt_no"] == fault["attempt_no"] and isinstance(raw_payload, dict),
                                 "P3_UNREGISTERED_OUTPUT_MUTATION")
                            expected = deepcopy(raw_payload)
                            expected[fault["transform"]["field"]] = fault["transform"]["replacement_value"]
                            need(same(expected, result["payload"]), "P3_ERR_TRANSFORM_CHANGED")
                            delivered = [a for a in audits if a.get("result_record_id") == result["result_id"]
                                         and a.get("condition") == "ERR" and a.get("delivered_output") == result["payload"]]
                            need(len(delivered) == 1 and same(delivered[0]["private_original_response"], raw_payload),
                                 "P3_UNEXPLAINED_OUTPUT_MUTATION")
                    else:
                        need(same(call["delivered_output"], raw_payload), "P3_FAILED_PUBLICATION_RAW_OUTPUT_CHANGED")
                    published_ids.append(cid)
            need(set(published_ids) == set(local), "P3_LOCAL_CALL_WITHOUT_RESULT")
            expected_calls = {cid for cid, c in external.items() if c["run_id"] == actual_run_id
                              and (prefix == "replay" or c["phase"] == "initial")}
            need(set(local) == expected_calls, "P3_EXTERNAL_CALL_WITHOUT_WORKFLOW_LINK")
            text_protocol = verify_p1_text_protocol(task,
                [external[cid]["evidence"]["sidecar"] for cid in local], condition=summary["condition"])
            need(text_protocol["passed"], "P3_FROZEN_TEXT_PROTOCOL_CHANGED:" + str(text_protocol["reason_codes"]))
            report = summary[report_key]
            decision = evaluate_trial_snapshot(task, snapshot, report["selected"], audits if prefix == "initial" else [],
                summary["initial_check"]["fault_identity"] if prefix == "initial" else None,
                policy=summary["policy"] if prefix == "initial" else "FULL_RESTART",
                terminal_known=report["log_complete"])
            saved = summary["initial_check"] if prefix == "initial" else summary["replay_check"]
            need(saved == decision, "P3_BUSINESS_SUMMARY_CHANGED")
            checks.append({"rule": "raw_workflow_and_http_links_" + prefix, "passed": True,
                           "result_count": len(results), "linked_calls": len(local)})
        freeze = summary.get("freeze")
        if freeze:
            raw_scene = read(path / "frozen/scene.json")
            need(hashlib.sha256(canonical(raw_scene).encode()).hexdigest() == freeze["scene_digest"], "P3_SCENE_JSON_CHANGED")
            need(hashlib.sha256((path / "frozen/scene.sqlite").read_bytes()).hexdigest() == freeze["database_digest"],
                 "P3_FROZEN_DATABASE_CHANGED")
            with sqlite3.connect((path / "frozen/scene.sqlite").resolve().as_uri() + "?mode=ro", uri=True) as connection:
                need(raw_snapshot(connection) == raw_scene["snapshot"] == read(path / "initial_snapshot.json"),
                     "P3_FROZEN_SNAPSHOT_CHANGED")
            if summary["condition"] == "TMO":
                timeout = next(a for a in audits if a.get("status") == "tool_timeout")
                waits = summary["waits"]
                need(timeout["clock_kind"] == "actual_monotonic_controlled_tool_clock"
                     and len(waits) == 2 and waits[0]["actual_wait_s"] >= .99
                     and waits[0]["finished_s"] >= waits[0]["target_s"]
                     and abs(waits[1]["target_s"] - waits[0]["target_s"] - 1) < .000001
                     and waits[-1]["finished_s"] >= waits[-1]["target_s"], "P3_SYNTHETIC_TIMING_PASSED_AS_REAL")
                need(timeout["monotonic_s"] <= freeze["freeze_started_monotonic_s"]
                     <= freeze["freeze_completed_monotonic_s"] == freeze["freeze_monotonic_s"]
                     < waits[1]["target_s"], "P3_FREEZE_COMPLETION_MISSED_REPLY_DEADLINE")
                need(summary["drain"]["late_reply_rejected"]
                     and summary["drain"]["admission_check"]["database_sha256_before"] == freeze["database_digest"]
                     == summary["drain"]["admission_check"]["database_sha256_after"], "P3_TMO_DRAIN_NOT_PROVEN")
                need(read(path / "drain_receipt.json") == summary["drain"], "P3_DRAIN_RECEIPT_NOT_PERSISTED")
                if replay_expected:
                    need(summary["before_drain"]["status"] == "blocked", "P3_TMO_RESTART_BEFORE_DRAIN")
            reserved = restarts.get(summary["trial_key"])
            if replay_expected:
                need(summary["duplicate_restart"]["status"] == "already_started", "P3_DUPLICATE_RESTART")
                need(reserved and reserved["scene_digest"] == freeze["scene_digest"]
                     and reserved["source_run_id"] == raw_scene["ctx"]["source_run_id"]
                     and reserved["destination"] == str((path / "restart").resolve()), "P3_RESTART_NOT_EXTERNALLY_RESERVED")
            else:
                need(summary.get("admission") is None and summary.get("duplicate_restart") is None
                     and summary.get("before_drain") is None and reserved is None, "P3_DRAIN_ONLY_ADMITTED_A_RESTART")
            checks.append({"rule": "frozen_scene_drain_and_optional_once_restart", "passed": True})
        return {"status": "passed", "checks": checks}
    except Exception as exc:
        return {"status": "failed", "checks": checks, "error": str(exc)}
