"""One feedback-guided business replan, shared by both recovery policies.

This module adds no HTTP retry and never edits an existing model result. A
known atomic business refusal can admit one new causal replay before the phase
is closed. Permission refusals, source drift and uncertain calls are terminal.
"""
from __future__ import annotations

from copy import deepcopy
import json

from .contracts import (PARENTS, STEPS, CommitOutcomeUnknown, ContractError,
                        canonical_json, digest, new_id, require, utc_now)
from .workflow import Workflow


REPLAN_REVISION = "bounded-business-replan-v1"
MAX_REPLANS_PER_PHASE = 1
READ_STEPS = STEPS[:3]


def selected_ancestry(store, result):
    """Select actual producers, including the new plan of a repaired Executor."""
    selected, pending, seen = {}, [result], set()
    while pending:
        row = pending.pop()
        if row["result_id"] in seen:
            continue
        seen.add(row["result_id"])
        require(row["execution_status"] == "success", "A repaired chain contains a failed producer",
                "INVALID_PARENT")
        old = selected.get(row["step_id"])
        require(old in (None, row["result_id"]), "A repaired chain has duplicate producers",
                "INVALID_PARENT")
        selected[row["step_id"]] = row["result_id"]
        pending += [store.get_result(rid) for rid in row["parent_result_ids"]]
    return selected


def causal_replay_steps(guard):
    """Only copied payload and business-calculation errors are repairable."""
    require(guard["error_code"] == "BUSINESS_VALIDATION_FAILED" and guard["mismatches"],
            "Only a known business-validation refusal admits replanning", "REPLAN_NOT_ADMITTED")
    bad_readers = set()
    for difference in guard["mismatches"]:
        location = difference["location"]
        matched = False
        for step in READ_STEPS:
            if location.startswith(step + ".payload"):
                bad_readers.add(step)
                matched = True
                break
        if not matched:
            require(location.startswith(("plan.payload", "command.arguments", "command.action")),
                    "Source identity or version differences require a new frozen scene",
                    "REPLAN_SOURCE_DRIFT")
    return [step for step in READ_STEPS if step in bad_readers] + ["plan", "execute"]


class BoundedReplanStoreMixin:
    """Append-only phase admission with durable diagnostic and outcome records."""

    def __init__(self, path):
        super().__init__(path)
        self.connection.execute("CREATE TABLE IF NOT EXISTS replan_rounds "
            "(replan_id TEXT PRIMARY KEY, phase_key TEXT UNIQUE NOT NULL, body TEXT NOT NULL)")

    def claim_business_replan(self, record):
        with self._transaction(write=True):
            run = self._run(record["run_id"])
            require(self._admitted(run, record["recovery_id"]),
                    "Replan phase is no longer active", "STALE_ATTEMPT")
            require(not self.connection.execute("SELECT 1 FROM attempts WHERE status='active'").fetchone(),
                    "Replan requires a closed first attempt", "REPLAN_UNCERTAIN")
            require(not self.connection.execute("SELECT 1 FROM effects WHERE state='applied'").fetchone(),
                    "Replan cannot follow an applied write", "REPLAN_UNCERTAIN")
            require(self.connection.execute("SELECT 1 FROM replan_rounds WHERE phase_key=?",
                    (record["phase_key"],)).fetchone() is None,
                    "The phase already used its one replan", "REPLAN_LIMIT_REACHED")
            first = self._result(record["first_failed_result_id"])
            require(first == record["first_failure_result"] and first["error"]["code"] ==
                    "BUSINESS_VALIDATION_FAILED" and not first["effect_ids"],
                    "Replan admission differs from durable first refusal", "REPLAN_NOT_ADMITTED")
            self.connection.execute("INSERT INTO replan_rounds VALUES(?,?,?)",
                (record["replan_id"], record["phase_key"], canonical_json(record)))
            # Failed Executor attempts are already ineligible producers. Retire
            # the superseded successful readers/plan as durable status events,
            # including in the initial phase where mark_unusable requires a
            # recovery identity and therefore cannot be called.
            retired = [rid for rid in record["invalidated_result_ids"]
                       if self._result(rid)["execution_status"] == "success"]
            if retired:
                seq = self._event("replan", record["replan_id"], "invalidate_results", retired)
                for rid in retired:
                    event = dict(event_seq=seq, result_id=rid, validity="invalidated",
                                 reasons=["business_validation_failed"])
                    self.connection.execute("INSERT INTO result_status_events VALUES(?,?,?)",
                                            (seq, rid, canonical_json(event)))

    def update_business_replan(self, record):
        with self._transaction(write=True):
            old = self.connection.execute("SELECT body FROM replan_rounds WHERE replan_id=?",
                    (record["replan_id"],)).fetchone()
            require(old is not None, "Missing replan admission", "REPLAN_NOT_ADMITTED")
            prior = json.loads(old[0])
            immutable = set(record) - {"status", "repair_result_ids", "extra_call_ids", "extra_call_count",
                                      "selected_after", "finished_at", "failure"}
            require(all(prior[key] == record[key] for key in immutable),
                    "Replan admission or first failure was changed", "IDEMPOTENCY_MISMATCH")
            require(prior["status"] == "started", "Replan outcome is already closed", "REPLAN_LIMIT_REACHED")
            self.connection.execute("UPDATE replan_rounds SET body=? WHERE replan_id=?",
                (canonical_json(record), record["replan_id"]))

    def snapshot_run(self, run_id=None):
        value = super().snapshot_run(run_id)
        value["replan_rounds"] = [json.loads(row[0]) for row in self.connection.execute(
            "SELECT body FROM replan_rounds ORDER BY rowid")]
        return value


class BoundedReplanGatewayMixin:
    """Keep the original public envelope and append bound system feedback."""

    def render(self, role, bundle):
        messages = super().render(role, bundle)
        feedback = getattr(self, "business_replan_feedback", None)
        if feedback is not None:
            messages = deepcopy(messages)
            messages[0]["content"] += "\n\nBUSINESS_REPLAN_FEEDBACK\n" + canonical_json(feedback)
            # P3 stores the actual rendered messages as immutable call evidence.
            # PreparedGateway creates the original public envelope first; this
            # additive revision binds the diagnostic text before admission.
            self._current["rendered_messages"] = deepcopy(messages)
            self._current["rendered_messages_digest"] = digest(messages)
            self._current["business_replan_revision"] = REPLAN_REVISION
            self._current["business_replan_feedback"] = deepcopy(feedback)
        return messages


class BoundedReplanWorkflow(Workflow):
    """At most one extra causal replay after an Executor's known refusal."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.selected_replacements = {}
        self.first_failure_snapshot = None
        self.last_replan = None

    def _known_campaign(self):
        campaign = getattr(self.gateway, "campaign", None)
        if campaign is None:
            return
        snapshot = campaign.snapshot()
        require(snapshot["status"] == "active" and snapshot["budget"]["held_cost_nano_usd"] == 0
                and all(c["status"] == "settled" for c in snapshot["calls"]),
                "Unknown settlement or budget state forbids replanning", "REPLAN_UNCERTAIN")

    def _sources_unchanged(self, sources):
        current = self.store.read_objects([row["object_key"] for row in sources])
        require(current == sources, "Authoritative sources changed after the first refusal",
                "REPLAN_SOURCE_DRIFT")

    def run_step(self, step_id, parent_result_ids):
        result = super().run_step(step_id, parent_result_ids)
        if step_id != "execute" or result["execution_status"] == "success" or (
                result.get("error") or {}).get("code") != "BUSINESS_VALIDATION_FAILED":
            return result
        first = self.store.snapshot_run()
        self.first_failure_snapshot = deepcopy(first)
        guards = [g for g in first["business_guard_checks"] if g["result_id"] == result["result_id"]]
        require(len(guards) == 1, "A business refusal lacks its durable guard record", "REPLAN_NOT_ADMITTED")
        guard = guards[0]
        self._known_campaign()
        try:
            steps = causal_replay_steps(guard)
            self._sources_unchanged(guard["source_objects"])
        except ContractError as exc:
            # A version/source-identity refusal remains a terminal first result.
            if exc.code == "REPLAN_SOURCE_DRIFT":
                return result
            raise
        phase_key = self.recovery_id or "initial"
        # Existing records also fence a restarted controller; no duplicate call
        # may be issued merely because the in-memory workflow object is fresh.
        if any(r["phase_key"] == phase_key for r in first.get("replan_rounds", [])):
            return result
        selected = {}
        pending, seen = list(result["parent_result_ids"]), set()
        while pending:
            rid = pending.pop()
            if rid in seen:
                continue
            seen.add(rid)
            row = self.store.get_result(rid)
            require(row["execution_status"] == "success", "First refusal has a failed parent", "INVALID_PARENT")
            selected[row["step_id"]] = rid
            pending += row["parent_result_ids"]
        before_selected = dict(selected)
        replan_id, base_key = new_id(), self.gateway.trial_key
        feedback = dict(schema_version="business-replan-feedback-v1", replan_id=replan_id,
            first_failed_result_id=result["result_id"], guard_digest=digest(guard),
            instruction=("The previous candidate was refused before any write. Regenerate the requested "
                "step from the supplied inputs, correct the listed differences, and compute ceil division "
                "exactly. Retain the required JSON format. This is the only permitted replan."),
            mismatches=deepcopy(guard["mismatches"]), expected_config=deepcopy(guard["expected_config"]))
        first_snapshot = deepcopy(first)
        first_snapshot.pop("replan_rounds", None)
        first_calls = [c["call_id"] for c in self.store.model_accounting_snapshot()["calls"]]
        record = dict(schema_version=REPLAN_REVISION, replan_id=replan_id, run_id=result["run_id"],
            phase_key=phase_key, recovery_id=self.recovery_id, round_no=1, status="started",
            first_failed_result_id=result["result_id"], first_failure_result=deepcopy(result),
            first_failure_snapshot=first_snapshot, guard_record=deepcopy(guard),
            selected_before=before_selected, replay_steps=steps,
            invalidated_result_ids=[before_selected[s] for s in steps if s in before_selected] + [result["result_id"]],
            feedback=feedback, base_trial_key=base_key, repair_trial_key=base_key + "__repair01",
            first_call_ids=first_calls, extra_call_ids=[], extra_call_count=0, repair_result_ids=[],
            selected_after={}, source_objects=deepcopy(guard["source_objects"]),
            started_at=utc_now(), finished_at=None, failure=None)
        self.store.claim_business_replan(record)
        self.last_replan = record
        prior_feedback = getattr(self.gateway, "business_replan_feedback", None)
        self.gateway.business_replan_feedback = feedback
        self.gateway.trial_key = record["repair_trial_key"]
        try:
            for step in steps:
                self._known_campaign()
                self._sources_unchanged(record["source_objects"])
                # Calling the base implementation prevents nested retries.
                result = super().run_step(step, [selected[p] for p in PARENTS[step]])
                record["repair_result_ids"].append(result["result_id"])
                if result["execution_status"] != "success":
                    record.update(status="failed", failure=deepcopy(result["error"]))
                    break
                selected[step] = result["result_id"]
            else:
                record["status"] = "completed"
                self.selected_replacements = selected_ancestry(self.store, result)
            record["selected_after"] = dict(selected)
            return result
        except BaseException as exc:
            record.update(status="blocked", failure={"code": getattr(exc, "code", "INTERNAL_ERROR"),
                                                     "message": "Replan stopped; inspect durable evidence"})
            raise
        finally:
            self.gateway.business_replan_feedback = prior_feedback
            self.gateway.trial_key = base_key
            record["extra_call_ids"] = [c["call_id"] for c in self.store.model_accounting_snapshot()["calls"]
                                         if c["call_id"] not in first_calls]
            record["extra_call_count"] = len(record["extra_call_ids"])
            require(record["extra_call_count"] <= 5, "Replan exceeded five extra calls", "REPLAN_LIMIT_REACHED")
            record["finished_at"] = utc_now()
            self.store.update_business_replan(record)


# The frozen version-aware controller is retained here with two explicit
# changes: shared bounded workflow construction and adoption of its true
# repaired ancestry. Its compensation, fencing and terminal protocol stay the same.
from time import perf_counter
from .contracts import StageNotImplemented
from .trace import build_graph, find_invalidated


class BoundedReplanRecovery:
    def __init__(self, store, gateway=None, scenario=None):
        self.store, self.gateway, self.scenario = store, gateway, scenario

    def handle_notice(self, trial_id, notice_id, scene, scene_digest, policy="full_restart"):
        if policy not in ("full_restart", "selective"):
            raise StageNotImplemented("Only full_restart and selective are supported")
        require(digest(scene) == scene_digest and scene["notice"]["notice_id"] == notice_id,
                "Invalid frozen scene identity", "SCENARIO_ERROR")
        previous = self.store.recovery_progress(notice_id)
        if previous is not None:
            if previous["report"] is not None:
                require(previous["report"]["scene_digest"] == scene_digest, "Recovery scene identity changed", "IDEMPOTENCY_MISMATCH")
            admitted = self.store.start_recovery(trial_id, notice_id, policy)
            return admitted["report"] or {"status": "already_running", **admitted}
        require(self.store.scene_manifest(scene["initial_cost"]) == scene,
                "Branch differs from the frozen scene", "SCENARIO_ERROR")
        initial = self.store.snapshot_run()
        begin = perf_counter()
        identity = self.store.start_recovery(trial_id, notice_id, policy)
        recovery_id = identity["recovery_id"]
        if not identity["created"]:
            return identity["report"] or {"status": "already_running", **identity}
        view = self.store.runtime_view()
        faulty = scene["notice"]["faulty_result_id"]
        cost = {**scene["initial_cost"], "recovery_steps_started": 0, "recovery_model_calls": 0,
                "recovery_input_tokens": 0, "recovery_output_tokens": 0, "reused_result_count": None,
                "compensated_effect_groups": 0, "recovery_wall_ms": 0, "total_wall_ms": 0,
                "setup_wall_ms": 0, "oracle_wall_ms": 0, "model_wall_ms": 0,
                "tracking_and_version_wall_ms": None}
        report = {"schema_version": "1.1", "case_id": view["case_id"], "run_id": view["run_id"],
                  "trial_id": trial_id, "repeat_index": 0, "scene_digest": scene_digest,
                  "scene_status": "ready", "fault_delivered": any(event["kind"] == "corrupt_result"
                    and event.get("target_result_id") == faulty for event in scene["applied_events"]),
                  "fault_exposed": any(faulty in result["parent_result_ids"] for result in initial["results"]),
                  "initial_state_check": "not_available", "recovery_id": recovery_id, "notice_id": notice_id,
                  "policy": policy, "faulty_result_ids": [faulty], "engine_status": "running",
                  "phase": "planning", "invalidation_rounds": [], "reuse_candidates": [], "reused_results": [],
                  "compensations": [], "reexecutions": [], "final_result_ids": {}, "final_objects": [],
                  "cost": cost, "failure": None, "evaluation": None, "outcome": "pending_evaluation",
                  "started_at": utc_now(), "finished_at": None}
        step = None
        try:
            selected = {result["step_id"]: result["result_id"] for result in initial["results"]
                        if result["execution_status"] == "success"}
            # The prototype supports at most two rounds, even for a larger
            # configured limit. No model calls or unbounded automatic retries.
            round_limit = min(2, view["execution_settings"]["max_recovery_rounds"])
            workflow = BoundedReplanWorkflow(self.store, self.gateway, recovery_id=recovery_id, scenario=self.scenario)
            for round_no in range(1, round_limit + 1):
                current = self.store.snapshot_run()
                graph = build_graph(current["results"])
                plan = find_invalidated(graph, selected, faulty,
                                        {obj["object_key"]: obj for obj in current["source_objects"]},
                                        current["result_status_events"], policy=policy)
                self.store.record_recovery_round(recovery_id, selected)
                report["reuse_candidates"] = plan["reuse_candidates"]
                report["invalidation_rounds"].append({"round_no": round_no, **{key: plan[key] for key in
                    ("fault_closure", "stale_seeds", "invalidated", "replay_steps")}})
                report["phase"] = "invalidating"
                self.store.save_recovery_progress(recovery_id, report)
                self.store.mark_unusable(plan["invalidated"], recovery_id)
                report["phase"] = "compensating"
                self.store.save_recovery_progress(recovery_id, report)
                invalid = {item["result_id"] for item in plan["invalidated"]}
                # The live snapshot includes any first-round effects; a closed
                # old effect is skipped rather than compensated a second time.
                for effect in reversed(current["effects"]):
                    if effect["owner_result_id"] not in invalid or effect["state"] != "applied":
                        continue
                    compensation = self.store.compensate(effect["effect_id"], recovery_id)
                    report["compensations"].append({key: compensation[key] for key in
                                                  ("effect_id", "status", "conflicts", "restored_versions")})
                    if compensation["status"] == "compensation_conflict":
                        report["engine_status"] = "conflict"
                        report["failure"] = {"code": "COMPENSATION_CONFLICT", "step_id": "execute",
                                             "message": "Output group changed after the original write",
                                             "object_keys": [item["object_key"] for item in compensation["conflicts"]]}
                        break
                if report["engine_status"] == "conflict":
                    break
                report["phase"] = "replaying"
                self.store.save_recovery_progress(recovery_id, report)
                selected = {role: rid for role, rid in selected.items() if rid not in invalid}
                source_changed = False
                for step in plan["replay_steps"]:
                    result = workflow.run_step(step, [selected[parent] for parent in PARENTS[step]])
                    report["reexecutions"].append({key: result[key] for key in
                                                  ("step_id", "attempt_no", "result_id", "execution_status")})
                    if result["execution_status"] == "stale_input" and result["error"]["code"] == "STALE_SOURCE":
                        # This failed attempt is diagnostic history, never a
                        # selected producer. All successful new results remain
                        # available for the next round's version checks.
                        source_changed = True
                        if round_no == round_limit:
                            report["engine_status"] = "budget_exceeded"
                            report["failure"] = {"code": "RECOVERY_ROUND_LIMIT", "step_id": step,
                                "message": "Source changed and the recovery round limit was reached",
                                "object_keys": result["error"]["object_keys"]}
                        break
                    if result["execution_status"] != "success":
                        raise ContractError(result["error"]["code"], result["error"]["message"])
                    selected[step] = result["result_id"]
                    selected.update(workflow.selected_replacements)
                    report["final_result_ids"] = dict(selected)
                    self.store.save_recovery_progress(recovery_id, report)
                    if self.scenario:
                        self.scenario.on_boundary("after_commit", step, result["attempt_no"])
                if source_changed:
                    if report["engine_status"] == "budget_exceeded":
                        break
                    report["phase"] = "planning"
                    self.store.save_recovery_progress(recovery_id, report)
                    continue
                report["engine_status"] = "completed"
                # Only actual ancestors of the acknowledged new execution are
                # candidates for independently verified original-result reuse.
                adopted, pending = set(), [selected["execute"]]
                while pending:
                    rid = pending.pop()
                    if rid not in adopted:
                        adopted.add(rid)
                        pending.extend(self.store.get_result(rid)["parent_result_ids"])
                report["reused_results"] = sorted(adopted.intersection(
                    result["result_id"] for result in initial["results"]))
                break
        except Exception as exc:
            code = "UNKNOWN_COMMIT_OUTCOME" if isinstance(exc, CommitOutcomeUnknown) else (
                exc.code if isinstance(exc, ContractError) else "INTERNAL_ERROR")
            report["engine_status"] = "budget_exceeded" if code in (
                "MODEL_CALL_BUDGET_EXCEEDED", "MODEL_COST_BUDGET_EXCEEDED", "MODEL_TOKEN_BUDGET", "MODEL_BUDGET_EXCEEDED"
            ) else "runtime_error"
            report["failure"] = {"code": code, "message": str(exc), "step_id": step, "object_keys": []}
            if isinstance(exc, CommitOutcomeUnknown):
                report["failure"].update({key: getattr(exc, key) for key in
                    ("operation_id", "result_id") if getattr(exc, key, None) is not None})
        final = self.store.snapshot_run()
        report["business_replans"] = [{key: row[key] for key in ("replan_id", "phase_key", "status", "first_failed_result_id", "repair_result_ids", "extra_call_ids", "extra_call_count")} for row in final.get("replan_rounds", []) if row["recovery_id"] == recovery_id]
        # Report raw persisted results even if their commit response was lost;
        # their existence does not turn an uncertain controller outcome into a
        # successful recovery or admit another write.
        report["reexecutions"] = [{key: result[key] for key in
            ("step_id", "attempt_no", "result_id", "execution_status")}
            for result in final["results"][len(initial["results"]):]]
        cost.update(recovery_steps_started=len(final["attempts"]) - len(initial["attempts"]),
                    recovery_model_calls=sum(len(result["model_calls"]) for result in final["results"][len(initial["results"]):]),
                    compensated_effect_groups=sum(item["status"] == "compensated" for item in report["compensations"]),
                    recovery_wall_ms=(perf_counter() - begin) * 1000)
        if view["execution_settings"]["gateway_mode"] == "model":
            initial_ids = {call["call_id"] for result in initial["results"] for call in result["model_calls"]}
            calls = [call for call in self.store.model_accounting_snapshot()["calls"]
                     if call["call_id"] not in initial_ids]
            cost.update(recovery_model_calls=len(calls),
                        recovery_input_tokens=sum((c.get("usage") or {}).get("prompt_tokens", 0) for c in calls),
                        recovery_output_tokens=sum((c.get("usage") or {}).get("completion_tokens", 0) for c in calls),
                        model_wall_ms=sum(c["duration_ms"] for c in calls))
        cost["total_wall_ms"] = cost["initial_wall_ms"] + cost["recovery_wall_ms"]
        report.update(phase="done", finished_at=utc_now(), final_objects=final["output_objects"])
        if report["engine_status"] != "completed":
            report.update(final_result_ids={}, reused_results=[])
        if report["failure"] and report["failure"]["code"] == "UNKNOWN_COMMIT_OUTCOME":
            self.store.fence_uncertain_recovery(recovery_id, report)
        elif any(attempt["status"] == "active" for attempt in final["attempts"]):
            report["failure"] = {"code": "UNKNOWN_COMMIT_OUTCOME", "message": "Active attempt requires investigation",
                                 "step_id": None, "object_keys": []}
            report["engine_status"] = "runtime_error"
            report.update(final_result_ids={}, reused_results=[])
            self.store.fence_uncertain_recovery(recovery_id, report)
        else:
            self.store.finish_recovery(recovery_id, report)
        return report
