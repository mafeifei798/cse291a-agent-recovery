"""Bounded recovery rounds using actual history and version-aware replay."""

from __future__ import annotations

from time import perf_counter

from .contracts import (
    PARENTS, STEPS, CommitOutcomeUnknown, ContractError, StageNotImplemented,
    digest, require, utc_now,
)
from .trace import build_graph, find_invalidated
from .workflow import Workflow


class Recovery:
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
            workflow = Workflow(self.store, self.gateway, recovery_id=recovery_id, scenario=self.scenario)
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
