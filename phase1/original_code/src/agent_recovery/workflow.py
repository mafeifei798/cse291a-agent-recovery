"""S1 prefix and S2 five-step offline workflow; no fault/recovery scheduler."""

from __future__ import annotations

from time import perf_counter

from .contracts import (
    PARENTS, PREFIX_STEPS, CommitOutcomeUnknown, ContractError, StageNotImplemented,
    digest, new_id, output_keys, require, source_keys, utc_now, validate_action, validate_payload,
)
from .gateway import ScriptedGateway
from .store import Store
from .trace import build_input_bundle, derive_read_set


class PrefixWorkflow:
    def __init__(self, store: Store, gateway: ScriptedGateway | None = None,
                 recovery_id: str | None = None, scenario=None, hooks=None):
        self.store = store
        self.gateway = gateway or ScriptedGateway()
        self.recovery_id = recovery_id
        self.scenario = scenario
        self.hooks = hooks

    def _after_capture(self, attempt, step_id, bundle):
        if self.hooks is not None:
            self.hooks.after_capture(self.store, attempt, step_id, bundle)

    def _before_publish(self, attempt, result):
        published, events = self.scenario.before_publish(result) if self.scenario else (result, [])
        if self.hooks is not None:
            published, hook_events = self.hooks.before_publish(self.store, attempt, published)
            events = list(events) + list(hook_events)
        return published, events

    def _after_publish(self, attempt, published):
        # A verifier refusal is a control stop after a durable publication. It
        # must propagate, never be converted into another result for this token.
        if self.hooks is not None:
            self.hooks.after_publish(self.store, attempt, published)
        return published

    def _generate(self, attempt, step_id, messages, bundle):
        """Only ModelGateway has an invocation with persistent accounting."""
        if hasattr(self.gateway, "invoke"):
            return self.gateway.invoke(self.store, attempt, step_id, messages, bundle)
        require(self.store.runtime_view()["execution_settings"]["gateway_mode"] == "scripted",
                "A model run requires an explicitly injected ModelGateway", "MODEL_CONFIG_ERROR")
        return self.gateway.generate(step_id, messages, bundle)

    def _calls(self, attempt):
        return self.store.calls_for_attempt(attempt["token"])

    def _model_count(self):
        return len(self.store.model_accounting_snapshot()["calls"])

    @staticmethod
    def _failure_status(code):
        if code in ("MODEL_TIMEOUT", "TOOL_TIMEOUT"):
            return "timeout"
        if code in ("SCHEMA_ERROR", "MODEL_SCHEMA_ERROR"):
            return "schema_error"
        if code.startswith("MODEL_"):
            return "model_error"
        if code in ("INVALID_PARENT", "INCONSISTENT_READ_SET"):
            return "dependency_error"
        return "runtime_error"

    def run_step(self, step_id: str, parent_result_ids: list[str]) -> dict:
        if step_id not in PREFIX_STEPS:
            raise StageNotImplemented("S1 runs three queries and Planner only")
        view = self.store.runtime_view()
        begin = perf_counter()
        attempt = self.store.begin_attempt(view["run_id"], step_id, parent_result_ids, self.recovery_id)
        snapshots, direct, effective, input_snapshot = [], [], [], None
        result = {
            "schema_version": "1.1", "run_id": view["run_id"], "step_id": step_id,
            "attempt_no": attempt["attempt_no"], "result_id": attempt["result_id"],
            "execution_status": "success", "payload": None,
            "parent_result_ids": list(parent_result_ids), "direct_reads": [],
            "effective_read_set": [], "input_snapshot": None, "input_digest": None,
            "effect_ids": [], "model_calls": [], "started_at": attempt["started_at"],
            "finished_at": attempt["started_at"], "duration_ms": 0, "error": None,
        }
        try:
            parents = [self.store.get_result(rid) for rid in parent_result_ids]
            if step_id in PREFIX_STEPS[:3]:
                key = dict(zip(PREFIX_STEPS[:3], source_keys(view["request"])))[step_id]
                snapshots = self.store.read_objects([key], attempt_token=attempt["token"])
                require(snapshots[0]["exists"], "Source object is missing", "INTERNAL_ERROR")
                direct = [{"object_key": obj["object_key"], "version": obj["version"]} for obj in snapshots]
            effective = derive_read_set(direct, parents)
            bundle = build_input_bundle(step_id, view["request"], parents, snapshots)
            self._after_capture(attempt, step_id, bundle)
            messages = self.gateway.render(step_id, bundle)
            input_snapshot = {**bundle, "prompt_revision": self.gateway.prompt_revision,
                              "rendered_messages": messages}
            result["payload"] = self._generate(attempt, step_id, messages, bundle)
            result["model_calls"] = self._calls(attempt)
            validate_payload(step_id, result["payload"])
            result.update(direct_reads=direct, effective_read_set=effective,
                          input_snapshot=input_snapshot, input_digest=digest(input_snapshot),
                          finished_at=utc_now(), duration_ms=(perf_counter() - begin) * 1000)
            published, events = self._before_publish(attempt, result)
            saved = self.store.append_result(attempt["token"], published, events)
        except Exception as exc:
            # No external effect exists in S1. Failure closes this exact attempt.
            code = exc.code if isinstance(exc, ContractError) else "INTERNAL_ERROR"
            status = self._failure_status(code)
            result.update(execution_status=status, payload=None, direct_reads=direct,
                          model_calls=self._calls(attempt),
                          effective_read_set=effective, input_snapshot=input_snapshot,
                          input_digest=digest(input_snapshot) if input_snapshot is not None else None,
                          finished_at=utc_now(), duration_ms=(perf_counter() - begin) * 1000,
                          error={"code": code, "message": str(exc), "step_id": step_id,
                                 "related_result_ids": list(parent_result_ids),
                                 "object_keys": [item["object_key"] for item in direct]
                                 if code == "TOOL_TIMEOUT" else []})
            return self.store.append_result(attempt["token"], result)
        return self._after_publish(attempt, saved)

    def run_prefix(self) -> dict:
        require(self.store.snapshot_run()["results"] == [], "Use a fresh run for the first integration")
        selected = {}
        for step in PREFIX_STEPS:
            result = self.run_step(step, [selected[parent] for parent in PARENTS[step]])
            if result["execution_status"] != "success":
                return {"scope": "S1", "status": "failed", "selected": selected, "failure": result,
                        "model_calls": self._model_count()}
            selected[step] = result["result_id"]
        return {"scope": "S1", "status": "planner_complete", "selected": selected,
                "model_calls": self._model_count(), "business_output_writes": 0}


class Workflow(PrefixWorkflow):
    def run_step(self, step_id: str, parent_result_ids: list[str]) -> dict:
        if step_id != "execute":
            return super().run_step(step_id, parent_result_ids)
        view = self.store.runtime_view()
        begin = perf_counter()
        attempt = self.store.begin_attempt(view["run_id"], "execute", parent_result_ids, self.recovery_id)
        result = {
            "schema_version": "1.1", "run_id": view["run_id"], "step_id": "execute",
            "attempt_no": attempt["attempt_no"], "result_id": attempt["result_id"],
            "execution_status": "success", "payload": None,
            "parent_result_ids": list(parent_result_ids), "direct_reads": [],
            "effective_read_set": [], "input_snapshot": None, "input_digest": None,
            "effect_ids": [], "model_calls": [], "started_at": attempt["started_at"],
            "finished_at": attempt["started_at"], "duration_ms": 0, "error": None,
        }
        try:
            parents = [self.store.get_result(rid) for rid in parent_result_ids]
            result["effective_read_set"] = derive_read_set([], parents)
            bundle = build_input_bundle("execute", view["request"], parents, [])
            # Precondition snapshots are control data, not additional model context.
            expected = self.store.read_objects(list(output_keys(view["run_id"])))
            self._after_capture(attempt, "execute", bundle)
            messages = self.gateway.render("execute", bundle)
            snapshot = {**bundle, "prompt_revision": self.gateway.prompt_revision,
                        "rendered_messages": messages}
            result.update(input_snapshot=snapshot, input_digest=digest(snapshot))
            action = self._generate(attempt, "execute", messages, bundle)
            result["model_calls"] = self._calls(attempt)
            validate_action(action)
            # Executor business effects still use the original atomic commit
            # path. P1 delivery hooks cannot bypass or manufacture that receipt.
            if self.hooks is not None:
                result, publication_events = self.hooks.before_publish(self.store, attempt, result)
                require(not publication_events, "Executor publication events are unsupported", "SCENARIO_ERROR")
            command = {"run_id": view["run_id"], "step_id": "execute", "attempt_no": attempt["attempt_no"],
                       **action, "target_keys": list(output_keys(view["run_id"]))}
            operation_id = new_id()
            result.update(finished_at=utc_now(), duration_ms=(perf_counter() - begin) * 1000)
        except Exception as exc:
            code = exc.code if isinstance(exc, ContractError) else "INTERNAL_ERROR"
            result.update(execution_status=self._failure_status(code), model_calls=self._calls(attempt),
                          payload=None, effect_ids=[], finished_at=utc_now(),
                          duration_ms=(perf_counter() - begin) * 1000,
                          error={"code": code, "message": str(exc), "step_id": "execute",
                                 "related_result_ids": list(parent_result_ids), "object_keys": []})
            return self.store.append_result(attempt["token"], result)
        try:
            if self.scenario:
                self.scenario.on_boundary("before_executor_commit", "execute", attempt["attempt_no"])
            saved = self.store.commit_execution(attempt["token"], result, command, expected, operation_id)["result"]
        except Exception as exc:
            # A lost response is not evidence of a failed write. Never mint a new ID here.
            try:
                observed = self.store.get_operation(view["run_id"], operation_id)
                if observed["state"] == "applied":
                    require(observed["receipt"]["operation_digest"] == digest(command)
                            and observed["receipt"]["owner_result_id"] == attempt["result_id"],
                            "Queried operation has different ownership", "IDEMPOTENCY_MISMATCH")
                    saved = observed["result"]
                else:
                    require(observed["state"] == "absent", "Operation has already closed", "OPERATION_CLOSED")
                    # A readable absent operation can be stopped without retrying or making a new attempt.
                    result.update(execution_status="runtime_error", payload=None, effect_ids=[],
                                  finished_at=utc_now(), duration_ms=(perf_counter() - begin) * 1000,
                                  error={"code": "COMMIT_FAILED", "message": str(exc), "step_id": "execute",
                                         "related_result_ids": list(parent_result_ids), "object_keys": command["target_keys"]})
                    return self.store.append_result(attempt["token"], result)
            except Exception as query_error:
                raise CommitOutcomeUnknown(
                    f"UNKNOWN_COMMIT_OUTCOME for operation {operation_id}: {query_error}",
                    operation_id=operation_id, result_id=attempt["result_id"],
                    attempt_no=attempt["attempt_no"], step_id="execute",
                ) from exc
        return self._after_publish(attempt, saved)

    def run_initial(self) -> dict:
        prefix = self.run_prefix()
        view = self.store.runtime_view()
        selected = prefix["selected"]
        if prefix["status"] != "planner_complete":
            self.store.finish_run(view["run_id"])
            return {**prefix, "scope": "S2", "log_complete": True}
        try:
            result = self.run_step("execute", [selected["plan"]])
        except CommitOutcomeUnknown as exc:
            self.store.fence_uncertain_initial(view["run_id"], exc)
            return {"scope": "S2", "status": "failed_uncertain", "selected": selected,
                    "error": {"code": "UNKNOWN_COMMIT_OUTCOME", "message": str(exc),
                              "operation_id": exc.operation_id, "result_id": exc.result_id,
                              "attempt_no": exc.attempt_no, "step_id": exc.step_id},
                    "log_complete": False, "model_calls": self._model_count()}
        self.store.finish_run(view["run_id"])
        if result["execution_status"] != "success":
            return {"scope": "S2", "status": "failed", "selected": selected,
                    "failure": result, "log_complete": True, "model_calls": self._model_count()}
        selected["execute"] = result["result_id"]
        return {"scope": "S2", "status": "completed", "selected": selected,
                "log_complete": True, "model_calls": self._model_count(), "business_output_writes": 2}
