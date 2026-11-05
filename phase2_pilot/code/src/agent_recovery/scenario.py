"""Private experiment events. Their scripts never enter agent/recovery inputs."""

from __future__ import annotations

from copy import deepcopy
from time import perf_counter

from .contracts import PARENTS, STEPS, digest, require, validate_payload, validate_task
from .workflow import Workflow


class Scenario:
    def __init__(self, store, task):
        validate_task(task)
        require(store.runtime_view()["task_spec_digest"] == digest(task), "Scenario differs from initialized TaskSpec", "SCENARIO_ERROR")
        self.store, self.task = store, deepcopy(task)

    def matching(self, boundary, step_id, attempt_no):
        return sorted([event for event in self.task["events"] if event["trigger"] ==
                       {"boundary": boundary, "step_id": step_id, "attempt_no": attempt_no}],
                      key=lambda event: event["order"])

    def before_publish(self, result):
        published, records = deepcopy(result), []
        for event in self.matching("before_publish", result["step_id"], result["attempt_no"]):
            require(event["kind"] == "corrupt_result", "Only corruption is allowed before publication", "SCENARIO_ERROR")
            published["payload"] = deepcopy(event["parameters"]["replacement_payload"])
            validate_payload(result["step_id"], published["payload"])
            # Recovery sees exactly the delivered response. The pre-injection
            # provider response remains in the private evaluation audit table.
            for call in published["model_calls"]:
                call["delivered_output"] = deepcopy(published["payload"])
            records.append({"event_id": event["event_id"], "event_digest": digest(event),
                            "kind": "corrupt_result", "target_result_id": result["result_id"]})
        return published, records

    def on_boundary(self, boundary, step_id, attempt_no):
        events = self.matching(boundary, step_id, attempt_no)
        require(not any(event["kind"] == "fault_notice" for event in events[:-1]),
                "Notice must be last at a boundary", "SCENARIO_ERROR")
        for event in events:
            params = event["parameters"]
            if event["kind"] == "external_update":
                self.store.apply_external_update(event["event_id"], event_digest=digest(event), **params)
            elif event["kind"] == "fault_notice":
                results = [result for result in self.store.snapshot_run()["results"]
                           if result["step_id"] == params["target_step_id"]
                           and result["attempt_no"] == params["target_attempt_no"]]
                require(len(results) == 1, "Notice target has not been delivered", "INVALID_NOTICE")
                self.store.record_notice_and_pause({"notice_id": event["event_id"],
                    "run_id": self.store.runtime_view()["run_id"], "faulty_result_id": results[0]["result_id"]}, digest(event))
            else:
                raise ValueError("Corruption must be scheduled before publication")

    def run_to_notice(self, gateway=None):
        require(self.store.runtime_view()["run_state"] == "initial"
                and not self.store.snapshot_run()["results"], "Scenario needs a fresh initial run")
        begin = perf_counter()
        workflow = Workflow(self.store, gateway=gateway, scenario=self)
        selected, initial_snapshot = {}, None
        for step in STEPS:
            result = workflow.run_step(step, [selected[parent] for parent in PARENTS[step]])
            if result["execution_status"] != "success":
                return {"status": "failed_initial", "failure": result, "selected": selected}
            selected[step] = result["result_id"]
            if step == "execute":
                initial_snapshot = self.store.snapshot_run()
            self.on_boundary("after_commit", step, result["attempt_no"])
            if self.store.runtime_view()["run_state"] == "paused":
                require(initial_snapshot is not None and len(selected) == 5,
                        "S3 requires a complete written fault scene", "SCENARIO_ERROR")
                calls = self.store.model_accounting_snapshot()["calls"]
                return {"status": "ready", "selected": selected, "initial_snapshot": initial_snapshot,
                        "initial_cost": {"initial_steps": 5, "initial_model_calls": len(calls),
                                         "initial_input_tokens": sum((c.get("usage") or {}).get("prompt_tokens", 0) for c in calls),
                                         "initial_output_tokens": sum((c.get("usage") or {}).get("completion_tokens", 0) for c in calls),
                                         "initial_wall_ms": (perf_counter() - begin) * 1000}}
        raise ValueError("Scenario did not reach a fault notice")
