"""Read-only verification of the offline model ledger and business evidence.

The money arithmetic below is deliberately independent of the Store's ledger.
The wrappers run the existing business/provenance checks on a deep-copy view
whose model-call lists are empty.  Only the obsolete scripted-call assertion
and its associated counter are projected away; inputs, payloads, object
versions, journal, receipts, task and scene identities remain unchanged.
The original evidence is always checked first and is never modified.
"""

from __future__ import annotations

import math
from copy import deepcopy
from datetime import datetime
from types import SimpleNamespace

from .contracts import PARENTS, STEPS, digest, validate_action, validate_id, validate_result
from .oracle import NormalRunOracle
from .s5_oracle import S5RecoveryOracle


CALL_FIELDS = {
    "call_id", "run_id", "step_id", "attempt_no", "result_id", "config_ref",
    "config_digest", "model", "transport", "simulated", "cost_kind",
    "request_digest", "prompt_digest", "response_format_digest", "status",
    "usage", "known_cost_nano_usd", "held_cost_nano_usd", "reserved_cost_nano_usd",
    "delivered_output", "error_code", "request_id", "duration_ms", "started_at",
    "finished_at",
}
CONFIG_FIELDS = {
    "config_ref", "model", "transport", "max_input_tokens", "max_output_tokens",
    "timeout_s", "input_nano_usd_per_token", "output_nano_usd_per_token",
    "max_cost_nano_usd",
}


def _need(condition, message):
    if not condition:
        raise ValueError(message)


def _integer(value, name):
    _need(type(value) is int and value >= 0, f"{name} must be a nonnegative integer")
    return value


def _utc(value):
    _need(isinstance(value, str) and value.endswith("Z"), "Timestamp must be UTC")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _legacy_snapshot(snapshot):
    projected = deepcopy(snapshot)
    for result in projected["results"]:
        result["model_calls"] = []
    return projected


class ModelCallOracle:
    """Verify safe call evidence; fake token prices never claim actual billing."""

    def check(self, task, snapshot, accounting, report=None, frozen_snapshot=None):
        checks = []

        def add(rule_id, verifier):
            try:
                verifier()
                passed, error = True, None
            except (KeyError, TypeError, ValueError, IndexError, AttributeError,
                    StopIteration, OverflowError) as exc:
                passed, error = False, str(exc)
            checks.append({"rule_id": rule_id, "passed": passed,
                           "evidence": {"error": error}})

        def pins():
            config = accounting["config"]
            _need(set(config) == CONFIG_FIELDS, "Unexpected model configuration fields")
            _need(task["execution_settings"]["gateway_mode"] == "model",
                  "Model oracle requires an explicitly configured model run")
            _need(config["config_ref"] == task["execution_settings"]["model_config_ref"],
                  "Task and model configuration references differ")
            _need(config["model"] == "gpt-4.1-mini-2025-04-14"
                  and config["transport"] == "offline_fake", "Unapproved model or transport")
            _need(config["input_nano_usd_per_token"] == 400
                  and config["output_nano_usd_per_token"] == 1600,
                  "Simulated standard token-price pin changed")
            for key in ("max_input_tokens", "max_output_tokens", "max_cost_nano_usd",
                        "input_nano_usd_per_token", "output_nano_usd_per_token"):
                _integer(config[key], key)
            _need(0 < config["max_input_tokens"] <= 4000 and 0 < config["max_output_tokens"] <= 768,
                  "Token caps exceed the approved offline configuration")
            _need(type(config["timeout_s"]) in (int, float)
                  and math.isfinite(config["timeout_s"]) and 0 < config["timeout_s"] <= 120
                  and config["timeout_s"] == task["execution_settings"]["call_timeout_s"],
                  "Timeout is not the task's finite positive deadline")
            _need(accounting["config_digest"] == digest(config), "Configuration digest differs")
            _need(accounting["schema_version"] == "s6-offline-v1"
                  and accounting["transport"] == "offline_fake"
                  and accounting["simulated"] is True,
                  "Accounting is not labelled as offline simulation")
            _need(type(accounting["real_requests"]) is int and accounting["real_requests"] == 0
                  and type(accounting["real_cost_nano_usd"]) is int
                  and accounting["real_cost_nano_usd"] == 0,
                  "Offline evidence claims actual requests or billed cost")

        def identities_and_delivery():
            from .model_gateway import build_request, render_messages

            config = accounting["config"]
            calls = accounting["calls"]
            attempts = {row["result_id"]: row for row in snapshot["attempts"]}
            results = {row["result_id"]: row for row in snapshot["results"]}
            _need(len(attempts) == len(snapshot["attempts"]), "Duplicate attempt result identity")
            _need(len(results) == len(snapshot["results"]), "Duplicate published result identity")
            bycall = {row["call_id"]: row for row in calls}
            _need(len(bycall) == len(calls), "Duplicate model call identity")
            byresult = {}
            for call in calls:
                _need(set(call) == CALL_FIELDS, "Unexpected safe model-call fields")
                for name in ("call_id", "run_id", "result_id"):
                    validate_id(call[name])
                _need(call["result_id"] not in byresult, "More than one call was dispatched for an attempt")
                byresult[call["result_id"]] = call
                attempt = attempts[call["result_id"]]
                _need(all(call[key] == attempt[key] for key in
                          ("run_id", "step_id", "attempt_no", "result_id")),
                      "Call and actual attempt identity differ")
                _need(call["config_ref"] == config["config_ref"]
                      and call["config_digest"] == digest(config)
                      and call["model"] == config["model"]
                      and call["transport"] == "offline_fake" and call["simulated"] is True
                      and call["cost_kind"] == "simulated_standard_tokens",
                      "Call configuration or simulated-cost identity differs")
                _need(type(call["duration_ms"]) in (int, float)
                      and math.isfinite(call["duration_ms"]) and call["duration_ms"] >= 0,
                      "Model duration is invalid")
                _need(_utc(call["started_at"]) >= _utc(attempt["started_at"]),
                      "Call started before its actual attempt")
                if call["status"] != "reserved":
                    _need(_utc(call["finished_at"]) >= _utc(call["started_at"]),
                          "Call timestamps decrease")
                else:
                    _need(call["finished_at"] is None and call["delivered_output"] is None
                          and call["error_code"] is None and snapshot["run_state"] != "terminal",
                          "Reserved call has a completion or survived a terminal stop")
                _need(call["request_id"] is None or isinstance(call["request_id"], str),
                      "Malformed provider request ID")
                result = results.get(call["result_id"])
                captured = accounting["attempt_inputs_by_result"][call["result_id"]]
                _need(set(captured) == {"parent_result_ids", "tool_snapshots"},
                      "Actual attempt input audit has unexpected fields")
                _need(isinstance(captured["parent_result_ids"], list)
                      and len(captured["parent_result_ids"]) == len(set(captured["parent_result_ids"])),
                      "Actual attempt parent identities are malformed")
                parents = [results[parent_id] for parent_id in captured["parent_result_ids"]]
                _need(tuple(parent["step_id"] for parent in parents) == PARENTS[call["step_id"]]
                      and all(parent["execution_status"] == "success" and parent["run_id"] == call["run_id"]
                              and _utc(parent["finished_at"]) <= _utc(attempt["started_at"]) for parent in parents),
                      "Actual attempt has a failed, foreign, future or wrong-role parent")
                bundle = {"request": deepcopy(task["request"]),
                          "parents": [{"result_id": parent["result_id"], "payload": deepcopy(parent["payload"])}
                                      for parent in parents],
                          "tool_snapshots": deepcopy(captured["tool_snapshots"])}
                expected_messages = render_messages(call["step_id"], bundle)
                request = build_request(call["step_id"], expected_messages, SimpleNamespace(**config))
                if result is None:
                    _need(snapshot["run_state"] == "uncertain" and attempt["status"] == "uncertain",
                          "Dispatched call has no publication or uncertainty fence")
                    invalid = {row["result_id"] for row in snapshot["result_status_events"]
                               if row["validity"] == "invalidated"}
                    _need(not invalid.intersection(captured["parent_result_ids"]),
                          "Uncertain submission used an invalidated parent")
                else:
                    _need(result["model_calls"] == [call], "Result and persistent call ledger differ")
                    _need(call["status"] != "reserved"
                          and _utc(call["finished_at"]) <= _utc(result["finished_at"]),
                          "Model response was settled after its workflow result was already closed")
                    actual = result["input_snapshot"]
                    _need(actual is not None and actual["prompt_revision"] == "s6-model-v1",
                          "Dispatched model call lacks a pinned captured input")
                    _need(result["parent_result_ids"] == captured["parent_result_ids"]
                          and {key: actual[key] for key in ("request", "parents", "tool_snapshots")} == bundle,
                          "Saved result inputs differ from actual admitted attempt inputs")
                    _need(actual["rendered_messages"] == expected_messages,
                          "Rendered model messages differ from actual captured inputs")
                _need(accounting["requests_by_call"].get(call["call_id"]) == request,
                      "Safe request audit differs from actual captured model inputs")
                _need(call["request_digest"] == digest(request)
                      and call["prompt_digest"] == digest(request["messages"])
                      and call["response_format_digest"] == digest(request["response_format"]),
                      "Actual request, prompt or strict schema digest differs")
                _need(request["model"] == config["model"] and request["n"] == 1
                      and request["store"] is False and request["stream"] is False
                      and request["temperature"] == 0
                      and request["service_tier"] == "default"
                      and request["max_completion_tokens"] == config["max_output_tokens"]
                      and request["response_format"]["type"] == "json_schema"
                      and request["response_format"]["json_schema"]["strict"] is True,
                      "Request is not the pinned single strict completion")
                if call["status"] == "success":
                    _need(call["error_code"] is None and call["delivered_output"] is not None,
                          "Successful call lacks delivered output or has an error")
                    _need(call["duration_ms"] < config["timeout_s"] * 1000,
                          "A completion after the deadline was accepted as successful")
                    if call["step_id"] == "execute":
                        validate_action(call["delivered_output"])
                        _need(call["delivered_output"]["arguments"] == parents[0]["payload"],
                              "Executor action differs from its saved producer")
                    elif result is not None and result["execution_status"] == "success":
                        _need(call["delivered_output"] == result["payload"],
                              "Call log does not describe the response actually delivered")
                elif call["status"] != "reserved":
                    _need(call["delivered_output"] is None and isinstance(call["error_code"], str)
                          and bool(call["error_code"]), "Failed call invented delivered output or omitted its error")
                    _need(result is None or result["execution_status"] != "success",
                          "Failed model call was published as a successful workflow step")
            for result in snapshot["results"]:
                validate_result(result)
                rows = result["model_calls"]
                _need(isinstance(rows, list) and len(rows) <= 1, "An attempt contains multiple model calls")
                _need(rows == ([byresult[result["result_id"]]] if result["result_id"] in byresult else []),
                      "A result invented or omitted its persistent model-call record")
                _need(result["execution_status"] != "success" or len(rows) == 1,
                      "Successful model step bypassed model dispatch")
            _need(set(accounting["requests_by_call"]) == set(bycall),
                  "Request audit invented or omitted a model request")
            _need(set(accounting["attempt_inputs_by_result"]) == set(byresult),
                  "Actual attempt input audit invented or omitted a dispatched attempt")

        def amounts_and_budget():
            config, calls, budget = accounting["config"], accounting["calls"], accounting["budget"]
            reserve = config["max_input_tokens"] * config["input_nano_usd_per_token"] \
                + config["max_output_tokens"] * config["output_nano_usd_per_token"]
            known = held = prompt = completion = unknown = 0
            for call in calls:
                _need(call["status"] in ("reserved", "success", "timeout", "model_error", "schema_error"),
                      "Unknown call settlement state")
                _need(_integer(call["reserved_cost_nano_usd"], "reserved cost") == reserve,
                      "Worst-case reservation differs from pinned token caps and prices")
                usage = call["usage"]
                if usage is None:
                    expected_known, expected_hold = 0, reserve
                    unknown += 1
                    _need(call["status"] != "success", "Successful completion omitted usage")
                else:
                    _need(set(usage) == {"prompt_tokens", "completion_tokens"}, "Unexpected usage fields")
                    p = _integer(usage["prompt_tokens"], "prompt tokens")
                    c = _integer(usage["completion_tokens"], "completion tokens")
                    expected_known = p * config["input_nano_usd_per_token"] + c * config["output_nano_usd_per_token"]
                    expected_hold = 0
                    prompt += p
                    completion += c
                    _need(call["status"] != "reserved", "Reserved call already has completion usage")
                    _need(call["status"] != "success"
                          or (p <= config["max_input_tokens"] and c <= config["max_output_tokens"]),
                          "Successful call exceeded its configured token caps")
                _need(_integer(call["known_cost_nano_usd"], "known cost") == expected_known
                      and _integer(call["held_cost_nano_usd"], "held cost") == expected_hold,
                      "Recorded cost or retained unknown-usage reservation is wrong")
                known += expected_known
                held += expected_hold
            maximum_calls = task["execution_settings"]["max_model_calls"]
            _integer(maximum_calls, "maximum model calls")
            expected = {
                "max_model_calls": maximum_calls, "model_calls_used": len(calls),
                "model_calls_remaining": max(0, maximum_calls - len(calls)),
                "max_cost_nano_usd": config["max_cost_nano_usd"], "known_cost_nano_usd": known,
                "held_cost_nano_usd": held, "committed_cost_nano_usd": known + held,
                "remaining_cost_nano_usd": max(0, config["max_cost_nano_usd"] - known - held),
                "known_prompt_tokens": prompt, "known_completion_tokens": completion,
                "known_total_tokens": prompt + completion, "unknown_usage_calls": unknown,
            }
            _need(set(budget) == set(expected), "Unexpected budget summary fields")
            _need(all(type(budget[key]) is int and budget[key] == value for key, value in expected.items()),
                  "Budget summary differs from independent ledger arithmetic")
            _need(len(calls) <= maximum_calls, "Model call limit was exceeded")
            # Reservation admission must be checked against pre-existing spend,
            # not only the cheap actual usage eventually returned.
            running = 0
            for call in calls:
                _need(running + reserve <= config["max_cost_nano_usd"],
                      "A call was dispatched without sufficient pre-dispatch reservation")
                running += call["known_cost_nano_usd"] + call["held_cost_nano_usd"]

        def report_counts():
            if report is None:
                return
            _need(frozen_snapshot is not None, "Recovery counters need the original frozen snapshot")
            initial_ids = {row["result_id"] for row in frozen_snapshot["results"]}
            initial = [call for call in accounting["calls"] if call["result_id"] in initial_ids]
            fresh = [call for call in accounting["calls"] if call["result_id"] not in initial_ids]
            frozen_calls = [call for row in frozen_snapshot["results"] for call in row["model_calls"]]
            _need(initial == frozen_calls, "Copied initial call identities or charges were reset or rewritten")
            cost = report["cost"]
            for prefix, rows in (("initial", initial), ("recovery", fresh)):
                _need(cost[f"{prefix}_model_calls"] == len(rows)
                      and cost[f"{prefix}_input_tokens"] == sum((row["usage"] or {}).get("prompt_tokens", 0) for row in rows)
                      and cost[f"{prefix}_output_tokens"] == sum((row["usage"] or {}).get("completion_tokens", 0) for row in rows),
                      "Recovery report disagrees with actual initial/recovery call usage")
            _need(type(cost["model_wall_ms"]) in (int, float)
                  and math.isclose(cost["model_wall_ms"], sum(row["duration_ms"] for row in fresh),
                                   rel_tol=1e-9, abs_tol=1e-6),
                  "Reported recovery model duration differs from actual fresh calls")

        add("S6_MODEL_PINS_AND_OFFLINE_BOUNDARY", pins)
        add("S6_MODEL_CALL_IDENTITIES_AND_DELIVERY", identities_and_delivery)
        add("S6_INDEPENDENT_TOKEN_COST_AND_BUDGET", amounts_and_budget)
        add("S6_RECOVERY_MODEL_COUNTERS", report_counts)
        return {"scope": "S6_offline_call_accounting", "passed": all(row["passed"] for row in checks),
                "checks": checks, "simulated": True, "real_requests": 0,
                "limitation": "Fake-client evidence does not establish provider billing, HTTP cancellation, or model quality."}


class ModelRunOracle:
    def check(self, task, snapshot, accounting):
        calls = ModelCallOracle().check(task, snapshot, accounting)
        business = NormalRunOracle().check(task, _legacy_snapshot(snapshot))
        checks = calls["checks"] + business["checks"]
        return {"scope": "S6_offline_normal_workflow", "passed": all(row["passed"] for row in checks),
                "checks": checks, "simulated": True, "real_requests": 0,
                "legacy_projection": "Only copied model-call lists are empty; original model evidence is independently verified."}


class ModelRecoveryOracle:
    def check(self, task, scene, frozen_snapshot, final_snapshot, report, accounting):
        calls = ModelCallOracle().check(task, final_snapshot, accounting, report, frozen_snapshot)
        try:
            self._scene_identity_and_budget(task, scene, frozen_snapshot, report)
            scene_check = {"rule_id": "S6_FROZEN_SCENE_AND_INHERITED_BUDGET", "passed": True,
                           "evidence": {"error": None}}
        except (KeyError, TypeError, ValueError, IndexError, StopIteration) as exc:
            scene_check = {"rule_id": "S6_FROZEN_SCENE_AND_INHERITED_BUDGET", "passed": False,
                           "evidence": {"error": str(exc)}}
        projected = deepcopy(report)
        projected["cost"]["recovery_model_calls"] = 0
        business = S5RecoveryOracle().check(task, scene, _legacy_snapshot(frozen_snapshot),
                                            _legacy_snapshot(final_snapshot), projected)
        checks = calls["checks"] + [scene_check] + business["checks"]
        if (report.get("failure") or {}).get("code") in ("MODEL_CALL_BUDGET_EXCEEDED", "MODEL_COST_BUDGET_EXCEEDED"):
            try:
                self._budget_stop_safety(task, frozen_snapshot, final_snapshot, report, accounting)
                safety = {"rule_id": "S6_MODEL_BUDGET_STOP_SAFETY", "passed": True, "evidence": {"error": None}}
            except (KeyError, TypeError, ValueError, IndexError, StopIteration) as exc:
                safety = {"rule_id": "S6_MODEL_BUDGET_STOP_SAFETY", "passed": False,
                          "evidence": {"error": str(exc)}}
            checks.append(safety)
        passed = all(row["passed"] for row in checks)
        return {**business, "scope": "S6_offline_recovery", "checks": checks, "passed": passed,
                "verified_reused_results": business["verified_reused_results"] if passed else [],
                "simulated": True, "real_requests": 0,
                "legacy_projection": "Only copied call lists and their copied legacy counter are empty; no business evidence is corrected."}

    @staticmethod
    def _scene_identity_and_budget(task, scene, frozen, report):
        """Bind the unprojected frozen ledger and the inherited call allowance."""
        _need(scene["schema_version"] == "1.1" and scene["run_state"] == frozen["run_state"] == "paused"
              and scene["task_spec_digest"] == digest(task)
              and scene["request"] == frozen["request"] == task["request"]
              and scene["execution_settings"] == task["execution_settings"],
              "Frozen scene task, request, settings or lifecycle differs")
        _need(scene["initial_results_digest"] == digest(frozen["results"]),
              "Frozen scene digest does not bind the original model-call-bearing results")
        _need(len(frozen["results"]) == len(frozen["attempts"]) == 5
              and {row["step_id"] for row in frozen["results"]} == set(STEPS)
              and all(row["execution_status"] == "success" for row in frozen["results"])
              and all(row["status"] == "closed" for row in frozen["attempts"])
              and all(row["run_id"] == scene["run_id"] for row in frozen["results"]),
              "Frozen scene is not a complete five-step closed initial execution")
        _need(scene["source_objects"] == frozen["source_objects"]
              and scene["output_objects"] == frozen["output_objects"]
              and frozen["notices"] == [scene["notice"]]
              and scene["notice"]["run_id"] == scene["run_id"]
              and scene["notice"]["faulty_result_id"] in {row["result_id"] for row in frozen["results"]},
              "Scene objects or notice differs from the actual frozen state")
        receipt_cores = [{key: value for key, value in row.items() if key not in ("state", "compensation_attempts")}
                         for row in frozen["effects"]]
        _need(scene["write_receipt_cores_digest"] == digest(receipt_cores)
              and scene["effect_states"] == [{"effect_id": row["effect_id"], "state": row["state"]}
                                             for row in frozen["effects"]]
              and scene["last_event_seq"] == max(row["event_seq"] for row in frozen["event_log"]),
              "Scene receipt identities, effect states or journal boundary differs")
        _need(frozen["result_status_events"] == []
              and scene["result_states"] == [{"result_id": row["result_id"], "validity": "usable", "invalid_reasons": []}
                                             for row in frozen["results"]],
              "Initial scene invented an invalidation or changed initial result validity")
        initial_calls = [call for row in frozen["results"] for call in row["model_calls"]]
        _need(len(initial_calls) == 5, "Frozen model scene did not inherit five dispatched calls")
        settings = task["execution_settings"]
        expected_budget = {"max_model_calls": settings["max_model_calls"], "model_calls_used": len(initial_calls),
                           "model_calls_remaining": max(0, settings["max_model_calls"] - len(initial_calls)),
                           "max_recovery_rounds": settings["max_recovery_rounds"], "recovery_rounds_used": 0}
        _need(set(scene["remaining_budget"]) == set(expected_budget)
              and all(type(scene["remaining_budget"][key]) is int and scene["remaining_budget"][key] == value
                      for key, value in expected_budget.items()),
              "Frozen scene reset or forged the inherited call or recovery-round budget")
        initial_cost = scene["initial_cost"]
        expected_cost = {"initial_steps": len(frozen["attempts"]), "initial_model_calls": len(initial_calls),
                         "initial_input_tokens": sum((row["usage"] or {}).get("prompt_tokens", 0) for row in initial_calls),
                         "initial_output_tokens": sum((row["usage"] or {}).get("completion_tokens", 0) for row in initial_calls)}
        _need(all(type(initial_cost[key]) is int and initial_cost[key] == value for key, value in expected_cost.items())
              and type(initial_cost["initial_wall_ms"]) in (int, float)
              and math.isfinite(initial_cost["initial_wall_ms"]) and initial_cost["initial_wall_ms"] >= 0
              and all(report["cost"][key] == value for key, value in initial_cost.items())
              and report["scene_digest"] == digest(scene),
              "Scene initial usage or the report's inherited initial cost differs from actual frozen calls")

    @staticmethod
    def _budget_stop_safety(task, frozen, final, report, accounting):
        """A model budget rejection is a verified safe stop, never recovery success."""
        code = report["failure"]["code"]
        _need(code in ("MODEL_CALL_BUDGET_EXCEEDED", "MODEL_COST_BUDGET_EXCEEDED")
              and report["engine_status"] == "budget_exceeded"
              and final["run_state"] == "terminal"
              and all(row["status"] == "closed" for row in final["attempts"])
              and report["final_result_ids"] == {} and report["reused_results"] == [],
              "Model budget failure did not close work and clear adopted results")
        fresh_attempts = final["attempts"][len(frozen["attempts"]):]
        fresh_results = final["results"][len(frozen["results"]):]
        _need(fresh_attempts and fresh_results and fresh_attempts[-1]["result_id"] == fresh_results[-1]["result_id"]
              and fresh_results[-1]["error"]["code"] == code
              and fresh_results[-1]["execution_status"] == "model_error"
              and fresh_results[-1]["model_calls"] == []
              and report["failure"]["step_id"] == fresh_results[-1]["step_id"],
              "Budget failure did not stop at the exact rejected no-dispatch attempt")
        _need(all(row["execution_status"] != "success" or row["step_id"] != "execute" for row in fresh_results)
              and all(row["effect_ids"] == [] for row in fresh_results)
              and {row["effect_id"] for row in final["effects"]} == {row["effect_id"] for row in frozen["effects"]}
              and all(row["state"] == "compensated" for row in final["effects"]),
              "Budget stop produced a fresh commit or left an invalid live effect")
        calls, config = accounting["calls"], accounting["config"]
        _need(not any(row["result_id"] == fresh_results[-1]["result_id"] for row in calls),
              "Rejected budget attempt reached model dispatch")
        spent = 0
        for call in calls:
            usage = call["usage"]
            spent += (usage["prompt_tokens"] * config["input_nano_usd_per_token"]
                      + usage["completion_tokens"] * config["output_nano_usd_per_token"]) if usage is not None \
                else config["max_input_tokens"] * config["input_nano_usd_per_token"] \
                + config["max_output_tokens"] * config["output_nano_usd_per_token"]
        worst = config["max_input_tokens"] * config["input_nano_usd_per_token"] \
            + config["max_output_tokens"] * config["output_nano_usd_per_token"]
        _need((len(calls) == task["execution_settings"]["max_model_calls"]) if code == "MODEL_CALL_BUDGET_EXCEEDED"
              else (len(calls) < task["execution_settings"]["max_model_calls"] and spent + worst > config["max_cost_nano_usd"]),
              "Actual dispatched calls and conservative spend do not explain this budget rejection")
        _need(final["event_log"][:len(frozen["event_log"])] == frozen["event_log"],
              "Budget stop changed the frozen journal")
        objects = {row["object_key"]: deepcopy(row) for row in frozen["source_objects"] + frozen["output_objects"]}
        for event in final["event_log"][len(frozen["event_log"]):]:
            _need(event["action"] != "commit_group" and len(event["before_objects"]) == len(event["after_objects"]),
                  "Budget stop performed a commit or partial object write")
            for before, after in zip(event["before_objects"], event["after_objects"]):
                _need(event["action"] in ("external_update", "compensate_group")
                      and objects[before["object_key"]] == before
                      and after["object_key"] == before["object_key"]
                      and after["version"] == before["version"] + 1
                      and after["last_writer_id"] == event["actor_id"],
                      "Budget stop object transition differs from its journal")
                objects[after["object_key"]] = after
        _need(objects == {row["object_key"]: row for row in final["source_objects"] + final["output_objects"]},
              "Stopped output state differs from independent post-freeze journal reconstruction")
