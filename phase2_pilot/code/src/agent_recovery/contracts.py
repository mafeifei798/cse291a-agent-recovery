"""Data format 1.1, with no model or recovery-policy dependencies."""

from __future__ import annotations

import hashlib
import json
import math
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = "1.1"
STEPS = ("read_metadata", "read_permission", "read_resources", "plan", "execute")
PREFIX_STEPS = STEPS[:-1]
PARENTS = {
    "read_metadata": (), "read_permission": (), "read_resources": (),
    "plan": STEPS[:3], "execute": ("plan",),
}
REQUEST_FIELDS = {"dataset_id", "purpose", "batch_size", "epochs", "requested_workers"}
CONFIG_FIELDS = {
    "dataset_id", "purpose", "batch_size", "epochs", "num_examples", "steps",
    "workers", "permission_allowed",
}
OBJECT_FIELDS = {"object_key", "exists", "payload", "version", "last_writer_id"}
RESULT_FIELDS = {
    "schema_version", "run_id", "step_id", "attempt_no", "result_id",
    "execution_status", "payload", "parent_result_ids", "direct_reads",
    "effective_read_set", "input_snapshot", "input_digest", "effect_ids",
    "model_calls", "started_at", "finished_at", "duration_ms", "error",
}
STATUSES = {
    "success", "timeout", "model_error", "schema_error", "dependency_error",
    "stale_input", "write_conflict", "runtime_error",
}
BUSINESS_RULES = (
    "O_REQUEST_MATCH", "O_CURRENT_METADATA", "O_CURRENT_PERMISSION",
    "O_CURRENT_RESOURCES", "O_SINGLE_DRAFT",
)


class ContractError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


class StageNotImplemented(NotImplementedError):
    """An intentional stage boundary, not an implicitly successful operation."""


class CommitOutcomeUnknown(RuntimeError):
    """A commit response cannot be reconciled; do not issue a new operation."""

    def __init__(self, message: str, *, operation_id: str | None = None,
                 result_id: str | None = None, attempt_no: int | None = None,
                 step_id: str = "execute"):
        self.code = "UNKNOWN_COMMIT_OUTCOME"
        self.operation_id = operation_id
        self.result_id = result_id
        self.attempt_no = attempt_no
        self.step_id = step_id
        super().__init__(message)


def require(condition: bool, message: str, code: str = "SCHEMA_ERROR") -> None:
    if not condition:
        raise ContractError(code, message)


def exact_fields(value: Any, fields: set[str], label: str) -> None:
    require(isinstance(value, dict), f"{label} must be an object")
    require(set(value) == fields, f"{label} fields differ: {set(value) ^ fields}")


def positive_int(value: Any) -> bool:
    return type(value) is int and value > 0


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def new_id() -> str:
    return str(uuid.uuid4())


def validate_id(value: Any) -> None:
    require(isinstance(value, str), "ID must be a UUID string")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ContractError("SCHEMA_ERROR", "Invalid UUID") from exc
    require(str(parsed) == value, "UUID must use canonical lowercase form")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def source_keys(request: dict) -> tuple[str, str, str]:
    return (f"metadata:{request['dataset_id']}",
            f"permission:{request['dataset_id']}:{request['purpose']}",
            "resource_policy:default")


def output_keys(run_id: str) -> tuple[str, str]:
    return (f"job_config:{run_id}", f"job_draft:{run_id}")


def validate_request(request: dict) -> None:
    exact_fields(request, REQUEST_FIELDS, "request")
    import re
    for key in ("dataset_id", "purpose"):
        require(isinstance(request[key], str) and
                re.fullmatch(r"[A-Za-z0-9_-]+", request[key]) is not None,
                f"Invalid {key}")
    for key in REQUEST_FIELDS - {"dataset_id", "purpose"}:
        require(positive_int(request[key]), f"{key} must be a positive integer")


def validate_object(obj: dict) -> None:
    exact_fields(obj, OBJECT_FIELDS, "object snapshot")
    require(isinstance(obj["object_key"], str) and bool(obj["object_key"]), "Empty object key")
    require(type(obj["exists"]) is bool, "exists must be boolean")
    require(type(obj["version"]) is int and obj["version"] >= 0, "Invalid version")
    if obj["exists"]:
        require(isinstance(obj["payload"], dict) and obj["version"] > 0,
                "Existing object needs a payload and positive version")
    else:
        require(obj["payload"] is None, "Absent object must have null payload")
    if obj["last_writer_id"] is not None:
        validate_id(obj["last_writer_id"])


def validate_reads(reads: list) -> None:
    require(isinstance(reads, list), "Read set must be an array")
    keys = []
    for ref in reads:
        exact_fields(ref, {"object_key", "version"}, "read reference")
        require(isinstance(ref["object_key"], str) and bool(ref["object_key"]), "Invalid read key")
        require(positive_int(ref["version"]), "Source version must be positive")
        keys.append(ref["object_key"])
    require(keys == sorted(set(keys)), "Read references must be unique and sorted")


def validate_payload(step: str, payload: dict) -> None:
    require(step in STEPS, "Unknown step")
    if step == "read_metadata":
        exact_fields(payload, {"dataset_id", "num_examples"}, "metadata result")
        require(isinstance(payload["dataset_id"], str) and bool(payload["dataset_id"]), "Invalid dataset")
        require(positive_int(payload["num_examples"]), "Invalid example count")
    elif step == "read_permission":
        exact_fields(payload, {"dataset_id", "purpose", "allowed"}, "permission result")
        require(all(isinstance(payload[k], str) and payload[k] for k in ("dataset_id", "purpose")), "Invalid permission identity")
        require(type(payload["allowed"]) is bool, "allowed must be boolean")
    elif step == "read_resources":
        exact_fields(payload, {"max_workers"}, "resource result")
        require(positive_int(payload["max_workers"]), "Invalid worker limit")
    elif step == "plan":
        exact_fields(payload, CONFIG_FIELDS, "plan")
        require(all(isinstance(payload[k], str) and payload[k] for k in ("dataset_id", "purpose")), "Invalid plan identity")
        for key in CONFIG_FIELDS - {"dataset_id", "purpose", "permission_allowed"}:
            require(positive_int(payload[key]), f"Invalid {key}")
        require(type(payload["permission_allowed"]) is bool, "Invalid permission flag")
    else:
        exact_fields(payload, {"config_key", "draft_key", "effect_id", "commit_state"}, "execute result")
        validate_id(payload["effect_id"])
        require(payload["commit_state"] == "committed", "Invalid commit state")
        require(all(isinstance(payload[k], str) and payload[k] for k in ("config_key", "draft_key")), "Invalid output key")


def validate_action(action: dict) -> None:
    exact_fields(action, {"action", "arguments"}, "Executor action")
    require(action["action"] == "save_job", "Unsupported Executor action")
    validate_payload("plan", action["arguments"])


def validate_result(result: dict) -> None:
    exact_fields(result, RESULT_FIELDS, "StepResult")
    require(result["schema_version"] == SCHEMA_VERSION, "Unsupported schema")
    for key in ("run_id", "result_id"):
        validate_id(result[key])
    require(result["step_id"] in STEPS, "Unknown step")
    require(positive_int(result["attempt_no"]), "Invalid attempt")
    require(result["execution_status"] in STATUSES, "Invalid execution status")
    require(isinstance(result["parent_result_ids"], list), "Parents must be an array")
    require(len(result["parent_result_ids"]) == len(set(result["parent_result_ids"])), "Duplicate parent")
    require(isinstance(result["effect_ids"], list), "Effects must be an array")
    for value in result["parent_result_ids"] + result["effect_ids"]:
        validate_id(value)
    validate_reads(result["direct_reads"])
    validate_reads(result["effective_read_set"])
    require(isinstance(result["model_calls"], list), "Calls must be an array")
    require(type(result["duration_ms"]) in (int, float) and math.isfinite(result["duration_ms"])
            and result["duration_ms"] >= 0, "Invalid duration")
    times = []
    for key in ("started_at", "finished_at"):
        require(isinstance(result[key], str) and result[key].endswith("Z"), "Time must be UTC")
        try:
            times.append(datetime.fromisoformat(result[key].replace("Z", "+00:00")))
        except ValueError as exc:
            raise ContractError("SCHEMA_ERROR", "Invalid timestamp") from exc
    require(times[1] >= times[0], "Negative wall duration")
    snapshot = result["input_snapshot"]
    if snapshot is None:
        require(result["input_digest"] is None, "Null input must have null digest")
    else:
        exact_fields(snapshot, {"request", "parents", "tool_snapshots", "prompt_revision", "rendered_messages"}, "input snapshot")
        validate_request(snapshot["request"])
        require(isinstance(snapshot["parents"], list) and isinstance(snapshot["tool_snapshots"], list), "Invalid input arrays")
        require(isinstance(snapshot["prompt_revision"], str) and bool(snapshot["prompt_revision"]), "Missing prompt revision")
        require(isinstance(snapshot["rendered_messages"], list), "Messages must be an array")
        for parent in snapshot["parents"]:
            exact_fields(parent, {"result_id", "payload"}, "parent input")
            validate_id(parent["result_id"])
        for obj in snapshot["tool_snapshots"]:
            validate_object(obj)
        require(result["input_digest"] == digest(snapshot), "Input digest mismatch")
        require([p["result_id"] for p in snapshot["parents"]] == result["parent_result_ids"], "Recorded parents differ from actual inputs")
    if result["execution_status"] == "success":
        require(snapshot is not None and result["error"] is None, "Successful result needs complete input")
        validate_payload(result["step_id"], result["payload"])
        require((result["step_id"] == "execute") == bool(result["effect_ids"]), "Unexpected effects")
        if result["step_id"] == "execute":
            require(result["effect_ids"] == [result["payload"]["effect_id"]], "Effect IDs differ")
    else:
        require(result["payload"] is None and result["effect_ids"] == [], "Failed step must not claim payload/effects")
        exact_fields(result["error"], {"code", "message", "step_id", "related_result_ids", "object_keys"}, "error")


def validate_task(task: dict) -> None:
    exact_fields(task, {"schema_version", "case_id", "split", "request", "initial_objects",
                        "events", "oracle_rules", "execution_settings", "tags"}, "TaskSpec")
    require(task["schema_version"] == SCHEMA_VERSION, "Unsupported schema")
    require(isinstance(task["case_id"], str) and bool(task["case_id"]), "Invalid case ID")
    require(task["split"] in ("dev", "eval"), "Invalid split")
    validate_request(task["request"])
    require(isinstance(task["initial_objects"], list), "Objects must be an array")
    expected = source_keys(task["request"])
    objects = {obj["object_key"]: obj for obj in task["initial_objects"]}
    require(len(task["initial_objects"]) == 3 and set(objects) == set(expected), "Expected exactly three source objects")
    for obj in objects.values():
        validate_object(obj)
        require(obj["exists"] and obj["version"] == 1 and obj["last_writer_id"] is None, "Invalid initial state")
    validate_payload("read_metadata", objects[expected[0]]["payload"])
    validate_payload("read_permission", objects[expected[1]]["payload"])
    validate_payload("read_resources", objects[expected[2]]["payload"])
    require(objects[expected[0]]["payload"]["dataset_id"] == task["request"]["dataset_id"], "Metadata identity mismatch")
    require(all(objects[expected[1]]["payload"][k] == task["request"][k] for k in ("dataset_id", "purpose")), "Permission identity mismatch")
    settings = task["execution_settings"]
    exact_fields(settings, {"gateway_mode", "model_config_ref", "call_timeout_s", "max_model_calls", "max_recovery_rounds"}, "settings")
    require(settings["gateway_mode"] in ("scripted", "model"), "Invalid gateway mode")
    require((settings["gateway_mode"] == "scripted" and settings["model_config_ref"] is None)
            or (settings["gateway_mode"] == "model" and isinstance(settings["model_config_ref"], str)
                and bool(settings["model_config_ref"])), "Invalid model config reference")
    for key in ("call_timeout_s", "max_model_calls", "max_recovery_rounds"):
        require(positive_int(settings[key]), "Invalid budget")
    for field in ("oracle_rules", "tags"):
        require(isinstance(task[field], list) and all(isinstance(x, str) for x in task[field]), f"Invalid {field}")
    require(isinstance(task["events"], list), "Events must be an array")
    seen_ids, seen_triggers = set(), set()
    for event in task["events"]:
        exact_fields(event, {"event_id", "kind", "trigger", "order", "parameters"}, "event")
        validate_id(event["event_id"])
        require(event["event_id"] not in seen_ids, "Duplicate event ID")
        seen_ids.add(event["event_id"])
        trigger = event["trigger"]
        exact_fields(trigger, {"boundary", "step_id", "attempt_no"}, "trigger")
        require(trigger["boundary"] in ("before_publish", "after_commit", "before_executor_commit"), "Unknown boundary")
        require(trigger["step_id"] in STEPS and positive_int(trigger["attempt_no"]), "Invalid trigger")
        require(positive_int(event["order"]), "Invalid event order")
        slot = (trigger["boundary"], trigger["step_id"], trigger["attempt_no"], event["order"])
        require(slot not in seen_triggers, "Ambiguous event ordering")
        seen_triggers.add(slot)
        parameters = event["parameters"]
        if event["kind"] == "corrupt_result":
            exact_fields(parameters, {"replacement_payload"}, "corruption")
            require(trigger["boundary"] == "before_publish" and trigger["step_id"] in PREFIX_STEPS, "Invalid corruption boundary")
            validate_payload(trigger["step_id"], parameters["replacement_payload"])
        elif event["kind"] == "external_update":
            exact_fields(parameters, {"object_key", "expected_version", "new_payload"}, "update")
            require(isinstance(parameters["object_key"], str) and bool(parameters["object_key"])
                    and positive_int(parameters["expected_version"])
                    and isinstance(parameters["new_payload"], dict), "Invalid update")
        elif event["kind"] == "fault_notice":
            exact_fields(parameters, {"target_step_id", "target_attempt_no"}, "notice")
            require(parameters["target_step_id"] in STEPS and positive_int(parameters["target_attempt_no"]), "Invalid notice target")
        else:
            raise ContractError("SCHEMA_ERROR", "Unknown event kind")


def public_task_view(task: dict) -> dict:
    validate_task(task)
    return deepcopy({key: task[key] for key in (
        "case_id", "request", "initial_objects", "execution_settings")}) | {"task_spec_digest": digest(task)}
