"""Read-only P3 HTTP and budget auditor, independent of runtime arithmetic.

The auditor reads SQLite directly.  It does not instantiate a budget, gateway,
transport or message renderer.  In particular, an unknown provider charge is a
held reservation, never a zero-cost completion.  Fake HTTP evidence is labelled
as simulation and cannot establish that a live provider was called.
"""
from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
import base64
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from .contracts import (PARENTS, STEPS, source_keys, validate_action, validate_id,
                        validate_object, validate_payload, validate_request)


ROOT = Path(__file__).resolve().parents[2]
PROMPT = ROOT / "phase1/p0/contracts/prompt_spec.json"
PROMPT_SHA = "0c8f095a1ab68fbd5ccaa6fecf0976d3b60254e148747e024ef6d3187ac3001f"


def _need(condition, code):
    if not condition:
        raise ValueError(code)


def _integer(value, code="NONINTEGER_BUDGET_AMOUNT"):
    _need(type(value) is int and value >= 0, code)
    return value


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


def _hash(value):
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _strict_json(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            _need(key not in out, "DUPLICATE_JSON_KEY")
            out[key] = value
        return out

    def reject(_):
        raise ValueError("NONFINITE_JSON")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=reject)


@contextmanager
def _readonly(path):
    db = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
    try:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        _need(db.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "SQLITE_INTEGRITY_FAILED")
        yield db
    finally:
        db.close()


def _usage(response):
    """Interpret original OpenAI-shaped usage, without a transport helper."""
    if not isinstance(response, dict) or not isinstance(response.get("usage"), dict):
        return None
    raw = response["usage"]
    try:
        prompt = _integer(raw["prompt_tokens"], "INVALID_PROVIDER_USAGE")
        completion = _integer(raw["completion_tokens"], "INVALID_PROVIDER_USAGE")
        total = _integer(raw["total_tokens"], "INVALID_PROVIDER_USAGE")
        _need(total == prompt + completion, "INVALID_PROVIDER_USAGE")
        details_in = raw.get("prompt_tokens_details", {})
        details_out = raw.get("completion_tokens_details", {})
        details_in = {} if details_in is None else details_in
        details_out = {} if details_out is None else details_out
        _need(isinstance(details_in, dict) and isinstance(details_out, dict), "INVALID_PROVIDER_USAGE")
        cached = _integer(details_in.get("cached_tokens", 0), "INVALID_PROVIDER_USAGE")
        reasoning = _integer(details_out.get("reasoning_tokens", 0), "INVALID_PROVIDER_USAGE")
        _need(cached <= prompt and reasoning <= completion, "INVALID_PROVIDER_USAGE")
        return {"prompt_tokens": prompt, "completion_tokens": completion, "total_tokens": total,
                "cached_input_tokens": cached, "reasoning_tokens": reasoning, "raw": raw}
    except (KeyError, TypeError, ValueError):
        return None


def _no_secrets(value, forbidden_secrets=()):
    """Reject secret-bearing fields or recognizable bearer/API key values."""
    if isinstance(value, dict):
        for key, child in value.items():
            _need(str(key).lower().replace("-", "_") not in {
                "authorization", "proxy_authorization", "api_key", "x_api_key", "password", "secret"},
                "CREDENTIAL_IN_EVIDENCE")
            _no_secrets(child, forbidden_secrets)
    elif isinstance(value, list):
        for child in value:
            _no_secrets(child, forbidden_secrets)
    elif isinstance(value, str):
        _need(not re.search(r"(?i)\bbearer\s+[A-Za-z0-9_./+=-]{6,}|\bsk-[A-Za-z0-9_-]{12,}", value),
              "CREDENTIAL_IN_EVIDENCE")
        _need(not any(isinstance(secret, str) and secret and secret in value for secret in forbidden_secrets),
              "CREDENTIAL_IN_EVIDENCE")


def _message_evidence(call, evidence, binding, spec):
    request, side = evidence["request"], evidence["sidecar"]
    _need(call["request"] == request and call["sidecar"] == side, "EVIDENCE_REQUEST_OR_SIDECAR_MISMATCH")
    for key in ("call_id", "run_id", "attempt_id", "result_id", "step_id", "trial_key",
                "logical_run_key", "branch_id", "phase"):
        _need(side[key] == call[key], "SIDECAR_IDENTITY_MISMATCH")
    step, bundle = call["step_id"], side["input_bundle"]
    _need(step in STEPS and set(bundle) == {"request", "parents", "tool_snapshots"}, "INVALID_BUNDLE")
    validate_request(bundle["request"])
    parents, snapshots = bundle["parents"], bundle["tool_snapshots"]
    _need(isinstance(parents, list) and len(parents) == len(PARENTS[step]), "INVALID_PARENT_BINDING")
    _need(all(isinstance(p, dict) and set(p) == {"result_id", "payload"} for p in parents), "INVALID_PARENT_BINDING")
    _need(isinstance(snapshots, list) and len(snapshots) == int(step in STEPS[:3]), "INVALID_SNAPSHOT_BINDING")
    for obj in snapshots:
        validate_object(obj)
    if snapshots:
        _need(snapshots[0]["exists"] and snapshots[0]["object_key"] == source_keys(bundle["request"])[STEPS.index(step)],
              "UNDECLARED_SOURCE")
    carriers = side["public_carriers"]
    _need(isinstance(carriers, list) and [r.get("carrier_kind") for r in carriers]
          == spec["public_carriers"]["placement"][step], "INVALID_CARRIER_PLACEMENT")
    for carrier in carriers:
        _need(set(carrier) == {"carrier_kind", "carrier_ref", "untrusted_text"}
              and isinstance(carrier["untrusted_text"], str), "INVALID_CARRIER")
        if carrier["carrier_kind"] == "source_note":
            source = snapshots[0]
            expected = {"object_key": source["object_key"], "version": source["version"]}
        else:
            expected = {"result_id": parents[0]["result_id"], "payload_digest": _hash(parents[0]["payload"])}
        _need(carrier["carrier_ref"] == expected, "CARRIER_REF_MISMATCH")
    system = spec["message_template"]["system"]
    messages = [{"role": "system", "content": system["system_prefix"] + system["instructions"][step]},
                {"role": "user", "content": _canonical({"step_id": step, "input": bundle, "public_carriers": carriers})}]
    _need(side["prompt_revision"] == "p1-model-v1" and side["prompt_spec_digest"] == PROMPT_SHA,
          "PROMPT_PIN_MISMATCH")
    _need(side["bundle_digest"] == _hash(bundle) and side["public_carriers_digest"] == _hash(carriers)
          and side["rendered_messages_digest"] == _hash(messages), "MESSAGE_DIGEST_MISMATCH")
    _need(side["rendered_messages"] == messages and request["messages"] == messages, "MESSAGE_BYTES_MISMATCH")
    schema = {"type": "json_schema", "json_schema": {
        "name": step, "strict": True, "schema": spec["output_schemas"][step]}}
    _need(request["response_format"] == schema, "RESPONSE_SCHEMA_MISMATCH")
    _need(request["model"] == binding["model"] and request["stream"] is False and request["n"] == 1,
          "PINNED_REQUEST_MISMATCH")
    token_parameter = binding.get("output_token_parameter", "max_completion_tokens")
    _need(request[token_parameter] == binding["max_output_tokens"], "PINNED_REQUEST_MISMATCH")
    expected_keys = {"model", "messages", "n", "stream", token_parameter, "response_format"}
    if binding.get("temperature", 0) is not None:
        expected_keys.add("temperature")
        _need(request.get("temperature") == binding.get("temperature", 0), "PINNED_REQUEST_MISMATCH")
    reasoning_effort = binding.get("reasoning_effort")
    if reasoning_effort is not None:
        _need(type(reasoning_effort) is str and reasoning_effort == "low"
              and "reasoning_effort" in binding.get("supported_parameters", ()),
              "PINNED_REQUEST_MISMATCH")
        expected_keys.add("reasoning_effort")
        _need(request.get("reasoning_effort") == reasoning_effort, "PINNED_REQUEST_MISMATCH")
    _need(set(request) == expected_keys and set(request) <= set(binding.get("supported_parameters", expected_keys)),
          "PINNED_REQUEST_MISMATCH")
    if binding["simulated"]:
        _need(call["input_token_upper_bound"] == len(_canonical(request).encode("utf-8")) + 256 + 128 * len(messages),
              "INPUT_TOKEN_ADMISSION_MISMATCH")
    return request, side


def _raw_response(evidence):
    raw = evidence.get("raw_response")
    return raw if isinstance(raw, dict) else None


def _status_error(status):
    return ("P3_HTTP_AUTH" if status in (401, 403) else "P3_HTTP_RATE_LIMIT" if status == 429
            else "P3_HTTP_SERVER_ERROR" if type(status) is int and 500 <= status <= 599
            else "P3_HTTP_REDIRECT" if type(status) is int and 300 <= status <= 399
            else "P3_HTTP_STATUS_ERROR")


def _cleanup_evidence(trace, binding, state):
    """Check parent-owned cancellation evidence without importing its sender."""
    receipt = trace.get("cleanup_receipt")
    if receipt is None:
        # Historical fake HTTP evidence has no child process. Real calls must
        # now establish that their bounded worker was reaped before proceeding.
        _need(binding["simulated"], "LIVE_WORKER_CLEANUP_EVIDENCE_MISSING")
        return
    _need(isinstance(receipt, dict) and type(receipt.get("schema_version")) is int
          and receipt["schema_version"] == 1,
          "WORKER_CLEANUP_SCHEMA_MISMATCH")
    for key in ("deadline_expired", "worker_started", "wire_result_received", "termination_sent",
                "kill_sent", "reaped", "cleanup_failed", "local_cancel_only", "provider_cancelled", "simulated"):
        _need(type(receipt.get(key)) is bool, "WORKER_CLEANUP_FLAG_INVALID")
    _need(receipt["process_start_method"] == "spawn"
          and receipt["local_cancel_only"] is True and receipt["provider_cancelled"] is False
          and receipt["simulated"] is binding["simulated"], "WORKER_CLEANUP_BOUNDARY_MISMATCH")
    _need(type(receipt["dispatch_index"]) is int
          and receipt["dispatch_index"] == trace["dispatch_index"]
          and receipt["timeout_s"] == trace["timeout_s"], "WORKER_CLEANUP_CALL_MISMATCH")
    for key in ("elapsed_s", "cleanup_elapsed_s"):
        value = receipt.get(key)
        _need(type(value) in (int, float) and math.isfinite(value) and value >= 0,
              "WORKER_CLEANUP_TIMING_INVALID")
    _need(receipt["cleanup_elapsed_s"] <= receipt["elapsed_s"] + 0.001
          and receipt["cleanup_elapsed_s"] <= 5.25,
          "WORKER_CLEANUP_WINDOW_EXCEEDED")
    if receipt["worker_started"]:
        _need(type(receipt["pid"]) is int and receipt["pid"] > 0, "WORKER_PID_MISMATCH")
        if receipt["reaped"]:
            _need(type(receipt["exitcode"]) is int, "WORKER_EXITCODE_MISSING")
    else:
        _need(receipt["pid"] is None and receipt["exitcode"] is None
              and not receipt["termination_sent"] and not receipt["kill_sent"]
              and not receipt["wire_result_received"], "WORKER_START_STATE_MISMATCH")
    _need(not receipt["kill_sent"] or receipt["termination_sent"]
          or (receipt["cleanup_failed"] and state == "quarantined"), "WORKER_KILL_WITHOUT_TERMINATE")
    error = trace["error_code"]
    worker_codes = {"P3_WORKER_CLEANUP_ERROR", "P3_WORKER_EXIT", "P3_WORKER_IPC_ERROR",
                    "P3_WORKER_START_ERROR", "P3_HTTP_TIMEOUT", "P3_NETWORK_ERROR", "P3_RESPONSE_TOO_LARGE"}
    if receipt["cleanup_failed"]:
        _need(error == "P3_WORKER_CLEANUP_ERROR" and state == "quarantined"
              and trace["response_body_b64"] is None, "WORKER_CLEANUP_FAILURE_NOT_FENCED")
    else:
        _need(receipt["reaped"], "WORKER_NOT_REAPED")
    if receipt["deadline_expired"]:
        _need(error in {"P3_HTTP_TIMEOUT", "P3_WORKER_CLEANUP_ERROR"}
              and state == "quarantined", "WORKER_LATE_RESULT_ACCEPTED")
    worker_error = receipt["worker_error"]
    _need(worker_error is None or worker_error in worker_codes, "WORKER_ERROR_INVALID")
    _need(worker_error is None or worker_error == error, "WORKER_ERROR_ALIAS_MISMATCH")
    if error is None:
        _need(receipt["worker_started"] and receipt["wire_result_received"]
              and receipt["reaped"] and receipt["exitcode"] == 0 and worker_error is None
              and not receipt["deadline_expired"] and not receipt["cleanup_failed"],
              "WORKER_SUCCESS_STATE_MISMATCH")
    if "request_digest" in receipt:
        _need(receipt["request_digest"] == trace["request_sha256"], "WORKER_REQUEST_DIGEST_MISMATCH")
    if "worker_pid" in receipt:
        _need(type(receipt["worker_pid"]) is type(receipt["pid"])
              and receipt["worker_pid"] == receipt["pid"], "WORKER_PID_MISMATCH")
    timed_out = receipt["deadline_expired"] or worker_error == "P3_HTTP_TIMEOUT"
    if "timed_out" in receipt:
        _need(type(receipt["timed_out"]) is bool and receipt["timed_out"] is timed_out,
              "WORKER_TIMEOUT_ALIAS_MISMATCH")
    if "terminated" in receipt:
        _need(receipt["terminated"] is receipt["termination_sent"], "WORKER_TERMINATION_ALIAS_MISMATCH")
    if "killed" in receipt:
        _need(receipt["killed"] is receipt["kill_sent"], "WORKER_KILL_ALIAS_MISMATCH")
    expected_status = ("cleanup_error" if receipt["cleanup_failed"] else
                       "timeout" if timed_out else
                       "worker_error" if worker_error is not None else "response")
    if "status" in receipt:
        _need(receipt["status"] == expected_status, "WORKER_STATUS_ALIAS_MISMATCH")
    if "unknown_consumption" in receipt:
        _need(type(receipt["unknown_consumption"]) is bool
              and receipt["unknown_consumption"] is (worker_error is not None),
              "WORKER_CONSUMPTION_ALIAS_MISMATCH")
    if "late_result_ignored" in receipt:
        _need(type(receipt["late_result_ignored"]) is bool
              and (not receipt["late_result_ignored"] or timed_out), "WORKER_LATE_RESULT_ALIAS_MISMATCH")
    if "execution_phase" in receipt:
        phases = {"cleanup_failed" if receipt["cleanup_failed"] else "cleanup_complete"}
        if (not receipt["worker_started"] and receipt["deadline_expired"]
                and worker_error == "P3_HTTP_TIMEOUT" and receipt["reaped"] and not receipt["cleanup_failed"]):
            phases.add("preworker_deadline_abort")
        _need(receipt["execution_phase"] in phases,
              "WORKER_EXECUTION_PHASE_MISMATCH")
    if "deadline_s" in receipt or "finished_s" in receipt:
        for key in ("deadline_s", "finished_s"):
            value = receipt.get(key)
            _need(type(value) in (int, float) and math.isfinite(value) and value >= 0,
                  "WORKER_ABSOLUTE_TIMING_INVALID")
        deadline, finished = receipt["deadline_s"], receipt["finished_s"]
        # This is the parent's original deadline, not a fresh child timeout.
        # A socket may independently time out earlier, so timed_out=True alone
        # does not require the absolute deadline to have expired.
        _need(finished >= receipt["elapsed_s"]
              and deadline <= finished - receipt["elapsed_s"] + receipt["timeout_s"] + 0.001,
              "WORKER_ABSOLUTE_TIMING_INVALID")
        _need(receipt["deadline_expired"] is (finished >= deadline), "WORKER_DEADLINE_ALIAS_MISMATCH")
        elapsed = trace.get("elapsed_s")
        _need(type(elapsed) in (int, float) and math.isfinite(elapsed)
              and elapsed + 0.001 >= finished - (deadline - receipt["timeout_s"]),
              "WORKER_PARENT_DEADLINE_MISMATCH")


def _http_evidence(call, evidence, config, spec, state, forbidden_secrets=()):
    """Reparse captured wire bytes and derive the accepted outcome itself."""
    binding, request = config["binding"], evidence["request"]
    trace, saved = evidence["http_trace"], _raw_response(evidence)
    _need(isinstance(trace, dict) and trace["dispatched"] is True, "HTTP_DISPATCH_MISMATCH")
    _need(trace["binding_digest"] == config["binding_digest"]
          and trace["simulated"] is binding["simulated"]
          and trace["transport"] == ("p3_fake_http" if binding["simulated"] else "p3_https"), "HTTP_BINDING_MISMATCH")
    _need(trace["method"] == "POST" and trace["url"] == binding["endpoint"] + "/chat/completions"
          and type(trace["timeout_s"]) in (int, float) and 0 < trace["timeout_s"] <= binding["timeout_s"],
          "HTTP_ROUTE_OR_DEADLINE_MISMATCH")
    request_bytes = base64.b64decode(trace["request_body_b64"], validate=True)
    _no_secrets(request_bytes.decode("utf-8", errors="replace"), forbidden_secrets)
    _need(request_bytes == _canonical(request).encode("utf-8")
          and hashlib.sha256(request_bytes).hexdigest() == trace["request_sha256"]
          and len(request_bytes) == trace["request_bytes"], "HTTP_REQUEST_BYTES_MISMATCH")
    _cleanup_evidence(trace, binding, state)
    headers = trace["headers"]
    _need(isinstance(headers, dict) and set(headers) <= {
        "content-type", "x-litellm-call-id", "x-request-id", "request-id"},
          "UNSAFE_CAPTURED_HTTP_HEADERS")
    # Re-derive from captured headers, never import the transport normalization.
    gateway_id = headers.get("x-litellm-call-id")
    gateway_id = gateway_id if isinstance(gateway_id, str) and gateway_id.strip() else None
    provider_id = None
    for name in ("x-request-id", "request-id"):
        candidate = headers.get(name)
        if isinstance(candidate, str) and candidate.strip():
            provider_id = candidate
            break
    request_id = gateway_id or provider_id
    if gateway_id is not None:
        _need(trace.get("gateway_call_id") == gateway_id
              and "provider_request_id" in trace and trace["provider_request_id"] == provider_id,
              "HTTP_GATEWAY_PROVIDER_ID_MISMATCH")
    else:
        _need(trace.get("gateway_call_id") is None
              and ("provider_request_id" not in trace or trace["provider_request_id"] == provider_id),
              "HTTP_GATEWAY_PROVIDER_ID_MISMATCH")
    _need(trace["request_id"] == request_id, "HTTP_REQUEST_ID_MISMATCH")
    _need(call["provider_request_id"] is None or request_id == call["provider_request_id"], "HTTP_REQUEST_ID_MISMATCH")
    response_b64 = trace["response_body_b64"]
    status, code, parsed = trace["status"], None, None
    if response_b64 is None:
        _need(saved is None and status is None and trace["response_sha256"] is None
              and trace["response_bytes"] in (None, 0), "MISSING_HTTP_BODY_MISMATCH")
        _need(trace["error_code"] in {"P3_HTTP_TIMEOUT", "P3_NETWORK_ERROR", "P3_RESPONSE_TOO_LARGE",
            "P3_WORKER_CLEANUP_ERROR", "P3_WORKER_EXIT", "P3_WORKER_IPC_ERROR", "P3_WORKER_START_ERROR"},
            "INVALID_TRANSPORT_FAILURE")
        code = trace["error_code"]
    else:
        response_bytes = base64.b64decode(response_b64, validate=True)
        _no_secrets(response_bytes.decode("utf-8", errors="replace"), forbidden_secrets)
        _need(hashlib.sha256(response_bytes).hexdigest() == trace["response_sha256"]
              and len(response_bytes) == trace["response_bytes"], "HTTP_RESPONSE_BYTES_MISMATCH")
        if len(response_bytes) > 2 * 1024 * 1024:
            code = "P3_RESPONSE_TOO_LARGE"
        else:
            try:
                parsed = _strict_json(response_bytes.decode("utf-8"))
                _need(isinstance(parsed, dict), "INVALID_RESPONSE_OBJECT")
            except (ValueError, TypeError, UnicodeError, RecursionError):
                code = "P3_RESPONSE_JSON_ERROR" if status == 200 else _status_error(status)
        if parsed is None or code is not None:
            _need(saved is None, "UNPARSEABLE_RESPONSE_HAS_JSON_EVIDENCE")
        else:
            _need(saved is not None and {k: v for k, v in saved.items() if k not in {"_request_id", "_p3_http"}} == parsed,
                  "RAW_RESPONSE_WIRE_MISMATCH")
            _need(saved.get("_request_id") == request_id and trace["body_response_id"] == parsed.get("id"),
                  "HTTP_RESPONSE_ID_MISMATCH")
            if "_p3_http" in saved:
                _need(saved["_p3_http"] == trace, "RAW_HTTP_TRACE_MISMATCH")
            usage = _usage(parsed)
            elapsed = trace.get("elapsed_s")
            _need(type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= 0,
                  "HTTP_ELAPSED_TIME_MISSING_OR_INVALID")
            if elapsed >= trace["timeout_s"]:
                code = "P3_HTTP_TIMEOUT"
            elif status != 200:
                code = _status_error(status)
            elif usage is None:
                code = "P3_USAGE_ERROR"
            elif request_id is None or not isinstance(parsed.get("id"), str) or not parsed["id"]:
                code = "P3_RESPONSE_ID_ERROR"
            elif "error" in parsed:
                code = "P3_PROVIDER_ERROR"
            elif parsed.get("model") not in binding["allowed_response_models"]:
                code = "P3_RESPONSE_MODEL_ERROR"
            elif usage["prompt_tokens"] > binding["max_input_tokens"] or usage["completion_tokens"] > binding["max_output_tokens"]:
                code = "P3_USAGE_LIMIT"
    transport_code = code
    payload = None
    if code is None:
        try:
            choices = parsed["choices"]
            _need(isinstance(choices, list) and len(choices) == 1, "INVALID_COMPLETION")
            choice, message = choices[0], choices[0]["message"]
            _need(type(choice["index"]) is int and choice["index"] == 0, "INVALID_COMPLETION")
            if choice["finish_reason"] != "stop" or message.get("refusal") not in (None, ""):
                code = "MODEL_ERROR"
            else:
                _need(message.get("role") == "assistant", "INVALID_COMPLETION")
                payload = _strict_json(message["content"])
                Draft202012Validator(spec["output_schemas"][call["step_id"]]).validate(payload)
                (validate_action(payload) if call["step_id"] == "execute" else validate_payload(call["step_id"], payload))
        except (ValueError, KeyError, TypeError, IndexError, ValidationError):
            code = "MODEL_SCHEMA_ERROR"
    observed = _usage(parsed)
    if observed is not None and (observed["prompt_tokens"] > call["input_tokens_reserved"]
                                 or observed["completion_tokens"] > call["output_tokens_reserved"]):
        code = "P3_ADMISSION_BOUND_VIOLATION"
    outcome = evidence["outcome"]
    _need(outcome.get("error_code") == code, "GATEWAY_OUTCOME_MISMATCH")
    _need(outcome["status"] == ("success" if code is None else "model_error"), "GATEWAY_OUTCOME_MISMATCH")
    _need(trace["error_code"] == transport_code, "HTTP_ERROR_CLASSIFICATION_MISMATCH")
    if code is None:
        _need(outcome["payload"] == payload, "DELIVERED_PAYLOAD_MISMATCH")
    elif code not in {"MODEL_SCHEMA_ERROR", "MODEL_ERROR"}:
        _need(state == "quarantined", "INFRASTRUCTURE_FAILURE_WITHOUT_FENCE")
    return parsed


def _undispatched_evidence(evidence, config, state):
    trace = evidence["http_trace"]
    _need(isinstance(trace, dict) and trace["dispatched"] is False and trace["dispatch_index"] is None,
          "HTTP_DISPATCH_MISMATCH")
    _need(evidence.get("raw_response") is None and trace["status"] is None
          and trace["response_body_b64"] is None and trace["response_sha256"] is None
          and trace["response_bytes"] == 0 and trace["request_id"] is None and trace["headers"] == {},
          "UNDISPATCHED_HTTP_RESPONSE")
    _need(trace["binding_digest"] == config["binding_digest"]
          and trace["simulated"] is config["binding"]["simulated"], "HTTP_BINDING_MISMATCH")
    if trace["request_body_b64"] is not None:
        request_bytes = base64.b64decode(trace["request_body_b64"], validate=True)
        _need(request_bytes == _canonical(evidence["request"]).encode()
              and hashlib.sha256(request_bytes).hexdigest() == trace["request_sha256"]
              and len(request_bytes) == trace["request_bytes"], "HTTP_REQUEST_BYTES_MISMATCH")
    else:
        _need(trace["request_sha256"] is None and trace["request_bytes"] == 0,
              "UNDISPATCHED_HTTP_REQUEST_MISMATCH")
    code = trace["error_code"]
    _need(isinstance(code, str) and code and evidence["outcome"]["status"] == "model_error"
          and evidence["outcome"].get("error_code") == code and state == "quarantined",
          "PREFLIGHT_FAILURE_WITHOUT_FENCE")


def audit_p3_campaign(campaign_path, evidence_records=None, *, expected_summary=None, forbidden_secrets=()):
    """Audit persisted campaign calls without trusting a runtime snapshot.

    Returns all failures as data.  ``expected_summary`` is optional output to
    compare against independently derived totals; it never supplies facts.
    ``forbidden_secrets`` supports an exact-value leak check without persisting
    those secrets.  The database is opened read-only throughout.
    """
    checks, calls, receipts, conflicts, restarts = [], [], {}, [], []
    counts = {}

    def add(rule, operation):
        try:
            operation()
            checks.append({"rule_id": rule, "passed": True, "reason_code": None})
        except (ValueError, TypeError, KeyError, IndexError, AttributeError, OSError,
                sqlite3.Error, OverflowError, ValidationError) as exc:
            checks.append({"rule_id": rule, "passed": False,
                           "reason_code": getattr(exc, "code", str(exc))})

    try:
        prompt_raw = PROMPT.read_bytes()
        _need(hashlib.sha256(prompt_raw).hexdigest() == PROMPT_SHA, "PROMPT_SPEC_DIGEST_MISMATCH")
        spec = _strict_json(prompt_raw)
        with _readonly(campaign_path) as db:
            campaign = db.execute("SELECT config,state,reason FROM p3_campaign WHERE singleton=1").fetchone()
            _need(campaign is not None, "CAMPAIGN_MISSING")
            config, state, reason = _strict_json(campaign["config"]), campaign["state"], campaign["reason"]
            rows = list(db.execute("SELECT call_id,attempt_id,body,reservation_digest,settlement_digest FROM p3_calls ORDER BY rowid"))
            calls = [_strict_json(r["body"]) for r in rows]
            receipt_rows = list(db.execute("SELECT * FROM p3_receipts ORDER BY rowid"))
            receipts = {r["call_id"]: dict(r) for r in receipt_rows}
            conflicts = [dict(r) for r in db.execute("SELECT * FROM p3_conflicts ORDER BY rowid")]
            restarts = [dict(r) for r in db.execute("SELECT * FROM p3_restarts ORDER BY rowid")]
            _need(len(receipts) == len(receipt_rows), "DUPLICATE_RECEIPT_CALL_ID")
        binding, limits = config["binding"], config["limits"]
        _need(config["schema_version"] == "p3-budget-v1" and config["binding_digest"] == _hash(binding),
              "BINDING_DIGEST_MISMATCH")
        maxima = {"call_cap": 71, "input_token_cap": 284000, "output_token_cap": 54528,
                  "max_cost_nano_usd": 1000000000, "slot_call_cap": 5, "logical_call_cap": 10}
        _need(set(limits) == set(maxima) and all(type(limits[k]) is int and 0 < limits[k] <= v
              for k, v in maxima.items()), "P3_LIMITS_ENLARGED")
        _need(binding["p0_freeze_id"] == "p0-v1-5aa953e9e83924eb"
              and binding["p0_content_digest"] == "5aa953e9e83924eb6f2266f478eec833a843e13d40b548df9b540ea0ad6f19c2"
              and binding["endpoint"] == "https://tritonai-api.ucsd.edu/v1", "P3_BINDING_PIN_MISMATCH")
        _need(type(binding["simulated"]) is bool and (not binding["simulated"] or binding["real_requests_authorized"] is False),
              "TRANSPORT_AUTHORIZATION_MISMATCH")
        _need(state in {"active", "quarantined", "stopped_budget"}, "UNKNOWN_CAMPAIGN_STATE")
        _no_secrets(config, forbidden_secrets)
        _no_secrets(reason, forbidden_secrets)
        for conflict in conflicts:
            _no_secrets(_strict_json(conflict["body"]), forbidden_secrets)
        for restart in restarts:
            _no_secrets(_strict_json(restart["body"]), forbidden_secrets)
        if evidence_records is not None:
            _need(isinstance(evidence_records, list), "INVALID_EVIDENCE_RECORDS")
            supplied = {e["call_id"]: e for e in evidence_records}
            _need(len(supplied) == len(evidence_records), "DUPLICATE_EVIDENCE_CALL_ID")
            _need(set(supplied) == {c["call_id"] for c in calls if c.get("evidence") is not None}, "HTTP_EVIDENCE_COVERAGE_MISMATCH")
            _need(all(supplied[c["call_id"]] == c["evidence"] for c in calls if c.get("evidence") is not None),
                  "EXTERNAL_EVIDENCE_MISMATCH")
        checks.append({"rule_id": "P3_RAW_DATABASE", "passed": True, "reason_code": None})
    except (ValueError, TypeError, KeyError, OSError, sqlite3.Error) as exc:
        return {"passed": False, "status": "failed", "findings": [getattr(exc, "code", str(exc))],
                "checks": [{"rule_id": "P3_RAW_DATABASE", "passed": False,
                            "reason_code": getattr(exc, "code", str(exc))}], "counts": counts}

    def unique():
        for field in ("call_id", "attempt_id", "result_id"):
            _need(len({c[field] for c in calls}) == len(calls), "DUPLICATE_" + field.upper())
        for row, call in zip(rows, calls):
            _need(row["call_id"] == call["call_id"] and row["attempt_id"] == call["attempt_id"], "SQL_ROW_IDENTITY_MISMATCH")
        _need(set(receipts) <= {c["call_id"] for c in calls}, "ORPHAN_PROVIDER_RECEIPT")
        request_ids = [_strict_json(r["body"]).get("provider_request_id") for r in rows]
        request_ids = [r for r in request_ids if r is not None]
        _need(len(set(request_ids)) == len(request_ids), "DUPLICATE_PROVIDER_REQUEST_ID")
        # Distinct gateway receipts must not conceal one repeated upstream
        # generation, nor may different upstream IDs conceal one gateway call.
        for names, finding in ((("x-litellm-call-id",), "DUPLICATE_GATEWAY_CALL_ID"),
                               (("x-request-id", "request-id"), "DUPLICATE_UPSTREAM_REQUEST_ID")):
            captured = []
            for call in calls:
                headers = ((call.get("evidence") or {}).get("http_trace") or {}).get("headers", {})
                for name in names:
                    value = headers.get(name)
                    if isinstance(value, str) and value.strip():
                        captured.append(value)
                        break
            _need(len(set(captured)) == len(captured), finding)
        response_ids = [(c.get("evidence") or {}).get("raw_response", {}).get("id")
                        for c in calls if isinstance((c.get("evidence") or {}).get("raw_response"), dict)]
        response_ids = [r for r in response_ids if r is not None]
        _need(len(set(response_ids)) == len(response_ids), "DUPLICATE_PROVIDER_RESPONSE_ID")
        for restart in restarts:
            body = _strict_json(restart["body"])
            _need(body["logical_run_key"] == restart["logical_run_key"] and body["status"] == "reserved"
                  and body["source_run_id"] == restart["source_run_id"]
                  and _hash({k: v for k, v in body.items() if k not in {"status", "reserved_at"}}) == restart["request_digest"],
                  "RESTART_ADMISSION_MISMATCH")
        _need(len({r["source_run_id"] for r in restarts}) == len(restarts), "RESTART_SOURCE_REUSED")
        restart_keys = {r["logical_run_key"] for r in restarts}
        _need(all(c["logical_run_key"] in restart_keys for c in calls if c["phase"] == "replay"), "UNADMITTED_RESTART_CALL")
    add("P3_GLOBAL_IDENTITIES", unique)

    derived = []
    for row, call in zip(rows, calls):
        def one(row=row, call=call):
            _no_secrets(call, forbidden_secrets)
            _need(call["schema_version"] == "p3-call-v1", "UNKNOWN_CALL_SCHEMA")
            for identity in ("call_id", "run_id", "attempt_id", "result_id", "branch_id"):
                validate_id(call[identity])
            _need(type(call["dispatched"]) is bool, "INVALID_DISPATCH_FLAG")
            _need(call["simulated"] is binding["simulated"], "TRANSPORT_LABEL_MISMATCH")
            evidence = call["evidence"]
            _need(isinstance(evidence, dict) or not call["dispatched"], "HTTP_EVIDENCE_MISSING")
            if evidence is not None:
                _need(evidence["call_id"] == call["call_id"], "EVIDENCE_CALL_IDENTITY_MISMATCH")
                _need(evidence["simulated"] is binding["simulated"], "TRANSPORT_LABEL_MISMATCH")
                _need(type(evidence["observed_dispatch_count"]) is int
                      and evidence["observed_dispatch_count"] == int(call["dispatched"]), "PHYSICAL_DISPATCH_COUNT_MISMATCH")
                request, side = _message_evidence(call, evidence, binding, spec)
            else:
                request, side = _message_evidence(call, {"request": call["request"], "sidecar": call["sidecar"]}, binding, spec)
            input_reserved = _integer(call["input_tokens_reserved"])
            output_reserved = _integer(call["output_tokens_reserved"])
            _need(input_reserved == call["input_token_upper_bound"] and 0 < input_reserved <= binding["max_input_tokens"]
                  and output_reserved == binding["max_output_tokens"], "TOKEN_RESERVATION_MISMATCH")
            input_rate = _integer(binding["input_nano_usd_per_token"])
            output_rate = _integer(binding["output_nano_usd_per_token"])
            cached_rate = binding.get("cached_input_nano_usd_per_token")
            cached_rate = input_rate if cached_rate is None else _integer(cached_rate)
            reserved = input_reserved * input_rate + output_reserved * output_rate
            for money_key in ("reserved_cost_nano_usd", "known_cost_nano_usd", "held_cost_nano_usd"):
                _integer(call[money_key])
            _need(call["reserved_cost_nano_usd"] == reserved, "RESERVATION_COST_MISMATCH")
            generated = {"schema_version", "status", "dispatched", "simulated", "input_tokens_reserved",
                "output_tokens_reserved", "reserved_cost_nano_usd", "known_cost_nano_usd", "held_cost_nano_usd",
                "usage", "provider_request_id", "reserved_at", "dispatched_at", "settled_at", "uncertainty_reason", "evidence"}
            _need(row["reservation_digest"] == _hash({k: v for k, v in call.items() if k not in generated}),
                  "RESERVATION_DIGEST_MISMATCH")
            raw = _raw_response(evidence or {})
            observed = _usage(raw)
            usage = call["usage"]
            if usage is not None:
                _need(observed == usage, "RAW_USAGE_MISMATCH")
                _need(usage["prompt_tokens"] <= input_reserved and usage["completion_tokens"] <= output_reserved,
                      "ACTUAL_USAGE_EXCEEDED_ADMISSION")
                _need(call["dispatched"] is True, "UNDISPATCHED_USAGE")
                cost = (usage["prompt_tokens"] - usage["cached_input_tokens"]) * input_rate
                cost += usage["cached_input_tokens"] * cached_rate + usage["completion_tokens"] * output_rate
                _need(call["known_cost_nano_usd"] == cost, "KNOWN_COST_MISMATCH")
                _need(call["call_id"] in receipts, "PROVIDER_RECEIPT_MISSING")
                receipt = receipts[call["call_id"]]
                saved_normalized = _strict_json(receipt["normalized_usage"])
                _need(_strict_json(receipt["raw_usage"]) == usage["raw"]
                      and {**saved_normalized, "raw": _strict_json(receipt["raw_usage"])} == usage, "RECEIPT_USAGE_MISMATCH")
                _need(receipt["provider_request_id"] == call["provider_request_id"], "RECEIPT_IDENTITY_MISMATCH")
                receipt_normalized = _strict_json(receipt["normalized_usage"])
                settlement = {"provider_request_id": receipt["provider_request_id"],
                              "raw_usage": _strict_json(receipt["raw_usage"]), "normalized_usage": receipt_normalized}
                _need(_hash(settlement) == receipt["receipt_digest"] == row["settlement_digest"], "RECEIPT_DIGEST_MISMATCH")
            else:
                _need(call["known_cost_nano_usd"] == 0, "UNKNOWN_USAGE_BECAME_KNOWN_COST")
                _need(call["held_cost_nano_usd"] == reserved, "UNKNOWN_USAGE_HOLD_RELEASED")
                _need(call["call_id"] not in receipts, "UNKNOWN_USAGE_HAS_RECEIPT")
                _need(row["settlement_digest"] is None, "UNKNOWN_USAGE_HAS_SETTLEMENT_DIGEST")
            _need(call["status"] in {"reserved", "dispatched", "settled", "uncertain"}, "UNKNOWN_CALL_STATUS")
            if call["status"] == "settled":
                _need(usage is not None and call["held_cost_nano_usd"] == 0 and call["dispatched"], "INVALID_SETTLEMENT")
            elif call["status"] in {"reserved", "dispatched"}:
                _need(usage is None and call["dispatched"] == (call["status"] == "dispatched"), "PENDING_CALL_INCONSISTENT")
            elif call["status"] == "uncertain":
                _need(state == "quarantined" and bool(call["uncertainty_reason"]), "UNCERTAIN_CALL_WITHOUT_FENCE")
                _need(call["held_cost_nano_usd"] == reserved, "UNKNOWN_USAGE_HOLD_RELEASED")
            if call["dispatched"]:
                _http_evidence(call, evidence, config, spec, state, forbidden_secrets)
            elif evidence is not None:
                _undispatched_evidence(evidence, config, state)
            derived.append({"call_id": call["call_id"], "input": 0 if usage is None else usage["prompt_tokens"],
                "output": 0 if usage is None else usage["completion_tokens"], "known": call["known_cost_nano_usd"],
                "held": call["held_cost_nano_usd"], "input_hold": input_reserved if call["status"] != "settled" else 0,
                "output_hold": output_reserved if call["status"] != "settled" else 0,
                "settled": call["status"] == "settled"})
        add("P3_CALL_" + str(call.get("call_id", "missing")), one)

    def totals():
        _need(len(derived) == len(calls), "INCOMPLETE_CALL_RECONCILIATION")
        counts.update({"calls_reserved_or_spent": len(calls), "calls_dispatched": sum(c["dispatched"] for c in calls),
            "calls_remaining": max(0, limits["call_cap"] - len(calls)),
            "known_input_tokens": sum(r["input"] for r in derived if r["settled"]),
            "known_output_tokens": sum(r["output"] for r in derived if r["settled"]),
            "held_input_tokens": sum(r["input_hold"] for r in derived), "held_output_tokens": sum(r["output_hold"] for r in derived),
            "known_cost_nano_usd": sum(r["known"] for r in derived), "held_cost_nano_usd": sum(r["held"] for r in derived),
            "real_api_requests": 0 if binding["simulated"] else sum(c["dispatched"] for c in calls),
            "fake_http_dispatches": sum(c["dispatched"] for c in calls) if binding["simulated"] else 0,
            "uncertain_calls": sum(c["status"] == "uncertain" for c in calls)})
        counts["remaining_cost_nano_usd"] = max(0, limits["max_cost_nano_usd"] - counts["known_cost_nano_usd"] - counts["held_cost_nano_usd"])
        _need(len(calls) <= limits["call_cap"], "CAMPAIGN_CALL_CAP_EXCEEDED")
        for key, field in (("slot_call_cap", "trial_key"), ("logical_call_cap", "logical_run_key")):
            _need(all(n <= limits[key] for n in Counter(c[field] for c in calls).values()), "PER_RUN_CALL_CAP_EXCEEDED")
        _need(counts["known_cost_nano_usd"] + counts["held_cost_nano_usd"] <= limits["max_cost_nano_usd"]
              or state == "quarantined", "CAMPAIGN_MONEY_CAP_EXCEEDED_WITHOUT_FENCE")
        for kind in ("input", "output"):
            _need(counts["known_" + kind + "_tokens"] + counts["held_" + kind + "_tokens"] <= limits[kind + "_token_cap"]
                  or state == "quarantined", "CAMPAIGN_TOKEN_CAP_EXCEEDED_WITHOUT_FENCE")
        if any(c["status"] in {"reserved", "dispatched", "uncertain"} for c in calls) or conflicts:
            _need(state == "quarantined", "UNRESOLVED_CAMPAIGN_NOT_FENCED")
        if expected_summary is not None:
            supplied = expected_summary.get("budget", expected_summary)
            for key, value in counts.items():
                if key in supplied:
                    _need(supplied[key] == value, "SUMMARY_TOTAL_MISMATCH:" + key)
            if "budget" in expected_summary:
                _need(expected_summary["config"] == config and expected_summary["status"] == state
                      and expected_summary.get("pause_reason") == reason, "SUMMARY_CAMPAIGN_STATE_MISMATCH")
                _need(expected_summary.get("real_api_requests") == counts["real_api_requests"]
                      and expected_summary.get("simulated") is binding["simulated"], "SUMMARY_TRANSPORT_LABEL_MISMATCH")
    add("P3_INDEPENDENT_TOTALS", totals)
    findings = [c["reason_code"] for c in checks if not c["passed"]]
    return {"passed": not findings, "status": "passed" if not findings else "failed", "checks": checks,
            "findings": findings, "counts": counts, "campaign_state": state, "campaign_reason": reason}
