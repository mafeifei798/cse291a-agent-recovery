"""Sealed P4 runtime choices; the original P0 registration stays unchanged.

These constants describe admission, not verified account debits. In particular,
4000 input tokens is the conservative allowance used by P3, not a calibrated
tokenizer. The old uncertain request remains charged at its full reservation.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from .contracts import digest, require
from .p3_transport import P3Binding, P0_FREEZE_ID, P0_CONTENT_DIGEST

REGISTRY_SHA256 = "132b4fc0818f88f66d3725b4252c3b51747f661111b53f9dc3edca9e3996853c"
BASELINE_SHA256 = "555388c4a68436cda3c7899ebf552daf9fcfbdbe3f2eb025926c8fd62313d74f"
BASELINE_CALLS = 1003
BASELINE_KNOWN_NANO_USD = 58_579_400
BASELINE_HELD_NANO_USD = 984_000
GLOBAL_MAX_NANO_USD = 1_000_000_000
AVAILABLE_NANO_USD = GLOBAL_MAX_NANO_USD - BASELINE_KNOWN_NANO_USD - BASELINE_HELD_NANO_USD
FORMAL_SLOT_COUNT = 168
FORMAL_CALL_CAP = 840
COUNTER_KIND = "input_budget_allowance_not_calibrated_tokenizer"
ALLOWANCE_EVIDENCE = "p4:4000-input-budget-allowance-not-tokenizer-verification"
DEFAULT_LIMITS = dict(call_cap=840, input_token_cap=3_360_000,
                      output_token_cap=645_120, max_cost_nano_usd=AVAILABLE_NANO_USD,
                      slot_call_cap=5, logical_call_cap=10)


def load_formal_registry(path=None):
    source = Path(path) if path is not None else Path(__file__).resolve().parents[2] / "phase1/p0/manifests/trials.jsonl"
    raw = source.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == REGISTRY_SHA256,
            "Original 168-slot registry has changed", "P4_REGISTRY_MISMATCH")
    rows = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    require(len(rows) == FORMAL_SLOT_COUNT and len({r["trial_key"] for r in rows}) == FORMAL_SLOT_COUNT
            and all(r["status"] == "not_started" for r in rows),
            "Formal registration does not match the sealed P0", "P4_REGISTRY_MISMATCH")
    return rows


def validate_baseline(path):
    source = Path(path)
    raw = source.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == BASELINE_SHA256,
            "Historical budget evidence has changed", "P4_BASELINE_MISMATCH")
    value = json.loads(raw)
    require(value.get("cumulative_calls") == BASELINE_CALLS
            and value.get("cumulative_known_cost_nano_usd") == BASELINE_KNOWN_NANO_USD
            and value.get("held_cost_nano_usd") == BASELINE_HELD_NANO_USD
            and value.get("old_unknown_reservation_released") is False,
            "Historical cost and retained unknown hold differ", "P4_BASELINE_MISMATCH")
    return value


def make_binding(*, simulated=False):
    require(type(simulated) is bool, "Explicit execution mode required", "P4_BINDING_INVALID")
    return P3Binding(binding_ref="fixture:p4-formal-flash-v1" if simulated else "p4:formal-flash-v1",
        model="fixture-glm-5.3-flash" if simulated else "api-glm-5.3-flash",
        allowed_response_models=("fixture-glm-5.3-flash",) if simulated else ("api-glm-5.3-flash", "glm-5.3-flash"),
        simulated=simulated, real_requests_authorized=not simulated,
        input_nano_usd_per_token=150, output_nano_usd_per_token=500,
        price_evidence="fixture:p4-prices" if simulated else "TritonAI public catalog verified 2026-10-20: GLM-5.3-Flash input USD0.15/M, output USD0.50/M; provider usage basis; account debit unverified",
        capability_evidence="fixture:p4-strict-schema" if simulated else "P3 real strict JSON Schema workflows including resume records SHA256 285a9e7b8e32c5bcdd4294d2d39805abff1f31cc3a19260d7e26abe442c73dbe",
        token_admission_evidence="fixture:p4-allowance" if simulated else ALLOWANCE_EVIDENCE,
        supported_parameters=("model", "messages", "n", "stream", "max_completion_tokens", "response_format", "reasoning_effort"),
        output_token_parameter="max_completion_tokens", temperature=None, reasoning_effort="low")


def formal_binding_record(binding):
    """Separate runtime record, with no edits to P0's unresolved binding."""
    require(isinstance(binding, P3Binding), "P4 requires a checked transport binding", "P4_BINDING_INVALID")
    value = dict(schema_version="p4-formal-runtime-binding-v1", p0_freeze_id=P0_FREEZE_ID,
        p0_content_digest=P0_CONTENT_DIGEST, registry_sha256=REGISTRY_SHA256,
        original_model_binding_digest="64966b56ed59b5c4185a416f2c8ddc914a6764f7463b53c6c0456e1ba8b15bab",
        transport_binding=binding.to_dict(), transport_binding_digest=binding.binding_digest,
        baseline_budget_sha256=BASELINE_SHA256, baseline_calls=BASELINE_CALLS,
        baseline_known_cost_nano_usd=BASELINE_KNOWN_NANO_USD,
        baseline_held_cost_nano_usd=BASELINE_HELD_NANO_USD,
        max_cumulative_cost_nano_usd=GLOBAL_MAX_NANO_USD,
        limits=deepcopy(DEFAULT_LIMITS), input_counter_kind=COUNTER_KIND,
        input_count_calibrated=False, automatic_http_retries=0,
        business_replanning_enabled=False, extra_business_guard_enabled=False,
        policies=["BASE", "VERIFY_STOP", "FULL_RESTART"], original_registration_modified=False)
    value["runtime_binding_digest"] = digest(value)
    return value
