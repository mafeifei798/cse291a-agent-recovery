"""Read-only audit of a first-stage launch, independent of its launcher.

Only raw JSON, read-only SQLite, and the established independent HTTP/workflow
auditors supply facts.  A failed launch can pass this safety audit while its
``successful`` field remains false; stopping is never counted as task success.
"""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import re
import sqlite3

from .p3_checker import audit_p3_campaign
from .p3_trial_checker import audit_offline_trial


FIRST_STAGE_MAXIMA = {
    "call_cap": 6, "input_token_cap": 24000, "output_token_cap": 4608,
    "max_cost_nano_usd": 1000000000, "slot_call_cap": 5,
    "logical_call_cap": 5,
}


def _need(value, code):
    if not value:
        raise ValueError(code)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def _hash(value):
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _read(path):
    def pairs(items):
        result = {}
        for key, value in items:
            _need(key not in result, "LAUNCH_DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    def reject(_):
        raise ValueError("LAUNCH_NONFINITE_JSON")

    return json.loads(Path(path).read_text(), object_pairs_hook=pairs,
                      parse_constant=reject)


def _secrets(value, forbidden):
    if isinstance(value, dict):
        for key, child in value.items():
            _need(str(key).lower().replace("-", "_") not in {
                "authorization", "proxy_authorization", "api_key", "x_api_key",
                "password", "secret", "credential_value"}, "LAUNCH_CREDENTIAL_IN_EVIDENCE")
            _secrets(child, forbidden)
    elif isinstance(value, list):
        for child in value:
            _secrets(child, forbidden)
    elif isinstance(value, str):
        _need(not re.search(r"(?i)\bbearer\s+[A-Za-z0-9_./+=-]{6,}|\bsk-[A-Za-z0-9_-]{12,}", value),
              "LAUNCH_CREDENTIAL_IN_EVIDENCE")
        _need(not any(isinstance(secret, str) and secret and secret in value
                      for secret in forbidden), "LAUNCH_CREDENTIAL_IN_EVIDENCE")


@contextmanager
def _readonly(path):
    connection = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        _need(connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok",
              "LAUNCH_SQLITE_INTEGRITY_FAILED")
        yield connection
    finally:
        connection.close()


def _bounded_integer(value, cap, code):
    _need(type(value) is int and 0 <= value <= cap, code)
    return value


def _path(value, expected, code):
    _need(isinstance(value, str) and value == str(expected.resolve()), code)


def audit_first_stage_launch(root, *, allow_pending=False, forbidden_secrets=()):
    """Audit a saved launch; this function never imports or calls its launcher."""
    root = Path(root).resolve()
    checks, counts, findings = [], {}, []
    successful = False
    try:
        receipt = _read(root / "launch_receipt.json")
        config = _read(root / "launch_config.json")
        grant = _read(root / "launch_grant.json")
        for value in (receipt, config, grant):
            _secrets(value, forbidden_secrets)
        _need(receipt.get("schema_version") == "p3-first-stage-launch-v1",
              "LAUNCH_SCHEMA_MISMATCH")
        _need(receipt.get("config_digest") == _hash(config)
              and receipt.get("grant_digest") == _hash(grant),
              "LAUNCH_INPUT_DIGEST_MISMATCH")
        _need(type(receipt.get("simulated")) is bool, "LAUNCH_SIMULATION_FLAG_INVALID")
        simulated = receipt["simulated"]
        _need(receipt.get("execution_kind") == (
            "offline_first_stage_fixture" if simulated else "authorized_first_stage_live"),
            "LAUNCH_EXECUTION_KIND_MISMATCH")
        _need(isinstance(receipt.get("launch_id"), str) and receipt["launch_id"],
              "LAUNCH_IDENTITY_MISSING")
        _need(type(allow_pending) is bool, "LAUNCH_PENDING_PERMISSION_INVALID")
        pending = receipt.get("status") == "pending_finalization"
        _need(not pending or allow_pending, "LAUNCH_NOT_FINALIZED")
        _need(receipt.get("status") in {"completed", "probe_failed", "normal_failed", "error"}
              or pending, "LAUNCH_NOT_TERMINAL")
        _need(type(receipt.get("normal_started")) is bool
              and type(receipt.get("gate_passed")) is bool,
              "LAUNCH_BOOLEAN_FLAG_INVALID")
        effective_receipt = dict(receipt)
        if pending:
            _need(receipt["gate_passed"] is False and receipt.get("candidate_status") in {
                "completed", "probe_failed", "normal_failed", "error"},
                "LAUNCH_PENDING_CANDIDATE_INVALID")
            effective_receipt["status"] = receipt["candidate_status"]
        _path(receipt.get("campaign_db"), root / "campaign.sqlite", "LAUNCH_LEDGER_PATH_MISMATCH")
        _path(receipt.get("probe_dir"), root / "probe", "LAUNCH_PROBE_PATH_MISMATCH")
        _path(receipt.get("normal_dir"), root / "normal", "LAUNCH_NORMAL_PATH_MISMATCH")
        limits = receipt.get("limits")
        _need(isinstance(limits, dict) and set(limits) == set(FIRST_STAGE_MAXIMA),
              "LAUNCH_LIMIT_FIELDS_MISMATCH")
        _need(all(type(limits[k]) is int and 0 < limits[k] <= cap
                  for k, cap in FIRST_STAGE_MAXIMA.items()), "LAUNCH_LIMITS_ENLARGED")
        # Input/grant schema and bindings are checked below from raw fields.
        _check_inputs(config, grant, receipt)
        checks.append({"rule": "raw_launch_inputs_scope_and_permissions", "passed": True})

        ledger = root / "campaign.sqlite"
        if not ledger.exists():
            _need(effective_receipt["status"] == "error" and receipt.get("phase") == "credential_input"
                  and receipt["gate_passed"] is False and receipt["normal_started"] is False
                  and not (root / "probe").exists() and not (root / "normal").exists(),
                  "LAUNCH_MISSING_LEDGER_AFTER_EXECUTION")
            _need(all(type(receipt.get(k)) is int and receipt[k] == 0 for k in
                      ("total_calls", "known_cost_nano_usd", "held_cost_nano_usd", "real_api_requests")),
                  "LAUNCH_PRELEDGER_CALL_CLAIM")
            counts.update(total_calls=0, calls_dispatched=0, known_cost_nano_usd=0,
                          held_cost_nano_usd=0, real_api_requests=0, trials=0)
            checks.append({"rule": "credential_failure_consumed_without_execution", "passed": True})
        else:
            counts, successful = _check_ledger(root, config, grant, effective_receipt,
                                               forbidden_secrets, checks)
        if not pending:
            _need(receipt["gate_passed"] is successful, "LAUNCH_GATE_CLAIM_MISMATCH")
            _check_final_proof(root, receipt, counts, successful, forbidden_secrets)
            checks.append({"rule": "final_receipt_audit_proof", "passed": True})
        # The internal readiness proof deliberately never claims launch success:
        # its publication and the final receipt still have to succeed.
        return {"schema_version": "p3-first-stage-audit-proof-v1",
                "status": "passed", "passed": True,
                "successful": bool(successful and not pending),
                "ready_for_success": bool(successful), "pending_readiness": pending,
                "launch_id": receipt["launch_id"], "config_digest": receipt["config_digest"],
                "grant_digest": receipt["grant_digest"], "binding_digest": receipt["binding_digest"],
                "campaign_id": receipt["campaign_id"],
                "candidate_status": receipt.get("candidate_status", receipt["status"]),
                "checks": checks, "counts": counts, "findings": []}
    except Exception as exc:
        findings.append(getattr(exc, "code", str(exc)))
        return {"status": "failed", "passed": False, "successful": False,
                "checks": checks, "counts": counts, "findings": findings}


def _check_final_proof(root, receipt, counts, successful, forbidden):
    proof_path = root / "independent_check.json"
    if not proof_path.exists():
        _need(not successful and receipt["status"] != "completed",
              "LAUNCH_FINAL_AUDIT_PROOF_MISSING")
        return
    proof = _read(proof_path)
    _secrets(proof, forbidden)
    # An error can occur after a valid readiness proof was saved, or before
    # its digest reached the final receipt. Such a fenced failure remains
    # a failure. A completed launch must establish the full proof linkage.
    if receipt.get("independent_check_digest") is None:
        _need(not successful and receipt["status"] != "completed",
              "LAUNCH_FINAL_AUDIT_PROOF_DIGEST_MISSING")
        return
    _need(receipt["independent_check_digest"] == _hash(proof),
          "LAUNCH_FINAL_AUDIT_PROOF_DIGEST_MISMATCH")
    if not successful and receipt["status"] == "error" and proof.get("status") == "failed":
        return
    _need(proof.get("schema_version") == "p3-first-stage-audit-proof-v1"
          and all(proof.get(key) == receipt[key] for key in (
              "launch_id", "config_digest", "grant_digest", "binding_digest", "campaign_id"))
          and proof.get("counts") == counts, "LAUNCH_FINAL_AUDIT_PROOF_BINDING_MISMATCH")
    if successful:
        _need(proof.get("status") == "passed" and proof.get("passed") is True
              and proof.get("successful") is False and proof.get("ready_for_success") is True
              and proof.get("pending_readiness") is True
              and proof.get("candidate_status") == "completed"
              and isinstance(proof.get("checks"), list) and bool(proof["checks"])
              and all(item.get("passed") is True for item in proof["checks"])
              and proof.get("findings") == [], "LAUNCH_FINAL_AUDIT_PROOF_NOT_READY")


def _check_inputs(config, grant, receipt):
    """The basic launch contract is copied deliberately, not imported."""
    _need(set(config) == {"schema_version", "enabled", "campaign_id", "output_root",
          "stage", "sequence", "call_cap", "max_cost_nano_usd", "concurrency",
          "automatic_retries", "p4_enabled", "binding", "token_counter"},
          "LAUNCH_CONFIG_FIELDS_MISMATCH")
    _need(config["schema_version"] == "p3-first-stage-launch-v1"
          and config["enabled"] is True and config["stage"] == "first_stage"
          and config["sequence"] == ["probe", "p1-dev-01/CLEAN/BASE"]
          and type(config["concurrency"]) is int and config["concurrency"] == 1
          and type(config["automatic_retries"]) is int and config["automatic_retries"] == 0
          and config["p4_enabled"] is False, "LAUNCH_CONFIG_SCOPE_OR_PERMISSION_MISMATCH")
    _need(type(config["call_cap"]) is int and config["call_cap"] == 6
          and type(config["max_cost_nano_usd"]) is int
          and 0 < config["max_cost_nano_usd"] <= 1000000000,
          "LAUNCH_CONFIG_LIMITS_ENLARGED")
    binding, counter, simulated = config["binding"], config["token_counter"], receipt["simulated"]
    _need(isinstance(binding, dict) and binding.get("simulated") is simulated
          and binding.get("real_requests_authorized") is (not simulated)
          and _hash(binding) == receipt.get("binding_digest"), "LAUNCH_BINDING_MISMATCH")
    _need(binding.get("endpoint") == "https://tritonai-api.ucsd.edu/v1"
          and binding.get("p0_freeze_id") == "p0-v1-5aa953e9e83924eb"
          and binding.get("p0_content_digest") == "5aa953e9e83924eb6f2266f478eec833a843e13d40b548df9b540ea0ad6f19c2",
          "LAUNCH_BINDING_PINS_MISMATCH")
    for key, cap in (("max_input_tokens", 4000), ("max_output_tokens", 768), ("timeout_s", 120)):
        _need(type(binding.get(key)) is int and 0 < binding[key] <= cap,
              "LAUNCH_BINDING_LIMITS_ENLARGED")
    for key in ("input_nano_usd_per_token", "output_nano_usd_per_token"):
        _need(type(binding.get(key)) is int and binding[key] >= 0, "LAUNCH_RATE_INVALID")
    worst = (binding["max_input_tokens"] * binding["input_nano_usd_per_token"]
             + binding["max_output_tokens"] * binding["output_nano_usd_per_token"])
    _need(config["call_cap"] * worst <= config["max_cost_nano_usd"],
          "LAUNCH_DECLARED_STAGE_CANNOT_BE_FUNDED")
    _need(isinstance(counter, dict) and set(counter) == {"counter_ref", "implementation_ref", "evidence_ref"}
          and all(isinstance(v, str) and bool(v.strip()) for v in counter.values())
          and counter["evidence_ref"] == binding["token_admission_evidence"],
          "LAUNCH_COUNTER_EVIDENCE_MISMATCH")
    refs = [binding["binding_ref"], binding["price_evidence"], binding["capability_evidence"],
            binding["token_admission_evidence"], *counter.values()]
    _need(all(isinstance(v, str) and bool(v.strip()) and v.startswith("fixture:") is simulated
              for v in refs) and isinstance(binding.get("model"), str)
          and binding["model"].startswith("fixture-") is simulated
          and isinstance(config["campaign_id"], str)
          and config["campaign_id"].startswith("fixture-") is simulated,
          "LAUNCH_FIXTURE_PROVENANCE_MISMATCH")
    expected_limits = {
        "call_cap": config["call_cap"],
        "input_token_cap": config["call_cap"] * binding["max_input_tokens"],
        "output_token_cap": config["call_cap"] * binding["max_output_tokens"],
        "max_cost_nano_usd": config["max_cost_nano_usd"],
        "slot_call_cap": min(5, config["call_cap"]),
        "logical_call_cap": min(5, config["call_cap"]),
    }
    _need(receipt["limits"] == expected_limits, "LAUNCH_DERIVED_LIMITS_MISMATCH")
    _need(set(grant) == {"schema_version", "authorized", "grant_id", "config_digest",
          "binding_digest", "campaign_id", "output_root", "counter_ref",
          "counter_implementation_ref", "counter_evidence_ref", "call_cap", "max_cost_nano_usd"},
          "LAUNCH_GRANT_FIELDS_MISMATCH")
    _need(grant["schema_version"] == "p3-first-stage-grant-v1" and grant["authorized"] is True
          and isinstance(grant["grant_id"], str) and bool(grant["grant_id"].strip())
          and grant["grant_id"].startswith("fixture:") is simulated
          and receipt.get("grant_id") == grant["grant_id"]
          and receipt.get("campaign_id") == grant["campaign_id"] == config["campaign_id"]
          and grant["config_digest"] == receipt["config_digest"]
          and grant["binding_digest"] == receipt["binding_digest"]
          and grant["output_root"] == config["output_root"]
          == str(Path(receipt["campaign_db"]).parent)
          and grant["counter_ref"] == counter["counter_ref"]
          and grant["counter_implementation_ref"] == counter["implementation_ref"]
          and grant["counter_evidence_ref"] == counter["evidence_ref"]
          and type(grant["call_cap"]) is int and grant["call_cap"] == config["call_cap"]
          and type(grant["max_cost_nano_usd"]) is int
          and grant["max_cost_nano_usd"] == config["max_cost_nano_usd"],
          "LAUNCH_GRANT_BINDING_MISMATCH")


def _check_ledger(root, config, grant, receipt, forbidden_secrets, checks):
    ledger = root / "campaign.sqlite"
    with _readonly(ledger) as db:
        raw = db.execute("SELECT config,state,reason FROM p3_campaign WHERE singleton=1").fetchone()
        _need(raw is not None, "LAUNCH_CAMPAIGN_MISSING")
        campaign_config, state = json.loads(raw["config"]), raw["state"]
        calls = [json.loads(row[0]) for row in db.execute("SELECT body FROM p3_calls ORDER BY rowid")]
        entry_rows = list(db.execute("SELECT cell_key,entry_id,body FROM p3_dev_entries ORDER BY rowid"))
        entries = [json.loads(row["body"]) for row in entry_rows]
        restarts = db.execute("SELECT COUNT(*) FROM p3_restarts").fetchone()[0]
    _need(campaign_config.get("campaign_id") == config["campaign_id"]
          and campaign_config.get("binding") == config["binding"]
          and campaign_config.get("binding_digest") == receipt["binding_digest"]
          and campaign_config.get("limits") == receipt["limits"],
          "LAUNCH_LEDGER_CONFIG_MISMATCH")
    _need(restarts == 0 and len(entries) <= 2, "LAUNCH_RESTART_OR_EXTRA_ENTRY")
    _need(all(row["cell_key"] == entry.get("cell_key") and row["entry_id"] == entry.get("entry_id")
              for row, entry in zip(entry_rows, entries))
          and len({entry.get("entry_id") for entry in entries}) == len(entries),
          "LAUNCH_ENTRY_SQL_IDENTITY_MISMATCH")
    _need(len(calls) <= receipt["limits"]["call_cap"] <= 6
          and all(call.get("phase") == "initial" for call in calls),
          "LAUNCH_EXTRA_CALL_OR_PHASE")
    # Detect a second budget inside this run, even if the receipt omits it.
    for path in root.rglob("*.sqlite"):
        if path.resolve() == ledger.resolve():
            continue
        with _readonly(path) as db:
            _need(db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='p3_campaign'").fetchone()
                  is None, "LAUNCH_SECOND_CAMPAIGN_LEDGER")
    campaign_audit = audit_p3_campaign(ledger, forbidden_secrets=forbidden_secrets)
    _need(campaign_audit.get("status") == "passed", "LAUNCH_INDEPENDENT_CAMPAIGN_CHECK_FAILED")
    checks.append({"rule": "independent_campaign_http_and_budget", "passed": True})
    totals = {
        "total_calls": len(calls), "calls_dispatched": sum(call["dispatched"] for call in calls),
        "known_cost_nano_usd": sum(call["known_cost_nano_usd"] for call in calls),
        "held_cost_nano_usd": sum(call["held_cost_nano_usd"] for call in calls),
        "real_api_requests": 0 if receipt["simulated"] else sum(call["dispatched"] for call in calls),
        "trials": len(entries),
    }
    for key in ("total_calls", "known_cost_nano_usd", "held_cost_nano_usd", "real_api_requests"):
        _need(type(receipt.get(key)) is int and receipt[key] == totals[key],
              "LAUNCH_CLAIMED_TOTALS_MISMATCH")
    _need(totals["known_cost_nano_usd"] + totals["held_cost_nano_usd"]
          <= receipt["limits"]["max_cost_nano_usd"], "LAUNCH_ONE_DOLLAR_CAP_EXCEEDED")
    by_cell, trial_keys, probe_passed, normal_passed = {}, set(), False, False
    for entry in entries:
        _secrets(entry, forbidden_secrets)
        cell = entry.get("cell_key")
        _need(cell in {"probe", "p1-dev-01__CLEAN__BASE"} and cell not in by_cell,
              "LAUNCH_CELL_NOT_FIRST_STAGE")
        by_cell[cell] = entry
        probe = cell == "probe"
        folder = root / ("probe" if probe else "normal")
        _path(entry.get("destination"), folder, "LAUNCH_ENTRY_DESTINATION_MISMATCH")
        _need(entry.get("campaign_id") == config["campaign_id"]
              and entry.get("campaign_budget_ref") == str(ledger)
              and entry.get("binding_digest") == receipt["binding_digest"]
              and entry.get("simulated") is receipt["simulated"]
              and entry.get("execution_kind") == (
                  "offline_authorized_entry_fixture" if receipt["simulated"] else "authorized_real_dev")
              and entry.get("task_id") == "p1-dev-01" and entry.get("condition") == "CLEAN"
              and entry.get("policy") == "BASE" and entry.get("probe_only") is probe,
              "LAUNCH_ENTRY_BINDING_MISMATCH")
        permit = entry.get("entry_permit", {})
        _need(permit.get("authorized") is True and permit.get("stage") == "first_stage"
              and permit.get("authorization_reference") == grant["grant_id"]
              and permit.get("binding_digest") == receipt["binding_digest"]
              and permit.get("campaign_id") == config["campaign_id"]
              and permit.get("campaign_budget_ref") == str(ledger)
              and type(permit.get("call_cap")) is int
              and permit["call_cap"] == receipt["limits"]["call_cap"],
              "LAUNCH_ENTRY_PERMISSION_MISMATCH")
        _need(entry.get("status") == "completed" and (folder / "summary.json").is_file(),
              "LAUNCH_ENTRY_EVIDENCE_INCOMPLETE")
        summary, saved_entry = _read(folder / "summary.json"), _read(folder / "entry_receipt.json")
        _need(summary.get("entry_receipt") == saved_entry == entry,
              "LAUNCH_ENTRY_RECEIPT_MISMATCH")
        _need(entry.get("summary_digest_before_entry") == _hash(
            {key: value for key, value in summary.items() if key != "entry_receipt"}),
            "LAUNCH_ENTRY_SUMMARY_DIGEST_MISMATCH")
        _need(summary.get("task_id") == "p1-dev-01" and summary.get("condition") == "CLEAN"
              and summary.get("policy") == "BASE" and summary.get("probe_only") is probe
              and summary.get("simulated") is receipt["simulated"]
              and summary.get("campaign_budget_ref") == str(ledger)
              and summary.get("execution_kind") == entry["execution_kind"],
              "LAUNCH_TRIAL_SCOPE_MISMATCH")
        _need(all(summary.get(key) is None for key in
                  ("freeze", "drain", "before_drain", "admission", "duplicate_restart", "replay", "replay_check"))
              and not (folder / "restart").exists(), "LAUNCH_TRIAL_RECOVERY_OUT_OF_SCOPE")
        trial_key = summary.get("trial_key")
        _need(isinstance(trial_key, str) and trial_key not in trial_keys
              and entry.get("trial_key") == trial_key, "LAUNCH_TRIAL_IDENTITY_MISMATCH")
        trial_keys.add(trial_key)
        trial_calls = [call for call in calls if call["trial_key"] == trial_key]
        _need(len(trial_calls) <= (1 if probe else 5), "LAUNCH_TRIAL_CALL_CAP_EXCEEDED")
        audit = audit_offline_trial(folder, ledger)
        _need(audit.get("status") == "passed", "LAUNCH_INDEPENDENT_TRIAL_CHECK_FAILED")
        all_calls_ok = all(call["status"] == "settled"
                           and call["evidence"]["outcome"]["status"] == "success" for call in trial_calls)
        if probe:
            probe_passed = (len(trial_calls) == 1 and all_calls_ok
                            and summary["initial"].get("status") == "probe_completed"
                            and summary["initial"].get("log_complete") is True)
            _need(entry.get("gate_passed") is probe_passed, "LAUNCH_PROBE_GATE_CLAIM_MISMATCH")
        else:
            normal_passed = (len(trial_calls) == 5 and all_calls_ok
                             and summary["initial_check"].get("correctness") == "correct"
                             and summary["initial"].get("log_complete") is True)
            _need(entry.get("gate_passed") is normal_passed, "LAUNCH_NORMAL_GATE_CLAIM_MISMATCH")
        checks.append({"rule": "independent_first_stage_trial_" + ("probe" if probe else "normal"),
                       "passed": True, "calls": len(trial_calls)})
    _need(all(call["trial_key"] in trial_keys for call in calls), "LAUNCH_ORPHAN_CALL")
    normal_started = "p1-dev-01__CLEAN__BASE" in by_cell
    _need(receipt["normal_started"] is normal_started
          and (normal_started or not (root / "normal").exists()), "LAUNCH_NORMAL_START_CLAIM_MISMATCH")
    _need(not normal_started or probe_passed, "LAUNCH_NORMAL_BEFORE_PROBE_PASSED")
    successful = bool(probe_passed and normal_passed and len(calls) == 6 and state == "active")
    if receipt["status"] == "completed":
        _need(successful, "LAUNCH_FALSE_SUCCESS_CLAIM")
    else:
        _need(not successful and state in {"quarantined", "stopped_budget"}, "LAUNCH_FAILURE_NOT_FENCED")
        if receipt["status"] == "probe_failed":
            _need(not probe_passed and not normal_started, "LAUNCH_PROBE_FAILURE_SCOPE_MISMATCH")
        elif receipt["status"] == "normal_failed":
            _need(probe_passed and normal_started and not normal_passed,
                  "LAUNCH_NORMAL_FAILURE_SCOPE_MISMATCH")
    return totals, successful
