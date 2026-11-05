"""Read-only split-stage checks and probe handoff sealing.

The launcher's config parser and runtime are deliberately not imported. Raw
JSON/SQLite and the established campaign/trial auditors supply the facts. A
probe can be ready for a separately granted continuation without task success.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import re
import sqlite3

from .p3_checker import audit_p3_campaign
from .p3_trial_checker import audit_offline_trial


_CONFIG_FIELDS = {"schema_version", "enabled", "campaign_id", "output_root", "stage",
    "sequence", "call_cap", "max_cost_nano_usd", "concurrency", "automatic_retries",
    "p4_enabled", "binding", "token_counter"}
_GRANT_FIELDS = {"schema_version", "authorized", "grant_id", "config_digest", "binding_digest",
    "campaign_id", "output_root", "counter_ref", "counter_implementation_ref", "counter_evidence_ref",
    "stage_call_cap", "max_cost_nano_usd", "phase", "cumulative_call_cap", "handoff_digest"}
_HANDOFF_FIELDS = {"schema_version", "config_digest", "binding_digest", "campaign_id", "output_root",
    "probe_stage_id", "probe_grant_digest", "probe_receipt_digest", "probe_proof_digest",
    "probe_ledger_projection", "probe_ledger_digest", "probe_artifacts", "probe_artifact_tree_digest",
    "source_campaign_sha256"}
_STEPS = ("read_metadata", "read_permission", "read_resources", "plan", "execute")
_HEX = re.compile(r"[0-9a-f]{64}\Z")


def _need(value, code):
    if not value:
        raise ValueError(code)


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _hash(value):
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _same(left, right):
    return _canonical(left) == _canonical(right)


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            _need(key not in result, "SPLIT_DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    def reject(_):
        raise ValueError("SPLIT_NONFINITE_JSON")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=reject)


def _read(path):
    _need(path.is_file() and not path.is_symlink(), "SPLIT_FILE_MISSING_OR_LINKED")
    return _json(path.read_text())


def _secrets(value, forbidden=()):
    if isinstance(value, dict):
        for key, child in value.items():
            _need(str(key).lower().replace("-", "_") not in {
                "authorization", "proxy_authorization", "api_key", "x_api_key", "password", "secret"},
                "SPLIT_CREDENTIAL_IN_EVIDENCE")
            _secrets(str(key), forbidden)
            _secrets(child, forbidden)
    elif isinstance(value, list):
        for child in value:
            _secrets(child, forbidden)
    elif isinstance(value, str):
        _need(not re.search(r"(?i)\bbearer\s+[A-Za-z0-9_./+=-]{6,}|\bsk-[A-Za-z0-9_-]{12,}", value)
              and not any(isinstance(s, str) and s and s in value for s in forbidden),
              "SPLIT_CREDENTIAL_IN_EVIDENCE")


def _integer(value, cap):
    return type(value) is int and 0 <= value <= cap


@contextmanager
def _readonly(path):
    _need(path.is_file() and not path.is_symlink(), "SPLIT_LEDGER_MISSING_OR_LINKED")
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        _need(connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "SPLIT_SQLITE_INTEGRITY")
        yield connection
    finally:
        connection.close()


def _limits(config):
    binding = config["binding"]
    return dict(call_cap=6, input_token_cap=6 * binding["max_input_tokens"],
        output_token_cap=6 * binding["max_output_tokens"], max_cost_nano_usd=config["max_cost_nano_usd"],
        slot_call_cap=5, logical_call_cap=5)


def _inputs(root, phase, config, grant, receipt):
    _need(set(config) == _CONFIG_FIELDS and config["schema_version"] == "p3-first-stage-launch-v1"
          and config["enabled"] is True and config["stage"] == "first_stage"
          and config["sequence"] == ["probe", "p1-dev-01/CLEAN/BASE"]
          and type(config["call_cap"]) is int and config["call_cap"] == 6
          and _integer(config["max_cost_nano_usd"], 1_000_000_000) and config["max_cost_nano_usd"] > 0
          and type(config["concurrency"]) is int and config["concurrency"] == 1
          and type(config["automatic_retries"]) is int and config["automatic_retries"] == 0
          and config["p4_enabled"] is False and config["output_root"] == str(root), "SPLIT_CONFIG_SCOPE")
    binding, counter, simulated = config["binding"], config["token_counter"], receipt["simulated"]
    _need(type(simulated) is bool and binding["simulated"] is simulated
          and binding["real_requests_authorized"] is (not simulated)
          and binding["endpoint"] == "https://tritonai-api.ucsd.edu/v1"
          and binding["p0_freeze_id"] == "p0-v1-5aa953e9e83924eb"
          and binding["p0_content_digest"] == "5aa953e9e83924eb6f2266f478eec833a843e13d40b548df9b540ea0ad6f19c2",
          "SPLIT_BINDING_SCOPE")
    for key, cap in (("max_input_tokens", 4000), ("max_output_tokens", 768), ("timeout_s", 120)):
        _need(_integer(binding[key], cap) and binding[key] > 0, "SPLIT_BINDING_LIMITS")
    for key in ("input_nano_usd_per_token", "output_nano_usd_per_token"):
        _need(type(binding[key]) is int and binding[key] >= 0, "SPLIT_BINDING_PRICE")
    worst = binding["max_input_tokens"] * binding["input_nano_usd_per_token"] + binding["max_output_tokens"] * binding["output_nano_usd_per_token"]
    _need(6 * worst <= config["max_cost_nano_usd"], "SPLIT_BUDGET_CANNOT_FUND_STAGE")
    _need(set(counter) == {"counter_ref", "implementation_ref", "evidence_ref"}
          and counter["evidence_ref"] == binding["token_admission_evidence"], "SPLIT_COUNTER_BINDING")
    references = [binding[k] for k in ("binding_ref", "price_evidence", "capability_evidence", "token_admission_evidence")]
    references += list(counter.values())
    _need(all(isinstance(v, str) and v.strip() and v.startswith("fixture:") is simulated for v in references)
          and isinstance(binding["model"], str) and binding["model"].startswith("fixture-") is simulated
          and isinstance(config["campaign_id"], str) and config["campaign_id"].startswith("fixture-") is simulated,
          "SPLIT_PROVENANCE")
    _need(set(grant) == _GRANT_FIELDS and grant["schema_version"] == "p3-split-stage-grant-v1"
          and grant["authorized"] is True and grant["phase"] == phase
          and isinstance(grant["grant_id"], str) and bool(grant["grant_id"].strip())
          and grant["grant_id"].startswith("fixture:") is simulated
          and grant["config_digest"] == _hash(config) and grant["binding_digest"] == _hash(binding)
          and grant["campaign_id"] == config["campaign_id"] and grant["output_root"] == str(root)
          and grant["counter_ref"] == counter["counter_ref"]
          and grant["counter_implementation_ref"] == counter["implementation_ref"]
          and grant["counter_evidence_ref"] == counter["evidence_ref"]
          and type(grant["max_cost_nano_usd"]) is int
          and grant["max_cost_nano_usd"] == config["max_cost_nano_usd"], "SPLIT_GRANT_BINDING")
    stage_cap, cumulative = (1, 1) if phase == "probe" else (5, 6)
    _need(type(grant["stage_call_cap"]) is int and grant["stage_call_cap"] == stage_cap
          and type(grant["cumulative_call_cap"]) is int and grant["cumulative_call_cap"] == cumulative
          and ((phase == "probe" and grant["handoff_digest"] == "")
               or (phase == "normal" and isinstance(grant["handoff_digest"], str) and _HEX.fullmatch(grant["handoff_digest"]))),
          "SPLIT_GRANT_SCOPE")
    _need(receipt["schema_version"] == "p3-split-stage-receipt-v1" and receipt["phase"] == phase
          and isinstance(receipt["stage_id"], str) and bool(receipt["stage_id"])
          and receipt["config_digest"] == _hash(config) and receipt["grant_digest"] == _hash(grant)
          and receipt["grant_id"] == grant["grant_id"] and receipt["binding_digest"] == _hash(binding)
          and receipt["campaign_id"] == config["campaign_id"] and receipt["campaign_db"] == str(root / "campaign.sqlite")
          and _same(receipt["limits"], _limits(config))
          and type(receipt["stage_call_cap"]) is int and receipt["stage_call_cap"] == stage_cap
          and type(receipt["cumulative_call_cap"]) is int and receipt["cumulative_call_cap"] == cumulative
          and receipt["handoff_digest"] == grant["handoff_digest"]
          and receipt["execution_kind"] == ("offline_split_stage_fixture" if simulated else "authorized_split_stage_live"),
          "SPLIT_RECEIPT_BINDING")


def _rows(root):
    with _readonly(root / "campaign.sqlite") as db:
        campaign = dict(db.execute("SELECT config,state,reason FROM p3_campaign WHERE singleton=1").fetchone())
        calls = [dict(r) for r in db.execute("SELECT * FROM p3_calls ORDER BY rowid")]
        receipts = [dict(r) for r in db.execute("SELECT * FROM p3_receipts ORDER BY rowid")]
        exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='p3_dev_entries'").fetchone()
        entries = [dict(r) for r in db.execute("SELECT * FROM p3_dev_entries ORDER BY rowid")] if exists else []
        conflicts = [dict(r) for r in db.execute("SELECT * FROM p3_conflicts ORDER BY rowid")]
        restarts = [dict(r) for r in db.execute("SELECT * FROM p3_restarts ORDER BY rowid")]
    return campaign, calls, receipts, entries, conflicts, restarts


def _projection(root):
    campaign, calls, receipts, entries, conflicts, restarts = _rows(root)
    probe = [r for r in entries if r["cell_key"] == "probe"]
    _need(len(probe) == 1 and not conflicts and not restarts, "SPLIT_PROBE_PROJECTION_HISTORY")
    key = _json(probe[0]["body"]).get("trial_key")
    selected = [r for r in calls if _json(r["body"]).get("trial_key") == key]
    _need(len(selected) == 1, "SPLIT_PROBE_PROJECTION_CALLS")
    ids = {r["call_id"] for r in selected}
    return {"campaign_config": campaign["config"], "calls": selected,
            "receipts": [r for r in receipts if r["call_id"] in ids], "entries": probe}


def _artifact_tree(root):
    targets = [root / "config.json"] + [root / "probe_stage" / name for name in ("grant.json", "receipt.json", "independent_check.json")]
    folder = root / "probe"
    _need(folder.is_dir() and not folder.is_symlink(), "SPLIT_PROBE_ARTIFACTS_MISSING")
    for path in folder.rglob("*"):
        _need(not path.is_symlink(), "SPLIT_LINKED_PROBE_ARTIFACT")
        if path.is_file():
            targets.append(path)
    result = []
    for path in sorted(targets):
        _need(path.is_file() and not path.is_symlink(), "SPLIT_PROBE_SOURCE_MISSING")
        raw = path.read_bytes()
        result.append({"path": str(path.relative_to(root)), "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)})
    return result


def _proof(root, phase, receipt, result, *, stage_ok):
    path = root / (phase + "_stage") / "independent_check.json"
    if receipt.get("independent_check_digest") is None:
        _need(not stage_ok, "SPLIT_FINAL_PROOF_DIGEST_MISSING")
        return
    proof = _read(path)
    _need(receipt["independent_check_digest"] == _hash(proof), "SPLIT_FINAL_PROOF_DIGEST")
    _need(all(_same(proof.get(k), result[k]) for k in
              ("phase", "stage_id", "config_digest", "grant_digest", "binding_digest", "campaign_id", "counts")),
          "SPLIT_FINAL_PROOF_BINDING")
    if stage_ok:
        _need(proof.get("status") == "passed" and proof.get("pending_readiness") is True
              and proof.get("ready_for_stage") is True and proof.get("stage_successful") is False
              and proof.get("successful") is False and proof.get("findings") == []
              and proof.get("candidate_status") == ("probe_completed" if phase == "probe" else "completed")
              and proof.get("ready_for_handoff") is (phase == "probe")
              and proof.get("ready_for_success") is (phase == "normal")
              and bool(proof.get("checks")) and all(r.get("passed") is True for r in proof["checks"]),
              "SPLIT_FINAL_PROOF_NOT_READY")


def _trial(root, entry_row, config, grant, calls, forbidden):
    entry = _json(entry_row["body"])
    probe = entry_row["cell_key"] == "probe"
    phase = "probe" if probe else "normal"
    folder, ledger = root / phase, root / "campaign.sqlite"
    _secrets(entry, forbidden)
    _need(entry_row["entry_id"] == entry["entry_id"] and entry_row["cell_key"] == entry["cell_key"]
          and entry["cell_key"] in {"probe", "p1-dev-01__CLEAN__BASE"}
          and entry["destination"] == str(folder) and entry["campaign_id"] == config["campaign_id"]
          and entry["campaign_budget_ref"] == str(ledger) and entry["binding_digest"] == _hash(config["binding"])
          and entry["simulated"] is config["binding"]["simulated"] and entry["task_id"] == "p1-dev-01"
          and entry["condition"] == "CLEAN" and entry["policy"] == "BASE" and entry["probe_only"] is probe,
          "SPLIT_ENTRY_BINDING")
    permit = entry["entry_permit"]
    _need(permit["authorized"] is True and permit["stage"] == "first_stage"
          and permit["authorization_reference"] == grant["grant_id"]
          and permit["binding_digest"] == _hash(config["binding"])
          and permit["campaign_id"] == config["campaign_id"] and permit["campaign_budget_ref"] == str(ledger)
          and type(permit["call_cap"]) is int and permit["call_cap"] == (1 if probe else 6), "SPLIT_ENTRY_PERMISSION")
    _need(entry["status"] == "completed", "SPLIT_ENTRY_NOT_FINAL")
    summary = _read(folder / "summary.json")
    _need(summary["entry_receipt"] == _read(folder / "entry_receipt.json") == entry
          and entry["summary_digest_before_entry"] == _hash({k: v for k, v in summary.items() if k != "entry_receipt"}),
          "SPLIT_ENTRY_SUMMARY")
    _need(summary["task_id"] == "p1-dev-01" and summary["condition"] == "CLEAN" and summary["policy"] == "BASE"
          and summary["probe_only"] is probe and summary["simulated"] is config["binding"]["simulated"]
          and summary["campaign_budget_ref"] == str(ledger)
          and all(summary.get(k) is None for k in ("freeze", "drain", "before_drain", "admission", "duplicate_restart", "replay", "replay_check"))
          and not (folder / "restart").exists(), "SPLIT_TRIAL_SCOPE")
    _need(audit_offline_trial(folder, ledger).get("status") == "passed", "SPLIT_TRIAL_AUDIT")
    trial_calls = [c for c in calls if c["trial_key"] == summary["trial_key"]]
    _need(entry["trial_key"] == summary["trial_key"] and len(trial_calls) <= (1 if probe else 5), "SPLIT_TRIAL_CALL_CAP")
    succeeded = (len(trial_calls) == (1 if probe else 5)
        and all(c["status"] == "settled" and c["evidence"]["outcome"]["status"] == "success" for c in trial_calls)
        and summary["initial"].get("log_complete") is True
        and (summary["initial"].get("status") == "probe_completed" if probe else summary["initial_check"].get("correctness") == "correct"))
    if succeeded:
        _need([c["step_id"] for c in trial_calls] == (["read_metadata"] if probe else list(_STEPS)), "SPLIT_TRIAL_STEP_ORDER")
    _need(entry["gate_passed"] is succeeded, "SPLIT_ENTRY_GATE_CLAIM")
    return succeeded, summary["trial_key"]


def audit_split_stage(root, phase, *, allow_pending=False, forbidden_secrets=()):
    """Return a safety audit; only finalized normal success is task success."""
    root = Path(root).resolve()
    checks, counts = [], {}
    result = dict(status="failed", passed=False, phase=phase, checks=checks, counts=counts,
        ready_for_stage=False, ready_for_handoff=False, ready_for_success=False,
        stage_successful=False, successful=False, pending_readiness=False, findings=[])
    try:
        _need(phase in {"probe", "normal"} and type(allow_pending) is bool, "SPLIT_AUDIT_ARGUMENTS")
        config = _read(root / "config.json")
        grant = _read(root / (phase + "_stage") / "grant.json")
        receipt = _read(root / (phase + "_stage") / "receipt.json")
        for value in (config, grant, receipt):
            _secrets(value, forbidden_secrets)
        _inputs(root, phase, config, grant, receipt)
        result.update({k: receipt[k] for k in ("stage_id", "config_digest", "grant_digest", "binding_digest", "campaign_id")})
        pending = receipt["status"] == "pending_finalization"
        _need(not pending or allow_pending, "SPLIT_NOT_FINALIZED")
        status = receipt.get("candidate_status") if pending else receipt["status"]
        _need(status in {"probe_completed", "completed", "probe_failed", "normal_failed", "error"}, "SPLIT_NOT_TERMINAL")
        _need(status not in ({"completed", "normal_failed"} if phase == "probe" else {"probe_completed", "probe_failed"}), "SPLIT_WRONG_PHASE_STATUS")
        for key in ("gate_passed", "normal_started", "ready_for_handoff", "successful"):
            _need(type(receipt.get(key)) is bool, "SPLIT_RECEIPT_BOOLEAN")
        if pending:
            _need(all(receipt[k] is False for k in ("gate_passed", "ready_for_handoff", "successful")), "SPLIT_PENDING_SUCCESS_CLAIM")
        if phase == "probe":
            _need(not (root / "normal").exists() and not (root / "normal_stage").exists()
                  and receipt["normal_started"] is False, "SPLIT_PROBE_STARTED_NORMAL")
        else:
            _need(grant["grant_id"] != _read(root / "probe_stage" / "grant.json")["grant_id"],
                  "SPLIT_STAGE_GRANT_REUSED")
            validate_probe_handoff(root, grant["handoff_digest"], for_continuation=False,
                                   forbidden_secrets=forbidden_secrets)
        checks.append({"rule": "raw_config_stage_grant_and_scope", "passed": True})
        ledger = root / "campaign.sqlite"
        stage_ok = False
        if not ledger.exists():
            _need(phase == "probe" and status == "error" and not (root / "probe").exists()
                  and all(type(receipt.get(k)) is int and receipt[k] == 0 for k in
                          ("total_calls", "stage_calls", "known_cost_nano_usd", "held_cost_nano_usd", "real_api_requests")),
                  "SPLIT_MISSING_LEDGER")
            counts.update(total_calls=0, stage_calls=0, calls_dispatched=0, known_cost_nano_usd=0,
                          held_cost_nano_usd=0, real_api_requests=0, trials=0)
        else:
            campaign, sql_calls, _, entries, conflicts, restarts = _rows(root)
            campaign_config = _json(campaign["config"])
            _need(campaign_config["campaign_id"] == config["campaign_id"]
                  and campaign_config["binding"] == config["binding"]
                  and campaign_config["binding_digest"] == _hash(config["binding"])
                  and campaign_config["limits"] == _limits(config) and not restarts,
                  "SPLIT_LEDGER_CONFIG_OR_RESTART")
            _need(audit_p3_campaign(ledger, forbidden_secrets=forbidden_secrets).get("status") == "passed", "SPLIT_CAMPAIGN_AUDIT")
            for path in root.rglob("*.sqlite"):
                if path == ledger:
                    continue
                with _readonly(path) as other:
                    _need(other.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='p3_campaign'").fetchone() is None,
                          "SPLIT_SECOND_BUDGET_LEDGER")
            calls = [_json(r["body"]) for r in sql_calls]
            _need(all(c["phase"] == "initial" for c in calls) and len(calls) <= (1 if phase == "probe" else 6), "SPLIT_CALL_SCOPE")
            cells = [r["cell_key"] for r in entries]
            _need(len(cells) == len(set(cells)) and set(cells) <= {"probe", "p1-dev-01__CLEAN__BASE"}
                  and (phase != "probe" or set(cells) <= {"probe"}), "SPLIT_ENTRY_SCOPE")
            outcomes, trial_keys = {}, set()
            for entry in entries:
                entry_phase = "probe" if entry["cell_key"] == "probe" else "normal"
                source_grant = grant if entry_phase == phase else _read(root / "probe_stage" / "grant.json")
                succeeded, key = _trial(root, entry, config, source_grant, calls, forbidden_secrets)
                _need(key not in trial_keys, "SPLIT_DUPLICATE_TRIAL_ID")
                trial_keys.add(key)
                outcomes[entry_phase] = succeeded
            _need(all(c["trial_key"] in trial_keys for c in calls), "SPLIT_ORPHAN_CALL")
            normal_started = "normal" in outcomes
            _need(not normal_started or outcomes.get("probe") is True, "SPLIT_NORMAL_BEFORE_PROBE")
            _need(receipt["normal_started"] is normal_started or (status == "error" and phase == "normal"), "SPLIT_NORMAL_START_CLAIM")
            stage_calls = len(calls) if phase == "probe" else len(calls) - 1
            _need(0 <= stage_calls <= grant["stage_call_cap"], "SPLIT_STAGE_CALL_CAP")
            counts.update(total_calls=len(calls), stage_calls=stage_calls,
                calls_dispatched=sum(c["dispatched"] for c in calls),
                known_cost_nano_usd=sum(c["known_cost_nano_usd"] for c in calls),
                held_cost_nano_usd=sum(c["held_cost_nano_usd"] for c in calls),
                real_api_requests=0 if receipt["simulated"] else sum(c["dispatched"] for c in calls), trials=len(entries))
            stage_ok = (outcomes.get(phase) is True and campaign["state"] == "active" and not conflicts
                        and len(calls) == (1 if phase == "probe" else 6))
            _need((status == ("probe_completed" if phase == "probe" else "completed")) is stage_ok,
                  "SPLIT_FALSE_STAGE_SUCCESS")
            _need(stage_ok or campaign["state"] in {"quarantined", "stopped_budget"}, "SPLIT_FAILURE_NOT_FENCED")
            checks.append({"rule": "independent_campaign_trials_and_stage_call_caps", "passed": True})
        for key in ("total_calls", "stage_calls", "known_cost_nano_usd", "held_cost_nano_usd", "real_api_requests"):
            _need(type(receipt.get(key)) is int and receipt[key] == counts[key], "SPLIT_RECEIPT_TOTALS")
        _need(counts["known_cost_nano_usd"] + counts["held_cost_nano_usd"] <= config["max_cost_nano_usd"], "SPLIT_MONEY_CAP")
        if not pending:
            _need(receipt["gate_passed"] is stage_ok
                  and receipt["ready_for_handoff"] is (stage_ok and phase == "probe")
                  and receipt["successful"] is (stage_ok and phase == "normal"), "SPLIT_FINAL_SUCCESS_CLAIM")
        result.update(status="passed", passed=True, candidate_status=status,
            pending_readiness=pending, ready_for_stage=stage_ok,
            ready_for_handoff=stage_ok and phase == "probe", ready_for_success=stage_ok and phase == "normal",
            stage_successful=stage_ok and not pending, successful=stage_ok and phase == "normal" and not pending)
        if not pending:
            _proof(root, phase, receipt, result, stage_ok=stage_ok)
            checks.append({"rule": "final_stage_proof_link", "passed": True})
        return result
    except Exception as exc:
        result.update(status="failed", passed=False, ready_for_stage=False, ready_for_handoff=False,
                      ready_for_success=False, stage_successful=False, successful=False,
                      findings=[getattr(exc, "code", str(exc))])
        return result


def build_probe_handoff(root, *, forbidden_secrets=()):
    """Return a seal manifest from finalized probe artifacts; never write it."""
    root = Path(root).resolve()
    result = audit_split_stage(root, "probe", forbidden_secrets=forbidden_secrets)
    _need(result["status"] == "passed" and result["ready_for_handoff"] is True
          and result["stage_successful"] is True and result["successful"] is False, "SPLIT_HANDOFF_PROBE_NOT_READY")
    config = _read(root / "config.json")
    receipt = _read(root / "probe_stage" / "receipt.json")
    projection, artifacts = _projection(root), _artifact_tree(root)
    return dict(schema_version="p3-probe-handoff-v1", config_digest=_hash(config),
        binding_digest=_hash(config["binding"]), campaign_id=config["campaign_id"], output_root=str(root),
        probe_stage_id=receipt["stage_id"], probe_grant_digest=receipt["grant_digest"],
        probe_receipt_digest=_hash(receipt), probe_proof_digest=receipt["independent_check_digest"],
        probe_ledger_projection=projection, probe_ledger_digest=_hash(projection),
        probe_artifacts=artifacts, probe_artifact_tree_digest=_hash(artifacts),
        source_campaign_sha256=hashlib.sha256((root / "campaign.sqlite").read_bytes()).hexdigest())


def validate_probe_handoff(root, expected_digest, *, for_continuation=True, forbidden_secrets=()):
    """Return the verified manifest or raise; a seal never grants execution.

    Continuation checks the complete one-call active source before any normal
    stage exists. Post-normal audits check immutable probe rows/artifacts,
    allowing the same ledger to contain the five authorized appended calls.
    """
    root = Path(root).resolve()
    _need(type(for_continuation) is bool and isinstance(expected_digest, str)
          and _HEX.fullmatch(expected_digest), "SPLIT_HANDOFF_ARGUMENTS")
    seal = _read(root / "handoff.json")
    _secrets(seal, forbidden_secrets)
    _need(set(seal) == _HANDOFF_FIELDS and seal["schema_version"] == "p3-probe-handoff-v1"
          and _hash(seal) == expected_digest
          and isinstance(seal["source_campaign_sha256"], str) and _HEX.fullmatch(seal["source_campaign_sha256"]),
          "SPLIT_HANDOFF_DIGEST")
    config = _read(root / "config.json")
    grant = _read(root / "probe_stage" / "grant.json")
    receipt = _read(root / "probe_stage" / "receipt.json")
    proof = _read(root / "probe_stage" / "independent_check.json")
    _inputs(root, "probe", config, grant, receipt)
    _need(receipt["status"] == "probe_completed" and receipt["gate_passed"] is True
          and receipt["ready_for_handoff"] is True and receipt["successful"] is False
          and receipt["normal_started"] is False and seal["config_digest"] == _hash(config)
          and seal["binding_digest"] == _hash(config["binding"])
          and seal["campaign_id"] == config["campaign_id"] and seal["output_root"] == str(root)
          and seal["probe_stage_id"] == receipt["stage_id"] and seal["probe_grant_digest"] == _hash(grant)
          and seal["probe_receipt_digest"] == _hash(receipt)
          and seal["probe_proof_digest"] == receipt["independent_check_digest"] == _hash(proof), "SPLIT_HANDOFF_SOURCE_BINDING")
    projection, artifacts = _projection(root), _artifact_tree(root)
    source_call = _json(projection["calls"][0]["body"])
    source_counts = dict(total_calls=1, stage_calls=1, calls_dispatched=int(source_call["dispatched"]),
        known_cost_nano_usd=source_call["known_cost_nano_usd"], held_cost_nano_usd=source_call["held_cost_nano_usd"],
        real_api_requests=0 if receipt["simulated"] else int(source_call["dispatched"]), trials=1)
    _need(source_call["status"] == "settled" and source_call["evidence"]["outcome"]["status"] == "success"
          and all(type(receipt.get(k)) is int and receipt[k] == source_counts[k] for k in
                  ("total_calls", "stage_calls", "known_cost_nano_usd", "held_cost_nano_usd", "real_api_requests")),
          "SPLIT_HANDOFF_SOURCE_TOTALS")
    proof_result = {k: receipt[k] for k in ("phase", "stage_id", "config_digest", "grant_digest", "binding_digest", "campaign_id")}
    proof_result["counts"] = source_counts
    _proof(root, "probe", receipt, proof_result, stage_ok=True)
    _need(_same(seal["probe_ledger_projection"], projection) and seal["probe_ledger_digest"] == _hash(projection), "SPLIT_HANDOFF_PROBE_LEDGER_CHANGED")
    _need(_same(seal["probe_artifacts"], artifacts) and seal["probe_artifact_tree_digest"] == _hash(artifacts), "SPLIT_HANDOFF_PROBE_ARTIFACT_CHANGED")
    campaign, calls, _, entries, conflicts, restarts = _rows(root)
    _need(not conflicts and not restarts, "SPLIT_HANDOFF_HISTORY")
    if for_continuation:
        _need(not (root / "normal").exists() and not (root / "normal_stage").exists()
              and len(calls) == 1 and len(entries) == 1 and campaign["state"] == "active"
              and _json(calls[0]["body"])["status"] == "settled"
              and _json(calls[0]["body"])["evidence"]["outcome"]["status"] == "success"
              and seal["source_campaign_sha256"] == hashlib.sha256((root / "campaign.sqlite").read_bytes()).hexdigest(),
              "SPLIT_HANDOFF_CONTINUATION_STATE")
        audit = audit_split_stage(root, "probe", forbidden_secrets=forbidden_secrets)
        _need(audit["status"] == "passed" and audit["ready_for_handoff"] is True, "SPLIT_HANDOFF_PROBE_REAUDIT")
    else:
        _need(audit_p3_campaign(root / "campaign.sqlite", forbidden_secrets=forbidden_secrets).get("status") == "passed"
              and audit_offline_trial(root / "probe", root / "campaign.sqlite").get("status") == "passed",
              "SPLIT_HANDOFF_SOURCE_REAUDIT")
    return seal


def validate_open_campaign_handoff(connection, handoff):
    """Check the actual opened continuation connection before credential input.

    Only SELECT statements are issued; the runtime's connection options and
    transaction state are untouched. This complements the earlier path-based
    preflight if the campaign path changes between validation and opening it.
    """
    def rows(sql):
        cursor = connection.execute(sql)
        names = [column[0] for column in cursor.description]
        return [dict(zip(names, tuple(row))) for row in cursor.fetchall()]

    campaigns = rows("SELECT config,state,reason FROM p3_campaign WHERE singleton=1")
    calls = rows("SELECT * FROM p3_calls ORDER BY rowid")
    receipts = rows("SELECT * FROM p3_receipts ORDER BY rowid")
    entries = rows("SELECT * FROM p3_dev_entries ORDER BY rowid")
    conflicts = rows("SELECT * FROM p3_conflicts ORDER BY rowid")
    restarts = rows("SELECT * FROM p3_restarts ORDER BY rowid")
    _need(len(campaigns) == 1 and campaigns[0]["state"] == "active" and len(calls) == 1
          and len(entries) == 1 and entries[0]["cell_key"] == "probe" and not conflicts and not restarts,
          "SPLIT_OPEN_CAMPAIGN_STATE")
    call = _json(calls[0]["body"])
    entry = _json(entries[0]["body"])
    _need(call["status"] == "settled" and call["dispatched"] is True
          and call["held_cost_nano_usd"] == 0 and call["evidence"]["outcome"]["status"] == "success"
          and entry["gate_passed"] is True and entry["status"] == "completed"
          and entry["trial_key"] == call["trial_key"], "SPLIT_OPEN_CAMPAIGN_PROBE")
    projection = dict(campaign_config=campaigns[0]["config"], calls=calls, receipts=receipts, entries=entries)
    _need(_same(handoff["probe_ledger_projection"], projection)
          and handoff["probe_ledger_digest"] == _hash(projection), "SPLIT_OPEN_CAMPAIGN_PROJECTION")
