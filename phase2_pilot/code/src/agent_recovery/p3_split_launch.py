"""Separately granted probe and five-step continuation over one P3 ledger.

There is no automatic transition, credential persistence, retry or campaign
reset. Importing this module or validating its CLI does not read a credential.
"""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import sqlite3
import sys

from .contracts import ContractError, canonical_json, digest, new_id, require, utc_now
from .p3_budget import DurableP3Budget
from .p3_launch import _SafeArgumentParser, _load_json, _write, read_hidden_api_key
from .p3_launch_config import LaunchConfig, parse_launch_config, resolve_token_counter
from .p3_live import (DevelopmentEntryPermit, FixtureEntryPermit,
    run_authorized_dev_trial, run_authorized_probe,
    run_fixture_authorized_dev_trial, run_fixture_authorized_probe)
from .p3_split_config import SplitStageGrant, parse_split_stage_grant
from .p3_transport import LiveRuntimePermit


SCHEMA = "p3-split-stage-receipt-v1"
_SAFE_CODES = frozenset({"P3_SPLIT_DISABLED", "P3_SPLIT_CONFIG_INVALID",
    "P3_SPLIT_GRANT_INVALID", "P3_SPLIT_GRANT_MISMATCH", "P3_SPLIT_ALREADY_STARTED",
    "P3_SPLIT_PATH_INVALID", "P3_SPLIT_HANDOFF_INVALID", "P3_SPLIT_LEDGER_INVALID",
    "P3_SPLIT_CLIENT_ERROR", "P3_TOKEN_COUNTER_REQUIRED", "P3_LAUNCH_DISABLED",
    "P3_LAUNCH_CONFIG_INVALID", "P3_LAUNCH_CONFIG_INCOMPLETE"})


def _phase_path(config, phase):
    return config.output_root / (phase + "_stage")


def _checks(config, grant, phase, *, fixture, execute, token_counter,
            counter_implementation_ref, counter_ref, client_factory):
    require(type(execute) is bool and execute, "Explicit split-stage execution is required",
            "P3_SPLIT_DISABLED")
    require(type(config) is LaunchConfig and type(grant) is SplitStageGrant,
            "A parsed configuration and separate stage grant are required", "P3_SPLIT_CONFIG_INVALID")
    config.validate_ready(fixture=fixture)
    require(config.call_cap == 6 and config.limits["slot_call_cap"] == 5
            and config.limits["logical_call_cap"] == 5,
            "Split execution requires the original six-call first-stage scope", "P3_SPLIT_CONFIG_INVALID")
    # Pure grant checks precede any file access. For normal, the independent
    # continuation audit below subsequently checks this digest against disk.
    grant.validate(config, phase=phase, fixture=fixture,
                   handoff_digest=grant.handoff_digest if phase == "normal" else None)
    if fixture:
        require(token_counter is None and counter_implementation_ref is None and counter_ref is None,
                "Fixture execution cannot receive a live counter", "P3_SPLIT_CONFIG_INVALID")
    else:
        resolve_token_counter(config, token_counter,
            implementation_ref=counter_implementation_ref, counter_ref=counter_ref)
    require(client_factory is None or callable(client_factory),
            "An injected client factory must be callable", "P3_SPLIT_CLIENT_ERROR")
    root = config.output_root
    require(not root.is_symlink() and not any(p.is_symlink() for p in root.parents),
            "Split execution cannot traverse symlinks", "P3_SPLIT_PATH_INVALID")
    phase_dir = _phase_path(config, phase)
    require(not phase_dir.exists() and not phase_dir.is_symlink(),
            "This stage is already consumed; interrupted execution cannot resume",
            "P3_SPLIT_ALREADY_STARTED")
    if phase == "probe":
        require(not root.exists(), "The probe root is already consumed", "P3_SPLIT_ALREADY_STARTED")
    else:
        return _normal_preflight(config, grant)


def _normal_preflight(config, grant):
    """Read-only validation, before mkdir, Budget construction or key access."""
    root = config.output_root
    require(root.is_dir() and config.ledger_path.is_file() and not config.ledger_path.is_symlink(),
            "The original campaign ledger is required", "P3_SPLIT_LEDGER_INVALID")
    try:
        require(_load_json(root / "config.json") == config.to_dict(),
                "The original campaign configuration differs", "P3_SPLIT_HANDOFF_INVALID")
        require(_load_json(root / "probe_stage" / "grant.json").get("grant_id") != grant.grant_id,
                "The continuation requires a separate grant identity", "P3_SPLIT_GRANT_MISMATCH")
        from .p3_split_checker import validate_probe_handoff
        handoff = validate_probe_handoff(root, grant.handoff_digest, for_continuation=True)
        actual_digest = digest(handoff)
        grant.validate(config, phase="normal", fixture=config.fixture, handoff_digest=actual_digest)
        return handoff
    except BaseException:
        raise ContractError("P3_SPLIT_HANDOFF_INVALID",
                            "The saved probe handoff did not pass read-only verification") from None


def _open_existing_campaign(config, handoff):
    """Open mode=rw; the creating DurableP3Budget constructor is never called.

    A missing, empty, reset, paused or replaced ledger cannot become a fresh
    budget even if its path changes after the read-only preflight.
    """
    require(config.ledger_path.is_file() and not config.ledger_path.is_symlink(),
            "The original campaign ledger is missing", "P3_SPLIT_LEDGER_INVALID")
    campaign = DurableP3Budget.__new__(DurableP3Budget)
    campaign.binding = deepcopy(config.binding.to_dict())
    campaign.config = {"schema_version": "p3-budget-v1", "campaign_id": config.campaign_id,
        "binding": campaign.binding, "binding_digest": config.binding.binding_digest,
        "limits": dict(config.limits)}
    campaign.path = config.ledger_path.resolve()
    campaign.ref = str(campaign.path)
    campaign._failed = False
    connection = None
    try:
        connection = sqlite3.connect(campaign.path.as_uri() + "?mode=rw", uri=True,
                                     isolation_level=None)
        campaign.connection = connection
        connection.row_factory = sqlite3.Row
        require(connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok",
                "The existing campaign ledger is invalid", "P3_SPLIT_LEDGER_INVALID")
        row = connection.execute("SELECT config,state FROM p3_campaign WHERE singleton=1").fetchone()
        require(row is not None and row["config"] == canonical_json(campaign.config)
                and row["state"] == "active", "The original active campaign is required",
                "P3_SPLIT_LEDGER_INVALID")
        calls = campaign.calls()
        require(len(calls) == 1 and calls[0]["status"] == "settled"
                and connection.execute("SELECT COUNT(*) FROM p3_restarts").fetchone()[0] == 0,
                "Continuation requires exactly one settled probe and no restart history",
                "P3_SPLIT_LEDGER_INVALID")
        entries = connection.execute("SELECT cell_key,body FROM p3_dev_entries").fetchall()
        require(len(entries) == 1 and entries[0]["cell_key"] == "probe"
                and json.loads(entries[0]["body"]).get("gate_passed") is True,
                "The saved probe entry is not an eligible predecessor", "P3_SPLIT_LEDGER_INVALID")
        from .p3_split_checker import validate_open_campaign_handoff
        validate_open_campaign_handoff(connection, handoff)
        connection.execute("PRAGMA synchronous=FULL")
        return campaign
    except BaseException:
        if connection is not None:
            connection.close()
        raise ContractError("P3_SPLIT_LEDGER_INVALID",
                            "The original campaign ledger could not be reopened safely") from None


def _receipt(config, grant, phase, *, fixture):
    return dict(schema_version=SCHEMA, stage_id=new_id(), phase=phase,
        simulated=fixture, execution_kind=("offline_split_stage_fixture" if fixture
                                          else "authorized_split_stage_live"),
        config_digest=config.config_digest, grant_digest=digest(grant.to_dict()),
        grant_id=grant.grant_id, binding_digest=config.binding.binding_digest,
        campaign_id=config.campaign_id, campaign_db=str(config.ledger_path),
        limits=dict(config.limits), stage_call_cap=grant.stage_call_cap,
        cumulative_call_cap=grant.cumulative_call_cap, handoff_digest=grant.handoff_digest,
        total_calls=0 if phase == "probe" else 1, stage_calls=0,
        known_cost_nano_usd=0, held_cost_nano_usd=0, real_api_requests=0,
        status="admitted", operation="admission", gate_passed=False,
        normal_started=False, ready_for_handoff=False, successful=False,
        independent_check_digest=None, started_at=utc_now(), finished_at=None, error_code=None)


def _write_once(path, value):
    """A handoff is a new, durable immutable artifact, never replaced in place."""
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def _run(config, grant, phase, *, fixture, execute, token_counter=None,
         counter_implementation_ref=None, counter_ref=None, key_reader=None,
         tty_check=None, client_factory=None):
    handoff = _checks(config, grant, phase, fixture=fixture, execute=execute, token_counter=token_counter,
        counter_implementation_ref=counter_implementation_ref, counter_ref=counter_ref,
        client_factory=client_factory)
    require(not fixture or (key_reader is None and tty_check is None),
            "Fixture execution cannot receive a key reader", "P3_SPLIT_CONFIG_INVALID")
    root, phase_dir = config.output_root, _phase_path(config, phase)
    try:
        if phase == "probe":
            root.mkdir(parents=True, exist_ok=False, mode=0o700)
        phase_dir.mkdir(exist_ok=False, mode=0o700)
    except FileExistsError:
        raise ContractError("P3_SPLIT_ALREADY_STARTED", "This split stage is already consumed") from None
    receipt = _receipt(config, grant, phase, fixture=fixture)
    secret, campaign = [], None
    candidate = "error"
    baseline = 0 if phase == "probe" else 1

    def provider():
        require(len(secret) == 1, "The in-memory credential is unavailable",
                "P3_LAUNCH_CREDENTIAL_ERROR")
        return secret[0]

    def totals():
        if campaign is not None:
            snapshot = campaign.snapshot()
            receipt.update(total_calls=snapshot["budget"]["calls_reserved_or_spent"],
                stage_calls=snapshot["budget"]["calls_reserved_or_spent"] - baseline,
                known_cost_nano_usd=snapshot["budget"]["known_cost_nano_usd"],
                held_cost_nano_usd=snapshot["budget"]["held_cost_nano_usd"],
                real_api_requests=snapshot["real_api_requests"])

    def fence(code):
        receipt.update(status="error", gate_passed=False, ready_for_handoff=False,
                       successful=False, error_code=code, finished_at=utc_now())
        if campaign is not None:
            try:
                campaign.quarantine(None, code)
            except BaseException:
                pass
        try:
            totals()
            _write(phase_dir / "receipt.json", receipt)
        except BaseException:
            pass

    try:
        if phase == "probe":
            _write_once(root / "config.json", config.to_dict())
        _write(phase_dir / "grant.json", grant.to_dict())
        _write(phase_dir / "receipt.json", receipt)
        receipt["operation"] = "campaign_open"
        _write(phase_dir / "receipt.json", receipt)
        campaign = (DurableP3Budget(config.ledger_path, campaign_id=config.campaign_id,
                    binding=config.binding.to_dict(), limits=config.limits)
                    if phase == "probe" else _open_existing_campaign(config, handoff))
        totals()
        if not fixture:
            receipt["operation"] = "credential_input"
            _write(phase_dir / "receipt.json", receipt)
            secret.append(read_hidden_api_key(reader=key_reader, tty_check=tty_check))
        permit_class = FixtureEntryPermit if fixture else DevelopmentEntryPermit
        permit = permit_class(True, config.binding.binding_digest, config.campaign_id,
            campaign.ref, stage="first_stage", call_cap=grant.cumulative_call_cap,
            authorization_reference=grant.grant_id)
        dependencies = dict(entry_permit=permit, client_factory=client_factory)
        if not fixture:
            dependencies.update(runtime_permit=LiveRuntimePermit(True,
                config.binding.binding_digest, grant.grant_id), token_counter=token_counter,
                credential_provider=provider)
        receipt["operation"] = "probe" if phase == "probe" else "five_step_task"
        receipt["normal_started"] = phase == "normal"
        _write(phase_dir / "receipt.json", receipt)
        if phase == "probe":
            runner = run_fixture_authorized_probe if fixture else run_authorized_probe
            result = runner(root / "probe", campaign, config.binding, **dependencies)
            candidate = "probe_completed" if result["entry_receipt"]["gate_passed"] is True else "probe_failed"
        else:
            runner = run_fixture_authorized_dev_trial if fixture else run_authorized_dev_trial
            result = runner(root / "normal", campaign, config.binding,
                task_id="p1-dev-01", condition="CLEAN", policy="BASE", restart=False, **dependencies)
            candidate = "completed" if result["entry_receipt"]["gate_passed"] is True else "normal_failed"
    except BaseException:
        receipt["error_code"] = "P3_SPLIT_EXECUTION_FAILED"
        if campaign is not None:
            try:
                campaign.quarantine(None, "P3_SPLIT_EXECUTION_FAILED")
            except BaseException:
                pass
    finally:
        secret.clear()
    try:
        totals()
        receipt.update(status="pending_finalization", candidate_status=candidate,
                       operation="independent_finalization", finished_at=utc_now())
        _write(phase_dir / "receipt.json", receipt)
        from .p3_split_checker import audit_split_stage, build_probe_handoff
        independent = audit_split_stage(root, phase, allow_pending=True)
        success = candidate == ("probe_completed" if phase == "probe" else "completed")
        require(independent.get("status") == "passed"
                and (independent.get("ready_for_stage") is True) is success,
                "Independent stage readiness disagrees with the outcome",
                "P3_SPLIT_INDEPENDENT_CHECK_FAILED")
        _write(phase_dir / "independent_check.json", independent)
        receipt.update(independent_check_digest=digest(independent), status=candidate,
            operation="stopped", gate_passed=success,
            ready_for_handoff=success and phase == "probe", successful=success and phase == "normal")
        _write(phase_dir / "receipt.json", receipt)
        if success and phase == "probe":
            _write_once(root / "handoff.json", build_probe_handoff(root))
    except BaseException:
        fence("P3_SPLIT_FINALIZATION_FAILED")
    finally:
        if campaign is not None:
            campaign.close()
    return receipt


def run_probe_only(config, grant, *, execute=False, token_counter=None,
        counter_implementation_ref=None, counter_ref=None, key_reader=None,
        tty_check=None, client_factory=None):
    return _run(config, grant, "probe", fixture=False, execute=execute,
        token_counter=token_counter, counter_implementation_ref=counter_implementation_ref,
        counter_ref=counter_ref, key_reader=key_reader, tty_check=tty_check,
        client_factory=client_factory)


def run_five_step_handoff(config, grant, *, execute=False, token_counter=None,
        counter_implementation_ref=None, counter_ref=None, key_reader=None,
        tty_check=None, client_factory=None):
    return _run(config, grant, "normal", fixture=False, execute=execute,
        token_counter=token_counter, counter_implementation_ref=counter_implementation_ref,
        counter_ref=counter_ref, key_reader=key_reader, tty_check=tty_check,
        client_factory=client_factory)


def run_fixture_probe_only(config, grant, *, execute=False, client_factory=None):
    return _run(config, grant, "probe", fixture=True, execute=execute, client_factory=client_factory)


def run_fixture_five_step_handoff(config, grant, *, execute=False, client_factory=None):
    return _run(config, grant, "normal", fixture=True, execute=execute, client_factory=client_factory)


def main(argv=None, *, token_counter=None, counter_implementation_ref=None,
         counter_ref=None, key_reader=None, tty_check=None):
    parser = _SafeArgumentParser(description="Validate a separately granted P3 stage")
    parser.add_argument("--config", required=True)
    parser.add_argument("--phase", choices=("probe", "normal"), required=True)
    parser.add_argument("--grant")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    try:
        config = parse_launch_config(_load_json(args.config))
        grant = parse_split_stage_grant(_load_json(args.grant)) if args.grant else None
        if not args.execute:
            if grant is not None:
                grant.validate(config, phase=args.phase, fixture=False,
                    handoff_digest=grant.handoff_digest if args.phase == "normal" else None)
            print(json.dumps({"status": "configuration_valid", "execution_requested": False,
                "phase": args.phase, "config_digest": config.config_digest,
                "call_cap": 1 if args.phase == "probe" else 5,
                "cumulative_call_cap": 1 if args.phase == "probe" else 6}, sort_keys=True))
            return 0
        require(grant is not None, "An independent stage grant is required", "P3_SPLIT_DISABLED")
        runner = run_probe_only if args.phase == "probe" else run_five_step_handoff
        result = runner(config, grant, execute=True, token_counter=token_counter,
            counter_implementation_ref=counter_implementation_ref, counter_ref=counter_ref,
            key_reader=key_reader, tty_check=tty_check)
        print(json.dumps({"status": result["status"], "gate_passed": result["gate_passed"],
            "phase": result["phase"], "successful": result["successful"]}, sort_keys=True))
        return 0 if result["gate_passed"] else 1
    except BaseException as exc:
        code = (exc.code if isinstance(exc, ContractError) and type(exc.code) is str
                and exc.code in _SAFE_CODES else "P3_SPLIT_FAILED")
        print("Split launch stopped [" + code + "]; inspect configuration and stage receipts.", file=sys.stderr)
        return 1
