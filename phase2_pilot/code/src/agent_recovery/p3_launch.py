"""First-stage launch orchestration; imports and validation never obtain a key.

Only the two frozen first-stage cells are reachable here. A launch consumes its
output root before requesting a credential, so failed and interrupted launches
cannot quietly be resumed under the same grant. Counter implementations are
ordinary explicitly injected Python objects, never names imported from JSON.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import sys
import warnings

from .contracts import ContractError, digest, new_id, require, utc_now
from .p3_budget import DurableP3Budget
from .p3_launch_config import (LaunchConfig, LaunchGrant, parse_launch_config,
                               parse_launch_grant, resolve_token_counter)
from .p3_live import (DevelopmentEntryPermit, FixtureEntryPermit,
                      run_authorized_dev_trial, run_authorized_probe,
                      run_fixture_authorized_dev_trial,
                      run_fixture_authorized_probe)
from .p3_transport import LiveRuntimePermit


_CLI_ERROR_CODES = frozenset({
    "P3_LAUNCH_CONFIG_INVALID", "P3_LAUNCH_CONFIG_INCOMPLETE",
    "P3_LAUNCH_DISABLED", "P3_LAUNCH_GRANT_MISMATCH",
    "P3_TOKEN_COUNTER_REQUIRED", "P3_LAUNCH_LIMIT_ERROR",
    "P3_LAUNCH_BUDGET_INSUFFICIENT", "P3_LAUNCH_ALREADY_STARTED",
    "P3_LAUNCH_PATH_INVALID", "P3_LAUNCH_MODE_MISMATCH",
    "P3_LAUNCH_CLIENT_ERROR", "P3_LAUNCH_CREDENTIAL_ERROR",
})


def _interactive_terminal():
    return bool(sys.stdin.isatty() and sys.stderr.isatty())


def read_hidden_api_key(*, reader=None, tty_check=None):
    """Read once from an actual terminal; refuse getpass's echoing fallback.

    Tests supply both callables. No environment, key file, stdin.read, keychain,
    command argument or default credential source is consulted.
    """
    check = _interactive_terminal if tty_check is None else tty_check
    prompt_reader = getpass.getpass if reader is None else reader
    try:
        require(callable(check) and check() is True,
                "Hidden key input requires the user's interactive terminal",
                "P3_LAUNCH_TTY_REQUIRED")
        require(callable(prompt_reader), "A hidden key reader is required",
                "P3_LAUNCH_CREDENTIAL_ERROR")
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            value = prompt_reader("TritonAI API key (hidden): ")
        require(type(value) is str and 0 < len(value) <= 4096
                and all(33 <= ord(char) <= 126 for char in value),
                "Hidden key input was empty or invalid",
                "P3_LAUNCH_CREDENTIAL_ERROR")
        return value
    except BaseException:
        # A reader exception or warning may itself contain the credential.
        raise ContractError("P3_LAUNCH_CREDENTIAL_ERROR",
                            "Hidden key input failed; no credential was saved") from None


def _write(path, value):
    temporary = path.with_name("." + path.name + ".tmp")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2,
                      allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        # A failed temporary write must not prevent the safe failure receipt
        # from replacing an earlier non-terminal receipt on the next attempt.
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _configuration_checks(config, grant, *, fixture, execute, token_counter=None,
                          counter_implementation_ref=None, counter_ref=None):
    require(type(execute) is bool and execute,
            "Execution needs an explicit launch action", "P3_LAUNCH_DISABLED")
    require(type(config) is LaunchConfig and type(grant) is LaunchGrant,
            "A parsed launch configuration and independent grant are required",
            "P3_LAUNCH_CONFIG_INVALID")
    config.validate_ready(fixture=fixture)
    grant.validate(config, fixture=fixture)
    maxima = {
        "call_cap": 6, "input_token_cap": 24_000,
        "output_token_cap": 4_608, "max_cost_nano_usd": 1_000_000_000,
        "slot_call_cap": 5, "logical_call_cap": 5}
    require(config.call_cap == 6 and set(config.limits) == set(maxima)
            and all(type(config.limits[key]) is int
                    and 0 < config.limits[key] <= cap for key, cap in maxima.items())
            and config.limits["slot_call_cap"] == 5
            and config.limits["logical_call_cap"] == 5,
        "First-stage budget limits differ from the frozen scope",
        "P3_LAUNCH_LIMIT_ERROR")
    require(6 * config.binding.worst_case_cost_nano_usd
            <= config.limits["max_cost_nano_usd"],
            "Six worst-case calls do not fit the first-stage budget",
            "P3_LAUNCH_LIMIT_ERROR")
    if fixture:
        require(token_counter is None and counter_implementation_ref is None
                and counter_ref is None,
                "Fixture launch cannot receive a live tokenizer dependency",
                "P3_LAUNCH_MODE_MISMATCH")
    else:
        resolve_token_counter(config, token_counter,
            implementation_ref=counter_implementation_ref, counter_ref=counter_ref)
    # A root itself is a durable consumed-launch marker, including a failed
    # credential prompt. Never open or repair an existing campaign here.
    require(not config.output_root.exists() and not config.output_root.is_symlink(),
            "The launch destination is already consumed; no retry is authorized",
            "P3_LAUNCH_ALREADY_STARTED")
    require(not any(parent.is_symlink() for parent in config.output_root.parents),
            "A launch destination cannot traverse a symlink",
            "P3_LAUNCH_PATH_INVALID")
    return config


def _receipt(config, grant, *, fixture):
    root = config.output_root
    return dict(schema_version="p3-first-stage-launch-v1", launch_id=new_id(),
        execution_kind="offline_first_stage_fixture" if fixture else "authorized_first_stage_live",
        simulated=fixture, config_digest=config.config_digest,
        grant_digest=digest(grant.to_dict()), grant_id=grant.grant_id,
        binding_digest=config.binding.binding_digest, campaign_id=config.campaign_id,
        campaign_db=str(config.ledger_path), probe_dir=str(root / "probe"),
        normal_dir=str(root / "normal"), status="admitted", phase="admission",
        limits=dict(config.limits), total_calls=0, known_cost_nano_usd=0,
        held_cost_nano_usd=0, real_api_requests=0, started_at=utc_now(),
        finished_at=None, gate_passed=False, normal_started=False, error_code=None)


def _launch(config, grant, *, fixture, execute, token_counter=None,
            counter_implementation_ref=None, counter_ref=None, key_reader=None,
            tty_check=None, client_factory=None):
    _configuration_checks(config, grant, fixture=fixture, execute=execute,
        token_counter=token_counter, counter_implementation_ref=counter_implementation_ref,
        counter_ref=counter_ref)
    require(client_factory is None or callable(client_factory),
            "A test client factory must be callable", "P3_LAUNCH_CLIENT_ERROR")
    require(not fixture or (key_reader is None and tty_check is None),
            "Fixture launch has no credential input", "P3_LAUNCH_MODE_MISMATCH")
    root = config.output_root
    # mkdir(exist_ok=False) is the concurrency claim. A losing process never
    # reads a key; the launch never changes or deletes a pre-existing root.
    try:
        root.mkdir(parents=True, exist_ok=False, mode=0o700)
    except FileExistsError:
        raise ContractError("P3_LAUNCH_ALREADY_STARTED",
                            "The launch destination is already consumed") from None
    receipt = _receipt(config, grant, fixture=fixture)
    _write(root / "launch_config.json", config.to_dict())
    _write(root / "launch_grant.json", grant.to_dict())
    _write(root / "launch_receipt.json", receipt)
    secret = []
    campaign = None
    candidate_status = "error"

    def credential_provider():
        require(len(secret) == 1, "The in-memory credential is unavailable",
                "P3_LAUNCH_CREDENTIAL_ERROR")
        return secret[0]

    def refresh_totals():
        if campaign is not None:
            snapshot = campaign.snapshot()
            receipt.update(total_calls=snapshot["budget"]["calls_reserved_or_spent"],
                known_cost_nano_usd=snapshot["budget"]["known_cost_nano_usd"],
                held_cost_nano_usd=snapshot["budget"]["held_cost_nano_usd"],
                real_api_requests=snapshot["real_api_requests"])

    def fence_finalization(code):
        # Keep the SQL connection open through every publication attempt.
        # If disk failure prevents a failure receipt, the already-persisted
        # pending receipt still cannot claim a completed launch.
        receipt.update(status="error", gate_passed=False, error_code=code)
        if campaign is not None:
            try:
                campaign.quarantine(None, code)
            except BaseException:
                pass
        try:
            refresh_totals()
        except BaseException:
            pass
        receipt["finished_at"] = utc_now()
        try:
            _write(root / "launch_receipt.json", receipt)
        except BaseException:
            # A persistent disk error leaves the prior pending receipt and
            # consumed root intact. This return value is never successful.
            pass

    try:
        if not fixture:
            receipt["phase"] = "credential_input"
            _write(root / "launch_receipt.json", receipt)
            secret.append(read_hidden_api_key(reader=key_reader, tty_check=tty_check))
        receipt["phase"] = "campaign_creation"
        campaign = DurableP3Budget(config.ledger_path, campaign_id=config.campaign_id,
                                  binding=config.binding.to_dict(), limits=config.limits)
        permit_type = FixtureEntryPermit if fixture else DevelopmentEntryPermit
        permit = permit_type(True, config.binding.binding_digest, config.campaign_id,
            campaign.ref, stage="first_stage", call_cap=6,
            authorization_reference=grant.grant_id)
        dependencies = dict(entry_permit=permit, client_factory=client_factory)
        if not fixture:
            dependencies.update(runtime_permit=LiveRuntimePermit(
                True, config.binding.binding_digest, grant.grant_id),
                token_counter=token_counter, credential_provider=credential_provider)
        receipt["phase"] = "probe"
        _write(root / "launch_receipt.json", receipt)
        probe_runner = run_fixture_authorized_probe if fixture else run_authorized_probe
        probe = probe_runner(root / "probe", campaign, config.binding, **dependencies)
        if probe["entry_receipt"]["gate_passed"] is not True:
            candidate_status = "probe_failed"
        else:
            receipt.update(phase="normal", normal_started=True)
            _write(root / "launch_receipt.json", receipt)
            normal_runner = run_fixture_authorized_dev_trial if fixture else run_authorized_dev_trial
            normal = normal_runner(root / "normal", campaign, config.binding,
                task_id="p1-dev-01", condition="CLEAN", policy="BASE",
                restart=False, **dependencies)
            complete = normal["entry_receipt"]["gate_passed"] is True
            candidate_status = "completed" if complete else "normal_failed"
    except BaseException:
        # Counter, reader and client implementations can raise arbitrary text.
        # Preserve evidence and a fixed code, never that text or a traceback.
        candidate_status = "error"
        receipt.update(gate_passed=False, error_code="P3_LAUNCH_EXECUTION_FAILED")
        if campaign is not None:
            try:
                campaign.quarantine(None, "P3_LAUNCH_EXECUTION_FAILED")
            except BaseException:
                pass
    finally:
        secret.clear()
    try:
        refresh_totals()
        receipt.update(status="pending_finalization", gate_passed=False,
                       candidate_status=candidate_status, finished_at=utc_now())
        _write(root / "launch_receipt.json", receipt)
        from .p3_launch_checker import audit_first_stage_launch
        independent = audit_first_stage_launch(root, allow_pending=True)
        if independent.get("status") != "passed":
            receipt["independent_check"] = independent
            fence_finalization("P3_LAUNCH_INDEPENDENT_CHECK_FAILED")
        else:
            require((independent.get("ready_for_success") is True)
                    is (candidate_status == "completed"),
                    "Independent readiness differs from the workflow outcome",
                    "P3_LAUNCH_INDEPENDENT_CHECK_FAILED")
            # Publish the non-success readiness proof first. Only its durable
            # digest-bound presence permits the final atomic success receipt.
            _write(root / "independent_check.json", independent)
            receipt.update(independent_check=independent,
                           independent_check_digest=digest(independent),
                           status=candidate_status,
                           gate_passed=candidate_status == "completed")
            _write(root / "launch_receipt.json", receipt)
    except BaseException:
        fence_finalization("P3_LAUNCH_FINALIZATION_FAILED")
    finally:
        if campaign is not None:
            campaign.close()
    return receipt


def run_first_stage(config, grant, *, execute=False, token_counter=None,
                    counter_implementation_ref=None, counter_ref=None,
                    key_reader=None, tty_check=None, client_factory=None):
    """Run only a separately granted probe and clean task, then stop.

    Real execution is not enabled by loading JSON or importing this function.
    A reviewed Python wrapper must inject the verified counter implementation.
    Reader/factory parameters exist for offline dependency spies in tests.
    """
    return _launch(config, grant, fixture=False, execute=execute,
        token_counter=token_counter, counter_implementation_ref=counter_implementation_ref,
        counter_ref=counter_ref, key_reader=key_reader, tty_check=tty_check,
        client_factory=client_factory)


def run_fixture_first_stage(config, grant, *, execute=False, client_factory=None):
    """Exercise the same two-cell launch with bounded HTTP fixtures, no key."""
    return _launch(config, grant, fixture=True, execute=execute,
                   client_factory=client_factory)


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's original message can echo an accidentally supplied key.
        self.print_usage(sys.stderr)
        self.exit(2, "Invalid launch arguments; credentials must never be arguments.\n")


def _load_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON field", "P3_LAUNCH_CONFIG_INVALID")
            result[key] = value
        return result

    try:
        return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=pairs,
            parse_constant=lambda ignored: (_ for _ in ()).throw(ValueError()))
    except BaseException:
        raise ContractError("P3_LAUNCH_CONFIG_INVALID",
                            "Launch JSON could not be loaded") from None


def main(argv=None, *, token_counter=None, counter_implementation_ref=None,
         counter_ref=None, key_reader=None, tty_check=None):
    """CLI defaults to pure validation. Counters can only enter through Python."""
    parser = _SafeArgumentParser(description="Validate a P3 first-stage configuration")
    parser.add_argument("--config", required=True)
    parser.add_argument("--grant")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    try:
        config = parse_launch_config(_load_json(args.config))
        if not args.execute:
            print(json.dumps({"status": "configuration_valid", "execution_requested": False,
                "enabled": config.enabled, "config_digest": config.config_digest,
                "binding_digest": config.binding.binding_digest,
                "stage": "first_stage", "call_cap": config.call_cap,
                "max_cost_nano_usd": config.max_cost_nano_usd}, sort_keys=True))
            return 0
        require(args.grant is not None, "Execution requires an independent grant",
                "P3_LAUNCH_DISABLED")
        grant = parse_launch_grant(_load_json(args.grant))
        receipt = run_first_stage(config, grant, execute=True, token_counter=token_counter,
            counter_implementation_ref=counter_implementation_ref, counter_ref=counter_ref,
            key_reader=key_reader, tty_check=tty_check)
        print(json.dumps({"status": receipt["status"], "gate_passed": receipt["gate_passed"],
                          "launch_id": receipt["launch_id"]}, sort_keys=True))
        return 0 if receipt["gate_passed"] else 1
    except BaseException as exc:
        code = (exc.code if isinstance(exc, ContractError) and type(exc.code) is str
                and exc.code in _CLI_ERROR_CODES
                else "P3_LAUNCH_FAILED")
        print("Launch stopped [" + code + "]; inspect non-sensitive configuration and receipts.",
              file=sys.stderr)
        return 1
