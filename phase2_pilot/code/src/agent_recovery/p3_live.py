"""Explicit, development-only P3 entry points; importing this module sends nothing.

The transport permission and the development campaign permission are distinct.
Neither has an enabled default, and neither is obtained from environment
variables. The fixture entry has its own permit type and cannot obtain a key.
One durable claim consumes each frozen pilot cell, even if it emits no output.
"""
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import sqlite3

from .contracts import canonical_json, digest, new_id, require, utc_now
from .p1_runner import load_dev_task, load_fault
from .p3_budget import DEFAULT_LIMITS, DurableP3Budget
from .p3_transport import (BoundTokenCounter, LiveRuntimePermit, P3Binding,
                           P3HTTPClient)


@dataclass(frozen=True)
class DevelopmentEntryPermit:
    authorized: bool = False
    binding_digest: str = ""
    campaign_id: str = ""
    campaign_budget_ref: str = ""
    stage: str = "first_stage"
    call_cap: int = 6
    authorization_reference: str = ""


@dataclass(frozen=True)
class FixtureEntryPermit:
    """A test permission, never an authorization to read credentials or use HTTPS."""
    authorized: bool = False
    binding_digest: str = ""
    campaign_id: str = ""
    campaign_budget_ref: str = ""
    stage: str = "first_stage"
    call_cap: int = 6
    authorization_reference: str = ""


_FAULT_CELLS = frozenset({("p1-dev-01", "ERR", "BASE"),
                          ("p1-dev-02", "ADV", "BASE"),
                          ("p1-dev-03", "TMO", "BASE"),
                          ("p1-dev-04", "STL", "BASE")})
_VERIFY_CELLS = frozenset(("p1-dev-01", condition, "VERIFY_STOP")
                          for condition in ("CLEAN", "ERR", "ADV", "TMO", "STL"))


def _pure_checks(campaign, binding, permit, *, fixture, task_id, condition,
                 policy, probe_only, runtime_permit, token_counter,
                 credential_provider, client_factory, restart):
    """Reject configuration before paths, ledger SQL, factory or credentials."""
    expected_type = FixtureEntryPermit if fixture else DevelopmentEntryPermit
    require(type(permit) is expected_type and permit.authorized is True,
            "P3 development execution requires a distinct explicit permit", "P3_DEV_DISABLED")
    require(type(binding) is P3Binding and binding.simulated is fixture,
            "Fixture and real development entry points are separate", "P3_ENTRY_BINDING_MISMATCH")
    require(type(campaign) is DurableP3Budget,
            "A single durable external campaign is required", "P3_ENTRY_CAMPAIGN_MISMATCH")
    require(isinstance(permit.authorization_reference, str)
            and bool(permit.authorization_reference.strip())
            and permit.authorization_reference.startswith("fixture:") is fixture,
            "Development authorization provenance does not match execution mode", "P3_DEV_DISABLED")
    require(permit.binding_digest == binding.binding_digest
            and campaign.binding == binding.to_dict()
            and campaign.config.get("binding_digest") == binding.binding_digest
            and permit.campaign_id == campaign.config.get("campaign_id")
            and permit.campaign_budget_ref == campaign.ref,
            "Permission, model binding and external ledger must identify one campaign", "P3_ENTRY_CAMPAIGN_MISMATCH")
    limits = campaign.config.get("limits")
    require(isinstance(limits, dict) and set(limits) == set(DEFAULT_LIMITS)
            and all(type(limits[k]) is int and 0 < limits[k] <= maximum
                    for k, maximum in DEFAULT_LIMITS.items()),
            "Live development cannot expand the frozen P3 maxima", "P3_ENTRY_LIMIT_ERROR")
    require(type(permit.call_cap) is int and 0 < permit.call_cap <= 71
            and permit.call_cap <= limits["call_cap"],
            "Stage request allowance exceeds the campaign cap", "P3_ENTRY_LIMIT_ERROR")
    require(type(probe_only) is bool and type(restart) is bool,
            "Probe and restart settings must be explicit booleans", "P3_ENTRY_SCOPE_ERROR")
    require(all(isinstance(value, str) and value for value in
                (task_id, condition, policy, permit.stage)),
            "A development task, condition, policy and stage must be explicit strings", "P3_ENTRY_SCOPE_ERROR")
    cell = (task_id, condition, policy)
    if permit.stage == "first_stage":
        require(permit.call_cap <= 6 and cell == ("p1-dev-01", "CLEAN", "BASE"),
                "First-stage permission covers the probe and dev-01 CLEAN only", "P3_ENTRY_SCOPE_ERROR")
    elif permit.stage == "fault_stage":
        require(permit.call_cap <= 46 and not probe_only and cell in _FAULT_CELLS,
                "Fault-stage permission does not cover this frozen pilot cell", "P3_ENTRY_SCOPE_ERROR")
        require(restart is True,
                "The frozen fault pilot requires its eligible once-only full restart", "P3_ENTRY_SCOPE_ERROR")
    elif permit.stage == "verify_stage":
        require(not probe_only and cell in _VERIFY_CELLS,
                "Verifier-stage permission does not cover this frozen pilot cell", "P3_ENTRY_SCOPE_ERROR")
    else:
        require(False, "Unknown P3 development stage", "P3_ENTRY_SCOPE_ERROR")
    # The manifest loader also checks split=dev; no task dictionary, formal
    # slot identifier, policy expansion, or arbitrary P0 root is accepted here.
    task = load_dev_task(task_id)
    load_fault(task, condition)
    require(client_factory is None or callable(client_factory),
            "An injected client factory must be callable", "P3_ENTRY_CLIENT_ERROR")
    if fixture:
        require(not binding.real_requests_authorized and runtime_permit is None
                and credential_provider is None and token_counter is None,
                "Fixture entry cannot receive live authorization or credentials", "P3_ENTRY_BINDING_MISMATCH")
    else:
        require(binding.real_requests_authorized
                and type(runtime_permit) is LiveRuntimePermit,
                "A separate HTTP runtime permission is required", "P3_LIVE_DISABLED")
        runtime_permit.validate(binding)
        require(runtime_permit.authorization_reference == permit.authorization_reference,
                "Development and transport permissions name different grants", "P3_LIVE_DISABLED")
        require(type(token_counter) is BoundTokenCounter
                and token_counter.evidence_ref == binding.token_admission_evidence
                and callable(token_counter.counter),
                "A verified bound tokenizer is required before live entry", "P3_TOKEN_COUNTER_REQUIRED")
        require(callable(credential_provider),
                "Live entry requires an explicitly supplied credential provider", "P3_CREDENTIAL_ERROR")


class _StageBudgetView:
    """A shrinking cumulative stage gate over the one immutable campaign ledger."""
    def __init__(self, campaign, call_cap):
        self._campaign, self._call_cap = campaign, call_cap

    def __getattr__(self, name):
        return getattr(self._campaign, name)

    def reserve(self, record):
        # The project is deliberately single-process/single-request. Enforce
        # this before the transport can obtain a key or emit a physical send.
        if len(self._campaign.calls()) >= self._call_cap:
            with self._campaign._transaction():
                self._campaign._error("P3_STAGE_CALL_CAP_EXCEEDED",
                    "Next request exceeds the explicitly authorized stage", budget=True)
        return self._campaign.reserve(record)


def _history_gate(campaign, permit, *, probe_only):
    """Read successful gates from this ledger; a fresh permit cannot invent them."""
    exists = campaign.connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='p3_dev_entries'").fetchone()
    previous = ({row[0]: json.loads(row[1]) for row in campaign.connection.execute(
        "SELECT cell_key,body FROM p3_dev_entries")} if exists else {})
    needed = []
    if permit.stage == "first_stage" and not probe_only:
        needed = ["probe"]
    elif permit.stage == "fault_stage":
        needed = ["probe", "p1-dev-01__CLEAN__BASE"]
    elif permit.stage == "verify_stage":
        needed = ["probe", "p1-dev-01__CLEAN__BASE"] + ["__".join(c) for c in _FAULT_CELLS]
    require(all(previous.get(key, {}).get("gate_passed") is True
                and previous[key].get("status") == "completed" for key in needed),
            "A prior pilot gate has not passed independent checks in this campaign", "P3_PRIOR_GATE_REQUIRED")


def _claim(campaign, permit, binding, *, fixture, task_id, condition, policy,
           probe_only, destination):
    """A consumed cell is never reopened, including crashes and zero-call TMO."""
    cell_key = "probe" if probe_only else "__".join((task_id, condition, policy))
    receipt = {"schema_version": "p3-dev-entry-v1", "entry_id": new_id(),
               "cell_key": cell_key, "status": "admitted", "task_id": task_id,
               "condition": condition, "policy": policy, "probe_only": probe_only,
               "simulated": fixture, "binding_digest": binding.binding_digest,
               "campaign_id": campaign.config["campaign_id"],
               "campaign_budget_ref": campaign.ref,
               "execution_kind": "offline_authorized_entry_fixture" if fixture else "authorized_real_dev",
               "destination": str(destination), "entry_permit": asdict(permit),
               "admitted_at": utc_now(), "gate_passed": False}
    campaign.connection.execute("CREATE TABLE IF NOT EXISTS p3_dev_entries "
                                "(cell_key TEXT PRIMARY KEY, entry_id TEXT UNIQUE NOT NULL, body TEXT NOT NULL)")
    with campaign._transaction():
        campaign._assert_active()
        require(not campaign.connection.execute(
            "SELECT 1 FROM p3_dev_entries WHERE cell_key=?", (cell_key,)).fetchone(),
            "This frozen pilot cell was already consumed; no retry is authorized", "P3_DEV_CELL_ALREADY_STARTED")
        campaign._write("INSERT INTO p3_dev_entries VALUES(?,?,?)",
                        (cell_key, receipt["entry_id"], canonical_json(receipt)))
    return receipt


def _entry(output_dir, campaign, binding, *, entry_permit, fixture,
           task_id="p1-dev-01", condition="CLEAN", policy="BASE",
           runtime_permit=None, token_counter=None, credential_provider=None,
           client_factory=None, restart=True, probe_only=False):
    _pure_checks(campaign, binding, entry_permit, fixture=fixture,
                 task_id=task_id, condition=condition, policy=policy,
                 probe_only=probe_only, runtime_permit=runtime_permit,
                 token_counter=token_counter, credential_provider=credential_provider,
                 client_factory=client_factory, restart=restart)
    # Everything above is pure configuration/manifest validation. No ledger
    # SQL, destination access, credential lookup or client construction occurs.
    require(campaign.snapshot()["status"] == "active",
            "The durable campaign is paused", "P3_CAMPAIGN_PAUSED")
    _history_gate(campaign, entry_permit, probe_only=probe_only)
    destination = Path(output_dir).resolve()
    require(not destination.exists(), "P3 refuses artifact overwrite", "P3_DESTINATION_EXISTS")
    try:
        receipt = _claim(campaign, entry_permit, binding, fixture=fixture,
                         task_id=task_id, condition=condition, policy=policy,
                         probe_only=probe_only, destination=destination)
    except sqlite3.Error:
        campaign.quarantine(None, "P3_ENTRY_CLAIM_PERSISTENCE_FAILED")
        raise

    def checked_factory():
        from .p3_deadline import BoundedHTTPSender
        if client_factory is not None:
            client = client_factory()
        elif fixture:
            from .p3_bounded_fixtures import bounded_fixture_client
            client = bounded_fixture_client(binding)
        else:
            client = P3HTTPClient(binding, BoundedHTTPSender(), token_counter=token_counter,
                credential_provider=credential_provider, runtime_permit=runtime_permit)
        require(type(client) is P3HTTPClient and client.binding == binding
                and type(client.sender) is BoundedHTTPSender
                and client.simulated is fixture,
                "Authorized entry requires the bound process-deadline HTTP client", "P3_ENTRY_CLIENT_ERROR")
        if fixture:
            require(client.credential_provider is None and client.runtime_permit is None,
                    "A fixture client cannot carry live credentials", "P3_ENTRY_CLIENT_ERROR")
        else:
            require(client.runtime_permit == runtime_permit
                    and client.token_counter is token_counter
                    and client.credential_provider is credential_provider,
                    "The injected HTTP client differs from the authorized dependencies", "P3_ENTRY_CLIENT_ERROR")
        return client

    from .p3_runner import _run_trial, write
    try:
        result = _run_trial(destination, _StageBudgetView(campaign, entry_permit.call_cap), binding,
            task_id=task_id, condition=condition, policy=policy,
            client_factory=checked_factory, restart=restart,
            execution_kind=receipt["execution_kind"], token_counter=token_counter,
            probe_only=probe_only)
        from .p3_checker import audit_p3_campaign
        from .p3_trial_checker import audit_offline_trial
        independent = {"campaign": audit_p3_campaign(campaign.path),
                       "trial": audit_offline_trial(destination, campaign.path)}
        gate_passed = (all(item.get("status") == "passed" for item in independent.values())
                       and result["initial"].get("log_complete") is True
                       and campaign.snapshot()["status"] == "active"
                       and (result.get("replay") is None
                            or result["replay"].get("log_complete") is True))
        if probe_only:
            calls = [c for c in campaign.calls() if c["trial_key"] == result["trial_key"]]
            gate_passed = (gate_passed and result["initial"].get("status") == "probe_completed"
                           and len(calls) == 1 and calls[0]["status"] == "settled"
                           and calls[0]["evidence"]["outcome"]["status"] == "success")
        elif entry_permit.stage == "first_stage":
            gate_passed = gate_passed and result["initial_check"]["correctness"] == "correct"
        receipt.update(status="completed", trial_key=result["trial_key"],
                       summary_digest_before_entry=digest(result),
                       gate_passed=bool(gate_passed), independent_checks=independent)
        with campaign._transaction():
            campaign._write("UPDATE p3_dev_entries SET body=? WHERE cell_key=? AND entry_id=?",
                (canonical_json(receipt), receipt["cell_key"], receipt["entry_id"]))
        result["entry_receipt"] = receipt
        write(destination / "entry_receipt.json", receipt)
        write(destination / "summary.json", result)
        if not gate_passed and campaign.snapshot()["status"] == "active":
            campaign.quarantine(None, "P3_DEVELOPMENT_GATE_FAILED")
        return result
    except BaseException:
        # The durable claim remains consumed. Do not turn a failed first entry
        # into another destination, retry, credential lookup or new campaign.
        campaign.quarantine(None, "P3_DEV_ENTRY_OR_PUBLICATION_UNCERTAIN")
        raise


def run_authorized_dev_trial(output_dir, campaign, binding, *, entry_permit,
        runtime_permit, token_counter, credential_provider, task_id="p1-dev-01",
        condition="CLEAN", policy="BASE", client_factory=None, restart=True):
    """Run one explicitly permitted frozen development cell, never formal P4."""
    return _entry(output_dir, campaign, binding, entry_permit=entry_permit, fixture=False,
        runtime_permit=runtime_permit, token_counter=token_counter,
        credential_provider=credential_provider, task_id=task_id, condition=condition,
        policy=policy, client_factory=client_factory, restart=restart)


def run_authorized_probe(output_dir, campaign, binding, *, entry_permit,
        runtime_permit, token_counter, credential_provider, client_factory=None):
    """One metadata-schema request, retained separately from task outcomes."""
    return _entry(output_dir, campaign, binding, entry_permit=entry_permit, fixture=False,
        runtime_permit=runtime_permit, token_counter=token_counter,
        credential_provider=credential_provider, client_factory=client_factory,
        restart=False, probe_only=True)


def run_fixture_authorized_dev_trial(output_dir, campaign, binding, *, entry_permit,
        task_id="p1-dev-01", condition="CLEAN", policy="BASE", client_factory=None,
        restart=True):
    """Exercise entry orchestration with bounded fake HTTP, visibly simulated."""
    return _entry(output_dir, campaign, binding, entry_permit=entry_permit, fixture=True,
        task_id=task_id, condition=condition, policy=policy,
        client_factory=client_factory, restart=restart)


def run_fixture_authorized_probe(output_dir, campaign, binding, *, entry_permit,
        client_factory=None):
    return _entry(output_dir, campaign, binding, entry_permit=entry_permit, fixture=True,
        client_factory=client_factory, restart=False, probe_only=True)
