"""Explicit Bank-pilot launch permission and dispatch-time credential gate.

This is configuration/permission plumbing, not permission to run a model.
The local 4,000-token check is policy, not a claim about TritonAI's billable
prompt length. A separate durable route-wide liability reserve is required.
There is no environment lookup, implicit key discovery or network operation.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from agent_recovery.contracts import ContractError, digest, require
from .unified_budget import INHERITANCE_PLAN_SHA256
from .budget_policy import CURRENT_BUDGET_REVISION, budget_policy

ADMISSION_MODE = "unverified-token-count-route-liability-reserve"
CONSERVATIVE_ADMISSION_MODE = "user-authorized-conservative-reserve"
CONSERVATIVE_RESERVE_NANO = 500_000_000
BATCH_ID = "bank-B01"
RUNS = (("C01", "SCOPED"), ("C02", "FULL_HISTORY"))


def _utc(value):
    require(isinstance(value, str) and value.endswith("Z"),
            "An explicit UTC timestamp ending in Z is required", "BANK_TIME")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        require(False, "Invalid UTC timestamp", "BANK_TIME")
    require(parsed.utcoffset().total_seconds() == 0, "Timestamp is not UTC", "BANK_TIME")
    return parsed


def _now(now_utc=None):
    value = now_utc if now_utc is not None else datetime.now(timezone.utc)
    require(isinstance(value, datetime) and value.tzinfo is not None
            and value.utcoffset().total_seconds() == 0,
            "Clock must provide an aware UTC datetime", "BANK_TIME")
    return value


def _sha(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _absolute_path(value):
    require(isinstance(value, str) and value and Path(value).is_absolute(),
            "An absolute authority/run path is required", "BANK_AUTHORITY_PATH")
    path = Path(value)
    require(str(path) == str(path.resolve()),
            "Paths must be canonical and cannot traverse symlinks", "BANK_AUTHORITY_PATH")
    return path


@dataclass(frozen=True)
class BankLaunchConfig:
    authority_path: str
    runs_root: str
    route_input_billable_cap: int
    route_output_billable_cap: int
    input_nano_usd_per_token: int
    output_nano_usd_per_token: int
    price_evidence_sha256: str
    route_evidence_sha256: str
    source_proof_expires_utc: str
    price_evidence_ref: str = "unverified"
    route_evidence_ref: str = "unverified"
    source_proof_status: str = "unverified"
    additional_nano_usd_per_call: int | None = None
    all_billable_components_confirmed: bool = False
    history_plan_sha256: str = INHERITANCE_PLAN_SHA256
    schema_version: str = "bank-pilot-launch-v1"
    batch_id: str = BATCH_ID
    runs: tuple = RUNS
    total_call_cap: int = 20
    per_run_call_cap: int = 10
    per_slot_call_cap: int = 5
    budget_revision: str = CURRENT_BUDGET_REVISION
    batch_cap_nano: int = 1_000_000_000
    pilot_cap_nano: int = 3_000_000_000
    project_cap_nano: int = 20_000_000_000
    endpoint: str = "https://tritonai-api.ucsd.edu/v1"
    model: str = "api-glm-5.3-flash"
    reasoning_effort: str = "low"
    temperature: int = 0
    max_output_tokens: int = 768
    local_input_policy_tokens: int = 4000
    absolute_deadline_s: int = 120
    admission_mode: str = ADMISSION_MODE
    automatic_retries: int = 0
    concurrency: int = 1

    def registry_policy(self):
        return ('bank-pilot-launch-v1',BATCH_ID,RUNS,20)

    def __post_init__(self):
        authority, runs_root = _absolute_path(self.authority_path), _absolute_path(self.runs_root)
        require(authority != runs_root and runs_root not in authority.parents,
                "Shared authority must be outside rollback/run directories", "BANK_AUTHORITY_PATH")
        schema,batch,runs,call_cap=self.registry_policy()
        require(self.schema_version == schema and self.batch_id == batch
                and type(self.runs) is tuple and self.runs == runs
                and all(type(item) is tuple for item in self.runs),
                "Bank batch and run/context sequence are fixed", "BANK_CONFIG")
        policy = budget_policy(self.budget_revision)
        exact = {"total_call_cap": call_cap, "per_run_call_cap": 10, "per_slot_call_cap": 5,
                 "batch_cap_nano": policy['batch_cap_nano'], "pilot_cap_nano": policy['pilot_cap_nano'],
                 "project_cap_nano": policy['project_cap_nano'], "temperature": 0,
                 "max_output_tokens": 768, "local_input_policy_tokens": 4000,
                 "absolute_deadline_s": 120, "automatic_retries": 0, "concurrency": 1}
        require(all(type(getattr(self, key)) is int and getattr(self, key) == number
                    for key, number in exact.items()),
                "Launch caps or execution parameters differ from the selected pilot", "BANK_CONFIG")
        require(self.endpoint == "https://tritonai-api.ucsd.edu/v1"
                and self.model == "api-glm-5.3-flash" and self.reasoning_effort == "low"
                and self.admission_mode in (ADMISSION_MODE, CONSERVATIVE_ADMISSION_MODE),
                "Endpoint, model and liability admission mode are fixed", "BANK_CONFIG")
        require(self.history_plan_sha256 == INHERITANCE_PLAN_SHA256,
                "Pinned history inheritance differs", "BANK_HISTORY")
        require(type(self.route_input_billable_cap) is int and self.route_input_billable_cap >= 4000
                and type(self.route_output_billable_cap) is int
                and self.route_output_billable_cap == (500000 if self.admission_mode == CONSERVATIVE_ADMISSION_MODE else 768)
                and type(self.input_nano_usd_per_token) is int and self.input_nano_usd_per_token >= 0
                and type(self.output_nano_usd_per_token) is int and self.output_nano_usd_per_token >= 0,
                "Explicit route-wide billable ceilings and price ceilings are required", "BANK_ROUTE_PROOF")
        require((self.additional_nano_usd_per_call is None or
                 (type(self.additional_nano_usd_per_call) is int and self.additional_nano_usd_per_call >= 0))
                and type(self.all_billable_components_confirmed) is bool,
                "Additional charges must be explicit or remain unknown", "BANK_ROUTE_PROOF")
        if self.admission_mode == CONSERVATIVE_ADMISSION_MODE:
            require(self.route_input_billable_cap == 500000
                    and self.input_nano_usd_per_token == 150 and self.output_nano_usd_per_token == 500
                    and self.additional_nano_usd_per_call is None
                    and self.all_billable_components_confirmed is False,
                    "Conservative admission must preserve unknown tariff semantics", "BANK_ROUTE_PROOF")
        token_ceiling = (self.route_input_billable_cap * self.input_nano_usd_per_token
                         + self.route_output_billable_cap * self.output_nano_usd_per_token)
        require(0 < token_ceiling <= self.batch_cap_nano,
                "One route-wide liability must fit the batch cap", "BANK_ROUTE_PROOF")
        require(_sha(self.price_evidence_sha256) and _sha(self.route_evidence_sha256)
                and isinstance(self.price_evidence_ref, str) and bool(self.price_evidence_ref)
                and isinstance(self.route_evidence_ref, str) and bool(self.route_evidence_ref)
                and self.source_proof_status in ("unverified", "synthetic", "verified"),
                "Pricing/route evidence must have explicit identities", "BANK_ROUTE_PROOF")
        _utc(self.source_proof_expires_utc)

    @property
    def route_liability_nano(self):
        if self.admission_mode == CONSERVATIVE_ADMISSION_MODE:
            return CONSERVATIVE_RESERVE_NANO
        require(type(self.additional_nano_usd_per_call) is int
                and self.additional_nano_usd_per_call == 0
                and self.all_billable_components_confirmed is True,
                "Unknown or nonzero additional charges have no admitted route ceiling", "BANK_ROUTE_PROOF")
        return (self.route_input_billable_cap * self.input_nano_usd_per_token
                + self.route_output_billable_cap * self.output_nano_usd_per_token
                + self.additional_nano_usd_per_call)

    @property
    def config_sha256(self):
        return digest(self.to_dict())

    @property
    def config_digest(self):
        return self.config_sha256

    def to_dict(self):
        return asdict(self)

    def route_liability_policy(self):
        """Exact monetary-reserve policy consumed by BankPilotBudget.

        A draft remains unconfirmed; only an explicitly synthetic fixture or
        separately verified source can set the confirmation fields true.
        This says nothing about local/server tokenizer agreement.
        """
        confirmed = self.source_proof_status in ("synthetic", "verified")
        result = {"schema_version": "bank-route-liability-v1", "model": self.model,
            "endpoint": self.endpoint, "confirmed": confirmed,
            "simulated": self.source_proof_status == "synthetic",
            "max_billable_input_tokens": self.route_input_billable_cap,
            "max_billable_output_tokens": self.route_output_billable_cap,
            "input_nano_usd_per_token": self.input_nano_usd_per_token,
            "output_nano_usd_per_token": self.output_nano_usd_per_token,
            "evidence_ref": self.route_evidence_ref, "source_sha256": self.route_evidence_sha256,
            "price_evidence_ref": self.price_evidence_ref,
            "additional_nano_usd_per_call": self.additional_nano_usd_per_call,
            "all_billable_components_confirmed": self.all_billable_components_confirmed}
        if self.admission_mode == CONSERVATIVE_ADMISSION_MODE:
            result.update(admission_mode=self.admission_mode,
                conservative_reserve_nano=CONSERVATIVE_RESERVE_NANO,
                reserve_is_provider_guarantee=False,
                successful_usage_releases_risk_by_authorized_policy=True)
        return result

    def validate_source_proof(self, *, fixture_only, now_utc=None):
        if self.admission_mode == ADMISSION_MODE:
            require(type(self.additional_nano_usd_per_call) is int
                    and self.additional_nano_usd_per_call == 0
                    and self.all_billable_components_confirmed is True,
                    "All billable components must explicitly be confirmed; this adapter supports zero additional fees only",
                    "BANK_ROUTE_PROOF")
        require(type(fixture_only) is bool and _now(now_utc) < _utc(self.source_proof_expires_utc),
                "Pricing/route evidence is expired", "BANK_SOURCE_PROOF_EXPIRED")
        expected = "synthetic" if fixture_only else "verified"
        require(self.source_proof_status == expected,
                "Synthetic or unverified route evidence cannot authorize live credentials", "BANK_ROUTE_PROOF")
        if not fixture_only:
            require(all(not ref.startswith("fixture:") and ref.lower() not in
                        ("unverified", "unknown", "pending", "synthetic")
                        for ref in (self.price_evidence_ref, self.route_evidence_ref)),
                    "Live pricing/route evidence is unresolved", "BANK_ROUTE_PROOF")


@dataclass(frozen=True)
class BankLaunchPermit:
    authorized: bool = False
    conservative_reserve_authorized: bool = False
    async_usage_settlement_authorized: bool = False
    config_sha256: str = ""
    authority_path: str = ""
    history_plan_sha256: str = ""
    price_evidence_sha256: str = ""
    route_evidence_sha256: str = ""
    price_cap_confirmed: bool = False
    route_cap_confirmed: bool = False
    authority_confirmed: bool = False
    credential_read_authorized: bool = False
    key_read_authorized: bool = False
    training_authorized: bool = False
    real_requests_authorized: bool = False
    credential_source: str = "none"
    authorization_reference: str = ""
    expires_utc: str = ""

    def validate(self, config, *, fixture_only, now_utc=None):
        require(isinstance(config, BankLaunchConfig) and type(fixture_only) is bool,
                "A fixed Bank launch configuration is required", "BANK_PERMIT")
        require(type(self.conservative_reserve_authorized) is bool
                and (config.admission_mode != CONSERVATIVE_ADMISSION_MODE
                     or self.conservative_reserve_authorized),
                "Unknown billing semantics require explicit conservative-reserve permission", "BANK_PERMIT")
        flags = (self.authorized, self.price_cap_confirmed, self.route_cap_confirmed,
                 self.authority_confirmed, self.credential_read_authorized)
        require(all(type(flag) is bool and flag for flag in flags)
                and type(self.real_requests_authorized) is bool
                and type(self.key_read_authorized) is bool and type(self.training_authorized) is bool
                and self.real_requests_authorized == (not fixture_only),
                "Explicit matching launch/credential permission is missing", "BANK_PERMIT")
        require(self.config_sha256 == config.config_sha256 and self.authority_path == config.authority_path
                and self.history_plan_sha256 == config.history_plan_sha256
                and self.price_evidence_sha256 == config.price_evidence_sha256
                and self.route_evidence_sha256 == config.route_evidence_sha256,
                "Permit is bound to different configuration, history, authority or source evidence", "BANK_PERMIT")
        require(isinstance(self.authorization_reference, str) and bool(self.authorization_reference.strip()),
                "An explicit authorization reference is required", "BANK_PERMIT")
        require(self.credential_source == "synthetic" if fixture_only else
                self.credential_source in ("injected-live-provider", "datahub-existing-env"),
                "Credential source is not authorized for this transport", "BANK_CREDENTIAL_SOURCE")
        require(fixture_only or self.key_read_authorized,
                "Live credential access requires separate key-read permission", "BANK_PERMIT")
        expires = _utc(self.expires_utc)
        require(_now(now_utc) < expires <= _utc(config.source_proof_expires_utc),
                "Launch permit is expired or outlives its source evidence", "BANK_PERMIT_EXPIRED")
        config.validate_source_proof(fixture_only=fixture_only, now_utc=now_utc)


class BankCredentialGate:
    """Read an injected provider only after the exact durable dispatch exists.

    The gate re-reads the real ledger on each invocation. It does not accept a
    caller-supplied snapshot and never caches returned credential material.
    ``arm`` only records the once-only call identity; preparing model messages
    therefore cannot trigger a credential lookup.
    """
    def __init__(self, config, permit, ledger, provider, *, fixture_only=False, now_utc=None):
        from .bank_pilot_budget import BankPilotBudget
        require(isinstance(config, BankLaunchConfig) and isinstance(permit, BankLaunchPermit)
                and isinstance(ledger, BankPilotBudget) and callable(provider)
                and type(fixture_only) is bool,
                "Explicit Bank configuration, authority and provider are required", "BANK_CREDENTIAL_GATE")
        self.config, self.permit, self.ledger, self.provider = config, permit, ledger, provider
        self.fixture_only = fixture_only
        self._clock = now_utc
        self._armed = None
        self._consumed = set()
        self._validate()

    def _now(self):
        return self._clock() if callable(self._clock) else self._clock

    def _validate(self):
        self.permit.validate(self.config, fixture_only=self.fixture_only, now_utc=self._now())
        require(str(self.ledger.path.resolve()) == self.config.authority_path
                and self.ledger.binding.get("simulated") is self.fixture_only
                and self.ledger.binding.get("price_evidence") == self.config.price_evidence_ref
                and self.ledger.binding.get("input_nano_usd_per_token") == self.config.input_nano_usd_per_token
                and self.ledger.binding.get("output_nano_usd_per_token") == self.config.output_nano_usd_per_token,
                "Credential gate points at another authority or transport", "BANK_AUTHORITY_PATH")

    def arm(self, call_id):
        self._validate()
        require(isinstance(call_id, str) and bool(call_id) and self._armed is None
                and call_id not in self._consumed,
                "A credential gate cannot be rearmed for an old or in-flight call", "BANK_CREDENTIAL_REUSE")
        self._armed = call_id

    def __call__(self):
        self._validate()
        call_id = self._armed
        require(isinstance(call_id, str) and call_id not in self._consumed,
                "Dispatch must explicitly arm a new call", "BANK_CREDENTIAL_NOT_ARMED")
        # A SQLite transaction keeps this validation coherent with the durable
        # dispatch intent. The provider returns only to the HTTPS sender; its
        # value is never put into a receipt, trace, exception or object field.
        with self.ledger._transaction():
            snapshot = self.ledger.snapshot()
            calls = [row for row in self.ledger.calls() if row["call_id"] == call_id]
            bank = snapshot.get("bank_budget", {})
            unified = snapshot.get("unified_budget", {})
            require(snapshot.get("status") == "active" and len(calls) == 1,
                    "Authority is stopped or call has no reservation", "BANK_DISPATCH_AUTHORITY")
            call = calls[0]
            require(call.get("status") == "dispatched" and call.get("dispatched") is True
                    and call.get("run_id") in dict(self.config.runs),
                    "Credential access requires committed dispatch in this pilot", "BANK_DISPATCH_AUTHORITY")
            require(unified.get("plan_sha256") == self.config.history_plan_sha256
                    and bank.get("batch_id") == self.config.batch_id
                    and bank.get("worstcase_per_call_nano") == self.config.route_liability_nano,
                    "Durable history, batch or route ceiling differs", "BANK_DISPATCH_AUTHORITY")
            risks = [item for item in bank.get("risks", []) if item.get("call_id") == call_id]
            require(len(risks) == 1, "Durable route liability is absent", "BANK_ROUTE_HOLD")
            risk = risks[0]
            batch = bank.get("batch_config", {})
            require(batch.get("batch_cap_nano") == self.config.batch_cap_nano
                    and batch.get("budget_revision", "bank-budget-20261024-r1") == self.config.budget_revision
                    and batch.get("batch_call_cap") == self.config.total_call_cap
                    and batch.get("run_call_cap") == self.config.per_run_call_cap
                    and batch.get("role_call_cap") == self.config.per_slot_call_cap
                    and batch.get("registered_runs") == dict(self.config.runs)
                    and batch.get("route_liability") == self.config.route_liability_policy()
                    and batch.get("route_liability_sha256") == digest(self.config.route_liability_policy())
                    and unified.get("project_cap_nano") == self.config.project_cap_nano
                    and unified.get("pilot_cap_nano") == self.config.pilot_cap_nano,
                    "Durable registration or caps differ from the launch permit", "BANK_DISPATCH_AUTHORITY")
            require(risk.get("status") == "dispatched"
                    and risk.get("worstcase_reserved_nano") == self.config.route_liability_nano
                    and type(risk.get("extra_held_nano")) is int and risk["extra_held_nano"] >= 0
                    and type(call.get("held_cost_nano_usd")) is int
                    and call["held_cost_nano_usd"] + risk["extra_held_nano"] >= self.config.route_liability_nano,
                    "Full route liability must remain held before credential access", "BANK_ROUTE_HOLD")
            # Once attempted, this identity cannot repeatedly read a credential,
            # even when its provider fails or the HTTP send never starts.
            self._consumed.add(call_id)
            self._armed = None
            try:
                value = self.provider()
            except Exception:
                raise ContractError("BANK_CREDENTIAL_PROVIDER", "Injected credential provider failed") from None
            require(isinstance(value, str) and bool(value) and "\r" not in value and "\n" not in value,
                    "Injected provider returned an invalid credential", "BANK_CREDENTIAL_PROVIDER")
            return value
