"""Strict, credential-free configuration for the first six-call P3 pilot.

JSON describes a binding and a separate human grant. It never names a module to
import, a credential environment variable, or a credential file. A tokenizer is
trusted executable code supplied by the calling program, with its identity and
review evidence explicitly matched here before a credential can be requested.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, fields
from pathlib import Path
import re

from .contracts import ContractError, digest, require
from .p3_transport import BoundTokenCounter, P3Binding


CONFIG_SCHEMA = "p3-first-stage-launch-v1"
GRANT_SCHEMA = "p3-first-stage-grant-v1"
FIRST_STAGE_SEQUENCE = ("probe", "p1-dev-01/CLEAN/BASE")
_ROOT_FIELDS = {
    "schema_version", "enabled", "campaign_id", "output_root", "stage",
    "sequence", "call_cap", "max_cost_nano_usd", "concurrency",
    "automatic_retries", "p4_enabled", "binding", "token_counter",
}
_COUNTER_FIELDS = {"counter_ref", "implementation_ref", "evidence_ref"}
_BINDING_FIELDS = {item.name for item in fields(P3Binding)}
_GRANT_FIELDS = {
    "schema_version", "authorized", "grant_id", "config_digest",
    "binding_digest", "campaign_id", "output_root", "counter_ref",
    "counter_implementation_ref", "counter_evidence_ref", "call_cap",
    "max_cost_nano_usd",
}
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}\Z")
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_RECOGNIZABLE_CREDENTIAL = re.compile(
    r"(?i)\bbearer\s+[A-Za-z0-9_./+=-]{6,}|\bsk-[A-Za-z0-9_-]{12,}")


def _check(condition, code="P3_LAUNCH_CONFIG_INVALID"):
    # No supplied value or field name enters the diagnostic: a misplaced key
    # or secret must not be echoed by a configuration failure.
    require(condition, "P3 launch configuration is invalid or incomplete", code)


def _exact(value, expected):
    _check(type(value) is dict and set(value) == expected)


def _reject_credentials(value, depth=0):
    """Screen accidental credentials before parsing any path or binding.

    This catches recognizable key formats, rather than claiming to identify
    every possible secret. It traverses keys too and never copies a rejected
    value into its diagnostic. The depth bound also keeps malformed non-JSON
    direct callers from creating an unbounded recursive inspection.
    """
    _check(depth <= 32)
    if type(value) is str:
        _check(not _RECOGNIZABLE_CREDENTIAL.search(value),
               "P3_LAUNCH_CREDENTIAL_IN_CONFIG")
    elif type(value) is dict:
        for key, child in value.items():
            _reject_credentials(key, depth + 1)
            _reject_credentials(child, depth + 1)
    elif type(value) in (list, tuple):
        for child in value:
            _reject_credentials(child, depth + 1)


def _text(value):
    return (type(value) is str and bool(value.strip()) and len(value) <= 1024
            and all(ord(char) >= 32 and ord(char) != 127 for char in value))


def _identifier(value):
    return type(value) is str and bool(_ID.fullmatch(value))


def _path(value):
    _check(_text(value))
    path = Path(value)
    # This is lexical only. It does not resolve a symlink, read an existing
    # file, create a directory, expand ~, or consult an environment variable.
    _check(path.is_absolute() and ".." not in path.parts)
    return path


def _positive_cap(value, maximum):
    return type(value) is int and 0 < value <= maximum


@dataclass(frozen=True)
class LaunchConfig:
    enabled: bool
    binding: P3Binding
    campaign_id: str
    output_root: Path
    counter_ref: str
    counter_implementation_ref: str
    counter_evidence_ref: str
    call_cap: int = 6
    max_cost_nano_usd: int = 1_000_000_000
    stage: str = "first_stage"
    sequence: tuple[str, ...] = FIRST_STAGE_SEQUENCE
    concurrency: int = 1
    automatic_retries: int = 0
    p4_enabled: bool = False

    @property
    def fixture(self):
        return self.binding.simulated

    @property
    def ledger_path(self):
        return self.output_root / "campaign.sqlite"

    @property
    def limits(self):
        return {
            "call_cap": self.call_cap,
            "input_token_cap": self.call_cap * self.binding.max_input_tokens,
            "output_token_cap": self.call_cap * self.binding.max_output_tokens,
            "max_cost_nano_usd": self.max_cost_nano_usd,
            "slot_call_cap": min(5, self.call_cap),
            "logical_call_cap": min(5, self.call_cap),
        }

    @property
    def config_digest(self):
        return digest(self.to_dict())

    def to_dict(self):
        return {
            "schema_version": CONFIG_SCHEMA, "enabled": self.enabled,
            "campaign_id": self.campaign_id, "output_root": str(self.output_root),
            "stage": self.stage, "sequence": list(self.sequence),
            "call_cap": self.call_cap, "max_cost_nano_usd": self.max_cost_nano_usd,
            "concurrency": self.concurrency, "automatic_retries": self.automatic_retries,
            "p4_enabled": self.p4_enabled, "binding": self.binding.to_dict(),
            "token_counter": {
                "counter_ref": self.counter_ref,
                "implementation_ref": self.counter_implementation_ref,
                "evidence_ref": self.counter_evidence_ref,
            },
        }

    def validate_ready(self, *, fixture=False):
        _check(type(fixture) is bool, "P3_LAUNCH_DISABLED")
        # Reparse direct dataclass construction as well as JSON construction.
        parser = parse_fixture_launch_config if fixture else parse_launch_config
        checked = parser(self.to_dict())
        _check(checked == self and self.enabled is True
               and self.fixture is fixture
               and self.binding.real_requests_authorized is (not fixture),
               "P3_LAUNCH_DISABLED")
        # The configuration must be able to fund its entire declared first
        # stage at admitted maxima, rather than hoping actual usage is lower.
        _check(self.call_cap * self.binding.worst_case_cost_nano_usd
               <= self.max_cost_nano_usd, "P3_LAUNCH_BUDGET_INSUFFICIENT")
        return self


def _parse_config(raw, *, fixture):
    _reject_credentials(raw)
    _exact(raw, _ROOT_FIELDS)
    _exact(raw["binding"], _BINDING_FIELDS)
    _exact(raw["token_counter"], _COUNTER_FIELDS)
    # These explicit unknowns are required to remain null in the shipped
    # template. Parsing cannot silently fill them with fixture defaults.
    required = (raw["campaign_id"], raw["output_root"],
                *raw["token_counter"].values(),
                raw["binding"]["binding_ref"], raw["binding"]["model"],
                raw["binding"]["allowed_response_models"],
                raw["binding"]["input_nano_usd_per_token"],
                raw["binding"]["output_nano_usd_per_token"],
                raw["binding"]["price_evidence"],
                raw["binding"]["capability_evidence"],
                raw["binding"]["token_admission_evidence"],
                raw["binding"]["supported_parameters"],
                raw["binding"]["output_token_parameter"])
    _check(all(value is not None for value in required), "P3_LAUNCH_CONFIG_INCOMPLETE")
    _check(raw["schema_version"] == CONFIG_SCHEMA
           and type(raw["enabled"]) is bool
           and raw["stage"] == "first_stage"
           and type(raw["sequence"]) is list
           and tuple(raw["sequence"]) == FIRST_STAGE_SEQUENCE
           and _positive_cap(raw["call_cap"], 6)
           and _positive_cap(raw["max_cost_nano_usd"], 1_000_000_000)
           and type(raw["concurrency"]) is int and raw["concurrency"] == 1
           and type(raw["automatic_retries"]) is int and raw["automatic_retries"] == 0
           and raw["p4_enabled"] is False)
    _check(_identifier(raw["campaign_id"]))
    root = _path(raw["output_root"])
    counter = raw["token_counter"]
    _check(_identifier(counter["counter_ref"])
           and _text(counter["implementation_ref"]) and _text(counter["evidence_ref"]))
    # P3Binding validates frozen endpoints, prices and parameter capabilities.
    # Catch its detailed errors too; this parser never echoes input values.
    try:
        binding = P3Binding.from_dict(raw["binding"])
    except (ContractError, TypeError, ValueError, KeyError):
        raise ContractError("P3_LAUNCH_CONFIG_INVALID",
                            "P3 launch binding is invalid") from None
    _check(binding.simulated is fixture
           and counter["evidence_ref"] == binding.token_admission_evidence)
    refs = (counter["counter_ref"], counter["implementation_ref"], counter["evidence_ref"])
    if fixture:
        _check(all(value.startswith("fixture:") for value in refs)
               and raw["campaign_id"].startswith("fixture-")
               and binding.binding_ref.startswith("fixture:"))
    else:
        _check(all(not value.startswith("fixture:") for value in refs)
               and not raw["campaign_id"].startswith("fixture-")
               and not binding.binding_ref.startswith("fixture:"))
    return LaunchConfig(raw["enabled"], binding, raw["campaign_id"], root,
                        counter["counter_ref"], counter["implementation_ref"],
                        counter["evidence_ref"], raw["call_cap"], raw["max_cost_nano_usd"])


def parse_launch_config(raw):
    """Parse only a real binding; does not authorize execution or read a key."""
    return _parse_config(raw, fixture=False)


def parse_fixture_launch_config(raw):
    """Separate test-only parser; its objects cannot authorize the real entry."""
    return _parse_config(raw, fixture=True)


@dataclass(frozen=True)
class LaunchGrant:
    authorized: bool = False
    grant_id: str = ""
    config_digest: str = ""
    binding_digest: str = ""
    campaign_id: str = ""
    output_root: str = ""
    counter_ref: str = ""
    counter_implementation_ref: str = ""
    counter_evidence_ref: str = ""
    call_cap: int = 6
    max_cost_nano_usd: int = 1_000_000_000

    def to_dict(self):
        return {"schema_version": GRANT_SCHEMA,
                **{item.name: getattr(self, item.name) for item in fields(self)}}

    @property
    def grant_digest(self):
        return digest(self.to_dict())

    def validate(self, config, *, fixture=False):
        _check(type(config) is LaunchConfig, "P3_LAUNCH_GRANT_MISMATCH")
        config.validate_ready(fixture=fixture)
        _check(parse_launch_grant(self.to_dict()) == self
               and self.authorized is True
               and self.grant_id.startswith("fixture:") is fixture
               and self.config_digest == config.config_digest
               and self.binding_digest == config.binding.binding_digest
               and self.campaign_id == config.campaign_id
               and self.output_root == str(config.output_root)
               and self.counter_ref == config.counter_ref
               and self.counter_implementation_ref == config.counter_implementation_ref
               and self.counter_evidence_ref == config.counter_evidence_ref
               and self.call_cap == config.call_cap
               and self.max_cost_nano_usd == config.max_cost_nano_usd,
               "P3_LAUNCH_GRANT_MISMATCH")
        return self


def parse_launch_grant(raw):
    _reject_credentials(raw)
    _exact(raw, _GRANT_FIELDS)
    _check(raw["schema_version"] == GRANT_SCHEMA
           and type(raw["authorized"]) is bool
           and _positive_cap(raw["call_cap"], 6)
           and _positive_cap(raw["max_cost_nano_usd"], 1_000_000_000))
    # A disabled grant is structurally valid with blank fields. It cannot pass
    # validate(), which is the execution gate.
    textual = _GRANT_FIELDS - {"schema_version", "authorized", "call_cap", "max_cost_nano_usd"}
    _check(all(type(raw[name]) is str and (not raw[name] or _text(raw[name]))
               for name in textual))
    if raw["authorized"]:
        _check(_identifier(raw["grant_id"]) and _identifier(raw["campaign_id"])
               and _identifier(raw["counter_ref"])
               and all(bool(raw[name].strip()) for name in textual)
               and bool(_SHA256.fullmatch(raw["config_digest"]))
               and bool(_SHA256.fullmatch(raw["binding_digest"])))
        _path(raw["output_root"])
    return LaunchGrant(**{key: deepcopy(value) for key, value in raw.items()
                          if key != "schema_version"})


def resolve_token_counter(config, injected, *, implementation_ref, counter_ref):
    """Bind reviewed caller-supplied code; never import a name from JSON.

The caller is responsible for reviewing the implementation and its framing
bound. Matching references establish provenance, not tokenizer correctness.
The provider usage versus admitted bound is checked again after a response.
"""
    _check(type(config) is LaunchConfig and type(injected) is BoundTokenCounter
           and callable(injected.counter)
           and injected.evidence_ref == config.counter_evidence_ref
           and config.counter_evidence_ref == config.binding.token_admission_evidence
           and implementation_ref == config.counter_implementation_ref
           and counter_ref == config.counter_ref,
           "P3_TOKEN_COUNTER_REQUIRED")
    return injected
