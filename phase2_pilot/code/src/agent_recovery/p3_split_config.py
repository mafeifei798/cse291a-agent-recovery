"""Separate, credential-free grants for one probe and a five-call handoff.

Both phases bind the same immutable six-call LaunchConfig and campaign budget.
A normal-phase grant additionally binds an already reviewed handoff digest;
this module neither creates that handoff nor grants permission by parsing JSON.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, fields

from .contracts import digest, require
from .p3_launch_config import (
    FIRST_STAGE_SEQUENCE, LaunchConfig, _identifier, _path, _positive_cap,
    _reject_credentials, _SHA256, _text,
)


SPLIT_GRANT_SCHEMA = "p3-split-stage-grant-v1"
_GRANT_FIELDS = {
    "schema_version", "authorized", "grant_id", "config_digest", "binding_digest",
    "campaign_id", "output_root", "counter_ref", "counter_implementation_ref",
    "counter_evidence_ref", "stage_call_cap", "max_cost_nano_usd", "phase",
    "cumulative_call_cap", "handoff_digest",
}
_TEXT_FIELDS = _GRANT_FIELDS - {
    "schema_version", "authorized", "stage_call_cap", "max_cost_nano_usd",
    "cumulative_call_cap",
}
_CAPS = {"probe": (1, 1), "normal": (5, 6)}


def _check(condition, code="P3_SPLIT_GRANT_INVALID"):
    # No caller-controlled fields, values, paths or credential text are echoed.
    require(condition, "P3 split-stage grant is invalid or does not match", code)


def _sha256(value):
    return type(value) is str and bool(_SHA256.fullmatch(value))


@dataclass(frozen=True)
class SplitStageGrant:
    authorized: bool = False
    grant_id: str = ""
    config_digest: str = ""
    binding_digest: str = ""
    campaign_id: str = ""
    output_root: str = ""
    counter_ref: str = ""
    counter_implementation_ref: str = ""
    counter_evidence_ref: str = ""
    stage_call_cap: int = 1
    max_cost_nano_usd: int = 1_000_000_000
    phase: str = "probe"
    cumulative_call_cap: int = 1
    handoff_digest: str = ""

    def to_dict(self):
        return {"schema_version": SPLIT_GRANT_SCHEMA,
                **{item.name: getattr(self, item.name) for item in fields(self)}}

    @property
    def grant_digest(self):
        return digest(self.to_dict())

    def validate(self, config, *, phase, fixture=False, handoff_digest=None):
        code = "P3_SPLIT_GRANT_MISMATCH"
        _check(type(self) is SplitStageGrant and type(config) is LaunchConfig
               and type(fixture) is bool and type(phase) is str and phase in _CAPS, code)
        config.validate_ready(fixture=fixture)
        _check(config.call_cap == 6 and config.stage == "first_stage"
               and config.sequence == FIRST_STAGE_SEQUENCE and config.concurrency == 1
               and config.automatic_retries == 0 and config.p4_enabled is False, code)
        _check(parse_split_stage_grant(self.to_dict()) == self and self.authorized is True
               and self.phase == phase and self.config_digest == config.config_digest
               and self.binding_digest == config.binding.binding_digest
               and self.campaign_id == config.campaign_id
               and self.output_root == str(config.output_root)
               and self.counter_ref == config.counter_ref
               and self.counter_implementation_ref == config.counter_implementation_ref
               and self.counter_evidence_ref == config.counter_evidence_ref
               and self.max_cost_nano_usd == config.max_cost_nano_usd, code)
        refs = (self.grant_id, self.counter_ref, self.counter_implementation_ref,
                self.counter_evidence_ref)
        if fixture:
            _check(all(value.startswith("fixture:") for value in refs)
                   and self.campaign_id.startswith("fixture-"), code)
        else:
            _check(all(not value.startswith(("fixture:", "fixture-")) for value in refs)
                   and not self.campaign_id.startswith(("fixture:", "fixture-")), code)
        if phase == "probe":
            _check(self.handoff_digest == "" and (handoff_digest is None
                   or (type(handoff_digest) is str and handoff_digest == "")), code)
        else:
            _check(_sha256(handoff_digest) and self.handoff_digest == handoff_digest, code)
        return self


def parse_split_stage_grant(raw):
    """Strict pure parsing; disabled blank templates never authorize execution."""
    _reject_credentials(raw)
    _check(type(raw) is dict and set(raw) == _GRANT_FIELDS)
    _check(type(raw["schema_version"]) is str and raw["schema_version"] == SPLIT_GRANT_SCHEMA
           and type(raw["authorized"]) is bool
           and type(raw["phase"]) is str and raw["phase"] in _CAPS
           and _positive_cap(raw["max_cost_nano_usd"], 1_000_000_000))
    _check(all(type(raw[name]) is str and (not raw[name] or _text(raw[name]))
               for name in _TEXT_FIELDS))
    stage, cumulative = _CAPS[raw["phase"]]
    _check(type(raw["stage_call_cap"]) is int and raw["stage_call_cap"] == stage
           and type(raw["cumulative_call_cap"]) is int and raw["cumulative_call_cap"] == cumulative)
    for name in ("config_digest", "binding_digest", "handoff_digest"):
        _check(raw[name] == "" or _sha256(raw[name]))
    if raw["phase"] == "probe":
        _check(raw["handoff_digest"] == "")
    if raw["authorized"]:
        required = _TEXT_FIELDS - {"schema_version", "handoff_digest"}
        _check(all(_text(raw[name]) for name in required)
               and _identifier(raw["grant_id"]) and _identifier(raw["campaign_id"])
               and _identifier(raw["counter_ref"]) and _sha256(raw["config_digest"])
               and _sha256(raw["binding_digest"]))
        _path(raw["output_root"])
        if raw["phase"] == "normal":
            _check(_sha256(raw["handoff_digest"]))
    return SplitStageGrant(**{name: deepcopy(value) for name, value in raw.items()
                              if name != "schema_version"})
