"""P4 formal admission using the audited P3 transaction/settlement engine.

Only the constructor and formal identity checks differ. Physical tables retain
their p3_ names so inherited settlement, duplicate-receipt and uncertainty
handling are exactly the previously exercised code. P3's 71-call limit is never
changed globally. P4 stores a distinct immutable config and 168-slot allowlist.
"""
from copy import deepcopy
import json
from pathlib import Path
import sqlite3

from .contracts import canonical_json, digest, require
from .p3_budget import DurableP3Budget
from .p3_transport import P3Binding
from .p4_config import (DEFAULT_LIMITS, BASELINE_CALLS, BASELINE_KNOWN_NANO_USD,
                        BASELINE_HELD_NANO_USD, GLOBAL_MAX_NANO_USD,
                        REGISTRY_SHA256, BASELINE_SHA256, load_formal_registry,
                        formal_binding_record)


class DurableP4Budget(DurableP3Budget):
    def __init__(self, path, *, campaign_id, binding, limits=None, resume_checkpoint=None):
        require(isinstance(campaign_id, str) and campaign_id and "::" not in campaign_id,
                "Invalid formal campaign identity", "CAMPAIGN_IDENTITY_MISMATCH")
        checked = P3Binding.from_dict(binding)
        require(checked.max_input_tokens == 4000 and checked.max_output_tokens == 768
                and checked.timeout_s == 120 and checked.reasoning_effort == "low"
                and checked.input_nano_usd_per_token == 150 and checked.output_nano_usd_per_token == 500
                and checked.cached_input_nano_usd_per_token is None,
                "P4 binding differs from the sealed Flash admission", "P4_BINDING_INVALID")
        require(checked.model == ("fixture-glm-5.3-flash" if checked.simulated else "api-glm-5.3-flash")
                and checked.real_requests_authorized is (not checked.simulated),
                "P4 model or authorization differs", "P4_BINDING_INVALID")
        configured = dict(DEFAULT_LIMITS)
        if limits is not None:
            require(isinstance(limits, dict) and set(limits) <= set(DEFAULT_LIMITS),
                    "Unknown formal campaign limit", "CAMPAIGN_CONFIG_MISMATCH")
            configured.update(limits)
        require(all(type(value) is int and 0 < value <= DEFAULT_LIMITS[key]
                    for key, value in configured.items()),
                "P4 limits may only shrink frozen maxima including historical costs", "CAMPAIGN_CONFIG_MISMATCH")
        self.binding = deepcopy(binding)
        self.registry = {r["trial_key"]: r for r in load_formal_registry()}
        runtime = formal_binding_record(checked)
        self.config = dict(schema_version="p4-budget-v1", campaign_id=campaign_id,
            binding=self.binding, binding_digest=digest(self.binding), limits=configured,
            registry_sha256=REGISTRY_SHA256, runtime_binding_digest=runtime["runtime_binding_digest"],
            baseline_budget_sha256=BASELINE_SHA256, baseline_calls=BASELINE_CALLS,
            baseline_known_cost_nano_usd=BASELINE_KNOWN_NANO_USD,
            baseline_held_cost_nano_usd=BASELINE_HELD_NANO_USD,
            max_cumulative_cost_nano_usd=GLOBAL_MAX_NANO_USD,
            transaction_engine="DurableP3Budget; original P3 defaults unchanged")
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.ref = str(self.path)
        self._failed = False
        self.connection = sqlite3.connect(self.path, isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS p3_campaign (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1), config TEXT NOT NULL,
                state TEXT NOT NULL, reason TEXT);
            CREATE TABLE IF NOT EXISTS p3_calls (
                call_id TEXT PRIMARY KEY, attempt_id TEXT UNIQUE NOT NULL, body TEXT NOT NULL,
                reservation_digest TEXT NOT NULL, settlement_digest TEXT);
            CREATE TABLE IF NOT EXISTS p3_receipts (
                call_id TEXT PRIMARY KEY, provider_request_id TEXT UNIQUE NOT NULL,
                raw_usage TEXT NOT NULL, normalized_usage TEXT NOT NULL, receipt_digest TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS p3_conflicts (
                id INTEGER PRIMARY KEY, call_id TEXT, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS p3_restarts (
                logical_run_key TEXT PRIMARY KEY, source_run_id TEXT UNIQUE NOT NULL,
                body TEXT NOT NULL, request_digest TEXT NOT NULL);
        """)
        try:
            with self._transaction():
                previous = self.connection.execute("SELECT * FROM p3_campaign").fetchone()
                if previous:
                    require(previous["config"] == canonical_json(self.config),
                            "Persisted formal binding or budget differs", "CAMPAIGN_CONFIG_MISMATCH")
                else:
                    self._write("INSERT INTO p3_campaign VALUES(1,?,'active',NULL)",
                                (canonical_json(self.config),))
            if previous and any(c["status"] != "settled" for c in self.calls()):
                self._pause_durable("REOPEN_WITH_PENDING_CALL")
            elif previous and (self.calls() or self.connection.execute("SELECT 1 FROM p3_restarts LIMIT 1").fetchone()):
                require(isinstance(resume_checkpoint, dict),
                        "P4 continuation requires the finalized batch checkpoint", "P4_CHECKPOINT_REQUIRED")
                expected = self.make_resume_checkpoint(resume_checkpoint.get("completed_trial_keys"))
                require(resume_checkpoint == expected,
                        "P4 checkpoint differs from durable calls or completed restarts", "P4_CHECKPOINT_MISMATCH")
        except BaseException:
            self.connection.close()
            raise

    def _formal_identity(self, trial_key):
        prefix = self.config["campaign_id"] + "::"
        require(isinstance(trial_key, str) and trial_key.startswith(prefix),
                "Formal trial must have the campaign namespace", "CAMPAIGN_IDENTITY_MISMATCH")
        original = trial_key[len(prefix):]
        require(original in self.registry, "Only registered formal slots are admitted", "P4_REGISTRY_MISMATCH")
        return prefix, self.registry[original]

    def reserve(self, call_record):
        require(isinstance(call_record, dict), "Call record must be an object", "CAMPAIGN_IDENTITY_MISMATCH")
        prefix, row = self._formal_identity(call_record.get("trial_key"))
        replay = row["policy"] == "FULL_RESTART"
        expected_logical = prefix + (row["parent_trial_key"] if replay else row["trial_key"])
        require(call_record.get("phase") == ("replay" if replay else "initial")
                and call_record.get("logical_run_key") == expected_logical,
                "Formal phase or original logical run differs", "CAMPAIGN_IDENTITY_MISMATCH")
        if replay:
            require(self.connection.execute("SELECT 1 FROM p3_restarts WHERE logical_run_key=?",
                    (expected_logical,)).fetchone() is not None,
                    "Replay requires a durable once-only admission", "RESTART_NOT_ADMITTED")
        return super().reserve(call_record)

    def reserve_restart(self, identity):
        require(isinstance(identity, dict), "Restart identity is incomplete", "CAMPAIGN_IDENTITY_MISMATCH")
        _, row = self._formal_identity(identity.get("logical_run_key"))
        require(row["policy"] == "BASE" and row["condition"] != "CLEAN",
                "Only a registered fault BASE may own a full restart", "CAMPAIGN_IDENTITY_MISMATCH")
        return super().reserve_restart(identity)

    def make_resume_checkpoint(self, completed_trial_keys):
        """Bind a caller's finalized workflow boundary to immutable ledger facts.

        The runner must additionally verify business commits and no in-progress
        trial before saving this proof. Settlement alone does not prove those.
        """
        require(isinstance(completed_trial_keys, list)
                and len(completed_trial_keys) in (14, 56, 112, 168),
                "Checkpoint must be an approved formal batch boundary", "P4_CHECKPOINT_MISMATCH")
        prefix = self.config["campaign_id"] + "::"
        expected_keys = [prefix + key for key in self.registry][:len(completed_trial_keys)]
        require(completed_trial_keys == expected_keys,
                "Checkpoint does not cover the original formal prefix", "P4_CHECKPOINT_MISMATCH")
        calls = self.calls()
        restarts = [json.loads(r[0]) for r in self.connection.execute("SELECT body FROM p3_restarts ORDER BY rowid")]
        require(all(c["status"] == "settled" and c["trial_key"] in completed_trial_keys for c in calls),
                "Checkpoint contains unfinished calls or trials", "P4_CHECKPOINT_MISMATCH")
        for admission in restarts:
            full_key = admission["logical_run_key"].removesuffix("__BASE") + "__FULL_RESTART"
            require(full_key in completed_trial_keys,
                    "Once-only restart lacks a finalized formal trial", "P4_CHECKPOINT_MISMATCH")
        value = dict(schema_version="p4-budget-resume-checkpoint-v1",
            campaign_id=self.config["campaign_id"], config_digest=digest(self.config),
            completed_trial_keys=deepcopy(completed_trial_keys),
            calls_digest=digest(calls), restart_admissions_digest=digest(restarts),
            all_calls_settled=True, expected_workflow_state="all_completed_trials_finalized_and_no_in_progress")
        value["checkpoint_digest"] = digest(value)
        return value

    def snapshot(self):
        value = super().snapshot()
        value["schema_version"] = "p4-budget-snapshot-v1"
        new = value["budget"]
        known = BASELINE_KNOWN_NANO_USD + new["known_cost_nano_usd"]
        held = BASELINE_HELD_NANO_USD + new["held_cost_nano_usd"]
        value["cumulative_budget"] = dict(baseline_calls=BASELINE_CALLS,
            cumulative_calls=BASELINE_CALLS + new["calls_dispatched"],
            cumulative_known_cost_nano_usd=known, held_cost_nano_usd=held,
            cumulative_known_plus_held_nano_usd=known + held,
            max_cost_nano_usd=GLOBAL_MAX_NANO_USD,
            remaining_after_known_and_held_nano_usd=max(0, GLOBAL_MAX_NANO_USD - known - held),
            old_unknown_reservation_released=False,
            basis="provider usage times pinned catalog; account debit unverified")
        return value
