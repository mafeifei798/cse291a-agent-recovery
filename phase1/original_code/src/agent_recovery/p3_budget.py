"""Durable P3 request admission and provider settlement, separate from workflow DBs.

This module never sends a request. ``mark_dispatched`` must commit before a
transport sends anything. A lost receipt or failed settlement keeps the complete
reservation, fences the campaign, and never authorizes an automatic retry.
"""
from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
import sqlite3

from .contracts import ContractError, canonical_json, digest, require, utc_now


DEFAULT_LIMITS = {
    "call_cap": 71, "input_token_cap": 284_000, "output_token_cap": 54_528,
    "max_cost_nano_usd": 1_000_000_000, "slot_call_cap": 5,
    "logical_call_cap": 10,
}
IDENTITY_FIELDS = ("call_id", "attempt_id", "trial_key", "logical_run_key",
                   "branch_id", "run_id", "result_id", "step_id")
GENERATED_FIELDS = {
    "schema_version", "status", "dispatched", "simulated", "input_tokens_reserved",
    "output_tokens_reserved", "reserved_cost_nano_usd", "known_cost_nano_usd",
    "held_cost_nano_usd", "usage", "provider_request_id", "reserved_at",
    "dispatched_at", "settled_at", "uncertainty_reason", "evidence",
}


def _nonnegative(value):
    return type(value) is int and value >= 0


def _usage(raw, normalized, *, input_cap, output_cap):
    """Validate provider usage independently of the transport's normalization."""
    require(isinstance(raw, dict) and isinstance(normalized, dict),
            "Provider usage is absent", "MISSING_PROVIDER_USAGE")
    prompt = raw.get("prompt_tokens")
    completion = raw.get("completion_tokens")
    total = raw.get("total_tokens")
    prompt_details = raw.get("prompt_tokens_details") or {}
    completion_details = raw.get("completion_tokens_details") or {}
    require(isinstance(prompt_details, dict) and isinstance(completion_details, dict),
            "Provider usage details must be objects", "INVALID_PROVIDER_USAGE")
    cached = prompt_details.get("cached_tokens", 0)
    reasoning = completion_details.get("reasoning_tokens", 0)
    values = (prompt, completion, total, cached, reasoning)
    require(all(_nonnegative(v) for v in values)
            and total == prompt + completion and cached <= prompt
            and reasoning <= completion,
            "Provider token fields are inconsistent", "INVALID_PROVIDER_USAGE")
    require(prompt <= input_cap and completion <= output_cap,
            "Actual usage exceeds the admitted token bounds", "TOKEN_CAP_EXCEEDED")
    expected = dict(prompt_tokens=prompt, completion_tokens=completion,
                    total_tokens=total, cached_input_tokens=cached,
                    reasoning_tokens=reasoning)
    require(all(normalized.get(k) == v and type(normalized.get(k)) is int
                for k, v in expected.items()),
            "Normalized usage differs from provider usage", "INVALID_PROVIDER_USAGE")
    if "raw" in normalized:
        require(normalized["raw"] == raw,
                "Normalized raw usage differs", "INVALID_PROVIDER_USAGE")
    return {**expected, "raw": deepcopy(raw)}


class DurableP3Budget:
    def __init__(self, path, *, campaign_id, binding, limits=None):
        require(isinstance(campaign_id, str) and campaign_id,
                "Missing campaign identity", "CAMPAIGN_IDENTITY_MISMATCH")
        require(isinstance(binding, dict), "Binding must be an object", "P3_BINDING_INVALID")
        self.binding = deepcopy(binding)
        for key in ("input_nano_usd_per_token", "output_nano_usd_per_token"):
            require(_nonnegative(binding.get(key)),
                    "Explicit integer provider rates are required", "P3_PRICING_UNVERIFIED")
        cached_rate = binding.get("cached_input_nano_usd_per_token")
        require(cached_rate is None or _nonnegative(cached_rate),
                "Invalid cached-input rate", "P3_PRICING_UNVERIFIED")
        require(cached_rate is None or cached_rate <= binding["input_nano_usd_per_token"],
                "A cached surcharge needs a separately reviewed admission model", "P3_PRICING_UNVERIFIED")
        require(isinstance(binding.get("price_evidence"), str) and binding["price_evidence"].strip(),
                "Provider pricing needs explicit evidence even when free", "P3_PRICING_UNVERIFIED")
        require(type(binding.get("simulated")) is bool,
                "Binding must identify simulated or real execution", "P3_BINDING_INVALID")
        require(binding["simulated"] or not binding["price_evidence"].startswith("fixture:"),
                "Fixture pricing cannot admit real execution", "P3_PRICING_UNVERIFIED")
        require(type(binding.get("max_input_tokens")) is int
                and 0 < binding["max_input_tokens"] <= 4000
                and type(binding.get("max_output_tokens")) is int
                and 0 < binding["max_output_tokens"] <= 768,
                "Binding token limits exceed P3", "TOKEN_CAP_EXCEEDED")
        configured = dict(DEFAULT_LIMITS)
        if limits is not None:
            require(isinstance(limits, dict) and set(limits) <= set(DEFAULT_LIMITS),
                    "Unknown campaign limit", "CAMPAIGN_CONFIG_MISMATCH")
            configured.update(limits)
        require(all(type(value) is int and 0 < value <= DEFAULT_LIMITS[key]
                    for key, value in configured.items()),
                "P3 limits may only shrink the frozen maxima", "CAMPAIGN_CONFIG_MISMATCH")
        self.config = dict(schema_version="p3-budget-v1", campaign_id=campaign_id,
                           binding=self.binding, binding_digest=digest(self.binding),
                           limits=configured)
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.ref = str(self.path)
        self._failed = False
        self.connection = sqlite3.connect(self.path, isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS p3_campaign (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                config TEXT NOT NULL, state TEXT NOT NULL, reason TEXT
            );
            CREATE TABLE IF NOT EXISTS p3_calls (
                call_id TEXT PRIMARY KEY, attempt_id TEXT UNIQUE NOT NULL,
                body TEXT NOT NULL, reservation_digest TEXT NOT NULL,
                settlement_digest TEXT
            );
            CREATE TABLE IF NOT EXISTS p3_receipts (
                call_id TEXT PRIMARY KEY, provider_request_id TEXT UNIQUE NOT NULL,
                raw_usage TEXT NOT NULL, normalized_usage TEXT NOT NULL,
                receipt_digest TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS p3_conflicts (
                id INTEGER PRIMARY KEY, call_id TEXT, body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS p3_restarts (
                logical_run_key TEXT PRIMARY KEY, source_run_id TEXT UNIQUE NOT NULL, body TEXT NOT NULL,
                request_digest TEXT NOT NULL
            );
        """)
        try:
            with self._transaction():
                previous = self.connection.execute("SELECT * FROM p3_campaign").fetchone()
                if previous:
                    require(previous["config"] == canonical_json(self.config),
                            "Persisted P3 binding or limits differ", "CAMPAIGN_CONFIG_MISMATCH")
                else:
                    self._write("INSERT INTO p3_campaign VALUES(1,?,'active',NULL)",
                                (canonical_json(self.config),))
            if previous and any(c["status"] in ("reserved", "dispatched") for c in self.calls()):
                self._pause_durable("REOPEN_WITH_PENDING_CALL")
            elif previous and self.connection.execute("SELECT 1 FROM p3_restarts LIMIT 1").fetchone():
                # A persisted once-only admission has no automatic continuation
                # protocol. This also covers a crash before its first model call.
                self._pause_durable("REOPEN_WITH_RESTART_HISTORY")
        except BaseException:
            self.connection.close()
            raise

    def close(self):
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _write(self, sql, params=()):
        """Single mutation hook also permits deterministic disk-failure tests."""
        return self.connection.execute(sql, params)

    @contextmanager
    def _transaction(self):
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            yield
            self.connection.commit()
        except BaseException as exc:
            if self.connection.in_transaction:
                self.connection.rollback()
            if isinstance(exc, sqlite3.Error):
                self._failed = True
                try:
                    self._pause_durable("LEDGER_PERSISTENCE_FAILED")
                except sqlite3.Error:
                    pass  # Durable pending reserves remain; reopen fences them.
            elif getattr(exc, "p3_pause", False):
                self._pause_durable(exc.code, call_id=getattr(exc, "p3_call_id", None),
                                    conflict=getattr(exc, "p3_conflict", None),
                                    stopped_budget=getattr(exc, "p3_budget", False))
            raise

    def _error(self, code, message, *, call_id=None, conflict=None, budget=False):
        error = ContractError(code, message)
        error.p3_pause = True
        error.p3_call_id = call_id
        error.p3_conflict = conflict
        error.p3_budget = budget
        raise error

    def _pause_durable(self, reason, *, call_id=None, conflict=None, stopped_budget=False):
        """Use raw SQL after rollback so a failed mutation cannot release a hold."""
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            state = "stopped_budget" if stopped_budget else "quarantined"
            self.connection.execute("UPDATE p3_campaign SET state=?,reason=?", (state, str(reason)))
            for row in self.connection.execute("SELECT call_id,body FROM p3_calls").fetchall():
                body = json.loads(row["body"])
                if body["status"] in ("reserved", "dispatched") or (
                        row["call_id"] == call_id and (body["status"] != "settled" or conflict is not None)):
                    body.update(status="uncertain", uncertainty_reason=str(reason),
                                held_cost_nano_usd=body["reserved_cost_nano_usd"])
                    self.connection.execute("UPDATE p3_calls SET body=? WHERE call_id=?",
                                            (canonical_json(body), row["call_id"]))
            if conflict is not None:
                self.connection.execute("INSERT INTO p3_conflicts(call_id,body) VALUES(?,?)",
                                        (call_id, canonical_json(conflict)))
            self.connection.commit()
        except BaseException:
            self._failed = True
            self.connection.rollback()
            raise

    def _assert_active(self):
        row = self.connection.execute("SELECT state,reason FROM p3_campaign").fetchone()
        require(not self._failed and row["state"] == "active",
                "P3 campaign is fenced; explicit reconciliation is required", "P3_CAMPAIGN_PAUSED")

    def calls(self):
        return [json.loads(row[0]) for row in self.connection.execute(
            "SELECT body FROM p3_calls ORDER BY rowid")]

    def reserve(self, call_record):
        require(isinstance(call_record, dict), "Call record must be an object", "CAMPAIGN_IDENTITY_MISMATCH")
        record = deepcopy(call_record)
        require(not (set(record) & GENERATED_FIELDS),
                "Call admission cannot supply ledger-owned fields", "CAMPAIGN_IDENTITY_MISMATCH")
        require(all(isinstance(record.get(k), str) and record[k] for k in IDENTITY_FIELDS),
                "Missing P3 call identity", "CAMPAIGN_IDENTITY_MISMATCH")
        require(record.get("phase") in ("initial", "replay", "probe"),
                "Invalid P3 call phase", "CAMPAIGN_IDENTITY_MISMATCH")
        upper = record.get("input_token_upper_bound")
        require(type(upper) is int and 0 < upper <= self.binding["max_input_tokens"],
                "Input token upper bound must fit the verified binding", "TOKEN_CAP_EXCEEDED")
        require(isinstance(record.get("request"), dict) and isinstance(record.get("sidecar"), dict),
                "Request and frozen input sidecar must be recorded", "CAMPAIGN_IDENTITY_MISMATCH")
        fingerprint = digest(record)
        call_id = record["call_id"]
        output = self.binding["max_output_tokens"]
        reserved = upper * self.binding["input_nano_usd_per_token"] + output * self.binding["output_nano_usd_per_token"]
        with self._transaction():
            old = self.connection.execute("SELECT * FROM p3_calls WHERE call_id=?", (call_id,)).fetchone()
            if old:
                if old["reservation_digest"] != fingerprint:
                    self._error("IDEMPOTENCY_MISMATCH", "Call ID reused with different inputs",
                                call_id=call_id, conflict={"kind":"reservation", "record":record})
                return json.loads(old["body"])
            self._assert_active()
            calls = self.calls()
            if any(c["status"] in ("reserved", "dispatched", "uncertain") for c in calls):
                self._error("UNKNOWN_SETTLEMENT", "Pending request blocks another reservation")
            limits = self.config["limits"]
            cap_tests = (
                (len(calls) + 1 <= limits["call_cap"], "CALL_CAP_EXCEEDED"),
                (sum(c["trial_key"] == record["trial_key"] for c in calls) + 1 <= limits["slot_call_cap"], "SLOT_CALL_CAP_EXCEEDED"),
                (sum(c["logical_run_key"] == record["logical_run_key"] for c in calls) + 1 <= limits["logical_call_cap"], "LOGICAL_CALL_CAP_EXCEEDED"),
                (sum((c["usage"]["prompt_tokens"] if c["status"] == "settled" else c["input_tokens_reserved"]) for c in calls) + upper <= limits["input_token_cap"], "INPUT_TOKEN_CAP_EXCEEDED"),
                (sum((c["usage"]["completion_tokens"] if c["status"] == "settled" else c["output_tokens_reserved"]) for c in calls) + output <= limits["output_token_cap"], "OUTPUT_TOKEN_CAP_EXCEEDED"),
                (sum(c["known_cost_nano_usd"] + c["held_cost_nano_usd"] for c in calls) + reserved <= limits["max_cost_nano_usd"], "MONEY_CAP_EXCEEDED"),
            )
            for passed, code in cap_tests:
                if not passed:
                    self._error(code, "Next request exceeds the durable P3 budget", budget=True)
            require(not self.connection.execute("SELECT 1 FROM p3_calls WHERE attempt_id=?", (record["attempt_id"],)).fetchone(),
                    "Attempt ID already has a physical request", "IDEMPOTENCY_MISMATCH")
            body = {**record, "schema_version":"p3-call-v1", "status":"reserved",
                    "dispatched":False, "simulated":self.binding["simulated"],
                    "input_tokens_reserved":upper, "output_tokens_reserved":output,
                    "reserved_cost_nano_usd":reserved, "known_cost_nano_usd":0,
                    "held_cost_nano_usd":reserved, "usage":None,
                    "provider_request_id":None, "reserved_at":utc_now(),
                    "dispatched_at":None, "settled_at":None,
                    "uncertainty_reason":None, "evidence":None}
            self._write("INSERT INTO p3_calls VALUES(?,?,?,?,NULL)",
                        (call_id, record["attempt_id"], canonical_json(body), fingerprint))
            return deepcopy(body)

    def mark_dispatched(self, call_id):
        with self._transaction():
            self._assert_active()
            row = self.connection.execute("SELECT body FROM p3_calls WHERE call_id=?", (call_id,)).fetchone()
            require(row is not None, "Dispatch needs a durable reservation", "LEDGER_PERSISTENCE_FAILED")
            body = json.loads(row[0])
            if body["dispatched"] or body["status"] != "reserved":
                self._error("CALL_ALREADY_DISPATCHED", "A physical request cannot be sent twice", call_id=call_id)
            body.update(dispatched=True, status="dispatched", dispatched_at=utc_now())
            self._write("UPDATE p3_calls SET body=? WHERE call_id=?", (canonical_json(body), call_id))
            return deepcopy(body)

    def settle(self, call_id, *, provider_request_id, raw_usage, normalized_usage, evidence=None):
        require(evidence is None or isinstance(evidence, dict),
                "Call evidence must be an object", "P3_EVIDENCE_INVALID")
        attempted = dict(provider_request_id=provider_request_id, raw_usage=raw_usage,
                         normalized_usage=normalized_usage)
        fingerprint = digest(attempted)
        with self._transaction():
            row = self.connection.execute("SELECT * FROM p3_calls WHERE call_id=?", (call_id,)).fetchone()
            require(row is not None, "Settlement has no reservation", "LEDGER_PERSISTENCE_FAILED")
            body = json.loads(row["body"])
            if row["settlement_digest"] is not None:
                if row["settlement_digest"] != fingerprint:
                    self._error("CONFLICTING_PROVIDER_RECEIPT", "Provider settlement changed",
                                call_id=call_id, conflict={"kind":"settlement", **attempted})
                return body
            require(body["dispatched"], "Provider receipt arrived before dispatch", "CAMPAIGN_IDENTITY_MISMATCH")
            state = self.connection.execute("SELECT state FROM p3_campaign").fetchone()[0]
            if state != "active" or body["status"] != "dispatched":
                self._error("LATE_PROVIDER_RECEIPT", "Late receipt cannot release an uncertain hold",
                            call_id=call_id, conflict={"kind":"late_receipt", **attempted})
            try:
                require(isinstance(provider_request_id, str) and provider_request_id,
                        "Missing provider request identity", "MISSING_PROVIDER_RECEIPT")
                usage = _usage(raw_usage, normalized_usage, input_cap=body["input_tokens_reserved"],
                               output_cap=body["output_tokens_reserved"])
            except ContractError as exc:
                self._error(exc.code, str(exc), call_id=call_id,
                            conflict={"kind":"invalid_receipt", **attempted})
            duplicate = self.connection.execute("SELECT call_id FROM p3_receipts WHERE provider_request_id=?",
                                                (provider_request_id,)).fetchone()
            if duplicate:
                self._error("CONFLICTING_PROVIDER_RECEIPT", "One provider receipt cannot settle two calls",
                            call_id=call_id, conflict={"kind":"reused_provider_id", **attempted})
            cache_rate = self.binding.get("cached_input_nano_usd_per_token")
            if cache_rate is None:
                cache_rate = self.binding["input_nano_usd_per_token"]
            cost = ((usage["prompt_tokens"] - usage["cached_input_tokens"]) * self.binding["input_nano_usd_per_token"]
                    + usage["cached_input_tokens"] * cache_rate
                    + usage["completion_tokens"] * self.binding["output_nano_usd_per_token"])
            body.update(status="settled", usage=usage, provider_request_id=provider_request_id,
                        known_cost_nano_usd=cost, held_cost_nano_usd=0, settled_at=utc_now())
            if evidence is not None:
                body["evidence"] = deepcopy(evidence)
            self._write("INSERT INTO p3_receipts VALUES(?,?,?,?,?)",
                        (call_id, provider_request_id, canonical_json(raw_usage),
                         canonical_json(normalized_usage), fingerprint))
            self._write("UPDATE p3_calls SET body=?,settlement_digest=? WHERE call_id=?",
                        (canonical_json(body), fingerprint, call_id))
            return deepcopy(body)

    def attach_evidence(self, call_id, evidence):
        require(isinstance(evidence, dict), "Call evidence must be an object", "P3_EVIDENCE_INVALID")
        with self._transaction():
            row = self.connection.execute("SELECT body FROM p3_calls WHERE call_id=?", (call_id,)).fetchone()
            require(row is not None, "Evidence has no reservation", "LEDGER_PERSISTENCE_FAILED")
            body = json.loads(row[0])
            if body["evidence"] is not None and body["evidence"] != evidence:
                self._error("CONFLICTING_CALL_EVIDENCE", "Call evidence changed", call_id=call_id,
                            conflict={"kind":"evidence", "evidence":evidence})
            body["evidence"] = deepcopy(evidence)
            self._write("UPDATE p3_calls SET body=? WHERE call_id=?", (canonical_json(body), call_id))
            return deepcopy(body)

    def quarantine(self, call_id, reason):
        require(isinstance(reason, str) and reason, "Missing quarantine reason", "P3_EVIDENCE_INVALID")
        if call_id is not None:
            require(self.connection.execute("SELECT 1 FROM p3_calls WHERE call_id=?", (call_id,)).fetchone(),
                    "Unknown quarantined call", "CAMPAIGN_IDENTITY_MISMATCH")
        self._pause_durable(reason, call_id=call_id)
        return self.snapshot()

    def reserve_restart(self, identity):
        """Admit a single complete replay without cloning/resetting the ledger.

        The first committed admission owns the replay. An exact repeated notice
        returns ``already_started`` and must not launch another workflow.
        """
        require(isinstance(identity, dict)
                and all(isinstance(identity.get(key), str) and identity[key]
                        for key in ("logical_run_key", "source_run_id", "scene_digest", "restart_request_id"))
                and isinstance(identity.get("destination"), (str, dict))
                and bool(identity["destination"]),
                "Restart identity is incomplete", "CAMPAIGN_IDENTITY_MISMATCH")
        request = deepcopy(identity)
        fingerprint = digest(request)
        logical_key = request["logical_run_key"]
        with self._transaction():
            old = self.connection.execute("SELECT * FROM p3_restarts WHERE logical_run_key=?",
                                          (logical_key,)).fetchone()
            if old:
                if old["request_digest"] != fingerprint:
                    self._error("RESTART_ALREADY_ADMITTED", "Logical run already owns its only restart",
                                conflict={"kind":"restart", "identity":request})
                return {**json.loads(old["body"]), "status":"already_started"}
            same_source = self.connection.execute("SELECT logical_run_key FROM p3_restarts WHERE source_run_id=?",
                                                  (request["source_run_id"],)).fetchone()
            if same_source:
                self._error("RESTART_ALREADY_ADMITTED", "Source run already owns its only restart",
                            conflict={"kind":"restart_source_clone", "identity":request})
            self._assert_active()
            require(not any(c["status"] != "settled" for c in self.calls()),
                    "Restart cannot bypass an uncertain provider request", "UNKNOWN_SETTLEMENT")
            body = {**request, "status":"reserved", "reserved_at":utc_now()}
            self._write("INSERT INTO p3_restarts VALUES(?,?,?,?)",
                        (logical_key, request["source_run_id"], canonical_json(body), fingerprint))
            return deepcopy(body)

    def snapshot(self):
        row = self.connection.execute("SELECT * FROM p3_campaign").fetchone()
        calls = self.calls()
        known = sum(c["known_cost_nano_usd"] for c in calls)
        held = sum(c["held_cost_nano_usd"] for c in calls)
        settled = [c for c in calls if c["status"] == "settled"]
        pending = [c for c in calls if c["status"] != "settled"]
        limits = self.config["limits"]
        budget = dict(calls_reserved_or_spent=len(calls), calls_dispatched=sum(c["dispatched"] for c in calls),
                      calls_remaining=max(0, limits["call_cap"] - len(calls)),
                      known_input_tokens=sum(c["usage"]["prompt_tokens"] for c in settled),
                      known_output_tokens=sum(c["usage"]["completion_tokens"] for c in settled),
                      held_input_tokens=sum(c["input_tokens_reserved"] for c in pending),
                      held_output_tokens=sum(c["output_tokens_reserved"] for c in pending),
                      known_cost_nano_usd=known, held_cost_nano_usd=held,
                      remaining_cost_nano_usd=max(0, limits["max_cost_nano_usd"] - known - held))
        return dict(schema_version="p3-budget-snapshot-v1", campaign_budget_ref=self.ref,
                    campaign_id=self.config["campaign_id"], config=deepcopy(self.config),
                    status=row["state"], pause_reason=row["reason"], calls=calls, budget=budget,
                    reserved_call_ids=[c["call_id"] for c in calls if c["status"] == "reserved"],
                    uncertain_call_ids=[c["call_id"] for c in calls if c["status"] == "uncertain"],
                    restart_admissions=[json.loads(r[0]) for r in self.connection.execute(
                        "SELECT body FROM p3_restarts ORDER BY rowid")],
                    simulated=self.binding["simulated"],
                    real_api_requests=0 if self.binding["simulated"] else budget["calls_dispatched"],
                    real_cost_usd=None if self.binding["simulated"] else known / 1_000_000_000)
