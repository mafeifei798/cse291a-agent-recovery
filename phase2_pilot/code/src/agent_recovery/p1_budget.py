"""One durable offline campaign budget, outside all workflow/branch databases.

Only bundled fake-client calls are admitted. Monetary amounts use the existing
S6 *simulated* nano-USD profile; they are not TritonAI prices or real charges.
"""
from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
import sqlite3

from .contracts import ContractError, canonical_json, digest, require, utc_now


class CampaignLedger:
    def __init__(self, path, *, campaign_id="p1-development", call_cap=100,
                 slot_call_cap=5, logical_call_cap=10,
                 max_cost_nano_usd=10_000_000_000):
        require(all(type(v) is int and v > 0 for v in
                    (call_cap, slot_call_cap, logical_call_cap, max_cost_nano_usd)),
                "Invalid campaign limit", "CALL_CAP_EXCEEDED")
        require(slot_call_cap <= 5 and logical_call_cap <= 10,
                "P1 cannot enlarge frozen per-slot/per-run limits", "CALL_CAP_EXCEEDED")
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.ref = str(self.path)
        self.connection = sqlite3.connect(self.path, isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS p1_campaign (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                config TEXT NOT NULL, state TEXT NOT NULL, reason TEXT
            );
            CREATE TABLE IF NOT EXISTS p1_calls (
                call_id TEXT PRIMARY KEY, attempt_id TEXT UNIQUE NOT NULL,
                body TEXT NOT NULL, reservation_digest TEXT NOT NULL,
                settlement_digest TEXT
            );
            CREATE TABLE IF NOT EXISTS p1_requests (
                call_id TEXT PRIMARY KEY, body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS p1_inputs (
                call_id TEXT PRIMARY KEY, result_id TEXT UNIQUE NOT NULL,
                body TEXT NOT NULL, body_digest TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS p1_publications (
                result_id TEXT PRIMARY KEY, body_digest TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS p1_restart_admissions (
                source_run_id TEXT PRIMARY KEY, source_trial_key TEXT UNIQUE NOT NULL,
                request_digest TEXT NOT NULL, identity TEXT NOT NULL,
                state TEXT NOT NULL, receipt TEXT
            );
        """)
        config = dict(campaign_id=campaign_id, call_cap=call_cap,
                      slot_call_cap=slot_call_cap, logical_call_cap=logical_call_cap,
                      max_cost_nano_usd=max_cost_nano_usd, transport="offline_fake",
                      real_api_enabled=False, cost_kind="simulated_s6_profile")
        with self._transaction():
            old = self.connection.execute("SELECT * FROM p1_campaign").fetchone()
            if old:
                require(old["config"] == canonical_json(config),
                        "Persisted campaign settings differ", "CAMPAIGN_CONFIG_MISMATCH")
            else:
                self.connection.execute("INSERT INTO p1_campaign VALUES(1,?,'active',NULL)",
                                        (canonical_json(config),))
        self.config = config

    def close(self):
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @contextmanager
    def _transaction(self):
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.connection.commit()
        except BaseException as exc:
            self.connection.rollback()
            reason=getattr(exc,"campaign_stop_reason",None)
            if reason:
                self.stop_budget(reason)
            raise

    def _calls(self):
        return [json.loads(r[0]) for r in self.connection.execute("SELECT body FROM p1_calls ORDER BY rowid")]

    def preflight(self, trial_key, logical_run_key, *, worst_cost_nano_usd=0):
        row = self.connection.execute("SELECT * FROM p1_campaign").fetchone()
        if row["state"] == "stopped_budget":
            code="MONEY_CAP_EXCEEDED" if row["reason"]=="MONEY_CAP_EXCEEDED" else "CALL_CAP_EXCEEDED"
            raise ContractError(code,"Campaign stopped at its known budget limit")
        require(row["state"] == "active", "Campaign is quarantined", "UNKNOWN_SETTLEMENT")
        require(isinstance(trial_key, str) and trial_key and isinstance(logical_run_key, str)
                and logical_run_key, "Missing trial identity", "CAMPAIGN_IDENTITY_MISMATCH")
        calls = self._calls()
        require(not any(c["status"] == "reserved" for c in calls),
                "A pending campaign call must be reconciled before another dispatch", "UNKNOWN_SETTLEMENT")
        if len(calls) >= self.config["call_cap"]:
            self._budget_error("CALL_CAP_EXCEEDED","Campaign call cap exhausted")
        require(sum(c["trial_key"] == trial_key for c in calls) < self.config["slot_call_cap"],
                "Slot call cap exhausted", "CALL_CAP_EXCEEDED")
        require(sum(c["logical_run_key"] == logical_run_key for c in calls) < self.config["logical_call_cap"],
                "Initial plus replay cap exhausted", "CALL_CAP_EXCEEDED")
        committed = sum(c["known_cost_nano_usd"] + c["held_cost_nano_usd"] for c in calls)
        if committed + worst_cost_nano_usd > self.config["max_cost_nano_usd"]:
            self._budget_error("MONEY_CAP_EXCEEDED","Campaign simulated cost cap exhausted")

    def _budget_error(self, code, message):
        error=ContractError(code,message)
        error.campaign_stop_reason=code
        if not self.connection.in_transaction:
            self.stop_budget(code)
        raise error

    def stop_budget(self, reason):
        with self._transaction():
            self.connection.execute("UPDATE p1_campaign SET state='stopped_budget',reason=? WHERE state!='uncertain'",
                                    (str(reason),))

    def reserve_call(self, model_record, request, sidecar, *, trial_key,
                     logical_run_key, branch_id, phase):
        require(phase in ("initial", "replay"), "Unknown call phase", "CAMPAIGN_IDENTITY_MISMATCH")
        require(model_record["transport"] == "offline_fake" and model_record["simulated"] is True,
                "Campaign is fake-client only", "OFFLINE_ONLY")
        require(model_record["call_id"] == sidecar["call_id"]
                and model_record["result_id"] == sidecar["result_id"],
                "Call/input identity differs", "CAMPAIGN_IDENTITY_MISMATCH")
        reservation = dict(model_record=model_record, request=request, sidecar=sidecar,
                           trial_key=trial_key, logical_run_key=logical_run_key,
                           branch_id=branch_id, phase=phase)
        fingerprint = digest(reservation)
        with self._transaction():
            old = self.connection.execute("SELECT * FROM p1_calls WHERE call_id=?", (model_record["call_id"],)).fetchone()
            if old:
                require(old["reservation_digest"] == fingerprint,
                        "Repeated call ID has different inputs", "IDEMPOTENCY_MISMATCH")
                return json.loads(old["body"])
            self.preflight(trial_key, logical_run_key,
                           worst_cost_nano_usd=model_record["reserved_cost_nano_usd"])
            body = {**deepcopy(model_record), "trial_key":trial_key,
                    "logical_run_key":logical_run_key, "branch_id":branch_id,
                    "phase":phase, "attempt_id":sidecar["attempt_id"],
                    "dispatched":False, "publication_result_id":None}
            self.connection.execute("INSERT INTO p1_calls VALUES(?,?,?,?,NULL)",
                                    (body["call_id"], sidecar["attempt_id"], canonical_json(body), fingerprint))
            self.connection.execute("INSERT INTO p1_requests VALUES(?,?)", (body["call_id"], canonical_json(request)))
            self.connection.execute("INSERT INTO p1_inputs VALUES(?,?,?,?)",
                                    (body["call_id"], body["result_id"], canonical_json(sidecar), digest(sidecar)))
            return deepcopy(body)

    def mark_dispatched(self, call_id):
        with self._transaction():
            row = self.connection.execute("SELECT body FROM p1_calls WHERE call_id=?", (call_id,)).fetchone()
            require(row is not None, "Dispatch without persisted reserve", "LEDGER_PERSISTENCE_FAILED")
            body = json.loads(row[0])
            require(not body["dispatched"], "Do not dispatch a physical call twice", "CALL_ALREADY_DISPATCHED")
            require(body["status"] == "reserved", "Call already closed", "CALL_ALREADY_DISPATCHED")
            require(self.connection.execute("SELECT state FROM p1_campaign").fetchone()[0] == "active",
                    "Campaign paused before dispatch", "UNKNOWN_SETTLEMENT")
            body["dispatched"] = True
            self.connection.execute("UPDATE p1_calls SET body=? WHERE call_id=?", (canonical_json(body),call_id))

    def settle_call(self, call_id, model_record):
        fingerprint = digest(model_record)
        with self._transaction():
            row = self.connection.execute("SELECT * FROM p1_calls WHERE call_id=?", (call_id,)).fetchone()
            require(row is not None, "Settlement without reserve", "LEDGER_PERSISTENCE_FAILED")
            body = json.loads(row["body"])
            if row["settlement_digest"] is not None:
                require(row["settlement_digest"] == fingerprint, "Settlement changed", "IDEMPOTENCY_MISMATCH")
                return body
            require(body["dispatched"] and model_record["call_id"] == call_id
                    and model_record["result_id"] == body["result_id"],
                    "Settlement identity or dispatch differs", "CAMPAIGN_IDENTITY_MISMATCH")
            require(model_record["status"] != "reserved", "Unsettled model call", "UNKNOWN_SETTLEMENT")
            usage = model_record["usage"]
            if usage is not None:
                require(set(usage) == {"prompt_tokens","completion_tokens"}
                        and all(type(v) is int and v >= 0 for v in usage.values())
                        and usage["prompt_tokens"] <= 4000 and usage["completion_tokens"] <= 768,
                        "Campaign usage is invalid or above frozen caps", "TOKEN_CAP_EXCEEDED")
                require(model_record["known_cost_nano_usd"] == usage["prompt_tokens"]*400 + usage["completion_tokens"]*1600
                        and model_record["held_cost_nano_usd"] == 0,
                        "Simulated cost does not match known usage", "CAMPAIGN_ACCOUNTING_MISMATCH")
            else:
                require(model_record["known_cost_nano_usd"] == 0
                        and model_record["held_cost_nano_usd"] == body["reserved_cost_nano_usd"],
                        "Unknown usage must retain its reservation", "CAMPAIGN_ACCOUNTING_MISMATCH")
            body.update(deepcopy(model_record))
            self.connection.execute("UPDATE p1_calls SET body=?,settlement_digest=? WHERE call_id=?",
                                    (canonical_json(body),fingerprint,call_id))
            if body["usage"] is None or body["status"] == "timeout":
                self.connection.execute("UPDATE p1_campaign SET state='uncertain',reason=?",
                                        (body.get("error_code") or "UNKNOWN_SETTLEMENT",))
            return deepcopy(body)

    def record_publication(self, result):
        """Sync delivered output only after the caller re-reads the stored result."""
        fingerprint = digest(result)
        with self._transaction():
            previous = self.connection.execute("SELECT body_digest FROM p1_publications WHERE result_id=?",
                                               (result["result_id"],)).fetchone()
            if previous:
                require(previous[0] == fingerprint, "Publication changed", "IDEMPOTENCY_MISMATCH")
                return
            for recorded in result["model_calls"]:
                row = self.connection.execute("SELECT body FROM p1_calls WHERE call_id=?", (recorded["call_id"],)).fetchone()
                require(row is not None, "Publication lost its campaign call", "LEDGER_PERSISTENCE_FAILED")
                body = json.loads(row[0])
                require(all(body[k] == recorded[k] for k in recorded if k != "delivered_output"),
                        "Publication changed usage/cost/identity", "CAMPAIGN_IDENTITY_MISMATCH")
                body.update(delivered_output=deepcopy(recorded["delivered_output"]),
                            publication_result_id=result["result_id"])
                self.connection.execute("UPDATE p1_calls SET body=? WHERE call_id=?", (canonical_json(body),body["call_id"]))
            self.connection.execute("INSERT INTO p1_publications VALUES(?,?)", (result["result_id"],fingerprint))

    def pause(self, reason):
        with self._transaction():
            self.connection.execute("UPDATE p1_campaign SET state='uncertain',reason=?", (str(reason),))

    def sidecars(self, trial_key=None):
        bodies = []
        for row in self.connection.execute("SELECT body,body_digest FROM p1_inputs ORDER BY rowid"):
            body = json.loads(row[0])
            require(digest(body) == row[1], "Input sidecar was changed", "P1_INPUT_MISMATCH")
            if trial_key is None or body["trial_key"] == trial_key:
                bodies.append(body)
        return bodies

    def snapshot(self):
        row = self.connection.execute("SELECT * FROM p1_campaign").fetchone()
        calls = self._calls()
        known = sum(c["known_cost_nano_usd"] for c in calls)
        held = sum(c["held_cost_nano_usd"] for c in calls)
        return {"schema_version":"p1-offline-campaign-v1", "campaign_budget_ref":self.ref,
                "campaign_id":self.config["campaign_id"], "config":deepcopy(self.config),
                "status":row["state"], "pause_reason":row["reason"], "calls":calls,
                "reserved_call_ids":[c["call_id"] for c in calls if c["status"] == "reserved"],
                "uncertain_call_ids":[c["call_id"] for c in calls if c["status"] != "reserved" and
                                      (c["usage"] is None or c["status"] == "timeout")],
                "requests_by_call":{r[0]:json.loads(r[1]) for r in self.connection.execute("SELECT call_id,body FROM p1_requests ORDER BY rowid")},
                "restart_admissions":[dict(r) for r in self.connection.execute("SELECT source_run_id,source_trial_key,request_digest,state FROM p1_restart_admissions ORDER BY rowid")],
                "budget":{"call_cap":self.config["call_cap"], "calls_reserved_or_spent":len(calls),
                          "calls_dispatched":sum(c["dispatched"] for c in calls),
                          "calls_remaining":max(0,self.config["call_cap"]-len(calls)),
                          "known_input_tokens":sum((c["usage"] or {}).get("prompt_tokens",0) for c in calls),
                          "known_output_tokens":sum((c["usage"] or {}).get("completion_tokens",0) for c in calls),
                          "known_cost_nano_usd":known,"held_cost_nano_usd":held,
                          "remaining_cost_nano_usd":max(0,self.config["max_cost_nano_usd"]-known-held)},
                "transport":"offline_fake", "simulated":True, "real_api_requests":0,
                "real_cost_usd":None, "real_provider_pricing":"unbound"}


def reserve_restart_once(campaign_budget_ref, identity):
    """Reserve the original run globally, so exporting another scene cannot retry.

    The ledger already exists and is outside the copied scene. A partial write
    remains quarantined; no automatic crash recovery or second admission exists.
    """
    path=Path(campaign_budget_ref)
    require(path.is_file(), "Campaign ledger must already exist", "BUDGET_REFERENCE_MISMATCH")
    require(all(identity.get(k) for k in ("source_run_id","source_trial_key","scene_id",
            "scene_digest","restart_request_id","destination")),
            "Incomplete restart identity", "RESTART_IDENTITY_MISMATCH")
    fingerprint=digest(identity)
    with sqlite3.connect(path,isolation_level=None) as db:
        db.row_factory=sqlite3.Row
        db.execute("BEGIN IMMEDIATE")
        try:
            row=db.execute("SELECT config,state,reason FROM p1_campaign WHERE singleton=1").fetchone()
            require(row is not None and json.loads(row["config"])["transport"]=="offline_fake",
                    "Restart does not reference the offline campaign", "BUDGET_REFERENCE_MISMATCH")
            old=db.execute("SELECT * FROM p1_restart_admissions WHERE source_run_id=? OR source_trial_key=?",
                           (identity["source_run_id"],identity["source_trial_key"])).fetchone()
            if old:
                require(old["request_digest"]==fingerprint and old["identity"]==canonical_json(identity),
                        "Original run already owns its only restart", "RESTART_ROUND_LIMIT")
                require(old["state"]=="ready" and old["receipt"] is not None,
                        "Restart admission is incomplete; inspect before any dispatch", "UNCERTAIN_COMMIT")
                return {"status":"already_started","receipt":json.loads(old["receipt"])}
            if row["state"]=="stopped_budget":
                raise ContractError(row["reason"],"Known campaign budget stop prohibits a restart")
            require(row["state"]=="active", "Campaign is quarantined", "UNCERTAIN_CALL_SETTLEMENT")
            calls=[json.loads(r[0]) for r in db.execute("SELECT body FROM p1_calls")]
            require(not any(c["status"]=="reserved" or c["usage"] is None or c["status"]=="timeout" for c in calls),
                    "Campaign has unresolved consumption", "UNCERTAIN_CALL_SETTLEMENT")
            config=json.loads(row["config"])
            committed=sum(c["known_cost_nano_usd"]+c["held_cost_nano_usd"] for c in calls)
            code=("CALL_CAP_EXCEEDED" if len(calls)>=config["call_cap"] else
                  "MONEY_CAP_EXCEEDED" if committed+4000*400+768*1600>config["max_cost_nano_usd"] else None)
            if code:
                db.execute("UPDATE p1_campaign SET state='stopped_budget',reason=?",(code,))
                db.commit()
                return {"status":"blocked","reason_codes":[code]}
            db.execute("INSERT INTO p1_restart_admissions VALUES(?,?,?,?,'admitting',NULL)",
                       (identity["source_run_id"],identity["source_trial_key"],fingerprint,canonical_json(identity)))
            db.commit()
            return {"status":"reserved","request_digest":fingerprint}
        except BaseException:
            db.rollback()
            raise


def finish_restart_reservation(campaign_budget_ref, identity, receipt):
    """Persist the single outcome; conflict/uncertain outcomes do not free a retry."""
    with sqlite3.connect(campaign_budget_ref,isolation_level=None) as db:
        db.row_factory=sqlite3.Row
        db.execute("BEGIN IMMEDIATE")
        try:
            row=db.execute("SELECT * FROM p1_restart_admissions WHERE source_run_id=?",
                           (identity["source_run_id"],)).fetchone()
            require(row is not None and row["request_digest"]==digest(identity),
                    "Global restart reservation differs", "RESTART_IDENTITY_MISMATCH")
            if row["receipt"] is not None:
                require(row["receipt"]==canonical_json(receipt), "Restart receipt changed", "IDEMPOTENCY_MISMATCH")
            else:
                state="ready" if receipt.get("status")=="ready" else "blocked"
                db.execute("UPDATE p1_restart_admissions SET state=?,receipt=? WHERE source_run_id=?",
                           (state,canonical_json(receipt),identity["source_run_id"]))
            db.commit()
        except BaseException:
            db.rollback()
            raise
