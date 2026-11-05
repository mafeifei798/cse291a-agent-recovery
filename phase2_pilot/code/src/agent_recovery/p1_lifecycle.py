"""P1-only terminal-scene freeze and one full restart, without fake notices.

The source SQLite backup is immutable. Admission receipts live beside that
backup, not inside it; late tool delivery audit is owned by the runner outside
the scene. The campaign ledger is referenced, never copied or reset.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from copy import deepcopy
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from .contracts import STEPS, canonical_json, digest, require, validate_id
from .p1_budget import reserve_restart_once, finish_restart_reservation
from .recovery_store import backup_database
from .store import Store


def _id(value):
    return str(uuid5(NAMESPACE_URL, "agent-recovery:p1:" + value))


def _write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _hash_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class P1Store(Store):
    """Opt-in recovery admission; the legacy Store contract stays unchanged.

    Reuse the existing invalidation and conditional compensation transactions,
    supplying their exact current recovery identity from a P1 table. No row is
    inserted into ``notices`` or legacy ``recoveries``.
    """

    def __init__(self, path):
        super().__init__(path)
        self.connection.execute("""CREATE TABLE IF NOT EXISTS p1_restart_control (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1), recovery_id TEXT UNIQUE,
            trial_id TEXT UNIQUE, request_id TEXT UNIQUE, body TEXT NOT NULL)""")

    def _p1_row(self, recovery_id):
        return self.connection.execute("""SELECT recovery_id, trial_id,
            request_id AS notice_id, 'full_restart' AS policy, body
            FROM p1_restart_control WHERE recovery_id=?""", (recovery_id,)).fetchone()

    def _admitted(self, run, recovery_id):
        if recovery_id is not None and self._p1_row(recovery_id) is not None:
            return run["mode"] == "recovering"
        return super()._admitted(run, recovery_id)

    def _assert_recovery(self, recovery_id, active=True):
        validate_id(recovery_id)
        row = self._p1_row(recovery_id)
        if row is None:
            return super()._assert_recovery(recovery_id, active)
        if active:
            require(self._run()["mode"] == "recovering", "P1 restart is closed", "STALE_ATTEMPT")
        return row

    def admit_p1_restart(self, recovery_id, trial_key, request_id):
        with self._transaction(write=True):
            require(self._run()["mode"] == "terminal", "Initial run is not terminal", "UNKNOWN_TERMINAL_STATE")
            require(not self.connection.execute("SELECT 1 FROM p1_restart_control").fetchone(),
                    "Only one P1 restart is allowed", "RESTART_ROUND_LIMIT")
            body = {"recovery_id": recovery_id, "trial_id": trial_key,
                    "notice_id": request_id, "policy": "full_restart", "phase": "planning",
                    "engine_status": "running", "report": None}
            self.connection.execute("INSERT INTO p1_restart_control VALUES(1,?,?,?,?)",
                                    (recovery_id, trial_key, request_id, canonical_json(body)))
            self.connection.execute("UPDATE runs SET mode='recovering'")
            self._event("recovery", recovery_id, "p1_begin_full_restart", [recovery_id])

    def begin_attempt(self, run_id, step_id, parent_result_ids, recovery_id=None):
        if recovery_id is not None and self._p1_row(recovery_id) is not None:
            # P1 has one serial five-step replay, not a general retry engine.
            previous = self.connection.execute("""SELECT attempts.step_id,
                attempts.result_id FROM attempts JOIN attempt_context USING(token)
                WHERE attempt_context.recovery_id=? ORDER BY attempts.rowid""", (recovery_id,)).fetchall()
            require(len(previous) < len(STEPS), "Restart step limit reached", "RESTART_ROUND_LIMIT")
            require(step_id == STEPS[len(previous)], "Restart must run the five fixed steps once", "INVALID_PARENT")
            require(all(self._result(row["result_id"])["execution_status"] == "success" for row in previous),
                    "Replay stopped after a failed step", "STALE_ATTEMPT")
        return super().begin_attempt(run_id, step_id, parent_result_ids, recovery_id)

    def finish_p1_restart(self, recovery_id, report):
        with self._transaction(write=True):
            row = self._assert_recovery(recovery_id)
            require(not self.connection.execute("SELECT 1 FROM attempts WHERE status='active'").fetchone(),
                    "Restart still has active work", "ACTIVE_ATTEMPT")
            body = json.loads(row["body"])
            body.update(phase="done", engine_status=report.get("status", "completed"), report=deepcopy(report))
            self.connection.execute("UPDATE p1_restart_control SET body=? WHERE recovery_id=?",
                                    (canonical_json(body), recovery_id))
            self.connection.execute("UPDATE runs SET mode='terminal'")
            self._event("recovery", recovery_id, "p1_finish_full_restart", [recovery_id])

    def quarantine(self, reason):
        """Fence uncertain settlement without inventing an execution result."""
        with self._transaction(write=True):
            ids = [row[0] for row in self.connection.execute(
                "SELECT result_id FROM attempts WHERE status='active' ORDER BY rowid")]
            self.connection.execute("UPDATE attempts SET status='uncertain' WHERE status='active'")
            if self._run()["mode"] != "uncertain":
                self.connection.execute("UPDATE runs SET mode='uncertain'")
                self._event("run", self._run()["run_id"], "p1_quarantine", ids)
            return {"status": "uncertain", "reason": str(reason), "fenced_result_ids": ids}


class P1Lifecycle:
    @staticmethod
    def _campaign_reasons(snapshot):
        require(isinstance(snapshot, dict), "Campaign snapshot is required", "UNCERTAIN_CALL_SETTLEMENT")
        budget = snapshot.get("budget", {})
        uncertain = (snapshot.get("campaign_pause", False) or snapshot.get("paused", False)
                     or snapshot.get("unknown_call_ids", []) or snapshot.get("uncertain_call_ids", [])
                     or snapshot.get("reserved_call_ids", []) or snapshot.get("status") == "uncertain"
                     or snapshot.get("calls_reserved", 0) or budget.get("unknown_usage_calls", 0)
                     or snapshot.get("settlement_state") in ("unknown", "uncertain"))
        calls = snapshot.get("calls", [])
        uncertain = uncertain or any(call.get("status") in ("reserved", "settlement_unknown")
                                     or ("usage" in call and call["usage"] is None) for call in calls)
        if uncertain:
            return ["UNCERTAIN_CALL_SETTLEMENT"]
        if snapshot.get("status") == "stopped_budget":
            reason = snapshot.get("pause_reason")
            return [reason] if reason in ("CALL_CAP_EXCEEDED", "MONEY_CAP_EXCEEDED") else ["UNCERTAIN_CALL_SETTLEMENT"]
        return []

    @staticmethod
    def _terminal_reasons(store, snapshot):
        if any(item["status"] == "active" for item in snapshot["attempts"]):
            return ["ACTIVE_ATTEMPT"]
        if snapshot["run_state"] == "uncertain" or any(item["status"] == "uncertain" for item in snapshot["attempts"]):
            return ["UNCERTAIN_COMMIT"]
        if snapshot["run_state"] != "terminal":
            return ["UNKNOWN_TERMINAL_STATE"]
        if (store.connection.execute("SELECT 1 FROM sqlite_master WHERE name='p1_restart_control'").fetchone()
                and store.connection.execute("SELECT 1 FROM p1_restart_control").fetchone()):
            return ["RESTART_ROUND_LIMIT"]
        calls = store.model_accounting_snapshot()["calls"]
        if any(call["status"] == "reserved" or call["usage"] is None for call in calls):
            return ["UNCERTAIN_CALL_SETTLEMENT"]
        return []

    @staticmethod
    def _fault_matches(store, fault_identity):
        require(isinstance(fault_identity, dict) and fault_identity.get("condition") in ("ERR", "ADV", "TMO", "STL"),
                "Invalid P1 fault identity", "SCENE_IDENTITY_MISMATCH")
        validate_id(fault_identity.get("event_id"))
        attempt_id = fault_identity.get("attempt_id") or fault_identity.get("failed_attempt_id")
        row = store.connection.execute("SELECT * FROM attempts WHERE token=?", (attempt_id,)).fetchone()
        require(row is not None and row["status"] == "closed"
                and row["step_id"] == fault_identity.get("step_id"),
                "Fault target is not the exact closed attempt", "SCENE_IDENTITY_MISMATCH")
        result = store.get_result(row["result_id"])
        if fault_identity["condition"] == "TMO":
            require(fault_identity.get("faulty_result_id") is None
                    and fault_identity.get("failed_attempt_id") == attempt_id
                    and result["execution_status"] == "timeout"
                    and result["error"]["code"] == "TOOL_TIMEOUT"
                    and result["model_calls"] == [] and result["payload"] is None
                    and result["effect_ids"] == [],
                    "Controlled tool timeout identity is invalid", "SCENE_IDENTITY_MISMATCH")
        elif fault_identity.get("faulty_result_id") is not None:
            require(fault_identity["faulty_result_id"] == result["result_id"]
                    and result["execution_status"] == "success",
                    "Successful fault identity differs", "SCENE_IDENTITY_MISMATCH")

    def freeze(self, store, destination, ctx, fault_identity, campaign_snapshot):
        destination = Path(destination)
        require(isinstance(ctx, dict) and all(ctx.get(key) for key in
                ("source_trial_key", "recovery_trial_key", "campaign_budget_ref")),
                "Incomplete freeze context", "SCENE_IDENTITY_MISMATCH")
        require(isinstance(campaign_snapshot, dict)
                and campaign_snapshot.get("campaign_budget_ref") == ctx["campaign_budget_ref"],
                "Freeze references a different campaign ledger", "BUDGET_REFERENCE_MISMATCH")
        identity = {key: deepcopy(ctx.get(key)) for key in (
            "source_trial_key", "recovery_trial_key", "campaign_budget_ref", "task_id", "task_digest",
            "branch_id", "pending_delivery_ref", "freeze_monotonic_s", "frozen_clock_ms")}
        request_digest = digest({"ctx": identity, "fault_identity": fault_identity})
        if destination.exists():
            receipt = self._verify_scene(destination)
            require(receipt["request_digest"] == request_digest, "Freeze identity changed", "SCENE_IDENTITY_MISMATCH")
            require(digest(store.snapshot_run()) == receipt["snapshot_digest"],
                    "Live scene changed after freeze", "SCENE_DIGEST_MISMATCH")
            return receipt
        snapshot = store.snapshot_run()
        reasons = self._terminal_reasons(store, snapshot) + self._campaign_reasons(campaign_snapshot)
        if reasons:
            return {"status": "uncertain" if any("UNCERTAIN" in reason for reason in reasons) else "blocked",
                    "reason_codes": reasons, "scene_id": None, "scene_digest": None}
        self._fault_matches(store, fault_identity)
        destination.mkdir(parents=True, exist_ok=False)
        with sqlite3.connect(destination / "scene.sqlite") as target:
            store.connection.backup(target)
        # Derive immutable material from the backup, not a second live read.
        with Store(destination / "scene.sqlite") as saved:
            frozen_snapshot = saved.snapshot_run()
            accounting = saved.model_accounting_snapshot()
            attempts = [dict(row) for row in saved.connection.execute("SELECT * FROM attempts ORDER BY rowid")]
        require(frozen_snapshot == snapshot, "Freeze changed during backup", "SCENE_DIGEST_MISMATCH")
        successful = [result["result_id"] for result in snapshot["results"] if result["execution_status"] == "success"]
        failed_attempts = [row["token"] for row in attempts if any(
            result["result_id"] == row["result_id"] and result["execution_status"] != "success" for result in snapshot["results"])]
        scene = {"p1_schema_version": "p1.0", "scene_id": _id(request_digest),
                 "scene_kind": "completed_run" if any(result["step_id"] == "execute" and
                    result["execution_status"] == "success" for result in snapshot["results"]) else "partial_failure",
                 "ctx": identity, "fault_identity": deepcopy(fault_identity), "snapshot": frozen_snapshot,
                 "attempts": attempts, "model_accounting": accounting,
                 "campaign_budget_ref": ctx["campaign_budget_ref"],
                 "campaign_snapshot_digest": digest(campaign_snapshot)}
        _write(destination / "scene.json", scene)
        receipt = {"status": "frozen", "scene_id": scene["scene_id"], "scene_digest": digest(scene),
                   "scene_kind": scene["scene_kind"], "run_id": store.runtime_view()["run_id"],
                   "branch_id": ctx.get("branch_id"), "source_trial_key": ctx["source_trial_key"],
                   "campaign_budget_ref": ctx["campaign_budget_ref"], "request_digest": request_digest,
                   "snapshot_digest": digest(frozen_snapshot), "database_digest": _hash_file(destination / "scene.sqlite"),
                   "successful_result_ids": successful, "failed_attempt_ids": failed_attempts,
                   "effect_ids": [effect["effect_id"] for effect in snapshot["effects"]],
                   "freeze_monotonic_s": ctx.get("freeze_monotonic_s"),
                   "frozen_clock_ms": ctx.get("frozen_clock_ms"), "reason_codes": ["KNOWN_TERMINAL_NO_ACTIVE"]}
        _write(destination / "freeze_receipt.json", receipt)
        return receipt

    @staticmethod
    def _verify_scene(scene_dir):
        receipt = _read(scene_dir / "freeze_receipt.json")
        scene = _read(scene_dir / "scene.json")
        require(receipt["scene_digest"] == digest(scene)
                and receipt["database_digest"] == _hash_file(scene_dir / "scene.sqlite")
                and receipt["snapshot_digest"] == digest(scene["snapshot"]),
                "Frozen scene content changed", "SCENE_DIGEST_MISMATCH")
        return receipt

    def begin_restart(self, scene_dir, dest, ctx, checker_decision, drain_receipt,
                      restart_request_id, campaign_snapshot):
        scene_dir, dest = Path(scene_dir), Path(dest)
        validate_id(restart_request_id)
        frozen = self._verify_scene(scene_dir)
        scene = _read(scene_dir / "scene.json")
        require(ctx.get("source_trial_key") == scene["ctx"]["source_trial_key"]
                and ctx.get("recovery_trial_key") == scene["ctx"]["recovery_trial_key"],
                "Restart slot differs", "RESTART_IDENTITY_MISMATCH")
        require(ctx.get("campaign_budget_ref") == frozen["campaign_budget_ref"]
                and campaign_snapshot.get("campaign_budget_ref", frozen["campaign_budget_ref"]) == frozen["campaign_budget_ref"],
                "Campaign ledger reference changed", "BUDGET_REFERENCE_MISMATCH")
        require(ctx.get("requested_recovery_round", 1) == 1,
                "Only one restart round is allowed", "RESTART_ROUND_LIMIT")
        request_digest = digest({"scene_digest": frozen["scene_digest"], "ctx": {
            key: ctx.get(key) for key in ("source_trial_key", "recovery_trial_key", "campaign_budget_ref")},
            "restart_request_id": restart_request_id, "destination": str(dest.resolve())})
        # This local file is an audit receipt only. The external campaign ledger
        # owns admission globally, including across multiple scene exports.
        admission_path = scene_dir / "restart_admission.json"
        reasons = self._campaign_reasons(campaign_snapshot)
        if reasons:
            return {"status": "uncertain" if any("UNCERTAIN" in reason for reason in reasons) else "blocked",
                    "reason_codes": reasons}
        if not (checker_decision.get("restart_eligible") is True
                and checker_decision.get("correctness") == "incorrect"
                and checker_decision.get("terminal_certain") is True):
            return {"status": "blocked", "reason_codes": ["RESTART_NOT_ELIGIBLE"]}
        require(checker_decision.get("fault_identity") == scene["fault_identity"],
                "Checker selected a different fault", "RESTART_IDENTITY_MISMATCH")
        pending = scene["ctx"].get("pending_delivery_ref")
        if scene["fault_identity"]["condition"] == "TMO":
            valid_drain = (isinstance(drain_receipt, dict)
                and drain_receipt.get("scene_id") == frozen["scene_id"]
                and drain_receipt.get("scene_digest") == frozen["scene_digest"]
                and drain_receipt.get("drain_complete_after_frozen") is True
                and drain_receipt.get("scene_modified") is False
                and pending is not None and pending in drain_receipt.get("drained_delivery_ids", [])
                and scene["fault_identity"]["failed_attempt_id"] in drain_receipt.get("closed_attempt_ids", []))
            if valid_drain:
                frozen_at = frozen.get("freeze_monotonic_s")
                drained_at = drain_receipt.get("monotonic_s")
                if drained_at is None and drain_receipt.get("completed_clock_ms") is not None:
                    drained_at = drain_receipt["completed_clock_ms"] / 1000
                valid_drain = (frozen_at is not None and drained_at is not None and drained_at > frozen_at)
            if not valid_drain:
                return {"status": "blocked", "reason_codes": ["DRAIN_INCOMPLETE"]}
        global_identity = {"source_run_id": frozen["run_id"],
                           "source_trial_key": ctx["source_trial_key"],
                           "recovery_trial_key": ctx["recovery_trial_key"],
                           "scene_id": frozen["scene_id"], "scene_digest": frozen["scene_digest"],
                           "restart_request_id": restart_request_id,
                           "destination": str(dest.resolve())}
        reservation = reserve_restart_once(frozen["campaign_budget_ref"], global_identity)
        if reservation["status"] == "already_started":
            return {**reservation["receipt"], "status": "already_started"}
        if reservation["status"] == "blocked":
            return reservation
        require(not dest.exists(), "Refusing to replace a branch directory", "RESTART_IDENTITY_MISMATCH")
        dest.mkdir(parents=True, exist_ok=False)
        recovery_id, branch_id = _id("recovery:" + request_digest), _id("branch:" + request_digest)
        reservation = {"status": "admitting", "request_digest": request_digest,
                       "branch_id": branch_id, "recovery_id": recovery_id}
        _write(admission_path, reservation)
        backup_database(scene_dir / "scene.sqlite", dest / "branch.sqlite")
        with P1Store(dest / "branch.sqlite") as branch:
            branch.admit_p1_restart(recovery_id, ctx["recovery_trial_key"], restart_request_id)
            old = scene["snapshot"]
            branch.mark_unusable([{"result_id": rid, "reasons": ["p1_full_restart"]}
                                  for rid in frozen["successful_result_ids"]], recovery_id)
            owned = [effect for effect in old["effects"] if effect["state"] == "applied"]
            compensations = [branch.compensate(effect["effect_id"], recovery_id) for effect in owned]
            conflict = any(item["status"] == "compensation_conflict" for item in compensations)
            compensation_status = "conflict" if conflict else "compensated" if owned else "skipped_no_effects"
            if conflict:
                branch.finish_p1_restart(recovery_id, {"status": "conflict"})
            first_attempt = branch.connection.execute(
                "SELECT COALESCE(MAX(attempt_no),0)+1 FROM attempts WHERE step_id='read_metadata'").fetchone()[0]
            receipt = {"status": "blocked" if conflict else "ready", "request_digest": request_digest,
                       "scene_id": frozen["scene_id"], "scene_digest": frozen["scene_digest"],
                       "run_id": frozen["run_id"], "branch_id": branch_id,
                       "parent_branch_id": frozen.get("branch_id"), "recovery_id": recovery_id,
                       "branch_db_path": str((dest / "branch.sqlite").resolve()),
                       "parent_trial_key": ctx["source_trial_key"], "recovery_trial_key": ctx["recovery_trial_key"],
                       "recovery_round": 1, "max_recovery_rounds": 1, "additional_call_cap": 5,
                       "campaign_budget_ref": frozen["campaign_budget_ref"],
                       "campaign_ledger_before_replay": deepcopy(campaign_snapshot),
                       "compensation_status": compensation_status,
                       "compensation_effect_ids": [effect["effect_id"] for effect in owned],
                       "compensation": {"status": compensation_status,
                           "effect_ids": [effect["effect_id"] for effect in owned], "receipts": compensations},
                       "reused_result_ids": [], "selected_result_ids": {}, "replay_steps": list(STEPS),
                       "initial_call_ids": [call["call_id"] for call in scene["model_accounting"]["calls"]],
                       "new_call_ids": [], "first_step_attempt_no": first_attempt,
                       "source_versions_preserved": True, "once_fault_enabled": False,
                       "restart_request_id": restart_request_id,
                       "reason_codes": ["COMPENSATION_CONFLICT"] if conflict else ["ONCE_FULL_RESTART"]}
        _write(admission_path, receipt)
        _write(dest / "restart_receipt.json", receipt)
        finish_restart_reservation(frozen["campaign_budget_ref"], global_identity, receipt)
        return receipt
