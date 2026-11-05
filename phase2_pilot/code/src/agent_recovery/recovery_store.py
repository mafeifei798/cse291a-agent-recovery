"""S3 persistence operations; full restart only, without selective execution."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from copy import deepcopy
from pathlib import Path

from .contracts import (
    STEPS, CommitOutcomeUnknown, ContractError, StageNotImplemented, canonical_json, digest, exact_fields,
    new_id, output_keys, positive_int, require, source_keys, utc_now,
    validate_id, validate_object, validate_payload,
)
from .trace import build_graph, project_states


def backup_database(source: Path, destination: Path) -> None:
    require(not destination.exists(), "Refusing to overwrite a branch database")
    # A sqlite connection context commits/rolls back but does not close the
    # handle. Close explicitly before callers hash the frozen database; WAL
    # sidecars must not disappear later when garbage collection runs.
    with closing(sqlite3.connect(f"file:{source}?mode=ro", uri=True)) as src:
        with closing(sqlite3.connect(destination)) as dst:
            src.backup(dst)
            require(dst.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "Invalid database backup")


class RecoveryStoreMixin:
    def _admitted(self, run, recovery_id):
        if run["mode"] == "initial":
            return recovery_id is None
        current = self.connection.execute("SELECT recovery_id FROM run_control WHERE singleton=1").fetchone()
        return (run["mode"] == "recovering" and recovery_id is not None
                and current is not None and current[0] == recovery_id)

    def _attempt_admitted(self, attempt):
        context = self.connection.execute("SELECT recovery_id FROM attempt_context WHERE token=?", (attempt["token"],)).fetchone()
        return self._admitted(self._run(), context[0] if context else None)

    def _assert_recovery(self, recovery_id, active=True):
        validate_id(recovery_id)
        row = self.connection.execute("SELECT * FROM recoveries WHERE recovery_id=?", (recovery_id,)).fetchone()
        current = self.connection.execute("SELECT recovery_id FROM run_control WHERE singleton=1").fetchone()
        require(row is not None and current is not None and current[0] == recovery_id,
                "Not the current recovery", "STALE_ATTEMPT")
        if active:
            require(self._run()["mode"] == "recovering", "Recovery is no longer active", "STALE_ATTEMPT")
        return row

    def _event(self, actor_type, actor_id, action, record_ids, before=None, after=None):
        event = {"event_seq": self._tick(), "actor_type": actor_type, "actor_id": actor_id,
                 "action": action, "record_ids": record_ids,
                 "before_objects": before or [], "after_objects": after or []}
        self.connection.execute("INSERT INTO event_log VALUES(?, ?)", (event["event_seq"], canonical_json(event)))
        return event["event_seq"]

    def _scene_event(self, body, command_digest, event_seq):
        validate_id(body["event_id"])
        old = self.connection.execute("SELECT * FROM scene_events WHERE event_id=?", (body["event_id"],)).fetchone()
        if old:
            require(old["command_digest"] == command_digest and old["event_digest"] == body["event_digest"],
                    "Event identity has different parameters", "IDEMPOTENCY_MISMATCH")
            return json.loads(old["body"])
        saved = {**body, "event_seq": event_seq, "status": "applied"}
        self.connection.execute("INSERT INTO scene_events VALUES(?, ?, ?, ?)",
                                (body["event_id"], body["event_digest"], command_digest, canonical_json(saved)))
        return saved

    def applied_events(self):
        with self._transaction():
            return [json.loads(row[0]) for row in self.connection.execute("SELECT body FROM scene_events ORDER BY rowid")]

    def apply_external_update(self, event_id, object_key, expected_version, new_payload, event_digest=None):
        validate_id(event_id)
        require(positive_int(expected_version) and isinstance(new_payload, dict), "Invalid external update")
        command_hash = digest({"object_key": object_key, "expected_version": expected_version, "new_payload": new_payload})
        with self._transaction(write=True):
            old = self.connection.execute("SELECT * FROM scene_events WHERE event_id=?", (event_id,)).fetchone()
            if old:
                return self._scene_event({"event_id": event_id, "event_digest": event_digest or old["event_digest"]}, command_hash, 0)
            event_digest = event_digest or command_hash
            run = self._run()
            require(run["mode"] not in ("terminal", "uncertain"), "External events are closed", "STALE_ATTEMPT")
            request = json.loads(run["public_view"])["request"]
            keys = source_keys(request)
            require(object_key in keys + output_keys(run["run_id"]), "External target is outside this run")
            row = self.connection.execute("SELECT body FROM objects WHERE object_key=?", (object_key,)).fetchone()
            require(row is not None, "External target is missing", "SCENARIO_ERROR")
            before = json.loads(row[0])
            require(before["exists"] and before["version"] == expected_version,
                    "External update version does not match", "SCENARIO_ERROR")
            if object_key in keys:
                validate_payload(dict(zip(keys, ("read_metadata", "read_permission", "read_resources")))[object_key], new_payload)
                if object_key != keys[2]:
                    require(new_payload["dataset_id"] == request["dataset_id"], "Source identity changed")
                if object_key == keys[1]:
                    require(new_payload["purpose"] == request["purpose"], "Permission purpose changed")
            elif object_key == output_keys(run["run_id"])[0]:
                validate_payload("plan", new_payload)
            else:
                require(new_payload.get("status") == "draft" and
                        new_payload.get("config_key") == output_keys(run["run_id"])[0], "Invalid external draft")
                validate_payload("plan", new_payload.get("config"))
            after = {"object_key": object_key, "exists": True, "payload": deepcopy(new_payload),
                     "version": before["version"] + 1, "last_writer_id": event_id}
            self.connection.execute("UPDATE objects SET body=? WHERE object_key=?", (canonical_json(after), object_key))
            seq = self._event("external", event_id, "external_update", [event_id], [before], [after])
            return self._scene_event({"event_id": event_id, "event_digest": event_digest, "kind": "external_update",
                                      "object_key": object_key, "before_version": before["version"],
                                      "after_version": after["version"]}, command_hash, seq)

    def record_notice_and_pause(self, notice, event_digest=None):
        exact_fields(notice, {"notice_id", "run_id", "faulty_result_id"}, "FaultNotice")
        for value in notice.values():
            validate_id(value)
        command_hash = digest(notice)
        with self._transaction(write=True):
            old = self.connection.execute("SELECT body FROM notices WHERE notice_id=?", (notice["notice_id"],)).fetchone()
            if old:
                require(json.loads(old[0]) == notice, "Notice identity changed", "IDEMPOTENCY_MISMATCH")
                saved_digest = self.connection.execute("SELECT event_digest FROM scene_events WHERE event_id=?", (notice["notice_id"],)).fetchone()[0]
                self._scene_event({"event_id": notice["notice_id"], "event_digest": event_digest or saved_digest}, command_hash, 0)
                return json.loads(old[0])
            event_digest = event_digest or command_hash
            run = self._run(notice["run_id"])
            faulty = self._result(notice["faulty_result_id"])
            require(faulty["run_id"] == run["run_id"] and faulty["execution_status"] == "success",
                    "Notice does not identify a successful result", "INVALID_NOTICE")
            require(run["mode"] == "initial" and not self.connection.execute(
                "SELECT 1 FROM attempts WHERE status='active'").fetchone(), "Cannot pause this run", "STALE_ATTEMPT")
            self.connection.execute("INSERT INTO notices VALUES(?, ?)", (notice["notice_id"], canonical_json(notice)))
            self.connection.execute("UPDATE runs SET mode='paused'")
            seq = self._event("notice", notice["notice_id"], "notice_pause", [notice["notice_id"], notice["faulty_result_id"]])
            self._scene_event({"event_id": notice["notice_id"], "event_digest": event_digest, "kind": "fault_notice"}, command_hash, seq)
            return deepcopy(notice)

    def scene_manifest(self, initial_cost):
        snapshot, view = self.snapshot_run(), self.runtime_view()
        require(snapshot["run_state"] == "paused" and len(snapshot["notices"]) == 1, "Scene must be paused")
        require(not any(row["status"] == "active" for row in snapshot["attempts"]), "Scene has active work")
        graph = build_graph(snapshot["results"])
        states = project_states(graph, snapshot["result_status_events"])
        settings = view["execution_settings"]
        model_calls_used = (self.model_accounting_snapshot()["budget"]["model_calls_used"]
                            if settings["gateway_mode"] == "model" else 0)
        return {"schema_version": "1.1", "run_id": view["run_id"], "run_state": "paused",
                "task_spec_digest": view["task_spec_digest"], "request": view["request"],
                "execution_settings": settings, "source_objects": snapshot["source_objects"],
                "output_objects": snapshot["output_objects"], "initial_results_digest": digest(snapshot["results"]),
                "result_states": [{"result_id": rid, "validity": state["validity"], "invalid_reasons": state["reasons"]}
                                  for rid, state in states.items()],
                "write_receipt_cores_digest": digest([{key: value for key, value in receipt.items()
                                                       if key not in ("state", "compensation_attempts")}
                                                      for receipt in snapshot["effects"]]),
                "effect_states": [{"effect_id": effect["effect_id"], "state": effect["state"]} for effect in snapshot["effects"]],
                "applied_events": self.applied_events(), "notice": snapshot["notices"][0],
                "initial_cost": deepcopy(initial_cost),
                "remaining_budget": {"max_model_calls": settings["max_model_calls"], "model_calls_used": model_calls_used,
                                     "model_calls_remaining": max(0, settings["max_model_calls"] - model_calls_used),
                                     "max_recovery_rounds": settings["max_recovery_rounds"], "recovery_rounds_used": 0},
                "last_event_seq": max(event["event_seq"] for event in snapshot["event_log"])}

    def export_scene(self, destination, initial_cost):
        destination = Path(destination)
        with self._transaction():
            require(self._run()["mode"] == "paused" and not self.connection.execute(
                "SELECT 1 FROM attempts WHERE status='active'").fetchone(), "Cannot export an active scene")
            destination.mkdir(parents=True, exist_ok=False)
            with sqlite3.connect(destination / "scene.sqlite") as target:
                self.connection.backup(target)
        # Compute the manifest from the consistent backup, never from a second live view.
        with type(self)(destination / "scene.sqlite") as saved:
            scene = saved.scene_manifest(initial_cost)
            snapshot = saved.snapshot_run()
        for name, body in (("scene.json", scene), ("snapshot.json", snapshot)):
            (destination / name).write_text(json.dumps(body, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return {"scene": scene, "scene_digest": digest(scene)}

    def start_recovery(self, trial_id, notice_id, policy="full_restart"):
        if policy not in ("full_restart", "selective"):
            raise StageNotImplemented("Only full_restart and selective are supported")
        validate_id(trial_id)
        validate_id(notice_id)
        with self._transaction(write=True):
            previous = self.connection.execute("SELECT * FROM recoveries WHERE notice_id=? OR trial_id=?", (notice_id, trial_id)).fetchone()
            if previous:
                require(previous["trial_id"] == trial_id and previous["notice_id"] == notice_id and previous["policy"] == policy,
                        "Recovery identity has different parameters", "IDEMPOTENCY_MISMATCH")
                return {"created": False, **json.loads(previous["body"])}
            require(self._run()["mode"] == "paused" and not self.connection.execute(
                "SELECT 1 FROM attempts WHERE status='active'").fetchone(), "Run is not ready for recovery", "STALE_ATTEMPT")
            require(self.connection.execute("SELECT 1 FROM notices WHERE notice_id=?", (notice_id,)).fetchone() is not None,
                    "Unknown notice", "INVALID_NOTICE")
            recovery_id = new_id()
            body = {"recovery_id": recovery_id, "trial_id": trial_id, "notice_id": notice_id,
                    "policy": policy, "phase": "planning", "engine_status": "running", "report": None}
            self.connection.execute("INSERT INTO recoveries VALUES(?, ?, ?, ?, ?)",
                                    (recovery_id, trial_id, notice_id, policy, canonical_json(body)))
            self.connection.execute("INSERT INTO run_control VALUES(1, ?) ON CONFLICT(singleton) DO UPDATE SET recovery_id=excluded.recovery_id", (recovery_id,))
            self.connection.execute("UPDATE runs SET mode='recovering'")
            self._event("recovery", recovery_id, "start_recovery", [recovery_id, trial_id, notice_id])
            return {"created": True, **body}

    def recovery_progress(self, notice_id):
        with self._transaction():
            row = self.connection.execute("SELECT body FROM recoveries WHERE notice_id=?", (notice_id,)).fetchone()
            return json.loads(row[0]) if row else None

    def save_recovery_progress(self, recovery_id, report):
        with self._transaction(write=True):
            row = self._assert_recovery(recovery_id)
            saved = json.loads(row["body"])
            saved.update(phase=report["phase"], engine_status=report["engine_status"], report=deepcopy(report))
            self.connection.execute("UPDATE recoveries SET body=? WHERE recovery_id=?", (canonical_json(saved), recovery_id))

    def record_recovery_round(self, recovery_id, selected):
        """Journal the actual selection before invalidation without changing objects."""
        require(isinstance(selected, dict) and set(selected) <= set(STEPS)
                and all(isinstance(value, str) for value in selected.values())
                and len(set(selected.values())) == len(selected), "Invalid round selection", "INVALID_PARENT")
        with self._transaction(write=True):
            self._assert_recovery(recovery_id)
            require(not self.connection.execute("SELECT 1 FROM attempts WHERE status='active'").fetchone(),
                    "Cannot begin a round with active work", "STALE_ATTEMPT")
            selected_ids = []
            for step in STEPS:
                if step not in selected:
                    continue
                validate_id(selected[step])
                result = self._result(selected[step])
                require(result["run_id"] == self._run()["run_id"] and result["step_id"] == step
                        and result["execution_status"] == "success",
                        "Round selection has a failed, foreign or wrong-role result", "INVALID_PARENT")
                selected_ids.append(selected[step])
            return self._event("recovery", recovery_id, "begin_recovery_round", selected_ids)

    def fence_uncertain_initial(self, run_id, error):
        """Fence an initial-run commit whose original operation cannot be read."""
        require(isinstance(error, CommitOutcomeUnknown), "Expected an unknown commit outcome")
        validate_id(error.operation_id)
        validate_id(error.result_id)
        records = [error.operation_id, error.result_id]
        with self._transaction(write=True):
            run = self._run(run_id)
            if run["mode"] == "uncertain":
                markers = [json.loads(row[0]) for row in self.connection.execute(
                    "SELECT body FROM event_log ORDER BY event_seq")]
                previous = next((row for row in reversed(markers)
                                 if row["action"] == "fence_uncertain_initial"), None)
                require(previous is not None and previous["actor_id"] == run_id
                        and previous["record_ids"] == records,
                        "Initial uncertainty identity has changed", "IDEMPOTENCY_MISMATCH")
                return previous["event_seq"]
            require(run["mode"] == "initial", "Initial run no longer admits fencing", "STALE_ATTEMPT")
            attempt = self.connection.execute("SELECT * FROM attempts WHERE result_id=?", (error.result_id,)).fetchone()
            require(attempt is not None and attempt["run_id"] == run_id and attempt["step_id"] == "execute",
                    "Unknown execution identity", "STALE_ATTEMPT")
            require(error.attempt_no is None or error.attempt_no == attempt["attempt_no"],
                    "Execution attempt number changed", "STALE_ATTEMPT")
            operation = self.connection.execute("SELECT owner_result_id FROM effects WHERE operation_id=?",
                                                (error.operation_id,)).fetchone()
            require(operation is None or operation[0] == error.result_id,
                    "Operation belongs to another result", "IDEMPOTENCY_MISMATCH")
            self.connection.execute("UPDATE attempts SET status='uncertain' WHERE status='active'")
            self.connection.execute("UPDATE runs SET mode='uncertain'")
            return self._event("run", run_id, "fence_uncertain_initial", records)

    def fence_uncertain_recovery(self, recovery_id, report):
        """Close admission after an unreadable commit outcome; never invent a result.

        A committed write can already have closed its attempt. It still needs the
        run-level fence until a human has reconciled the original operation ID.
        """
        require(isinstance(report.get("failure"), dict)
                and report["failure"].get("code") == "UNKNOWN_COMMIT_OUTCOME",
                "Uncertainty fencing requires an unknown commit outcome")
        require(report.get("recovery_id") == recovery_id, "Wrong report recovery", "STALE_ATTEMPT")
        fenced_report = deepcopy(report)
        fenced_report.update(phase="done", engine_status="runtime_error")
        with self._transaction(write=True):
            row = self._assert_recovery(recovery_id, active=False)
            saved = json.loads(row["body"])
            mode = self._run()["mode"]
            if mode == "uncertain":
                require(saved["report"] == fenced_report,
                        "Uncertainty fence report has changed", "IDEMPOTENCY_MISMATCH")
                return deepcopy(saved["report"])
            require(mode == "recovering", "Recovery is no longer active", "STALE_ATTEMPT")
            active_ids = [item[0] for item in self.connection.execute(
                "SELECT result_id FROM attempts WHERE status='active' ORDER BY rowid")]
            self.connection.execute("UPDATE attempts SET status='uncertain' WHERE status='active'")
            saved.update(phase="done", engine_status="runtime_error", report=fenced_report)
            self.connection.execute("UPDATE recoveries SET body=? WHERE recovery_id=?",
                                    (canonical_json(saved), recovery_id))
            self.connection.execute("UPDATE runs SET mode='uncertain'")
            failure = fenced_report["failure"]
            records = list(active_ids)
            for key in ("operation_id", "result_id"):
                if failure.get(key) and failure[key] not in records:
                    validate_id(failure[key])
                    records.append(failure[key])
            self._event("recovery", recovery_id, "fence_uncertain_recovery", records)
            return deepcopy(fenced_report)

    def mark_unusable(self, invalidated, recovery_id):
        with self._transaction(write=True):
            self._assert_recovery(recovery_id)
            additions = []
            for item in invalidated:
                result = self._result(item["result_id"])
                require(result["run_id"] == self._run()["run_id"] and result["execution_status"] == "success",
                        "Cannot invalidate foreign or failed results", "INVALID_PARENT")
                require(isinstance(item["reasons"], list) and item["reasons"] and
                        all(isinstance(reason, str) for reason in item["reasons"]), "Missing invalidation reasons")
                previous = set()
                for row in self.connection.execute("SELECT body FROM result_status_events WHERE result_id=?", (item["result_id"],)):
                    previous.update(json.loads(row[0])["reasons"])
                if not set(item["reasons"]) <= previous:
                    additions.append({"result_id": item["result_id"], "validity": "invalidated",
                                      "reasons": sorted(previous | set(item["reasons"]))})
            if additions:
                seq = self._event("recovery", recovery_id, "invalidate_results", [item["result_id"] for item in additions])
                for item in additions:
                    self.connection.execute("INSERT INTO result_status_events VALUES(?, ?, ?)",
                                            (seq, item["result_id"], canonical_json({"event_seq": seq, **item})))

    def compensate(self, effect_id, recovery_id):
        validate_id(effect_id)
        with self._transaction(write=True):
            self._assert_recovery(recovery_id, active=False)
            row = self.connection.execute("SELECT * FROM effects WHERE effect_id=?", (effect_id,)).fetchone()
            require(row is not None and row["run_id"] == self._run()["run_id"], "Foreign or missing effect", "INVALID_PARENT")
            require(any(json.loads(item[0])["validity"] == "invalidated" for item in self.connection.execute(
                "SELECT body FROM result_status_events WHERE result_id=?", (row["owner_result_id"],))),
                    "Cannot compensate a usable owner", "INVALID_PARENT")
            if row["state"] == "compensated":
                return {"effect_id": effect_id, "status": "already_compensated", "conflicts": [], "restored_versions": []}
            previous = self.connection.execute("SELECT body FROM compensation_attempts WHERE effect_id=? AND recovery_id=?", (effect_id, recovery_id)).fetchone()
            if previous:
                return {"effect_id": effect_id, **json.loads(previous[0])}
            self._assert_recovery(recovery_id)
            core = json.loads(row["body"])
            currents, conflicts = [], []
            for target in core["targets"]:
                stored = self.connection.execute("SELECT body FROM objects WHERE object_key=?", (target["object_key"],)).fetchone()
                current = json.loads(stored[0]) if stored else {"object_key": target["object_key"], "exists": False,
                          "payload": None, "version": 0, "last_writer_id": None}
                currents.append(current)
                expected = target["after"]
                if current != expected:
                    conflicts.append({"object_key": target["object_key"], "expected_version": expected["version"],
                                      "current_version": current["version"], "expected_writer": expected["last_writer_id"],
                                      "current_writer": current["last_writer_id"]})
            restored = []
            if not conflicts:
                for target, current in zip(core["targets"], currents):
                    after = {**deepcopy(target["before"]), "version": current["version"] + 1, "last_writer_id": recovery_id}
                    self.connection.execute("UPDATE objects SET body=? WHERE object_key=?", (canonical_json(after), after["object_key"]))
                    restored.append(after)
                self.connection.execute("UPDATE effects SET state='compensated' WHERE effect_id=?", (effect_id,))
            status = "compensation_conflict" if conflicts else "compensated"
            attempt = {"recovery_id": recovery_id, "status": status, "conflicts": conflicts,
                       "restored_versions": [{"object_key": obj["object_key"], "version": obj["version"]} for obj in restored],
                       "completed_at": utc_now()}
            self.connection.execute("INSERT INTO compensation_attempts VALUES(?, ?, ?)", (effect_id, recovery_id, canonical_json(attempt)))
            self._event("recovery", recovery_id, "compensation_conflict" if conflicts else "compensate_group", [effect_id],
                        [] if conflicts else currents, restored)
            return {"effect_id": effect_id, **attempt}

    def finish_recovery(self, recovery_id, report):
        with self._transaction(write=True):
            row = self._assert_recovery(recovery_id)
            require(not self.connection.execute("SELECT 1 FROM attempts WHERE status='active'").fetchone(),
                    "Recovery still has active attempts", "STALE_ATTEMPT")
            saved = json.loads(row["body"])
            saved.update(phase="done", engine_status=report["engine_status"], report=deepcopy(report))
            self.connection.execute("UPDATE recoveries SET body=? WHERE recovery_id=?", (canonical_json(saved), recovery_id))
            self.connection.execute("UPDATE runs SET mode='terminal'")
            self._event("recovery", recovery_id, "finish_recovery", [recovery_id])

    def attach_evaluation(self, recovery_id, evaluation, initial_state_check, setup_ms, oracle_ms):
        with self._transaction(write=True):
            row = self._assert_recovery(recovery_id, active=False)
            saved = json.loads(row["body"])
            report = saved["report"]
            require(report is not None and report["phase"] == "done", "Engine is not finished")
            report.update(evaluation=deepcopy(evaluation), initial_state_check=initial_state_check)
            report["cost"].update(setup_wall_ms=setup_ms, oracle_wall_ms=oracle_ms,
                reused_result_count=len(evaluation["verified_reused_results"])
                if report["engine_status"] == "completed" and evaluation["passed"] else 0)
            if report["engine_status"] == "completed":
                report["outcome"] = "recovered" if evaluation["passed"] else "failed_validation"
            elif report["engine_status"] == "conflict":
                report["outcome"] = "failed_conflict"
            elif report["engine_status"] == "budget_exceeded":
                report["outcome"] = "failed_budget"
            elif report["failure"] and report["failure"]["code"] == "UNKNOWN_COMMIT_OUTCOME":
                report["outcome"] = "failed_uncertain"
            else:
                report["outcome"] = "failed_runtime"
            self.connection.execute("UPDATE recoveries SET body=? WHERE recovery_id=?", (canonical_json(saved), recovery_id))
            return deepcopy(report)
