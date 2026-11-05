"""SQLite persistence, atomic business writes and S3 recovery state.

S3 adds controlled events and recovery persistence through RecoveryStoreMixin.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path

from .contracts import (
    PARENTS, STEPS, ContractError, canonical_json, digest,
    exact_fields, new_id, output_keys, public_task_view, require, source_keys, utc_now,
    validate_action, validate_id, validate_object, validate_result,
)
from .trace import build_graph, derive_read_set
from .recovery_store import RecoveryStoreMixin
from .model_store import ModelStoreMixin


class Store(ModelStoreMixin, RecoveryStoreMixin):
    def __init__(self, path: str | Path):
        self.path = str(path)
        self.connection = sqlite3.connect(self.path, isolation_level=None, timeout=2)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS runs (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                run_id TEXT UNIQUE NOT NULL, public_view TEXT NOT NULL,
                mode TEXT NOT NULL, event_seq INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS objects (
                object_key TEXT PRIMARY KEY, body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS attempts (
                token TEXT PRIMARY KEY, run_id TEXT NOT NULL, step_id TEXT NOT NULL,
                attempt_no INTEGER NOT NULL, result_id TEXT UNIQUE NOT NULL,
                parents TEXT NOT NULL, read_snapshots TEXT NOT NULL,
                status TEXT NOT NULL, started_at TEXT NOT NULL,
                UNIQUE(run_id, step_id, attempt_no)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_active_attempt
                ON attempts(run_id) WHERE status='active';
            CREATE TABLE IF NOT EXISTS results (
                result_id TEXT PRIMARY KEY, run_id TEXT NOT NULL,
                step_id TEXT NOT NULL, attempt_no INTEGER NOT NULL, body TEXT NOT NULL,
                UNIQUE(run_id, step_id, attempt_no)
            );
            CREATE TABLE IF NOT EXISTS event_log (
                event_seq INTEGER PRIMARY KEY, body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS result_status_events (
                event_seq INTEGER NOT NULL, result_id TEXT NOT NULL, body TEXT NOT NULL,
                PRIMARY KEY(event_seq, result_id)
            );
            CREATE TABLE IF NOT EXISTS effects (
                effect_id TEXT PRIMARY KEY, operation_id TEXT UNIQUE NOT NULL,
                run_id TEXT NOT NULL, owner_result_id TEXT UNIQUE NOT NULL,
                step_id TEXT NOT NULL, attempt_no INTEGER NOT NULL, action TEXT NOT NULL,
                operation_digest TEXT NOT NULL, body TEXT NOT NULL, state TEXT NOT NULL,
                UNIQUE(run_id, step_id, attempt_no, action)
            );
            CREATE TABLE IF NOT EXISTS scene_events (
                event_id TEXT PRIMARY KEY, event_digest TEXT NOT NULL,
                command_digest TEXT NOT NULL, body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notices (notice_id TEXT PRIMARY KEY, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS recoveries (
                recovery_id TEXT PRIMARY KEY, trial_id TEXT UNIQUE NOT NULL,
                notice_id TEXT UNIQUE NOT NULL, policy TEXT NOT NULL, body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS run_control (singleton INTEGER PRIMARY KEY CHECK(singleton=1), recovery_id TEXT);
            CREATE TABLE IF NOT EXISTS attempt_context (token TEXT PRIMARY KEY, recovery_id TEXT);
            CREATE TABLE IF NOT EXISTS compensation_attempts (
                effect_id TEXT NOT NULL, recovery_id TEXT NOT NULL, body TEXT NOT NULL,
                PRIMARY KEY(effect_id, recovery_id)
            );
        """)
        self._initialize_model_tables()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @contextmanager
    def _transaction(self, write=False):
        self.connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        try:
            yield
            self.connection.execute("COMMIT")
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise

    def _run(self, run_id=None):
        row = self.connection.execute("SELECT * FROM runs WHERE singleton=1").fetchone()
        require(row is not None, "Store has not been initialized", "INTERNAL_ERROR")
        require(run_id is None or row["run_id"] == run_id, "Wrong run", "INVALID_PARENT")
        return row

    def _tick(self) -> int:
        self.connection.execute("UPDATE runs SET event_seq=event_seq+1 WHERE singleton=1")
        return self._run()["event_seq"]

    def initialize_run(self, task: dict, run_id: str | None = None) -> str:
        public = public_task_view(task)
        run_id = run_id or new_id()
        validate_id(run_id)
        with self._transaction(write=True):
            require(self.connection.execute("SELECT count(*) FROM runs").fetchone()[0] == 0,
                    "Refusing to overwrite an existing run", "INTERNAL_ERROR")
            self.connection.execute("INSERT INTO runs VALUES(1, ?, ?, 'initial', 1)",
                                    (run_id, canonical_json(public)))
            self.connection.executemany("INSERT INTO objects VALUES(?, ?)",
                                        [(o["object_key"], canonical_json(o)) for o in public["initial_objects"]])
        return run_id

    def runtime_view(self) -> dict:
        with self._transaction():
            row = self._run()
            view = json.loads(row["public_view"])
            return {"run_id": row["run_id"], "run_state": row["mode"], **view}

    def _attempt(self, token: str):
        row = self.connection.execute("SELECT * FROM attempts WHERE token=?", (token,)).fetchone()
        require(row is not None, "Unknown attempt token", "STALE_ATTEMPT")
        return row

    def _result(self, result_id: str) -> dict:
        row = self.connection.execute("SELECT body FROM results WHERE result_id=?", (result_id,)).fetchone()
        require(row is not None, "Parent result does not exist", "INVALID_PARENT")
        return json.loads(row["body"])

    def get_result(self, result_id: str) -> dict:
        with self._transaction():
            return self._result(result_id)

    def begin_attempt(self, run_id: str, step_id: str, parent_result_ids: list[str],
                      recovery_id: str | None = None) -> dict:
        if recovery_id is not None:
            validate_id(recovery_id)
        require(step_id in STEPS, "Unknown step")
        require(isinstance(parent_result_ids, list)
                and all(isinstance(value, str) for value in parent_result_ids)
                and len(set(parent_result_ids)) == len(parent_result_ids),
                "Duplicate or invalid parents", "INVALID_PARENT")
        for parent_id in parent_result_ids:
            validate_id(parent_id)
        with self._transaction(write=True):
            row = self._run(run_id)
            require(self._admitted(row, recovery_id), "Run does not admit this execution identity", "STALE_ATTEMPT")
            require(self.connection.execute("SELECT count(*) FROM attempts WHERE status='active'").fetchone()[0] == 0,
                    "An attempt is already active", "STALE_ATTEMPT")
            parents = [self._result(rid) for rid in parent_result_ids]
            require(all(p["run_id"] == run_id and p["execution_status"] == "success" for p in parents),
                    "Failed or foreign parent", "INVALID_PARENT")
            require(tuple(p["step_id"] for p in parents) == PARENTS[step_id],
                    "Parents do not match the fixed workflow", "INVALID_PARENT")
            if parents:
                self._parent_chain(parent_result_ids, run_id)
            number = self.connection.execute("SELECT COALESCE(MAX(attempt_no),0)+1 FROM attempts WHERE step_id=?", (step_id,)).fetchone()[0]
            token, result_id, started = new_id(), new_id(), utc_now()
            self.connection.execute("INSERT INTO attempts VALUES(?, ?, ?, ?, ?, ?, '[]', 'active', ?)",
                                    (token, run_id, step_id, number, result_id, canonical_json(parent_result_ids), started))
            self.connection.execute("INSERT INTO attempt_context VALUES(?, ?)", (token, recovery_id))
            self._tick()
            return {"token": token, "run_id": run_id, "step_id": step_id,
                    "attempt_no": number, "result_id": result_id, "started_at": started}

    def read_objects(self, object_keys: list[str], attempt_token: str | None = None) -> list[dict]:
        require(isinstance(object_keys, list) and all(isinstance(key, str) and key for key in object_keys)
                and len(set(object_keys)) == len(object_keys), "Invalid object keys")
        with self._transaction(write=attempt_token is not None):
            run = self._run()
            snapshots = []
            for key in object_keys:
                row = self.connection.execute("SELECT body FROM objects WHERE object_key=?", (key,)).fetchone()
                snapshots.append(json.loads(row["body"]) if row else
                                 {"object_key": key, "exists": False, "payload": None,
                                  "version": 0, "last_writer_id": None})
            if attempt_token is not None:
                attempt = self._attempt(attempt_token)
                require(attempt["status"] == "active", "Closed attempt", "STALE_ATTEMPT")
                require(self._attempt_admitted(attempt), "Run no longer admits reads", "STALE_ATTEMPT")
                allowed = dict(zip(STEPS[:3], source_keys(json.loads(run["public_view"])["request"])))
                require(attempt["step_id"] in allowed and object_keys == [allowed[attempt["step_id"]]],
                        "Step tried to read outside its declared source", "INVALID_PARENT")
                require(json.loads(attempt["read_snapshots"]) == [], "S1 query can read once only")
                self.connection.execute("UPDATE attempts SET read_snapshots=? WHERE token=?",
                                        (canonical_json(snapshots), attempt_token))
                self._tick()
            return snapshots

    def append_result(self, attempt_token: str, result: dict, publication_events=None) -> dict:
        publication_events = publication_events or []
        validate_result(result)
        require(not (result["step_id"] == "execute" and result["execution_status"] == "success"),
                "Executor success requires the S2 atomic write interface", "INTERNAL_ERROR")
        with self._transaction(write=True):
            attempt = self._attempt(attempt_token)
            self._run(result["run_id"])
            require(all(result[k] == attempt[k] for k in ("run_id", "step_id", "attempt_no", "result_id")),
                    "Result does not belong to this attempt", "STALE_ATTEMPT")
            require(result["started_at"] == attempt["started_at"], "Attempt start time was changed", "STALE_ATTEMPT")
            existing = self.connection.execute("SELECT body FROM results WHERE result_id=?", (result["result_id"],)).fetchone()
            if existing:
                require(existing["body"] == canonical_json(result), "Attempt completed with different content", "IDEMPOTENCY_MISMATCH")
                for item in publication_events:
                    row = self.connection.execute("SELECT event_digest FROM scene_events WHERE event_id=?", (item["event_id"],)).fetchone()
                    require(row is not None and row[0] == item["event_digest"], "Publication event differs", "IDEMPOTENCY_MISMATCH")
                return json.loads(existing["body"])
            require(attempt["status"] == "active", "Closed attempt", "STALE_ATTEMPT")
            require(self._attempt_admitted(attempt), "Run no longer admits publication", "STALE_ATTEMPT")
            require(result["parent_result_ids"] == json.loads(attempt["parents"]), "Wrong parent selection", "INVALID_PARENT")
            if result["execution_status"] == "success":
                parents = [self._result(rid) for rid in result["parent_result_ids"]]
                snapshots = json.loads(attempt["read_snapshots"])
                snapshot = result["input_snapshot"]
                require(snapshot["request"] == json.loads(self._run()["public_view"])["request"], "Request changed", "INVALID_PARENT")
                require(snapshot["tool_snapshots"] == snapshots, "Tool snapshots were changed or omitted", "INVALID_PARENT")
                require(snapshot["parents"] == [{"result_id": p["result_id"], "payload": p["payload"]} for p in parents], "Parent payload was changed", "INVALID_PARENT")
                reads = [{"object_key": o["object_key"], "version": o["version"]}
                         for o in snapshots if o["exists"]]
                require(all(o["exists"] for o in snapshots), "Cannot publish missing source as success", "INVALID_PARENT")
                require(result["direct_reads"] == sorted(reads, key=lambda o: o["object_key"]), "Direct reads were forged", "INVALID_PARENT")
                if result["step_id"] in STEPS[:3]:
                    require(len(snapshots) == 1, "Query has no captured tool read", "INVALID_PARENT")
                require(result["effective_read_set"] == derive_read_set(reads, parents), "Source lineage changed", "INVALID_PARENT")
            for item in publication_events:
                exact_fields(item, {"event_id", "event_digest", "kind", "target_result_id"}, "publication event")
                require(item["kind"] == "corrupt_result" and item["target_result_id"] == result["result_id"]
                        and result["execution_status"] == "success", "Invalid corruption target", "SCENARIO_ERROR")
                require(self.connection.execute("SELECT 1 FROM scene_events WHERE event_id=?", (item["event_id"],)).fetchone() is None,
                        "Event was already published on a different operation", "IDEMPOTENCY_MISMATCH")
            self._publish(attempt_token, result, publication_events=publication_events)
            return deepcopy(result)

    def _publish(self, token: str, result: dict, receipt: dict | None = None, publication_events=None) -> None:
        """Caller owns the surrounding write transaction."""
        self._bind_model_publication(token, result, publication_events)
        self.connection.execute("INSERT INTO results VALUES(?, ?, ?, ?, ?)",
                                (result["result_id"], result["run_id"], result["step_id"],
                                 result["attempt_no"], canonical_json(result)))
        self.connection.execute("UPDATE attempts SET status='closed' WHERE token=?", (token,))
        targets = receipt["targets"] if receipt else []
        event = {"event_seq": self._tick(), "actor_type": "step", "actor_id": result["result_id"],
                 "action": "commit_group" if receipt else "publish_result",
                 "record_ids": [result["result_id"]] + ([receipt["effect_id"]] if receipt else [])
                               + [item["event_id"] for item in (publication_events or [])],
                 "before_objects": [target["before"] for target in targets],
                 "after_objects": [target["after"] for target in targets]}
        self.connection.execute("INSERT INTO event_log VALUES(?, ?)",
                                (event["event_seq"], canonical_json(event)))
        for item in publication_events or []:
            self._scene_event(item, digest({"target_result_id": result["result_id"], "payload": result["payload"]}), event["event_seq"])

    def _receipt(self, row) -> dict:
        attempts = [json.loads(item[0]) for item in self.connection.execute(
            "SELECT body FROM compensation_attempts WHERE effect_id=? ORDER BY rowid", (row["effect_id"],))]
        return {**json.loads(row["body"]), "state": row["state"], "compensation_attempts": attempts}

    def get_operation(self, run_id: str, operation_id: str) -> dict:
        validate_id(operation_id)
        with self._transaction():
            self._run(run_id)
            row = self.connection.execute("SELECT * FROM effects WHERE operation_id=? AND run_id=?",
                                          (operation_id, run_id)).fetchone()
            if row is None:
                return {"state": "absent", "result": None, "receipt": None}
            return {"state": row["state"], "result": self._result(row["owner_result_id"]),
                    "receipt": self._receipt(row)}

    def _parent_chain(self, parent_ids: list[str], run_id: str) -> dict[str, dict]:
        found, visiting = {}, set()
        invalid = {row["result_id"] for row in self.connection.execute(
            "SELECT result_id,body FROM result_status_events")
            if json.loads(row["body"])["validity"] == "invalidated"}

        def visit(rid):
            require(rid not in visiting, "Cyclic saved parent chain", "INVALID_PARENT")
            if rid in found:
                return
            require(rid not in invalid, "Parent or ancestor was invalidated", "INVALID_PARENT")
            result = self._result(rid)
            require(result["run_id"] == run_id and result["execution_status"] == "success",
                    "Parent is failed or foreign", "INVALID_PARENT")
            visiting.add(rid)
            for pid in result["parent_result_ids"]:
                visit(pid)
            visiting.remove(rid)
            found[rid] = result

        for rid in parent_ids:
            visit(rid)
        try:
            build_graph(list(found.values()))
        except ContractError as exc:
            raise ContractError("INVALID_PARENT", f"Saved ancestry is inconsistent: {exc}") from exc
        return found

    def _commit_failure(self, token: str, attempt, candidate: dict, exc: ContractError) -> dict:
        status = {"INVALID_PARENT": "dependency_error", "INCONSISTENT_READ_SET": "dependency_error",
                  "STALE_SOURCE": "stale_input", "OUTPUT_CONFLICT": "write_conflict"}.get(exc.code, "schema_error")
        failed = deepcopy(candidate)
        failed.update(schema_version="1.1", run_id=attempt["run_id"], step_id=attempt["step_id"],
                      attempt_no=attempt["attempt_no"], result_id=attempt["result_id"],
                      started_at=attempt["started_at"], finished_at=utc_now(), execution_status=status,
                      payload=None, effect_ids=[], parent_result_ids=json.loads(attempt["parents"]),
                      error={"code": exc.code, "message": str(exc), "step_id": "execute",
                             "related_result_ids": json.loads(attempt["parents"]),
                             "object_keys": list(output_keys(attempt["run_id"]))})
        try:
            validate_result(failed)
        except (ContractError, TypeError, ValueError):
            # Malformed attempted inputs must not prevent closing the real attempt.
            failed = {key: failed[key] for key in (
                "schema_version", "run_id", "step_id", "attempt_no", "result_id",
                "started_at", "finished_at", "execution_status", "payload", "effect_ids",
                "parent_result_ids", "error")}
            failed.update(direct_reads=[], effective_read_set=[], input_snapshot=None,
                          input_digest=None, duration_ms=0, model_calls=self._calls_for_attempt(token))
            validate_result(failed)
        self._publish(token, failed)
        return {"result": failed, "receipt": None}

    def commit_execution(self, attempt_token: str, result: dict, command: dict,
                         expected_outputs: list[dict], operation_id: str) -> dict:
        """Validate, then atomically create outputs, receipt, result and close attempt.

        A known precondition failure is persisted once, without business writes.
        Storage exceptions escape after rollback; the caller must query the operation.
        """
        validate_id(operation_id)
        command_hash = digest(command)
        with self._transaction(write=True):
            attempt = self._attempt(attempt_token)
            run = self._run(attempt["run_id"])
            previous = self.connection.execute("SELECT * FROM effects WHERE operation_id=?", (operation_id,)).fetchone()
            if previous is not None:
                require(previous["operation_digest"] == command_hash
                        and previous["owner_result_id"] == attempt["result_id"],
                        "Operation was submitted with different parameters", "IDEMPOTENCY_MISMATCH")
                require(previous["state"] == "applied", "Operation is already closed", "OPERATION_CLOSED")
                return {"result": self._result(previous["owner_result_id"]), "receipt": self._receipt(previous)}
            require(attempt["status"] == "active" and self._attempt_admitted(attempt),
                    "Attempt no longer admits commit", "STALE_ATTEMPT")
            require(attempt["step_id"] == "execute", "Only Executor can commit outputs", "INVALID_PARENT")
            # Keep identity errors outside the persisted validation-failure path.
            require(all(result.get(key) == attempt[key] for key in
                        ("run_id", "step_id", "attempt_no", "result_id", "started_at")),
                    "Candidate belongs to a different attempt", "STALE_ATTEMPT")
            self._bind_model_publication(attempt_token, result, command=command)
            try:
                exact_fields(command, {"run_id", "step_id", "attempt_no", "action", "arguments", "target_keys"}, "command")
                require(type(command["attempt_no"]) is int, "Command attempt number must be an integer")
                require(all(command[key] == attempt[key] for key in ("run_id", "step_id", "attempt_no")),
                        "Command belongs to a different attempt", "INVALID_PARENT")
                validate_action({"action": command["action"], "arguments": command["arguments"]})
                keys = list(output_keys(run["run_id"]))
                require(command["target_keys"] == keys, "Output namespace was changed", "OUTPUT_CONFLICT")
                parent_ids = json.loads(attempt["parents"])
                chain = self._parent_chain(parent_ids, run["run_id"])
                parents = [chain[rid] for rid in parent_ids]
                require(tuple(parent["step_id"] for parent in parents) == PARENTS["execute"],
                        "Executor does not point to its plan", "INVALID_PARENT")
                request = json.loads(run["public_view"])["request"]
                require(all(parent["input_snapshot"]["request"] == request for parent in chain.values()),
                        "Saved ancestry belongs to a different task", "INVALID_PARENT")
                reads = derive_read_set([], parents)
                effect_id = new_id()
                completed = deepcopy(result)
                completed.update(payload={"config_key": keys[0], "draft_key": keys[1],
                                          "effect_id": effect_id, "commit_state": "committed"},
                                 effect_ids=[effect_id], finished_at=utc_now())
                validate_result(completed)
                require(completed["execution_status"] == "success", "Executor candidate is not successful")
                require(completed["parent_result_ids"] == parent_ids
                        and completed["input_snapshot"]["request"] == request
                        and completed["input_snapshot"]["parents"] ==
                        [{"result_id": p["result_id"], "payload": p["payload"]} for p in parents]
                        and completed["input_snapshot"]["tool_snapshots"] == []
                        and completed["direct_reads"] == []
                        and completed["effective_read_set"] == reads,
                        "Executor inputs differ from saved ancestry", "INVALID_PARENT")
                require(command["arguments"] == parents[0]["payload"],
                        "Save arguments differ from the actual plan", "INVALID_PARENT")
                for ref in reads:
                    current = self.connection.execute("SELECT body FROM objects WHERE object_key=?", (ref["object_key"],)).fetchone()
                    current = json.loads(current["body"]) if current else None
                    require(current is not None and current["exists"] and current["version"] == ref["version"],
                            f"Source version changed: {ref['object_key']}", "STALE_SOURCE")
                require(isinstance(expected_outputs, list) and len(expected_outputs) == 2,
                        "Two output preconditions are required", "OUTPUT_CONFLICT")
                require(not self.connection.execute("SELECT 1 FROM effects WHERE state='applied'").fetchone(),
                        "Run already has an uncompensated write group", "OUTPUT_CONFLICT")
                targets = []
                for key, expected in zip(keys, expected_outputs):
                    validate_object(expected)
                    row = self.connection.execute("SELECT body FROM objects WHERE object_key=?", (key,)).fetchone()
                    before = json.loads(row["body"]) if row else {"object_key": key, "exists": False,
                              "payload": None, "version": 0, "last_writer_id": None}
                    require(before == expected and not before["exists"],
                            f"Output precondition failed: {key}", "OUTPUT_CONFLICT")
                    payload = command["arguments"] if key == keys[0] else {
                        "config_key": keys[0], "config": command["arguments"], "status": "draft"}
                    after = {"object_key": key, "exists": True, "payload": deepcopy(payload),
                             "version": before["version"] + 1, "last_writer_id": completed["result_id"]}
                    targets.append({"object_key": key, "before": before, "after": after})
            except ContractError as exc:
                return self._commit_failure(attempt_token, attempt, result, exc)
            receipt = {"schema_version": "1.1", "effect_id": effect_id, "operation_id": operation_id,
                       "operation_digest": command_hash, "run_id": run["run_id"],
                       "owner_result_id": completed["result_id"], "step_id": "execute",
                       "attempt_no": attempt["attempt_no"], "source_read_set": reads,
                       "targets": targets, "committed_at": completed["finished_at"]}
            for target in targets:
                self.connection.execute("INSERT INTO objects VALUES(?, ?) ON CONFLICT(object_key) DO UPDATE SET body=excluded.body",
                                        (target["object_key"], canonical_json(target["after"])))
            self.connection.execute("INSERT INTO effects VALUES(?, ?, ?, ?, 'execute', ?, 'save_job', ?, ?, 'applied')",
                                    (effect_id, operation_id, run["run_id"], completed["result_id"],
                                     attempt["attempt_no"], command_hash, canonical_json(receipt)))
            self._publish(attempt_token, completed, receipt)
            return {"result": completed, "receipt": {**receipt, "state": "applied", "compensation_attempts": []}}

    def finish_run(self, run_id: str) -> None:
        with self._transaction(write=True):
            row = self._run(run_id)
            require(row["mode"] != "uncertain", "Uncertain execution requires investigation", "STALE_ATTEMPT")
            require(not self.connection.execute("SELECT 1 FROM attempts WHERE status='active'").fetchone(),
                    "Cannot finish with an active attempt", "STALE_ATTEMPT")
            if row["mode"] != "terminal":
                self.connection.execute("UPDATE runs SET mode='terminal'")
                self._tick()

    def snapshot_run(self, run_id: str | None = None) -> dict:
        with self._transaction():
            row = self._run(run_id)
            public = json.loads(row["public_view"])
            objects = [json.loads(r["body"]) for r in self.connection.execute("SELECT body FROM objects ORDER BY object_key")]
            attempts = [{key: r[key] for key in ("run_id", "step_id", "attempt_no", "result_id", "status", "started_at")}
                        for r in self.connection.execute("SELECT * FROM attempts ORDER BY rowid")]
            return {
                "request": public["request"], "run_state": row["mode"],
                "source_objects": [obj for obj in objects if obj["object_key"] in source_keys(public["request"])],
                "output_objects": [obj for obj in objects if obj["object_key"] not in source_keys(public["request"])], "attempts": attempts,
                "results": [json.loads(r["body"]) for r in self.connection.execute("SELECT body FROM results ORDER BY rowid")],
                "result_status_events": [json.loads(r["body"]) for r in self.connection.execute("SELECT body FROM result_status_events ORDER BY event_seq,result_id")],
                "effects": [self._receipt(row) for row in self.connection.execute("SELECT * FROM effects ORDER BY rowid")],
                "event_log": [json.loads(r["body"]) for r in self.connection.execute("SELECT body FROM event_log ORDER BY event_seq")],
                "notices": [json.loads(r[0]) for r in self.connection.execute("SELECT body FROM notices ORDER BY rowid")],
            }
