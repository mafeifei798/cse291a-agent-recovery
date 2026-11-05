"""Offline call ledger and conservative per-run budget reservations.

The safe ledger is separate from the unchanged workflow snapshot. Provider
responses belong to a private audit table, never to recovery inputs. A scene
backup copies the ledger, including initial calls and unresolved reservations.
"""

from copy import deepcopy
import json

from .contracts import canonical_json, digest, exact_fields, new_id, require, utc_now
from .model_config import ModelConfig


OUTCOME_FIELDS = {"status", "usage", "delivered_output", "error_code", "request_id", "duration_ms"}


class ModelStoreMixin:
    def _initialize_model_tables(self):
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS model_configuration (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                config_digest TEXT NOT NULL, body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS model_call_ledger (
                call_id TEXT PRIMARY KEY, attempt_token TEXT UNIQUE NOT NULL,
                body TEXT NOT NULL, settlement_digest TEXT
            );
            CREATE TABLE IF NOT EXISTS private_model_audit (
                call_id TEXT PRIMARY KEY, response_digest TEXT NOT NULL,
                body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS model_request_audit (
                call_id TEXT PRIMARY KEY, body TEXT NOT NULL
            );
        """)

    def configure_model(self, config: ModelConfig):
        require(isinstance(config, ModelConfig), "Expected a pinned ModelConfig", "MODEL_CONFIG_ERROR")
        body = config.to_dict()
        with self._transaction(write=True):
            run = self._run()
            settings = json.loads(run["public_view"])["execution_settings"]
            require(settings["gateway_mode"] == "model"
                    and settings["model_config_ref"] == config.config_ref,
                    "Run and model configuration references differ", "MODEL_CONFIG_ERROR")
            require(settings["call_timeout_s"] == config.timeout_s,
                    "Run and model timeouts differ", "MODEL_CONFIG_ERROR")
            old = self.connection.execute("SELECT * FROM model_configuration WHERE singleton=1").fetchone()
            if old is not None:
                require(old["body"] == canonical_json(body) and old["config_digest"] == digest(body),
                        "The persisted model configuration is immutable", "MODEL_CONFIG_ERROR")
                return body
            require(run["mode"] == "initial", "Cannot add a model configuration after the initial phase", "STALE_ATTEMPT")
            self.connection.execute("INSERT INTO model_configuration VALUES(1,?,?)", (digest(body), canonical_json(body)))
        return body

    def _model_config(self):
        row = self.connection.execute("SELECT * FROM model_configuration WHERE singleton=1").fetchone()
        if row is None:
            return None
        body = json.loads(row["body"])
        require(digest(body) == row["config_digest"], "Persisted model configuration was changed", "MODEL_CONFIG_ERROR")
        return ModelConfig.from_dict(body)

    def _model_calls(self):
        return [json.loads(row[0]) for row in self.connection.execute("SELECT body FROM model_call_ledger ORDER BY rowid")]

    def _model_budget(self, config, calls):
        settings = json.loads(self._run()["public_view"])["execution_settings"]
        known = sum(call["known_cost_nano_usd"] for call in calls)
        held = sum(call["held_cost_nano_usd"] for call in calls)
        input_tokens = sum((call["usage"] or {}).get("prompt_tokens", 0) for call in calls)
        output_tokens = sum((call["usage"] or {}).get("completion_tokens", 0) for call in calls)
        limit = config.max_cost_nano_usd if config else 0
        return {"max_model_calls": settings["max_model_calls"], "model_calls_used": len(calls),
                "model_calls_remaining": max(0, settings["max_model_calls"] - len(calls)),
                "max_cost_nano_usd": limit, "known_cost_nano_usd": known, "held_cost_nano_usd": held,
                "committed_cost_nano_usd": known + held, "remaining_cost_nano_usd": max(0, limit - known - held),
                "known_prompt_tokens": input_tokens, "known_completion_tokens": output_tokens,
                "known_total_tokens": input_tokens + output_tokens,
                "unknown_usage_calls": sum(call["usage"] is None for call in calls)}

    def reserve_model_call(self, attempt_token, request, config: ModelConfig):
        """Reserve before dispatch. A crash leaves a hold rather than free calls."""
        require(isinstance(config, ModelConfig) and isinstance(request, dict), "Invalid model call", "MODEL_CONFIG_ERROR")
        exact_fields(request, {"model", "messages", "n", "store", "stream", "temperature", "service_tier",
                               "max_completion_tokens", "response_format"}, "offline model request")
        request_hash = digest(request)
        require(request.get("model") == config.model and type(request.get("n")) is int and request.get("n") == 1
                and request.get("store") is False
                and request.get("stream") is False and request.get("service_tier") == "default"
                and type(request.get("temperature")) in (int, float) and request["temperature"] == 0
                and type(request.get("max_completion_tokens")) is int
                and request["max_completion_tokens"] == config.max_output_tokens
                and isinstance(request.get("messages"), list)
                and isinstance(request.get("response_format"), dict),
                "Request differs from the pinned model configuration", "MODEL_CONFIG_ERROR")
        with self._transaction(write=True):
            attempt = self._attempt(attempt_token)
            require(attempt["status"] == "active" and self._attempt_admitted(attempt),
                    "Run no longer admits a model call", "STALE_ATTEMPT")
            stored_config = self._model_config()
            require(stored_config is not None and stored_config.to_dict() == config.to_dict(),
                    "The model configuration was not persisted or differs", "MODEL_CONFIG_ERROR")
            old = self.connection.execute("SELECT body FROM model_call_ledger WHERE attempt_token=?", (attempt_token,)).fetchone()
            require(old is None, "An attempt can dispatch only one model request", "MODEL_CALL_ALREADY_RESERVED")
            calls = self._model_calls()
            budget = self._model_budget(config, calls)
            require(budget["model_calls_remaining"] > 0, "Model call budget exhausted", "MODEL_CALL_BUDGET_EXCEEDED")
            reserve = config.worst_case_cost_nano_usd
            require(budget["remaining_cost_nano_usd"] >= reserve,
                    "Insufficient budget for a worst-case model request", "MODEL_COST_BUDGET_EXCEEDED")
            call_id = new_id()
            body = {"call_id": call_id, "run_id": attempt["run_id"], "step_id": attempt["step_id"],
                    "attempt_no": attempt["attempt_no"], "result_id": attempt["result_id"],
                    "config_ref": config.config_ref, "config_digest": digest(config.to_dict()),
                    "model": config.model, "transport": config.transport, "simulated": True,
                    "cost_kind": "simulated_standard_tokens", "request_digest": request_hash,
                    "prompt_digest": digest(request["messages"]),
                    "response_format_digest": digest(request["response_format"]),
                    "status": "reserved", "usage": None, "known_cost_nano_usd": 0,
                    "held_cost_nano_usd": reserve, "reserved_cost_nano_usd": reserve,
                    "delivered_output": None, "error_code": None, "request_id": None,
                    "duration_ms": 0, "started_at": utc_now(), "finished_at": None}
            self.connection.execute("INSERT INTO model_call_ledger VALUES(?,?,?,NULL)",
                                    (call_id, attempt_token, canonical_json(body)))
            self.connection.execute("INSERT INTO model_request_audit VALUES(?,?)", (call_id, canonical_json(request)))
            return deepcopy(body)

    def settle_model_call(self, call_id, outcome, private_response=None):
        exact_fields(outcome, OUTCOME_FIELDS, "model call outcome")
        require(outcome["status"] in ("success", "timeout", "model_error", "schema_error"), "Invalid model outcome")
        usage = outcome["usage"]
        if usage is not None:
            exact_fields(usage, {"prompt_tokens", "completion_tokens"}, "token usage")
            require(all(type(value) is int and value >= 0 for value in usage.values()), "Invalid token usage")
        require(type(outcome["duration_ms"]) is int and outcome["duration_ms"] >= 0, "Invalid call duration")
        require(outcome["request_id"] is None or isinstance(outcome["request_id"], str), "Invalid request ID")
        require(outcome["error_code"] is None or isinstance(outcome["error_code"], str), "Invalid error code")
        require(outcome["delivered_output"] is None or isinstance(outcome["delivered_output"], dict), "Invalid delivered model output")
        require(outcome["status"] != "success" or (usage is not None and isinstance(outcome["delivered_output"], dict)
                and outcome["error_code"] is None), "Successful model response needs known usage and output")
        require(outcome["status"] == "success" or outcome["delivered_output"] is None,
                "Failed model calls cannot deliver an output")
        settlement_hash = digest({"outcome": outcome, "private_response": private_response})
        with self._transaction(write=True):
            row = self.connection.execute("SELECT * FROM model_call_ledger WHERE call_id=?", (call_id,)).fetchone()
            require(row is not None, "Unknown model call", "MODEL_CALL_ERROR")
            body = json.loads(row["body"])
            if row["settlement_digest"] is not None:
                require(row["settlement_digest"] == settlement_hash,
                        "A closed model call cannot be settled with a different response", "IDEMPOTENCY_MISMATCH")
                return body
            attempt = self._attempt(row["attempt_token"])
            require(attempt["status"] == "active" and self._attempt_admitted(attempt),
                    "Late model response cannot settle a fenced attempt", "STALE_ATTEMPT")
            config = self._model_config()
            known_cost = (usage["prompt_tokens"] * config.input_nano_usd_per_token
                          + usage["completion_tokens"] * config.output_nano_usd_per_token) if usage is not None else 0
            body.update(deepcopy(outcome))
            body.update(known_cost_nano_usd=known_cost,
                        held_cost_nano_usd=body["reserved_cost_nano_usd"] if usage is None else 0,
                        finished_at=utc_now())
            self.connection.execute("UPDATE model_call_ledger SET body=?,settlement_digest=? WHERE call_id=?",
                                    (canonical_json(body), settlement_hash, call_id))
            self.connection.execute("INSERT INTO private_model_audit VALUES(?,?,?)",
                                    (call_id, digest(private_response), canonical_json(private_response)))
            return deepcopy(body)

    def calls_for_attempt(self, attempt_token):
        with self._transaction():
            self._attempt(attempt_token)
            return self._calls_for_attempt(attempt_token)

    def _calls_for_attempt(self, attempt_token):
        return [json.loads(row[0]) for row in self.connection.execute(
            "SELECT body FROM model_call_ledger WHERE attempt_token=? ORDER BY rowid", (attempt_token,))]

    def model_accounting_snapshot(self):
        with self._transaction():
            self._run()
            config = self._model_config()
            calls = self._model_calls()
            return {"schema_version": "s6-offline-v1", "config": config.to_dict() if config else None,
                    "config_digest": digest(config.to_dict()) if config else None,
                    "calls": calls, "requests_by_call": {row[0]: json.loads(row[1]) for row in self.connection.execute(
                        "SELECT call_id,body FROM model_request_audit ORDER BY rowid")},
                    "attempt_inputs_by_result": {row["result_id"]: {
                        "parent_result_ids": json.loads(row["parents"]),
                        "tool_snapshots": json.loads(row["read_snapshots"])}
                        for row in self.connection.execute("""
                            SELECT attempts.* FROM attempts JOIN model_call_ledger
                            ON attempts.token=model_call_ledger.attempt_token
                            ORDER BY model_call_ledger.rowid
                        """)},
                    "budget": self._model_budget(config, calls),
                    "transport": "offline_fake", "simulated": True, "real_requests": 0, "real_cost_nano_usd": 0}

    def _bind_model_publication(self, attempt_token, result, publication_events=None, command=None):
        """Caller owns publication transaction; never accepts forged usage or cost."""
        mode = json.loads(self._run()["public_view"])["execution_settings"]["gateway_mode"]
        if mode != "model":
            require(result["model_calls"] == [], "Scripted execution cannot claim model calls", "MODEL_CALL_MISMATCH")
            return
        calls = self._calls_for_attempt(attempt_token)
        supplied = result["model_calls"]
        require(len(supplied) == len(calls), "Result omitted or invented a model call", "MODEL_CALL_MISMATCH")
        require(all(call["status"] != "reserved" for call in calls),
                "A pending model call cannot publish a result", "MODEL_CALL_PENDING")
        for recorded, offered in zip(calls, supplied):
            if recorded != offered:
                expected = deepcopy(recorded)
                expected["delivered_output"] = deepcopy(result["payload"])
                require(bool(publication_events) and result["step_id"] != "execute"
                        and result["execution_status"] == "success" and recorded["status"] == "success"
                        and offered == expected,
                        "Result changed its model call accounting", "MODEL_CALL_MISMATCH")
                self.connection.execute("UPDATE model_call_ledger SET body=? WHERE call_id=?",
                                        (canonical_json(expected), recorded["call_id"]))
                recorded = expected
            require(all(recorded[key] == result[key] for key in ("run_id", "step_id", "attempt_no", "result_id")),
                    "Call belongs to a different result", "MODEL_CALL_MISMATCH")
            if result["input_snapshot"] is not None:
                require(recorded["prompt_digest"] == digest(result["input_snapshot"]["rendered_messages"]),
                        "Published messages differ from the reserved model request", "MODEL_CALL_MISMATCH")
        if result["execution_status"] == "success":
            require(len(calls) == 1 and supplied[0]["status"] == "success",
                    "Successful model execution requires one successful call", "MODEL_CALL_MISMATCH")
            if result["step_id"] != "execute":
                require(supplied[0]["delivered_output"] == result["payload"],
                        "Published payload differs from delivered model output", "MODEL_CALL_MISMATCH")
            elif command is not None:
                require(supplied[0]["delivered_output"] == {"action": command["action"], "arguments": command["arguments"]},
                        "Executor command differs from its delivered model action", "MODEL_CALL_MISMATCH")
