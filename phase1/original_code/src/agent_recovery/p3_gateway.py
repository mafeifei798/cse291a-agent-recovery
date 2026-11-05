"""Opt-in P3 gateway; legacy fake profiles and accounting remain unchanged.

The campaign owns money outside branch databases. A local immutable call link
binds each workflow publication to that campaign, without pretending that a
TritonAI response follows the historical S6 fake pricing/schema.
"""
from copy import deepcopy
import json
import math
from time import monotonic

from .contracts import (ContractError, canonical_json, digest, new_id, require,
                        validate_action, validate_payload)
from .model_gateway import _strict_json
from .p1_gateway import P1ModelGateway, PROMPT_REVISION, prompt_contract
from .p1_lifecycle import P1Store
from .p3_transport import (P3HTTPError, build_p3_request,
                           input_token_upper_bound, parse_p3_usage)


class P3Store(P1Store):
    def __init__(self, path):
        super().__init__(path)
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS p3_runtime_binding(singleton INTEGER PRIMARY KEY,
                body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS p3_local_calls(call_id TEXT PRIMARY KEY,
                attempt_id TEXT UNIQUE NOT NULL, body TEXT NOT NULL);
        """)

    def bind_p3(self, binding, budget_ref):
        body = {"binding": binding.to_dict(), "campaign_budget_ref": str(budget_ref)}
        old = self.connection.execute("SELECT body FROM p3_runtime_binding").fetchone()
        if old:
            require(json.loads(old[0]) == body, "P3 binding changed", "P3_BINDING_MISMATCH")
        else:
            require(self._run()["mode"] == "initial", "Bind P3 before execution", "P3_BINDING_MISMATCH")
            self.connection.execute("INSERT INTO p3_runtime_binding VALUES(1,?)", (canonical_json(body),))

    def save_p3_call(self, record):
        with self._transaction(write=True):
            attempt = self._attempt(record["attempt_id"])
            require(attempt["status"] == "active" and self._attempt_admitted(attempt),
                    "P3 call has a closed attempt", "STALE_ATTEMPT")
            require(all(record[k] == attempt[k] for k in ("run_id", "result_id", "step_id", "attempt_no")),
                    "P3 call identity differs", "MODEL_CALL_MISMATCH")
            self.connection.execute("INSERT INTO p3_local_calls VALUES(?,?,?) ON CONFLICT(call_id) "
                                    "DO UPDATE SET body=excluded.body",
                                    (record["call_id"], record["attempt_id"], canonical_json(record)))

    def _calls_for_attempt(self, token):
        return [json.loads(r[0]) for r in self.connection.execute(
            "SELECT body FROM p3_local_calls WHERE attempt_id=? ORDER BY rowid", (token,))]

    def model_accounting_snapshot(self):
        calls = [json.loads(r[0]) for r in self.connection.execute("SELECT body FROM p3_local_calls ORDER BY rowid")]
        return {"calls": calls, "transport": "p3_external_campaign", "simulated": all(c["simulated"] for c in calls),
                "real_requests": sum(not c["simulated"] for c in calls),
                "budget_ownership": "external_campaign_not_branch"}

    def _bind_model_publication(self, attempt_token, result, publication_events=None, command=None):
        calls = self._calls_for_attempt(attempt_token)
        require(len(calls) == len(result["model_calls"]), "P3 publication omitted a call", "MODEL_CALL_MISMATCH")
        for stored, offered in zip(calls, result["model_calls"]):
            expected = deepcopy(stored)
            if offered != stored:
                expected["delivered_output"] = deepcopy(result["payload"])
                require(bool(publication_events) and result["step_id"] != "execute"
                        and result["execution_status"] == "success" and offered == expected,
                        "P3 call was changed during publication", "MODEL_CALL_MISMATCH")
                self.connection.execute("UPDATE p3_local_calls SET body=? WHERE call_id=?",
                                        (canonical_json(expected), stored["call_id"]))
            require(expected == offered and all(offered[k] == result[k] for k in
                    ("run_id", "step_id", "attempt_no", "result_id")),
                    "P3 publication identity differs", "MODEL_CALL_MISMATCH")
            if result["input_snapshot"] is not None:
                require(offered["prompt_digest"] == digest(result["input_snapshot"]["rendered_messages"]),
                        "P3 publication changed messages", "MODEL_CALL_MISMATCH")
        if result["execution_status"] == "success":
            require(len(calls) == 1 and calls[0]["status"] == "success",
                    "P3 success requires one successful call", "MODEL_CALL_MISMATCH")
            if result["step_id"] != "execute" or command is not None:
                target = ({"action": command["action"], "arguments": command["arguments"]}
                          if command is not None else result["payload"])
                require(result["model_calls"][0]["delivered_output"] == target,
                        "P3 command/output changed", "MODEL_CALL_MISMATCH")


class P3ModelGateway(P1ModelGateway):
    def __init__(self, client, campaign, *, trial_key, branch_id, logical_run_key=None,
                 phase="initial", token_counter=None, clock=monotonic):
        self.client, self.campaign, self.binding, self.clock = client, campaign, client.binding, clock
        self.trial_key, self.branch_id = trial_key, branch_id
        self.logical_run_key, self.phase = logical_run_key or trial_key, phase
        require(phase in ("initial", "replay"), "Invalid P3 phase")
        require(campaign.binding == self.binding.to_dict(), "Gateway/ledger binding differs", "P3_BINDING_MISMATCH")
        self.token_counter = token_counter
        self._prepared, self._current, self._stores = {}, None, {}
        self.records = []
        prompt_contract()

    def invoke(self, store, attempt, step_id, messages, input_bundle):
        prepared = self._prepared.get(attempt["result_id"])
        require(prepared is not None and prepared == self._current
                and messages == self.render(step_id, input_bundle),
                "P3 invocation differs from prepared input", "P1_INPUT_MISMATCH")
        require(isinstance(store, P3Store), "P3 requires its explicit Store", "P3_BINDING_MISMATCH")
        request = build_p3_request(step_id, messages, self.binding)
        upper = input_token_upper_bound(request, self.binding, self.token_counter)
        require(upper <= self.binding.max_input_tokens, "P3 input cap exceeded", "MODEL_INPUT_LIMIT")
        sidecar = {**deepcopy(prepared), "call_id": new_id()}
        call = {k: sidecar[k] for k in ("call_id", "trial_key", "logical_run_key", "branch_id", "phase",
                                       "run_id", "attempt_id", "result_id", "step_id")}
        call.update(attempt_no=attempt["attempt_no"], input_token_upper_bound=upper,
                    request=deepcopy(request), sidecar=sidecar)
        self.campaign.reserve(call)
        local = {**call, "status": "reserved", "usage": None, "delivered_output": None,
                 "prompt_digest": digest(messages), "simulated": self.binding.simulated}
        self._stores[attempt["result_id"]] = store
        raw, usage, payload, code = None, None, None, None
        started = self.clock()
        before = self.client.request_count
        before_traces = len(getattr(self.client, "traces", []))
        try:
            store.save_p3_call(local)
            try:
                raw = self.client.create(deepcopy(request), timeout_s=self.binding.timeout_s,
                    deadline_monotonic=started + self.binding.timeout_s,
                    before_send=lambda: self.campaign.mark_dispatched(call["call_id"]))
                usage = parse_p3_usage(raw)
            except P3HTTPError as exc:
                raw, usage, code = exc.raw_response, exc.usage, exc.code
            except ContractError as exc:
                # Transport preflight can reject without a physical send. Its
                # trace and observed zero remain distinct from durable intent.
                code = exc.code
            except Exception:
                # A third-party exception may contain an authorization value.
                # Record only our stable error code, never exception text.
                code = "P3_CLIENT_ERROR"
            if code is None:
                try:
                    choice = raw["choices"][0]
                    require(len(raw["choices"]) == 1 and type(choice["index"]) is int and choice["index"] == 0,
                            "P3 invalid choice", "MODEL_SCHEMA_ERROR")
                    require(choice["finish_reason"] == "stop" and choice["message"].get("refusal") in (None, ""),
                            "P3 refusal or truncated output", "MODEL_ERROR")
                    require(choice["message"].get("role") == "assistant", "P3 invalid role", "MODEL_SCHEMA_ERROR")
                    payload = _strict_json(choice["message"]["content"])
                    (validate_action(payload) if step_id == "execute" else validate_payload(step_id, payload))
                except ContractError as exc:
                    code = "MODEL_ERROR" if exc.code == "MODEL_ERROR" else "MODEL_SCHEMA_ERROR"
                except (KeyError, IndexError, TypeError, ValueError, OverflowError, RecursionError):
                    code = "MODEL_SCHEMA_ERROR"
            within_admission = (usage is not None
                                and usage["prompt_tokens"] <= upper
                                and usage["completion_tokens"] <= self.binding.max_output_tokens)
            if usage is not None and not within_admission:
                code = "P3_ADMISSION_BOUND_VIOLATION"
            traces = getattr(self.client, "traces", [])
            elapsed = self.clock() - started
            duration_ms = int(elapsed * 1000) if math.isfinite(elapsed) and elapsed >= 0 else 0
            if code is None and (not math.isfinite(elapsed) or elapsed < 0
                                 or elapsed >= self.binding.timeout_s):
                code, payload = "P3_HTTP_TIMEOUT", None
                if len(traces) > before_traces:
                    # A cleanly reaped HTTP result can still finish local
                    # validation too late. Keep the wire receipt and known
                    # usage, but fence publication and record the same outcome
                    # in the independently checked invocation trace.
                    traces[-1].update(error_code=code,
                        elapsed_s=elapsed if math.isfinite(elapsed) and elapsed >= 0 else None)
                    if isinstance(raw, dict):
                        raw["_p3_http"] = deepcopy(traces[-1])
            evidence = {"call_id": call["call_id"], "request": request, "sidecar": sidecar,
                        "http_trace": deepcopy(traces[-1]) if len(traces) > before_traces
                                      else (raw or {}).get("_p3_http", {}),
                        "raw_response": raw, "simulated": self.binding.simulated,
                        "observed_dispatch_count": self.client.request_count - before,
                        "outcome": {"status": "success" if code is None else "model_error",
                                    "error_code": code, "payload": payload if code is None else None}}
            # Persist the provider bytes/usage before monetary settlement. If
            # settlement or branch persistence fails, recovery has a receipt
            # to reconcile instead of issuing another physical request.
            self.records.append(deepcopy(evidence))
            self.campaign.attach_evidence(call["call_id"], evidence)
            request_id = raw.get("_request_id") if isinstance(raw, dict) else None
            if within_admission and isinstance(request_id, str) and request_id:
                self.campaign.settle(call["call_id"], provider_request_id=request_id,
                                     raw_usage=usage["raw"], normalized_usage=usage)
                if code and code not in ("MODEL_SCHEMA_ERROR", "MODEL_ERROR"):
                    # Billing is known even for an unusable/mismatched model
                    # reply. Pause the campaign without inventing a new hold.
                    self.campaign.quarantine(None, code)
            else:
                self.campaign.quarantine(call["call_id"], code or "P3_USAGE_UNKNOWN")
            local.update(status="success" if code is None else "model_error", usage=usage,
                         delivered_output=payload if code is None else None, error_code=code,
                         duration_ms=duration_ms)
            store.save_p3_call(local)
        except Exception:
            self.campaign.quarantine(call["call_id"], "P3_GATEWAY_PERSISTENCE_OR_SETTLEMENT_FAILED")
            raise
        if code:
            raise ContractError(code, "P3 response failed; inspect sanitized campaign evidence")
        return deepcopy(payload)

    def record_publication(self, result):
        if not result["model_calls"]:
            # A controlled tool timeout publishes a real failed step without
            # dispatching a model request, and must remain freeze/restartable.
            return
        require(self._stores[result["result_id"]].get_result(result["result_id"]) == result,
                "P3 publication must be durable", "MODEL_CALL_MISMATCH")

    def sidecars(self):
        return [deepcopy(r["sidecar"]) for r in self.records]
