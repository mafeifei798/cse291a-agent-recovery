"""P1 one-shot delivery hooks and an independent public-rule verifier.

Only explicit fake runs may use these hooks. The clock models a controlled
tool deadline; its timestamps are synthetic and are never API latency data.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import sqlite3
from time import perf_counter

from .contracts import (STEPS, ContractError, digest, new_id, require,
                        source_keys, utc_now)


class VerificationStopped(RuntimeError):
    """A published candidate was rejected before downstream adoption."""

    def __init__(self, receipt):
        self.receipt = deepcopy(receipt)
        super().__init__("P1 runtime verifier rejected a published candidate")


class SyntheticToolClock:
    evidence_kind = "synthetic_controlled_tool_clock"

    def __init__(self):
        self.seconds = 0.0

    def advance_to(self, seconds):
        require(seconds >= self.seconds, "Controlled clock cannot move backwards", "INVALID_TRIGGER")
        self.seconds = float(seconds)
        return self.seconds


def admit_tool_reply(connection, attempt_id, captured_payload):
    """Read-only admission check for one real stored attempt and tool reply."""
    row = connection.execute("SELECT status,run_id,step_id FROM attempts WHERE token=?", (attempt_id,)).fetchone()
    require(row is not None, "Tool reply names no stored attempt", "DELIVERY_IDENTITY_MISMATCH")
    require(row["status"] == "active", "Tool reply belongs to an already closed attempt", "ATTEMPT_CLOSED")
    run = connection.execute("SELECT mode FROM runs WHERE run_id=?", (row["run_id"],)).fetchone()
    require(run is not None and run["mode"] in ("initial", "recovering"),
            "Tool reply belongs to a fenced run", "ATTEMPT_CLOSED")
    require(isinstance(captured_payload, dict) and captured_payload.get("exists") is True,
            "Invalid tool reply payload", "INVALID_PAYLOAD")
    return deepcopy(captured_payload)


def check_candidate(candidate, request, source_reader):
    """Use only the published candidate, public request and legal current reads.

    This code deliberately has no task manifest, FaultSpec or evaluator input.
    A reject never modifies the candidate or starts recovery.
    """
    started = perf_counter()
    immutable = digest(candidate)
    step = candidate["step_id"]
    require(step in STEPS[:-1], "Verifier expects a query or plan", "VERIFIER_IDENTITY_MISMATCH")
    keys = list(source_keys(request))
    requested = keys if step == "plan" else [keys[STEPS.index(step)]]
    objects = source_reader(requested)
    require(len(objects) == len(requested), "Missing verifier source", "VERIFIER_READ_FAILED")
    bykey = {obj["object_key"]: obj for obj in objects}
    require(set(bykey) == set(requested), "Wrong verifier source identities", "VERIFIER_READ_FAILED")
    reads = [{"object_key": key, "version": bykey[key]["version"], "read_at": utc_now()}
             for key in requested]
    reasons = []
    if not all(obj["exists"] for obj in objects):
        reasons.append("VERIFIER_SOURCE_MISSING")
    else:
        payload = candidate["payload"]
        if step == "plan":
            metadata, permission, resources = [bykey[key]["payload"] for key in keys]
            expected = {
                "dataset_id": request["dataset_id"], "purpose": request["purpose"],
                "batch_size": request["batch_size"], "epochs": request["epochs"],
                "num_examples": metadata["num_examples"],
                "steps": ((metadata["num_examples"] + request["batch_size"] - 1)
                          // request["batch_size"]) * request["epochs"],
                "workers": min(request["requested_workers"], resources["max_workers"]),
                "permission_allowed": permission["allowed"],
            }
        else:
            expected = bykey[requested[0]]["payload"]
        if payload != expected:
            reasons.append("VERIFIER_BUSINESS_MISMATCH")
    lineage = {ref["object_key"]: ref["version"] for ref in candidate["effective_read_set"]}
    if any(lineage.get(key) != bykey[key]["version"] for key in requested):
        reasons.append("VERIFIER_STALE_SOURCE")
    require(digest(candidate) == immutable, "Verifier mutated a candidate", "VERIFIER_IDENTITY_MISMATCH")
    return {"decision": "reject" if reasons else "accept", "candidate_ref": candidate["result_id"],
            "step_id": step, "read_refs": reads, "reason_codes": reasons,
            "logical_read_count": len(objects), "elapsed_ms": (perf_counter() - started) * 1000,
            "candidate_unchanged_digest": immutable}


class P1DeliveryHooks:
    """Narrow hooks: delivery evidence stays outside the model's business input."""

    def __init__(self, task_manifest, gateway, *, condition="CLEAN", policy="BASE",
                 fault_spec=None, recovery_round=0, clock=None):
        require(condition in ("CLEAN", "ERR", "ADV", "TMO", "STL"), "Unknown P1 condition")
        require(policy in ("BASE", "VERIFY_STOP", "FULL_RESTART"), "Unknown P1 policy")
        self.task = deepcopy(task_manifest)
        self.gateway = gateway
        self.condition, self.policy = condition, policy
        self.fault = deepcopy(fault_spec)
        self.recovery_round = recovery_round
        self.clock = clock or SyntheticToolClock()
        self.audit, self.verifier_receipts = [], []
        self.consumed = False
        self.pending_delivery = None
        self._fault_identity = None
        if self.fault:
            require(self.fault["task_id"] == self.task["task_id"]
                    and self.fault["task_digest"] == self.task["task_digest"]
                    and self.fault["condition"] == condition,
                    "Fault and task identities differ", "DELIVERY_IDENTITY_MISMATCH")

    def _eligible(self, attempt, step):
        return bool(self.fault and not self.consumed and self.recovery_round == 0
                    and attempt["attempt_no"] == self.fault["attempt_no"]
                    and step == self.fault["target_step"])

    def _carrier(self, step, bundle, attack=False):
        kind = "source_note" if step == "read_metadata" else "handoff_note" if step == "plan" else None
        if kind is None:
            return []
        if kind == "source_note":
            source = bundle["tool_snapshots"][0]
            ref = {"object_key": source["object_key"], "version": source["version"]}
        else:
            parent = bundle["parents"][0]
            ref = {"result_id": parent["result_id"], "payload_digest": digest(parent["payload"])}
        text = self.fault["transform"]["untrusted_text"] if attack else self.task["benign_notes"][kind]
        return [{"carrier_kind": kind, "carrier_ref": ref, "untrusted_text": text}]

    def _record(self, attempt, step, *, status, event_id=None, payload_delivered=True,
                model_exposed=None, **extra):
        event_id = event_id or new_id()
        record = {"delivery_id": new_id(), "event_id": event_id, "condition": self.condition,
                  "step_id": step, "attempt_id": attempt["token"], "attempt_no": attempt["attempt_no"],
                  "result_record_id": attempt["result_id"], "status": status,
                  "tool_payload_delivered": payload_delivered,
                  "timeout_event_delivered": status == "tool_timeout", "model_exposed": model_exposed,
                  "clock_kind": self.clock.evidence_kind, "monotonic_s": self.clock.seconds,
                  **deepcopy(extra)}
        self.audit.append(record)
        self._fault_identity = {
            "condition": self.condition, "event_id": event_id, "step_id": step,
            "attempt_id": attempt["token"],
            "failed_attempt_id": attempt["token"] if status == "tool_timeout" else None,
            "failed_result_id": attempt["result_id"] if status == "tool_timeout" else None,
            "faulty_result_id": None if status == "tool_timeout" else attempt["result_id"],
        }
        return record

    def after_capture(self, store, attempt, step_id, bundle):
        eligible = self._eligible(attempt, step_id)
        if eligible and self.condition == "TMO":
            self.consumed = True
            transform = self.fault["transform"]
            captured_at = self.clock.seconds
            self.clock.advance_to(captured_at + transform["deadline_seconds"])
            pending_ref = new_id()
            self.pending_delivery = {
                "pending_delivery_ref": pending_ref, "attempt_id": attempt["token"],
                "result_record_id": attempt["result_id"], "captured_at_s": captured_at,
                "reply_ready_s": captured_at + transform["reply_ready_seconds"],
                "captured_payload": deepcopy(bundle["tool_snapshots"][0]), "status": "pending",
            }
            self._record(attempt, step_id, status="tool_timeout", payload_delivered=False,
                         model_exposed=None, pending_delivery_ref=pending_ref,
                         captured_source_snapshot=bundle["tool_snapshots"][0],
                         failed_attempt_id=attempt["token"], failed_result_id=attempt["result_id"],
                         faulty_result_id=None)
            raise ContractError("TOOL_TIMEOUT", "Controlled tool deadline; late reply remains outside the scene")
        if eligible and self.condition == "STL":
            self.consumed = True
            t = self.fault["transform"]
            captured = deepcopy(bundle["tool_snapshots"][0])
            require(captured["object_key"] == t["object_key"] and captured["version"] == t["captured_version"],
                    "STL capture differs from frozen target", "DELIVERY_IDENTITY_MISMATCH")
            event_id = new_id()
            update = store.apply_external_update(event_id, t["object_key"],
                         t["expected_current_version_before_update"], t["new_current_payload"], digest(self.fault))
            current = store.read_objects([t["object_key"]])[0]
            require(current["version"] == t["new_current_version"], "STL update version differs")
            self._record(attempt, step_id, status="delivered", event_id=event_id, model_exposed=True,
                         captured_source_snapshot=captured, current_source_after_update=current,
                         ordering=["capture_v1", "external_update_v2", "deliver_v1"], update_receipt=update)
        attack = eligible and self.condition == "ADV"
        carriers = self._carrier(step_id, bundle, attack=attack)
        if attack:
            self.consumed = True
            self._record(attempt, step_id, status="delivered", model_exposed=True,
                         public_carriers=carriers, facts_unchanged=True)
        self.gateway.prepare_input(attempt, step_id, bundle, carriers)

    def before_publish(self, store, attempt, result):
        if not (self.condition == "ERR" and self._eligible(attempt, result["step_id"])
                and result["execution_status"] == "success"):
            return result, []
        self.consumed = True
        delivered = deepcopy(result)
        transform = self.fault["transform"]
        original = deepcopy(result["payload"])
        delivered["payload"][transform["field"]] = transform["replacement_value"]
        for call in delivered["model_calls"]:
            call["delivered_output"] = deepcopy(delivered["payload"])
        event_id = new_id()
        self._record(attempt, result["step_id"], status="delivered", event_id=event_id,
                     model_exposed=True, private_original_response=original,
                     delivered_output=delivered["payload"], mutation_changed=original != delivered["payload"])
        event = {"event_id": event_id, "event_digest": digest(self.fault),
                 "kind": "corrupt_result", "target_result_id": result["result_id"]}
        return delivered, [event]

    def after_publish(self, store, attempt, result):
        if hasattr(self.gateway, "record_publication"):
            self.gateway.record_publication(result)
        if self.policy == "VERIFY_STOP" and result["execution_status"] == "success" and result["step_id"] != "execute":
            receipt = check_candidate(result, self.task["request"], store.read_objects)
            self.verifier_receipts.append(receipt)
            if receipt["decision"] == "reject":
                raise VerificationStopped(receipt)

    def fault_identity(self):
        return deepcopy(self._fault_identity)

    def close_evidence(self, snapshot, accounting):
        """Bind exposure to an actual dispatched call, including failed steps."""
        if not self._fault_identity:
            return
        target = next((item for item in snapshot["results"]
                       if item["result_id"] == self.audit[0]["result_record_id"]), None)
        if target is not None:
            successful = target["execution_status"] == "success"
            self._fault_identity["faulty_result_id"] = target["result_id"] if successful else None
            if not successful:
                self._fault_identity.update(failed_result_id=target["result_id"],
                                            failed_attempt_id=self._fault_identity["attempt_id"])
        calls = accounting.get("calls", [])
        for record in self.audit:
            if record.get("status") in ("delivered", "tool_timeout"):
                if self.condition == "TMO":
                    record["model_exposed"] = None
                else:
                    record["model_exposed"] = any(call["result_id"] == record["result_record_id"]
                                                  for call in calls)

    def drain_after_freeze(self, freeze_receipt, *, frozen_database=None):
        if self.pending_delivery is None:
            return None
        require(freeze_receipt["status"] == "frozen", "Drain requires a frozen scene", "DRAIN_INCOMPLETE")
        frozen_at = freeze_receipt.get("freeze_monotonic_s", self.clock.seconds)
        require(frozen_at < self.pending_delivery["reply_ready_s"], "Reply was not pending at freeze", "DRAIN_INCOMPLETE")
        if self.pending_delivery["status"] == "rejected_late":
            return deepcopy(self.pending_delivery["drain_receipt"])
        require(frozen_database is not None, "Drain requires the actual immutable scene database", "DRAIN_INCOMPLETE")
        scene_path = Path(frozen_database).resolve()
        before_hash = hashlib.sha256(scene_path.read_bytes()).hexdigest()
        self.clock.advance_to(self.pending_delivery["reply_ready_s"])
        rejection_code = None
        with sqlite3.connect(scene_path.as_uri() + "?mode=ro", uri=True) as connection:
            connection.row_factory = sqlite3.Row
            try:
                admit_tool_reply(connection, self.pending_delivery["attempt_id"],
                                 self.pending_delivery["captured_payload"])
            except ContractError as exc:
                rejection_code = exc.code
        require(rejection_code == "ATTEMPT_CLOSED", "Late tool reply was not refused by its real closed attempt", "DRAIN_INCOMPLETE")
        after_hash = hashlib.sha256(scene_path.read_bytes()).hexdigest()
        require(after_hash == before_hash, "Late reply changed the frozen database", "SCENE_DIGEST_MISMATCH")
        receipt = {
            "pending_delivery_ref": self.pending_delivery["pending_delivery_ref"],
            "attempt_id": self.pending_delivery["attempt_id"],
            "scene_id": freeze_receipt["scene_id"], "scene_digest": freeze_receipt["scene_digest"],
            "drain_complete": True, "drain_complete_after_frozen": True,
            "late_reply_rejected": True, "status": "LATE_REPLY_REJECTED",
            "scene_modified": False,
            "drained_delivery_ids": [self.pending_delivery["pending_delivery_ref"]],
            "closed_attempt_ids": [self.pending_delivery["attempt_id"]],
            "clock_kind": self.clock.evidence_kind, "monotonic_s": self.clock.seconds,
            "freeze_monotonic_s": frozen_at, "new_call_ids": [], "new_effect_ids": [],
            "new_result_ids": [], "frozen_scene_mutated": False,
            "admission_check": {"rejected": True, "error_code": rejection_code,
                                "attempt_id": self.pending_delivery["attempt_id"],
                                "captured_payload_digest": digest(self.pending_delivery["captured_payload"]),
                                "database_sha256_before": before_hash, "database_sha256_after": after_hash,
                                "connection_mode": "read_only"},
        }
        self.pending_delivery.update(status="rejected_late", drain_receipt=receipt)
        self.audit.append({"condition": "TMO", "status": "late_reply_rejected", **deepcopy(receipt)})
        return deepcopy(receipt)
