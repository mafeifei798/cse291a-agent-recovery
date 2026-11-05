"""Serial offline shadow execution of the frozen P0 slot projection.

P0 remains a registration, not an execution database.  Every execution here
uses an explicitly different campaign namespace and the bundled fake client.
The P1 development-only runner and its exact transport allowlist are unchanged.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from time import monotonic

from .contracts import ContractError, digest, new_id, require
from .p1_budget import CampaignLedger
from .p1_checker import evaluate_initial
from .p1_delivery import P1DeliveryHooks, VerificationStopped
from .p1_gateway import P1ModelGateway, make_fake_client
from .p1_lifecycle import P1Lifecycle, P1Store
from .p1_runner import P0, _evidence, _run_five, _write, legacy_task, load_fault


CORE_TASK_IDS = ("p1-eval-01", "p1-eval-02", "p1-eval-03", "p1-eval-08")
PROFILES = ("attack_ignore", "attack_follow")
SCENARIOS = {
    "natural_error_before_fault", "natural_error", "fake_api_timeout",
    "schema_error", "pre_schema_invalid_err", "replay_failure",
    "false_reject", "duplicate_settlement", "no_change_err",
}


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_shadow_slots(task_ids=None, repeats=(1, 2, 3), *, p0_root=P0):
    """Return fresh copies in the frozen 168-row order, optionally filtered."""
    ids = tuple(CORE_TASK_IDS if task_ids is None else task_ids)
    repetitions = tuple(repeats)
    require(ids and len(ids) == len(set(ids)) and set(ids) <= set(CORE_TASK_IDS),
            "Shadow execution only admits the four frozen core tasks", "P2_SHADOW_SCOPE")
    require(repetitions and len(repetitions) == len(set(repetitions))
            and all(type(n) is int and n in (1, 2, 3) for n in repetitions),
            "Shadow repeats must be a nonempty subset of 1,2,3", "P2_SHADOW_SCOPE")
    rows = [json.loads(line) for line in (Path(p0_root) / "manifests/trials.jsonl").read_text().splitlines()
            if line.strip()]
    require(len(rows) == 168 and all(row["status"] == "not_started"
            and row["authorization"] == "not_authorized" and row["run_id"] is None
            and row["branch_id"] is None for row in rows),
            "Formal registration changed or is already active", "P2_FORMAL_REGISTRATION_CHANGED")
    picked = [deepcopy(row) for row in rows if row["task_id"] in ids and row["repeat"] in repetitions]
    require(len(picked) == 14 * len(ids) * len(repetitions),
            "Shadow projection has a missing/duplicate slot", "P2_SHADOW_SCOPE")
    return picked


def _task(task_id, p0_root):
    tasks = json.loads((Path(p0_root) / "manifests/tasks.json").read_text())["tasks"]
    found = [row for row in tasks if row["task_id"] == task_id]
    require(len(found) == 1 and task_id in CORE_TASK_IDS and found[0]["split"] == "eval_core",
            "Task does not belong to the frozen core shadow projection", "P2_SHADOW_SCOPE")
    return deepcopy(found[0])


def _scenario_for(scenario, source_key):
    if not scenario or scenario.get("target_source_trial_key") != source_key:
        return None
    require(scenario.get("kind") in SCENARIOS, "Unknown controlled boundary scenario", "P2_SCENARIO_INVALID")
    return deepcopy(scenario)


def _client(profile, scenario, replay):
    # The responder reads only the actual delivered envelope. Boundary controls
    # are trusted fixtures, never values supplied to the business model input.
    client = make_fake_client(follow_attacks=profile == "attack_follow" and not replay)
    if not scenario:
        return client
    kind = scenario["kind"]
    active = replay if kind == "replay_failure" else not replay
    if not active or kind not in {"natural_error_before_fault", "natural_error", "fake_api_timeout",
                                   "schema_error", "pre_schema_invalid_err", "replay_failure"}:
        return client
    original = client.on_create
    consumed = False

    def respond(request):
        nonlocal consumed
        envelope = json.loads(request["messages"][1]["content"])
        if consumed or envelope["step_id"] != scenario.get("step_id", "read_metadata"):
            return original(request)
        consumed = True
        if kind == "fake_api_timeout":
            raise TimeoutError("Controlled offline API timeout after dispatch; usage unknown")
        original(request)
        response = client.responses[-1]
        if kind == "natural_error":
            payload = json.loads(response["choices"][0]["message"]["content"])
            require("num_examples" in payload, "Natural error fixture expects metadata", "P2_SCENARIO_INVALID")
            payload["num_examples"] += 1
            response["choices"][0]["message"]["content"] = json.dumps(payload)
        else:
            response["choices"][0]["message"]["content"] = '{"unexpected_field":true}'
    client.on_create = respond
    return client


class _BoundaryHooks(P1DeliveryHooks):
    def __init__(self, *args, scenario=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.scenario = scenario
        self.boundary_audit = []

    def after_publish(self, store, attempt, result):
        super().after_publish(store, attempt, result)
        if not self.scenario or self.recovery_round or result["execution_status"] != "success":
            return
        kind = self.scenario["kind"]
        if kind == "duplicate_settlement" and result["model_calls"]:
            call = result["model_calls"][0]
            before = self.gateway.campaign.snapshot()
            self.gateway.campaign.settle_call(call["call_id"], call)
            self.gateway.campaign.settle_call(call["call_id"], call)
            unchanged = before == self.gateway.campaign.snapshot()
            require(unchanged, "Duplicate settlement changed the ledger", "IDEMPOTENCY_MISMATCH")
            self.boundary_audit.append({"kind": kind, "call_id": call["call_id"], "ledger_unchanged": True})
        if (kind == "false_reject" and self.policy == "VERIFY_STOP"
                and result["step_id"] == self.scenario.get("step_id", "read_metadata")):
            require(self.verifier_receipts and self.verifier_receipts[-1]["decision"] == "accept",
                    "False-reject fixture requires a legitimately accepted candidate", "P2_SCENARIO_INVALID")
            receipt = deepcopy(self.verifier_receipts[-1])
            receipt.update(decision="reject", reason_codes=["CONTROLLED_FALSE_REJECTION"],
                           controlled_boundary_fixture=True)
            self.verifier_receipts[-1] = receipt
            self.boundary_audit.append({"kind": kind, "candidate_ref": result["result_id"],
                                        "candidate_unchanged_digest": digest(result)})
            raise VerificationStopped(receipt)


def _hooks(task, gateway, *, condition, policy, fault_spec, recovery_round, scenario=None):
    fault = deepcopy(fault_spec)
    if scenario and scenario["kind"] == "no_change_err" and recovery_round == 0:
        require(condition == "ERR" and fault is not None, "No-change ERR needs an ERR slot", "P2_SCENARIO_INVALID")
        if fault["target_step"] == "read_metadata":
            field = fault["transform"]["field"]
            fault["transform"]["replacement_value"] = task["initial_objects"][0]["payload"][field]
        else:
            raise ContractError("P2_SCENARIO_INVALID", "No-change ERR fixture uses a metadata target")
    hooks = _BoundaryHooks(task, gateway, condition=condition, policy=policy,
                            fault_spec=fault, recovery_round=recovery_round, scenario=scenario)
    if scenario and scenario["kind"] == "no_change_err" and recovery_round == 0:
        hooks.boundary_audit.append({"kind": "no_change_err", "controlled_boundary_fixture": True,
                                     "frozen_fault_digest": digest(fault_spec),
                                     "fixture_fault_digest": digest(fault),
                                     "frozen_fault_file_modified": False})
    return hooks


def run_shadow_trial(output_dir, *, slot, profile, campaign, auto_restart=True,
                     client_factory=None, hooks_factory=None, scenario=None, p0_root=P0):
    """Run one namespaced initial slot and optionally its one paired restart.

    Factories are explicit seams: ``client_factory(replay: bool)`` still passes
    through P1's bundled fake-type allowlist; ``hooks_factory`` receives the task
    and gateway plus keyword condition, policy, fault_spec and recovery_round.
    """
    require(profile in PROFILES, "Unknown shadow fake-client profile", "P2_SHADOW_SCOPE")
    require(slot["policy"] in ("BASE", "VERIFY_STOP"), "An initial slot is required", "P2_SHADOW_SCOPE")
    require(campaign.snapshot()["status"] == "active", "Campaign already stopped", "P2_CAMPAIGN_STOPPED")
    task = _task(slot["task_id"], p0_root)
    fault = load_fault(task, slot["condition"], p0_root=p0_root)
    destination = Path(output_dir).resolve()
    require(not destination.exists(), "Refusing to overwrite shadow artifacts", "P2_DESTINATION_EXISTS")
    destination.mkdir(parents=True, exist_ok=False)
    trial_key = slot["trial_key"]
    recovery_trial_key = trial_key.rsplit("__", 1)[0] + "__FULL_RESTART"
    branch_id = new_id()
    scenario = _scenario_for(scenario, slot.get("source_trial_key", trial_key))
    make_client = client_factory or (lambda replay: _client(profile, scenario, replay))
    make_hooks = hooks_factory or (lambda task, gateway, **kw: _hooks(task, gateway, scenario=scenario, **kw))
    gateway = P1ModelGateway(make_client(False), campaign, trial_key=trial_key,
                             branch_id=branch_id, logical_run_key=trial_key)
    hooks = make_hooks(task, gateway, condition=slot["condition"], policy=slot["policy"],
                       fault_spec=fault, recovery_round=0)
    lifecycle = P1Lifecycle()
    _write(destination / "task_manifest.json", task)
    started = monotonic()
    with P1Store(destination / "initial.sqlite") as store:
        adapter = legacy_task(task, gateway.config)
        adapter["tags"] = ["P2", "offline_shadow", "simulated", "legacy_split_dev_adapter_only"]
        store.initialize_run(adapter)
        store.configure_model(gateway.config)
        source_run_id = store.runtime_view()["run_id"]
        initial_report = _run_five(store, gateway, hooks)
        initial_elapsed_ms = (monotonic() - started) * 1000
        evidence = _evidence(store, gateway, hooks, campaign, initial_report,
                             condition=slot["condition"], policy=slot["policy"], trial_key=trial_key)
        evidence["p2_boundary_audit"] = deepcopy(getattr(hooks, "boundary_audit", []))
        identity = hooks.fault_identity()
        decision = evaluate_initial(task, evidence, identity, policy=slot["policy"])
        _write(destination / "initial_report.json", initial_report)
        _write(destination / "initial_evidence.json", evidence)
        _write(destination / "initial_check.json", decision)
        ctx = {"source_trial_key": trial_key, "recovery_trial_key": recovery_trial_key,
               "campaign_budget_ref": campaign.snapshot()["campaign_budget_ref"],
               "branch_id": branch_id, "task_id": task["task_id"], "task_digest": task["task_digest"],
               "pending_delivery_ref": hooks.pending_delivery["pending_delivery_ref"] if hooks.pending_delivery else None,
               "freeze_monotonic_s": hooks.clock.seconds, "frozen_clock_ms": int(hooks.clock.seconds * 1000),
               "requested_recovery_round": 1}
        freeze = None
        recovery_control_elapsed_ms = 0.0
        if (auto_restart and slot["policy"] == "BASE" and decision["restart_eligible"]
                and campaign.snapshot()["status"] == "active"):
            control_started = monotonic()
            freeze = lifecycle.freeze(store, destination / "frozen", ctx, identity, campaign.snapshot())
            recovery_control_elapsed_ms += (monotonic() - control_started) * 1000
    admission = replay_report = replay_evidence = replay_check = drain = before_drain = duplicate = None
    replay_elapsed_ms = None
    if freeze and freeze["status"] == "frozen":
        control_started = monotonic()
        request_id = new_id()
        if slot["condition"] == "TMO":
            before_drain = lifecycle.begin_restart(destination / "frozen", destination / "restart", ctx,
                             decision, None, request_id, campaign.snapshot())
            require(before_drain["status"] == "blocked" and before_drain["reason_codes"] == ["DRAIN_INCOMPLETE"],
                    "TMO admitted before late reply drain", "DRAIN_INCOMPLETE")
        drain = hooks.drain_after_freeze(freeze, frozen_database=destination / "frozen/scene.sqlite")
        _write(destination / "delivery_audit.json", hooks.audit)
        _write(destination / "drain_receipt.json", drain)
        admission = lifecycle.begin_restart(destination / "frozen", destination / "restart", ctx,
                       decision, drain, request_id, campaign.snapshot())
        recovery_control_elapsed_ms += (monotonic() - control_started) * 1000
        if admission["status"] == "ready":
            replay_gateway = P1ModelGateway(make_client(True), campaign, trial_key=recovery_trial_key,
                                branch_id=admission["branch_id"], logical_run_key=trial_key, phase="replay")
            replay_hooks = make_hooks(task, replay_gateway, condition=slot["condition"], policy="FULL_RESTART",
                                      fault_spec=None, recovery_round=1)
            started = monotonic()
            with P1Store(admission["branch_db_path"]) as branch:
                replay_report = _run_five(branch, replay_gateway, replay_hooks, recovery_id=admission["recovery_id"])
                replay_elapsed_ms = (monotonic() - started) * 1000
                replay_evidence = _evidence(branch, replay_gateway, replay_hooks, campaign, replay_report,
                                  condition=slot["condition"], policy="FULL_RESTART", trial_key=recovery_trial_key)
                replay_evidence["p1_sidecars"] = gateway.sidecars() + replay_gateway.sidecars()
                replay_check = evaluate_initial(task, replay_evidence, None, policy="FULL_RESTART")
            _write(destination / "restart/report.json", replay_report)
            _write(destination / "restart/evidence.json", replay_evidence)
            _write(destination / "restart/check.json", replay_check)
            if campaign.snapshot()["status"] == "active":
                before_duplicate = campaign.snapshot()
                duplicate = lifecycle.begin_restart(destination / "frozen", destination / "restart", ctx,
                              decision, drain, request_id, campaign.snapshot())
                require(duplicate["status"] == "already_started" and duplicate["branch_id"] == admission["branch_id"]
                        and campaign.snapshot() == before_duplicate,
                        "Duplicate restart changed its branch or accounting", "RESTART_IDENTITY_MISMATCH")
    else:
        _write(destination / "delivery_audit.json", hooks.audit)
    summary = {
        "scope": "P2_offline_shadow_trial", "p2_schema_version": "p2-v1",
        "task_id": task["task_id"], "condition": slot["condition"], "policy": slot["policy"],
        "trial_key": trial_key, "source_trial_key": slot.get("source_trial_key"), "repeat": slot["repeat"],
        "run_id": source_run_id, "branch_id": branch_id, "profile": profile,
        "formal_slots_started": 0, "initial_report": initial_report, "initial_check": decision,
        "freeze": freeze, "before_drain_admission": before_drain, "drain_receipt": drain,
        "restart_admission": admission, "restart_report": replay_report, "restart_check": replay_check,
        "duplicate_restart": duplicate, "campaign": campaign.snapshot(),
        "clock_kind": hooks.clock.evidence_kind, "synthetic_controlled_tool_seconds": hooks.clock.seconds,
        "initial_elapsed_ms": initial_elapsed_ms, "replay_elapsed_ms": replay_elapsed_ms,
        "recovery_control_elapsed_ms": recovery_control_elapsed_ms if freeze else None,
        "restart_total_elapsed_ms": (recovery_control_elapsed_ms + replay_elapsed_ms
                                     if replay_elapsed_ms is not None else None),
        "elapsed_kind": "observed_cpu_wall_clock_including_local_store_io_excluding_postrun_oracle",
        "scenario": scenario, "boundary_audit": deepcopy(getattr(hooks, "boundary_audit", [])),
        "real_api_requests": 0, "cloud_resources_started": 0, "gpu_jobs_started": 0,
        "artifact_dir": str(destination),
    }
    _write(destination / "summary.json", summary)
    return summary


def _projection(row, campaign_id, source_sha, position):
    parent = row["parent_trial_key"]
    source = row["trial_key"]
    initial_key = parent if row["policy"] == "FULL_RESTART" else source
    return {"p2_schema_version": "p2-v1", "campaign_id": campaign_id,
            "trial_key": campaign_id + "::" + source, "source_trial_key": source,
            "parent_trial_key": campaign_id + "::" + parent if parent else None,
            "source_parent_trial_key": parent, "task_id": row["task_id"], "task_digest": row["task_digest"],
            "condition": row["condition"], "repeat": row["repeat"], "policy": row["policy"],
            "sequence_index": position, "source_sequence_index": row["sequence_index"],
            "formal_manifest_sha256": source_sha, "source_manifest_ref": "phase1/p0/manifests/trials.jsonl",
            "trial_dir": "trials/" + initial_key, "phase": "replay" if parent else "initial",
            "executed": False, "skipped_reason": "pending_offline_execution", "run_id": None,
            "branch_id": None, "status": "not_started", "call_ids": [], "new_call_ids": [], "result_ids": []}


def run_shadow_campaign(destination, *, profile="attack_ignore", task_ids=None, repeats=(1, 2, 3),
                        campaign_id=None, call_cap=840, max_cost_nano_usd=10_000_000_000,
                        scenario=None, p0_root=P0):
    """Execute the serial shadow projection, retaining every planned slot row."""
    require(profile in PROFILES, "Unknown shadow fake-client profile", "P2_SHADOW_SCOPE")
    source = Path(p0_root) / "manifests/trials.jsonl"
    source_sha = _sha(source)
    rows = load_shadow_slots(task_ids, repeats, p0_root=p0_root)
    campaign_id = campaign_id or "p2-shadow-" + profile + "-" + new_id()
    require(isinstance(campaign_id, str) and campaign_id.startswith("p2-") and "::" not in campaign_id,
            "P2 requires an explicit separate campaign namespace", "P2_SHADOW_SCOPE")
    if scenario:
        require(scenario.get("kind") in SCENARIOS and scenario.get("target_source_trial_key")
                in {row["trial_key"] for row in rows if row["policy"] != "FULL_RESTART"},
                "Scenario must target exactly one projected initial slot", "P2_SCENARIO_INVALID")
    dest = Path(destination).resolve()
    require(not dest.exists(), "Refusing to overwrite a shadow campaign", "P2_DESTINATION_EXISTS")
    dest.mkdir(parents=True, exist_ok=False)
    slots = [_projection(row, campaign_id, source_sha, i + 1) for i, row in enumerate(rows)]
    common = {"p2_schema_version": "p2-v1", "campaign_id": campaign_id, "profile": profile,
              "scope": "P2_offline_shadow", "formal_manifest_sha256": source_sha,
              "p0_freeze_id": json.loads((Path(p0_root) / "FREEZE.json").read_text())["freeze_id"],
              "task_ids": list(dict.fromkeys(row["task_id"] for row in rows)), "repeats": list(repeats),
              "call_cap": call_cap, "max_cost_nano_usd": max_cost_nano_usd,
              "scenario": deepcopy(scenario), "formal_slots_started": 0, "real_api_requests": 0,
              "cloud_resources_started": 0, "gpu_jobs_started": 0, "concurrency": 1}
    _write(dest / "campaign_manifest.json", {**common, "slots": deepcopy(slots)})
    summaries = {}
    started = monotonic()
    with CampaignLedger(dest / "campaign.sqlite", campaign_id=campaign_id, call_cap=call_cap,
                        max_cost_nano_usd=max_cost_nano_usd) as campaign:
        for slot in slots:
            if slot["phase"] == "replay":
                parent = summaries.get(slot["parent_trial_key"])
                if parent is None:
                    state = campaign.snapshot()["status"]
                    slot.update(skipped_reason="campaign_" + state if state != "active" else "parent_not_started")
                    continue
                replay = parent["restart_report"]
                if replay is None:
                    eligible = parent["initial_check"]["restart_eligible"]
                    state = campaign.snapshot()["status"]
                    reason = ("campaign_" + state if state != "active" else "not_needed"
                              if parent["initial_check"]["correctness"] == "correct" else "not_eligible")
                    if eligible and parent.get("restart_admission"):
                        reason = "restart_admission_" + parent["restart_admission"]["status"]
                    slot.update(skipped_reason=reason)
                    continue
                evidence = json.loads((dest / slot["trial_dir"] / "restart/evidence.json").read_text())
                actual_calls = [call for call in campaign.snapshot()["calls"] if call["trial_key"] == slot["trial_key"]]
                new_results = [row for row in evidence["snapshot"]["results"]
                               if row["result_id"] not in {r["result_id"] for r in json.loads(
                                   (dest / slot["trial_dir"] / "initial_evidence.json").read_text())["snapshot"]["results"]}]
                slot.update(executed=True, skipped_reason=None, status=replay["status"],
                            run_id=parent["run_id"], branch_id=parent["restart_admission"]["branch_id"],
                            call_ids=[c["call_id"] for c in actual_calls], new_call_ids=[c["call_id"] for c in actual_calls],
                            result_ids=[r["result_id"] for r in new_results])
                continue
            state = campaign.snapshot()["status"]
            if state != "active":
                slot.update(skipped_reason="campaign_" + state)
                continue
            # A cap already exactly consumed by the previous slot must stop
            # before creating another trial or dispatching a zero-output TMO.
            try:
                campaign.preflight(slot["trial_key"], slot["trial_key"])
            except ContractError as exc:
                require(campaign.snapshot()["status"] in ("stopped_budget", "uncertain"),
                        "Unexpected preflight rejection", getattr(exc, "code", "P2_CAMPAIGN_STOPPED"))
                slot.update(skipped_reason="campaign_" + campaign.snapshot()["status"])
                continue
            summary = run_shadow_trial(dest / slot["trial_dir"], slot=slot, profile=profile,
                                       campaign=campaign, scenario=scenario, p0_root=p0_root)
            # Retain only the small dependency state. Every full evidence and
            # campaign snapshot is already durable in the per-trial directory.
            summaries[slot["trial_key"]] = {
                "run_id": summary["run_id"],
                "initial_check": {key: summary["initial_check"][key]
                                  for key in ("restart_eligible", "correctness")},
                "restart_report": summary["restart_report"],
                "restart_admission": ({key: summary["restart_admission"].get(key)
                                       for key in ("status", "branch_id")}
                                      if summary["restart_admission"] else None),
            }
            evidence = json.loads((dest / slot["trial_dir"] / "initial_evidence.json").read_text())
            calls = [call for call in campaign.snapshot()["calls"] if call["trial_key"] == slot["trial_key"]]
            slot.update(executed=True, skipped_reason=None, run_id=summary["run_id"], branch_id=summary["branch_id"],
                        status=summary["initial_report"]["status"], call_ids=[c["call_id"] for c in calls],
                        new_call_ids=[c["call_id"] for c in calls],
                        result_ids=[r["result_id"] for r in evidence["snapshot"]["results"]])
        snapshot = campaign.snapshot()
    require(_sha(source) == source_sha, "Shadow execution altered the formal registration", "P2_FORMAL_REGISTRATION_CHANGED")
    _write(dest / "execution_manifest.json", {**common, "slots": slots})
    _write(dest / "campaign_snapshot.json", snapshot)
    report = {**common, "execution_manifest": slots, "campaign_snapshot": snapshot,
              "slot_count": len(slots), "executed_slots": sum(row["executed"] for row in slots),
              "skipped_slots": sum(not row["executed"] for row in slots),
              "elapsed_ms": (monotonic() - started) * 1000,
              "p3_started": False, "formal_manifest_unchanged": True}
    _write(dest / "campaign_report.json", report)
    return report
