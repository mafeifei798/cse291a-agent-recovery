"""Manual, single-development-task P1 integration with fake clients only.

This module cannot launch the frozen evaluation matrix. A caller must name one
development task, condition and initial policy; its IDs are development IDs and
never replace or start one of P0's 168 formal slots.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from .contracts import BUSINESS_RULES, PARENTS, STEPS, CommitOutcomeUnknown, new_id, require
from .model_config import ModelConfig
from .p1_delivery import P1DeliveryHooks, VerificationStopped
from .workflow import Workflow


P0 = Path(__file__).resolve().parents[2] / "phase1/p0"


def _write(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_dev_task(task_id, *, p0_root=P0):
    tasks = json.loads((Path(p0_root) / "manifests/tasks.json").read_text(encoding="utf-8"))["tasks"]
    matched = [task for task in tasks if task["task_id"] == task_id]
    require(len(matched) == 1 and matched[0]["split"] == "dev",
            "P1 runner accepts one explicit development task only", "P1_DEV_ONLY")
    return deepcopy(matched[0])


def load_fault(task_manifest, condition, *, p0_root=P0):
    if condition == "CLEAN":
        return None
    specs = json.loads((Path(p0_root) / "manifests/faults.private.json").read_text(encoding="utf-8"))["fault_specs"]
    key = task_manifest["task_id"] + "__" + condition
    require(key in specs, "Condition has no frozen development fault", "INVALID_TRIGGER")
    return deepcopy(specs[key])


def legacy_task(task_manifest, config=None):
    """Adapt public task facts without extending the legacy exact-field schema."""
    config = config or ModelConfig(config_ref="p1-offline-fake-v1")
    return {
        "schema_version": "1.1", "case_id": task_manifest["task_id"], "split": "dev",
        "request": deepcopy(task_manifest["request"]),
        "initial_objects": deepcopy(task_manifest["initial_objects"]), "events": [],
        "oracle_rules": list(BUSINESS_RULES),
        "execution_settings": {"gateway_mode": "model", "model_config_ref": config.config_ref,
                               "call_timeout_s": config.timeout_s, "max_model_calls": 10,
                               "max_recovery_rounds": 1},
        "tags": ["P1", "development_only", "offline_fake", "simulated"],
    }


def _run_five(store, gateway, hooks, *, recovery_id=None):
    workflow = Workflow(store, gateway, recovery_id=recovery_id, hooks=hooks)
    selected = {}
    try:
        for step in STEPS:
            result = workflow.run_step(step, [selected[parent] for parent in PARENTS[step]])
            if result["execution_status"] != "success":
                report = {"status": "failed", "selected": selected, "failure": result, "log_complete": True}
                break
            selected[step] = result["result_id"]
        else:
            report = {"status": "completed", "selected": selected, "log_complete": True}
    except VerificationStopped as stop:
        report = {"status": "verifier_rejected", "selected": selected,
                  "verifier_receipt": stop.receipt, "log_complete": True}
    except CommitOutcomeUnknown as exc:
        store.quarantine(exc)
        return {"status": "failed_uncertain", "selected": selected,
                "reason_codes": ["UNKNOWN_COMMIT_OUTCOME"], "log_complete": False,
                "unknown_operation_ids": [exc.operation_id] if exc.operation_id else [],
                "model_calls": len(store.model_accounting_snapshot()["calls"])}
    except Exception as exc:
        # A failed publication/persistence path may still own a reservation or
        # an applied write. Preserve it for inspection instead of inventing a
        # settled failure result or attempting another model dispatch.
        store.quarantine(exc)
        return {"status": "failed_uncertain", "selected": selected,
                "reason_codes": [getattr(exc, "code", "P1_UNRECONCILED_RUNTIME")],
                "log_complete": False, "model_calls": len(store.model_accounting_snapshot()["calls"])}
    calls = store.model_accounting_snapshot()["calls"]
    campaign_state = gateway.campaign.snapshot()
    if (campaign_state["status"] == "uncertain"
            or any(call["status"] == "reserved" or call["usage"] is None for call in calls)):
        store.quarantine("Unknown model consumption or settlement")
        return {**report, "status": "failed_uncertain", "log_complete": False,
                "reason_codes": ["UNCERTAIN_CALL_SETTLEMENT"], "model_calls": len(calls)}
    if campaign_state["status"] == "stopped_budget":
        # A denied reservation has known zero new consumption. Close this run
        # normally and preserve the campaign stop separately from uncertainty.
        report.update(status="campaign_stopped", log_complete=True,
                      reason_codes=[campaign_state.get("pause_reason") or "CALL_CAP_EXCEEDED"])
    if recovery_id is None:
        store.finish_run(store.runtime_view()["run_id"])
    else:
        store.finish_p1_restart(recovery_id, report)
    report["model_calls"] = len(store.model_accounting_snapshot()["calls"])
    return report


def _evidence(store, gateway, hooks, campaign, report, *, condition, policy, trial_key):
    snapshot, accounting = store.snapshot_run(), store.model_accounting_snapshot()
    hooks.close_evidence(snapshot, accounting)
    return {"snapshot": snapshot, "selected": deepcopy(report["selected"]),
            "accounting": accounting, "p1_sidecars": gateway.sidecars(),
            "campaign_snapshot": campaign.snapshot(), "delivery_audit": deepcopy(hooks.audit),
            "verifier_receipts": deepcopy(hooks.verifier_receipts),
            "condition": condition, "policy": policy, "trial_key": trial_key,
            "terminal_state_known": report["log_complete"],
            "unknown_operation_ids": report.get("unknown_operation_ids", []),
            "uncertain_call_ids": campaign.snapshot().get("uncertain_call_ids", [])}


def run_dev_trial(output_dir, *, task_id="p1-dev-01", condition="TMO", policy="BASE",
                  fake_follow_attacks=False, auto_restart=True, campaign=None,
                  p0_root=P0, client_factory=None):
    """Run one development integration, with at most one five-step full restart.

    ``client_factory`` is a test seam; P1ModelGateway still enforces its exact
    offline fake-client allowlist. Formal/evaluation tasks are rejected before
    creating the destination or a model client.
    """
    from .p1_budget import CampaignLedger
    from .p1_checker import evaluate_initial
    from .p1_gateway import P1ModelGateway, make_fake_client
    from .p1_lifecycle import P1Lifecycle, P1Store

    require(condition in ("CLEAN", "ERR", "ADV", "TMO", "STL"), "Unknown condition")
    require(policy in ("BASE", "VERIFY_STOP"), "Select BASE or VERIFY_STOP; restart is not an initial policy")
    task = load_dev_task(task_id, p0_root=p0_root)
    fault = load_fault(task, condition, p0_root=p0_root)
    destination = Path(output_dir).resolve()
    require(not destination.exists(), "Refusing to overwrite development artifacts", "P1_DESTINATION_EXISTS")
    destination.mkdir(parents=True, exist_ok=False)
    owned_campaign = campaign is None
    campaign = campaign or CampaignLedger(destination / "campaign.sqlite", campaign_id="p1-development-" + new_id())
    trial_key = "p1-development__" + task_id + "__" + condition + "__" + policy + "__" + new_id()
    recovery_trial_key = trial_key.replace("__" + policy + "__", "__FULL_RESTART__")
    branch_id = new_id()
    factory = client_factory or (lambda: make_fake_client(follow_attacks=fake_follow_attacks))
    gateway = P1ModelGateway(factory(), campaign, trial_key=trial_key,
                             branch_id=branch_id, logical_run_key=trial_key)
    hooks = P1DeliveryHooks(task, gateway, condition=condition, policy=policy, fault_spec=fault)
    lifecycle = P1Lifecycle()
    _write(destination / "task_manifest.json", task)
    try:
        with P1Store(destination / "initial.sqlite") as store:
            store.initialize_run(legacy_task(task, gateway.config))
            # A first-step controlled TMO dispatches no model call. Persist the
            # fake profile now so its frozen zero-call branch can later use the
            # unchanged S6 rule forbidding first-time configuration in recovery.
            store.configure_model(gateway.config)
            initial_report = _run_five(store, gateway, hooks)
            evidence = _evidence(store, gateway, hooks, campaign, initial_report,
                                 condition=condition, policy=policy, trial_key=trial_key)
            identity = hooks.fault_identity()
            decision = evaluate_initial(task, evidence, identity, policy=policy)
            _write(destination / "initial_report.json", initial_report)
            _write(destination / "initial_evidence.json", evidence)
            _write(destination / "initial_check.json", decision)
            ctx = {"source_trial_key": trial_key, "recovery_trial_key": recovery_trial_key,
                   "campaign_budget_ref": campaign.snapshot()["campaign_budget_ref"],
                   "branch_id": branch_id, "task_id": task_id, "task_digest": task["task_digest"],
                   "pending_delivery_ref": hooks.pending_delivery["pending_delivery_ref"] if hooks.pending_delivery else None,
                   "freeze_monotonic_s": hooks.clock.seconds,
                   "frozen_clock_ms": int(hooks.clock.seconds * 1000), "requested_recovery_round": 1}
            freeze = None
            if (auto_restart and policy == "BASE" and decision["restart_eligible"]
                    and campaign.snapshot()["status"] != "stopped_budget"):
                freeze = lifecycle.freeze(store, destination / "frozen", ctx, identity, campaign.snapshot())
        admission = replay_report = replay_evidence = replay_check = drain = before_drain = duplicate = None
        if freeze and freeze["status"] == "frozen":
            request_id = new_id()
            if condition == "TMO":
                before_drain = lifecycle.begin_restart(destination / "frozen", destination / "restart", ctx,
                                 decision, None, request_id, campaign.snapshot())
                require(before_drain["status"] == "blocked" and before_drain["reason_codes"] == ["DRAIN_INCOMPLETE"],
                        "Zero-output TMO admitted before late reply drain", "DRAIN_INCOMPLETE")
            drain = hooks.drain_after_freeze(freeze, frozen_database=destination / "frozen/scene.sqlite")
            # External audit is intentionally written after freeze, beside the
            # scene directory rather than into the frozen SQLite or scene JSON.
            _write(destination / "delivery_audit.json", hooks.audit)
            _write(destination / "drain_receipt.json", drain)
            admission = lifecycle.begin_restart(destination / "frozen", destination / "restart", ctx,
                           decision, drain, request_id, campaign.snapshot())
            if admission["status"] == "ready":
                replay_gateway = P1ModelGateway(factory(), campaign, trial_key=recovery_trial_key,
                                   branch_id=admission["branch_id"], logical_run_key=trial_key, phase="replay")
                replay_hooks = P1DeliveryHooks(task, replay_gateway, condition=condition,
                                    policy="FULL_RESTART", recovery_round=1)
                with P1Store(admission["branch_db_path"]) as branch:
                    replay_report = _run_five(branch, replay_gateway, replay_hooks,
                                             recovery_id=admission["recovery_id"])
                    replay_evidence = _evidence(branch, replay_gateway, replay_hooks, campaign, replay_report,
                                      condition=condition, policy="FULL_RESTART", trial_key=recovery_trial_key)
                    replay_evidence["p1_sidecars"] = gateway.sidecars() + replay_gateway.sidecars()
                    replay_check = evaluate_initial(task, replay_evidence, None, policy="FULL_RESTART")
                _write(destination / "restart/report.json", replay_report)
                _write(destination / "restart/evidence.json", replay_evidence)
                _write(destination / "restart/check.json", replay_check)
                before_duplicate = campaign.snapshot()
                duplicate = lifecycle.begin_restart(destination / "frozen", destination / "restart", ctx,
                             decision, drain, request_id, campaign.snapshot())
                require(duplicate["status"] == "already_started" and duplicate["branch_id"] == admission["branch_id"]
                        and campaign.snapshot() == before_duplicate,
                        "Duplicate restart changed branch or campaign accounting", "RESTART_IDENTITY_MISMATCH")
        else:
            _write(destination / "delivery_audit.json", hooks.audit)
        summary = {
            "scope": "P1_development_integration", "task_id": task_id, "condition": condition, "policy": policy,
            "trial_key": trial_key, "formal_slots_started": 0, "initial_report": initial_report,
            "initial_check": decision, "freeze": freeze, "before_drain_admission": before_drain,
            "drain_receipt": drain, "restart_admission": admission, "restart_report": replay_report,
            "restart_check": replay_check, "duplicate_restart": duplicate,
            "campaign": campaign.snapshot(), "clock_kind": hooks.clock.evidence_kind,
            "synthetic_controlled_tool_seconds": hooks.clock.seconds,
            "real_api_requests": 0, "cloud_resources_started": 0, "gpu_jobs_started": 0,
            "artifact_dir": str(destination),
        }
        _write(destination / "summary.json", summary)
        return summary
    finally:
        if owned_campaign and hasattr(campaign, "close"):
            campaign.close()
