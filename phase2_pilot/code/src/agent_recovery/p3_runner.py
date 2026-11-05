"""P3 development-only fake-HTTP integration, with actual tool timing.

There is deliberately no live runner entry point or formal-matrix switch here.
The transport's real sender must be authorized separately in a future step.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sqlite3

from .contracts import (PARENTS, STEPS, ContractError, digest, new_id,
                        require)
from .p1_delivery import VerificationStopped
from .p1_gateway import make_fake_client
from .p1_lifecycle import P1Lifecycle
from .p1_runner import load_dev_task, load_fault, legacy_task
from .p3_delivery import P3DeliveryHooks
from .p3_gateway import P3ModelGateway, P3Store
from .p3_transport import P3HTTPClient, FakeHTTPSender, fake_http_response
from .p3_trial_checker import evaluate_trial_snapshot


def write(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fixture_client(binding, *, follow_attacks=False, fixtures=None):
    """A finite HTTP boundary fed only by actually delivered public messages."""
    require(binding.simulated and not binding.real_requests_authorized,
            "Offline preparation cannot construct a live client", "OFFLINE_ONLY")
    if fixtures is None:
        model = make_fake_client(follow_attacks=follow_attacks)
        prefix = new_id()

        def respond(request):
            raw = model.create(json.loads(request.body), timeout_s=request.timeout_s)
            raw["id"] = "fixture-response-" + prefix + "-" + str(model.request_count)
            raw.pop("_request_id", None)
            return fake_http_response(raw=raw, request_id="fixture-request-" + prefix + "-" + str(model.request_count))

        fixtures = [respond] * 5
    return P3HTTPClient(binding, FakeHTTPSender(fixtures))


def run_five(store, gateway, hooks, recovery_id=None, *, max_steps=5):
    from .workflow import Workflow
    workflow = Workflow(store, gateway, recovery_id=recovery_id, hooks=hooks)
    selected = {}
    try:
        require(type(max_steps) is int and max_steps in (1, 5), "P3 runs a probe or five steps only")
        for step in STEPS[:max_steps]:
            result = workflow.run_step(step, [selected[p] for p in PARENTS[step]])
            if result["execution_status"] != "success":
                report = {"status": "failed", "selected": selected, "failure": result}
                break
            selected[step] = result["result_id"]
        else:
            report = {"status": "probe_completed" if max_steps == 1 else "completed", "selected": selected}
    except VerificationStopped as exc:
        report = {"status": "verifier_rejected", "selected": selected, "verifier_receipt": exc.receipt}
    except Exception as exc:
        gateway.campaign.quarantine(None, "P3_WORKFLOW_UNKNOWN_OUTCOME")
        store.quarantine("P3 workflow publication or commit uncertain")
        return {"status": "failed_uncertain", "selected": selected, "log_complete": False,
                "reason_codes": [getattr(exc, "code", "P3_UNKNOWN_COMMIT")]}
    campaign_state = gateway.campaign.snapshot()["status"]
    if campaign_state not in ("active", "stopped_budget"):
        store.quarantine("P3 campaign stopped; no next dispatch")
        report.update(status="failed_uncertain", log_complete=False)
    else:
        if campaign_state == "stopped_budget":
            report.update(status="campaign_stopped", reason_codes=[gateway.campaign.snapshot()["pause_reason"]])
        if recovery_id:
            store.finish_p1_restart(recovery_id, report)
        else:
            store.finish_run(store.runtime_view()["run_id"])
        report["log_complete"] = True
    return report


def evaluate_p3_trial(task, snapshot, selected, audits, identity, *, policy, terminal_known=True):
    return evaluate_trial_snapshot(task, snapshot, selected, audits, identity,
                                   policy=policy, terminal_known=terminal_known)


def freeze_p3(store, path, ctx, identity, campaign, *, clock, reply_ready_s=None):
    path = Path(path)
    require(not path.exists() and campaign.snapshot()["status"] == "active",
            "Cannot freeze unknown campaign", "UNKNOWN_SETTLEMENT")
    snapshot = store.snapshot_run()
    source_run_id = store.runtime_view()["run_id"]
    require(ctx.get("source_run_id") == source_run_id,
            "Frozen context names a different source run", "RESTART_IDENTITY_MISMATCH")
    source_calls = [c for c in campaign.calls() if c["run_id"] == source_run_id]
    require(all(c["logical_run_key"] == ctx["logical_run_key"] and c["phase"] == "initial"
                for c in source_calls),
            "Frozen logical identity differs from external campaign calls", "RESTART_IDENTITY_MISMATCH")
    require(snapshot["run_state"] == "terminal" and all(a["status"] != "active" for a in snapshot["attempts"]),
            "Freeze requires a known terminal scene", "UNKNOWN_TERMINAL_STATE")
    P1Lifecycle._fault_matches(store, identity)
    path.mkdir()
    with sqlite3.connect(path / "scene.sqlite") as target:
        store.connection.backup(target)
    scene = {"snapshot": snapshot, "accounting": store.model_accounting_snapshot(),
             "ctx": deepcopy(ctx), "fault_identity": deepcopy(identity)}
    write(path / "scene.json", scene)
    completed = clock.seconds
    require(reply_ready_s is None or completed < reply_ready_s,
            "Actual freeze completed after the controlled reply became ready", "P3_FREEZE_DEADLINE_MISSED")
    receipt = {"status": "frozen", "scene_id": new_id(), "scene_digest": digest(scene),
               "database_digest": sha(path / "scene.sqlite"), "snapshot_digest": digest(snapshot),
               "freeze_started_monotonic_s": ctx["freeze_monotonic_s"],
               "freeze_monotonic_s": completed, "freeze_completed_monotonic_s": completed,
               "campaign_budget_ref": campaign.ref}
    write(path / "freeze_receipt.json", receipt)
    require(reply_ready_s is None or clock.seconds < reply_ready_s,
            "Freeze receipt persistence missed controlled reply readiness", "P3_FREEZE_DEADLINE_MISSED")
    return receipt


def begin_p3_restart(scene_dir, dest, ctx, decision, drain, campaign):
    scene_dir, dest = Path(scene_dir), Path(dest)
    receipt = json.loads((scene_dir / "freeze_receipt.json").read_text())
    scene = json.loads((scene_dir / "scene.json").read_text())
    require(receipt["scene_digest"] == digest(scene) and receipt["database_digest"] == sha(scene_dir / "scene.sqlite"),
            "P3 scene changed", "SCENE_DIGEST_MISMATCH")
    require(decision["restart_eligible"] and decision["fault_identity"] == scene["fault_identity"]
            and ctx == scene["ctx"] and campaign.ref == receipt["campaign_budget_ref"],
            "P3 restart identity differs", "RESTART_IDENTITY_MISMATCH")
    with sqlite3.connect((scene_dir / "scene.sqlite").resolve().as_uri() + "?mode=ro", uri=True) as source:
        source_run = source.execute("SELECT run_id,mode FROM runs WHERE singleton=1").fetchone()
    require(source_run is not None and source_run[1] == "terminal"
            and ctx.get("source_run_id") == source_run[0],
            "Restart source is not its actual frozen terminal run", "RESTART_IDENTITY_MISMATCH")
    source_calls = [c for c in campaign.calls() if c["run_id"] == source_run[0]]
    require(all(c["logical_run_key"] == ctx["logical_run_key"] for c in source_calls),
            "Restart logical identity differs from external campaign calls", "RESTART_IDENTITY_MISMATCH")
    if scene["fault_identity"]["condition"] == "TMO":
        if not (drain and drain.get("scene_digest") == receipt["scene_digest"]
                and drain.get("scene_id") == receipt["scene_id"]
                and drain.get("late_reply_rejected") is True and drain.get("scene_modified") is False
                and scene["fault_identity"]["failed_attempt_id"] in drain.get("closed_attempt_ids", [])
                and drain.get("monotonic_s", 0) > receipt["freeze_monotonic_s"]):
            return {"status": "blocked", "reason_codes": ["DRAIN_INCOMPLETE"]}
    identity = {"logical_run_key": ctx["logical_run_key"], "source_run_id": source_run[0],
                "scene_digest": receipt["scene_digest"],
                "restart_request_id": ctx["restart_request_id"], "destination": str(dest.resolve())}
    admission = campaign.reserve_restart(identity)
    if admission["status"] == "already_started":
        return admission
    created_destination = False
    try:
        require(not dest.exists(), "P3 restart destination exists", "P3_DESTINATION_EXISTS")
        dest.mkdir()
        created_destination = True
        with sqlite3.connect((scene_dir / "scene.sqlite").as_uri() + "?mode=ro", uri=True) as source:
            with sqlite3.connect(dest / "branch.sqlite") as target:
                source.backup(target)
        recovery_id = new_id()
        with P3Store(dest / "branch.sqlite") as branch:
            branch.admit_p1_restart(recovery_id, ctx["recovery_trial_key"], ctx["restart_request_id"])
            old = scene["snapshot"]
            branch.mark_unusable([{"result_id": r["result_id"], "reasons": ["p3_full_restart"]}
                                  for r in old["results"] if r["execution_status"] == "success"], recovery_id)
            compensations = [branch.compensate(e["effect_id"], recovery_id) for e in old["effects"] if e["state"] == "applied"]
            require(all(r["status"] != "compensation_conflict" for r in compensations),
                    "P3 compensation conflict", "COMPENSATION_CONFLICT")
        result = {"status": "ready", "recovery_id": recovery_id, "branch_id": new_id(),
                  "branch_db_path": str((dest / "branch.sqlite").resolve()), "reused_result_ids": [],
                  "replay_steps": list(STEPS), "campaign_budget_ref": campaign.ref,
                  "compensation": compensations, "scene_digest": receipt["scene_digest"]}
        write(dest / "restart_receipt.json", result)
        return result
    except BaseException:
        # The admission remains consumed. Neither a different destination nor a
        # second notification may turn an interrupted clone into a fresh replay.
        try:
            campaign.quarantine(None, "P3_RESTART_ADMISSION_OR_COPY_FAILED")
        finally:
            if created_destination and (dest / "branch.sqlite").exists():
                try:
                    with P3Store(dest / "branch.sqlite") as branch:
                        branch.quarantine("P3 restart admission/copy outcome is uncertain")
                except Exception:
                    pass  # The external campaign already blocks every dispatch.
        raise


def run_offline_trial(output_dir, campaign, binding, *, task_id="p1-dev-01", condition="CLEAN",
                      policy="BASE", follow_attacks=False, client_factory=None, restart=True):
    require(binding.simulated and not binding.real_requests_authorized, "Fake HTTP preparation only", "OFFLINE_ONLY")
    return _run_trial(output_dir, campaign, binding, task_id=task_id, condition=condition,
                      policy=policy, follow_attacks=follow_attacks, client_factory=client_factory,
                      restart=restart, execution_kind="offline_fake_http")


def _run_trial(output_dir, campaign, binding, *, task_id="p1-dev-01", condition="CLEAN",
               policy="BASE", follow_attacks=False, client_factory=None, restart=True,
               execution_kind, token_counter=None, probe_only=False):
    """Shared mechanics; public entry gates own permission and frozen-cell admission."""
    require(execution_kind in ("offline_fake_http", "offline_authorized_entry_fixture", "authorized_real_dev"),
            "Unknown P3 execution kind", "P3_ENTRY_MODE_MISMATCH")
    require((execution_kind == "authorized_real_dev") is (not binding.simulated),
            "P3 execution kind differs from its binding", "P3_ENTRY_MODE_MISMATCH")
    require(not probe_only or (task_id == "p1-dev-01" and condition == "CLEAN" and policy == "BASE"),
            "The one interface probe has a fixed development input", "P3_ENTRY_MODE_MISMATCH")
    task = load_dev_task(task_id)
    fault = load_fault(task, condition)
    dest = Path(output_dir).resolve()
    require(not dest.exists(), "P3 refuses artifact overwrite", "P3_DESTINATION_EXISTS")
    dest.mkdir(parents=True)
    write(dest / "task.json", task)
    logical = ("p3-offline__" if binding.simulated else "p3-live-development__") + task_id + "__" + condition + "__" + policy + "__" + new_id()
    factory = client_factory or (lambda: fixture_client(binding, follow_attacks=follow_attacks))
    gateway = P3ModelGateway(factory(), campaign, trial_key=logical, logical_run_key=logical, branch_id=new_id(),
                             token_counter=token_counter)
    hooks = P3DeliveryHooks(task, gateway, condition=condition, policy=policy, fault_spec=fault)
    legacy = legacy_task(task)
    legacy["execution_settings"].update(model_config_ref=binding.binding_ref, call_timeout_s=binding.timeout_s)
    legacy["tags"] = ["P3", "development_only", execution_kind,
                      "simulated" if binding.simulated else "real_api"]
    freeze = drain = admission = replay_report = replay_check = None
    before_drain = duplicate = None
    with P3Store(dest / "initial.sqlite") as store:
        store.initialize_run(legacy)
        store.bind_p3(binding, campaign.ref)
        report = run_five(store, gateway, hooks, max_steps=1 if probe_only else 5)
        snapshot = store.snapshot_run()
        hooks.close_evidence(snapshot, store.model_accounting_snapshot())
        identity = hooks.fault_identity()
        decision = evaluate_p3_trial(task, snapshot, report["selected"], hooks.audit, identity,
                                     policy=policy, terminal_known=report["log_complete"])
        write(dest / "initial_snapshot.json", snapshot)
        write(dest / "initial_report.json", report)
        write(dest / "initial_check.json", decision)
        ctx = {"logical_run_key": logical, "source_run_id": store.runtime_view()["run_id"],
               "recovery_trial_key": logical + "__FULL_RESTART",
               "restart_request_id": new_id(), "freeze_monotonic_s": hooks.clock.seconds}
        should_restart = restart and decision["restart_eligible"]
        should_freeze = should_restart or hooks.pending_delivery is not None
        if should_freeze and report["log_complete"] and campaign.snapshot()["status"] == "active":
            try:
                freeze = freeze_p3(store, dest / "frozen", ctx, identity, campaign, clock=hooks.clock,
                                  reply_ready_s=hooks.pending_delivery["reply_ready_s"] if hooks.pending_delivery else None)
            except BaseException:
                campaign.quarantine(None, "P3_FREEZE_OR_PERSISTENCE_FAILED")
                raise
    if freeze:
        if condition == "TMO" and should_restart:
            before_drain = begin_p3_restart(dest / "frozen", dest / "restart", ctx, decision, None, campaign)
        try:
            drain = hooks.drain_after_freeze(freeze, frozen_database=dest / "frozen/scene.sqlite")
            # Cleanup is required even for VERIFY_STOP or an explicitly disabled
            # restart. A durable late-reply receipt precedes every replay dispatch.
            write(dest / "drain_receipt.json", drain)
            write(dest / "delivery_audit.json", hooks.audit)
        except BaseException:
            campaign.quarantine(None, "P3_TOOL_DRAIN_OR_PERSISTENCE_FAILED")
            raise
        if should_restart:
            admission = begin_p3_restart(dest / "frozen", dest / "restart", ctx, decision, drain, campaign)
            duplicate = begin_p3_restart(dest / "frozen", dest / "restart", ctx, decision, drain, campaign)
        if admission and admission["status"] == "ready":
            replay_gateway = P3ModelGateway(factory(), campaign, trial_key=ctx["recovery_trial_key"],
                logical_run_key=logical, branch_id=admission["branch_id"], phase="replay", token_counter=token_counter)
            replay_hooks = P3DeliveryHooks(task, replay_gateway, condition=condition,
                                           policy="FULL_RESTART", recovery_round=1)
            with P3Store(admission["branch_db_path"]) as branch:
                branch.bind_p3(binding, campaign.ref)
                replay_report = run_five(branch, replay_gateway, replay_hooks, admission["recovery_id"])
                replay_snapshot = branch.snapshot_run()
                replay_check = evaluate_p3_trial(task, replay_snapshot, replay_report["selected"], [], None,
                                                 policy="FULL_RESTART", terminal_known=replay_report["log_complete"])
                write(dest / "replay_snapshot.json", replay_snapshot)
                write(dest / "replay_report.json", replay_report)
                write(dest / "replay_check.json", replay_check)
    summary = {"task_id": task_id, "condition": condition, "policy": policy, "simulated": binding.simulated,
               "execution_kind": execution_kind, "probe_only": probe_only,
               "initial": report, "initial_check": decision, "freeze": freeze, "drain": drain,
               "before_drain": before_drain, "admission": admission, "duplicate_restart": duplicate,
               "replay": replay_report, "replay_check": replay_check, "waits": hooks.clock.waits,
               "trial_key": logical, "campaign_budget_ref": campaign.ref}
    write(dest / "delivery_audit.json", hooks.audit)
    write(dest / "verifier_receipts.json", hooks.verifier_receipts)
    write(dest / "summary.json", summary)
    return summary
