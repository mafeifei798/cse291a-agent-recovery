"""Explicit fake-client S6 integration; none of these are model-quality results."""

import json
from copy import deepcopy
from pathlib import Path

from .contracts import digest, new_id, require
from .model_config import ModelConfig
from .model_gateway import DeterministicFakeClient, ModelGateway
from .model_oracle import ModelRecoveryOracle, ModelRunOracle
from .oracle import BasicOracle
from .recovery import Recovery
from .recovery_store import backup_database
from .reference import ReferenceBundle
from .s3_experiment import make_task, write_json
from .s4_experiment import comparable_state, file_hash
from .scenario import Scenario
from .store import Store
from .workflow import Workflow


def model_task(base, *, config=None):
    task = deepcopy(base)
    config = config or ModelConfig()
    task["execution_settings"].update(gateway_mode="model", model_config_ref=config.config_ref,
                                      call_timeout_s=config.timeout_s)
    task["tags"] = ["S6", "offline_fake", "simulated"]
    return task


def prepare_model_scene(base, destination, case="T02", dynamic=False):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    run_id = new_id()
    task = model_task(make_task(base, case, run_id))
    if dynamic:
        task["case_id"] = "s6_offline_dynamic"
        task["events"].append({"event_id": new_id(), "kind": "external_update",
            "trigger": {"boundary": "before_executor_commit", "step_id": "execute", "attempt_no": 2},
            "order": 1, "parameters": {"object_key": "resource_policy:default",
            "expected_version": 1, "new_payload": {"max_workers": 4}}})
    write_json(destination / "task.json", task)
    client = DeterministicFakeClient()
    with Store(destination / "initial.sqlite") as store:
        store.initialize_run(task, run_id)
        prepared = Scenario(store, task).run_to_notice(gateway=ModelGateway(client))
        require(prepared["status"] == "ready", "Fake model initial workflow did not pause")
        write_json(destination / "initial_snapshot.json", prepared["initial_snapshot"])
        exported = store.export_scene(destination / "frozen", prepared["initial_cost"])
        accounting = store.model_accounting_snapshot()
        write_json(destination / "frozen/accounting.json", accounting)
    require(client.request_count == 5 and accounting["budget"]["model_calls_used"] == 5,
            "Initial calls were not charged exactly once")
    return task, exported["scene"], accounting


def run_model_recovery(source, destination, policy="selective", *, store_type=Store, fault_mode=None, config=None):
    source, destination = Path(source), Path(destination)
    task = json.loads((source / "task.json").read_text())
    scene = json.loads((source / "frozen/scene.json").read_text())
    frozen = json.loads((source / "frozen/snapshot.json").read_text())
    source_hash = file_hash(source / "frozen/scene.sqlite")
    destination.mkdir(parents=True, exist_ok=False)
    backup_database(source / "frozen/scene.sqlite", destination / "branch.sqlite")
    client = DeterministicFakeClient()
    with store_type(destination / "branch.sqlite") as store:
        if fault_mode:
            store.fault_mode = fault_mode
        engine = Recovery(store, gateway=ModelGateway(client, config), scenario=Scenario(store, task))
        trial = new_id()
        report = engine.handle_notice(trial, scene["notice"]["notice_id"], scene, digest(scene), policy)
        snapshot = store.snapshot_run()
        accounting = store.model_accounting_snapshot()
        evaluation = ModelRecoveryOracle().check(task, scene, frozen, snapshot, report, accounting)
        report = store.attach_evaluation(report["recovery_id"], evaluation, "incorrect", 0, 0)
        snapshot = store.snapshot_run()
        before = store.model_accounting_snapshot()
        repeated = engine.handle_notice(trial, scene["notice"]["notice_id"], scene, digest(scene), policy)
        repeat_unchanged = repeated == report and snapshot == store.snapshot_run() and before == store.model_accounting_snapshot()
        accounting = store.model_accounting_snapshot()
    require(len(accounting["calls"]) == 5 + client.request_count, "Copied initial calls were dropped or redispatched")
    write_json(destination / "snapshot.json", snapshot)
    write_json(destination / "accounting.json", accounting)
    write_json(destination / "report.json", report)
    evidence = {"duplicate_notice_unchanged": repeat_unchanged, "new_fake_dispatches": client.request_count,
                "source_unchanged": source_hash == file_hash(source / "frozen/scene.sqlite"),
                "simulated": True, "real_api_requests": 0}
    write_json(destination / "evidence.json", evidence)
    return snapshot, report, accounting, evaluation, evidence


def s6_offline_demo(reference, destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    base = ReferenceBundle.load(reference).task
    normal_path = destination / "normal"
    normal_path.mkdir()
    normal_task = model_task(base)
    normal_task.update(case_id="s6_offline_normal", events=[])
    normal_client = DeterministicFakeClient()
    with Store(normal_path / "normal.sqlite") as store:
        store.initialize_run(normal_task)
        workflow = Workflow(store, ModelGateway(normal_client)).run_initial()
        normal_snapshot, normal_accounting = store.snapshot_run(), store.model_accounting_snapshot()
    normal_evaluation = ModelRunOracle().check(normal_task, normal_snapshot, normal_accounting)
    write_json(normal_path / "task.json", normal_task)
    write_json(normal_path / "snapshot.json", normal_snapshot)
    write_json(normal_path / "accounting.json", normal_accounting)
    write_json(normal_path / "evaluation.json", normal_evaluation)
    normal_checks = {"completed": workflow["status"] == "completed", "independent_oracle": normal_evaluation["passed"],
                     "five_model_calls": normal_client.request_count == len(normal_accounting["calls"]) == 5}
    rows = [{"case": "normal", "status": "passed" if all(normal_checks.values()) else "failed", "checks": normal_checks}]
    unique_calls = {call["call_id"]: call for call in normal_accounting["calls"]}
    for name, case, dynamic, counts, reuses in (
        ("T02", "T02", False, (5, 3), (0, 2)),
        ("T03", "T03", False, (5, 4), (0, 1)),
        ("T04", "T04", False, (0, 0), (0, 0)),
        ("dynamic", "T02", True, (10, 6), (0, 1)),
    ):
        folder = destination / name
        _, scene, initial_accounting = prepare_model_scene(base, folder, case, dynamic)
        frozen = json.loads((folder / "frozen/snapshot.json").read_text())
        initial_wrong = not BasicOracle().check("initial", json.loads((folder / "task.json").read_text()), frozen)["passed"]
        branches = [run_model_recovery(folder, folder / policy, policy) for policy in ("full_restart", "selective")]
        checks = {"initial_wrong_state_preserved": initial_wrong,
                  "initial_budget_inherited": scene["remaining_budget"]["model_calls_used"] == 5 and scene["remaining_budget"]["model_calls_remaining"] == 10,
                  "same_final_business_state": comparable_state(branches[0][0]) == comparable_state(branches[1][0])}
        for index, policy in enumerate(("full_restart", "selective")):
            snapshot, report, accounting, evaluation, evidence = branches[index]
            checks.update({f"{policy}_actual_calls": evidence["new_fake_dispatches"] == counts[index] == report["cost"]["recovery_model_calls"],
                           f"{policy}_actual_steps": report["cost"]["recovery_steps_started"] == counts[index],
                           f"{policy}_actual_reuse": report["cost"]["reused_result_count"] == reuses[index],
                           f"{policy}_idempotent_notice": evidence["duplicate_notice_unchanged"],
                           f"{policy}_frozen_unchanged": evidence["source_unchanged"],
                           f"{policy}_expected_outcome": report["outcome"] == ("failed_conflict" if case == "T04" else "recovered")})
            if case != "T04":
                checks[f"{policy}_independent_oracle"] = evaluation["passed"]
            else:
                required = {"S5_CONFLICT_SAFETY", "S6_MODEL_PINS_AND_OFFLINE_BOUNDARY",
                            "S6_MODEL_CALL_IDENTITIES_AND_DELIVERY", "S6_INDEPENDENT_TOKEN_COST_AND_BUDGET",
                            "S6_RECOVERY_MODEL_COUNTERS", "S6_FROZEN_SCENE_AND_INHERITED_BUDGET"}
                observed = {row["rule_id"]: row["passed"] for row in evaluation["checks"]}
                checks[f"{policy}_safe_conflict"] = required.issubset(observed) and all(observed[name] for name in required)
            for call in accounting["calls"]:
                if call["call_id"] in unique_calls:
                    require(unique_calls[call["call_id"]] == call, "Copied initial call changed between branches")
                unique_calls[call["call_id"]] = call
        row = {"case": name, "status": "passed" if all(checks.values()) else "failed", "checks": checks,
               "new_fake_calls_full_selective": list(counts), "actual_reuse_full_selective": list(reuses)}
        write_json(folder / "integration.json", row)
        rows.append(row)
    summary = {"scope": "S6_offline_fake_client_only", "status": "passed" if all(row["status"] == "passed" for row in rows) else "failed",
               "cases": rows, "simulated": True, "unique_fake_dispatches": len(unique_calls),
               "simulated_known_cost_nano_usd": sum(call["known_cost_nano_usd"] for call in unique_calls.values()),
               "simulated_held_cost_nano_usd": sum(call["held_cost_nano_usd"] for call in unique_calls.values()),
               "real_api_requests": 0, "real_cost_nano_usd": 0, "cloud_resources_started": False,
               "limitations": ["No real model quality or provider billing measured", "Fake token counts are synthetic",
                               "Budget cap is per logical run; no shared multi-process campaign budget", "No automatic crash resume or timeout reconciliation"]}
    write_json(destination / "integration.json", summary)
    return summary
