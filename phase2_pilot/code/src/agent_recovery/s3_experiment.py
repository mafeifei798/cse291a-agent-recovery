"""S3 fixtures and experiments: T02/T03 full restart and T04 safe conflict."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from time import perf_counter

from .contracts import digest, new_id, output_keys
from .oracle import BasicOracle
from .recovery import Recovery
from .recovery_oracle import FullRestartOracle
from .recovery_store import backup_database
from .reference import ReferenceBundle
from .scenario import Scenario
from .store import Store


def make_task(base, case, run_id):
    if case not in ("T02", "T03", "T04"):
        raise ValueError("S3 supports T02, T03 and T04 only")
    task = deepcopy(base)
    task["case_id"] = "s3_" + case.lower()
    if case == "T02":
        task["events"] = [event for event in task["events"] if event["kind"] != "external_update"]
        task["events"][-1]["order"] = 1
    elif case == "T04":
        event = next(event for event in task["events"] if event["kind"] == "external_update")
        request = task["request"]
        n = task["events"][0]["parameters"]["replacement_payload"]["num_examples"]
        config = {"dataset_id": request["dataset_id"], "purpose": request["purpose"],
                  "batch_size": request["batch_size"], "epochs": request["epochs"], "num_examples": n,
                  "steps": ((n + request["batch_size"] - 1) // request["batch_size"]) * request["epochs"],
                  "workers": min(request["requested_workers"], task["initial_objects"][2]["payload"]["max_workers"]),
                  "permission_allowed": True}
        event["parameters"] = {"object_key": output_keys(run_id)[1], "expected_version": 1,
                               "new_payload": {"config_key": output_keys(run_id)[0], "config": config,
                                               "status": "draft", "review_note": "legitimate external review"}}
    task["tags"] = ["S3", "scripted", case, "full_restart"]
    return task


def write_json(path, body):
    path.write_text(json.dumps(body, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def run_case(base, case, destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    run_id = new_id()
    task = make_task(base, case, run_id)
    write_json(destination / "task.json", task)
    with Store(destination / "initial.sqlite") as store:
        store.initialize_run(task, run_id)
        prepared = Scenario(store, task).run_to_notice()
        if prepared["status"] != "ready":
            store.finish_run(run_id)
            write_json(destination / "failed_initial_snapshot.json", store.snapshot_run())
            failure = {**prepared, "case": case, "status": "failed", "observed_outcome": "failed_initial",
                       "recovery_steps": 0, "compensated_groups": 0, "safe_conflict_refusal": False}
            write_json(destination / "integration.json", failure)
            return failure
        initial = prepared["initial_snapshot"]
        write_json(destination / "initial_snapshot.json", initial)
        oracle_begin = perf_counter()
        initial_check = BasicOracle().check("initial", task, initial)
        initial_oracle_ms = (perf_counter() - oracle_begin) * 1000
        setup_begin = perf_counter()
        exported = store.export_scene(destination / "frozen", prepared["initial_cost"])
    scene, scene_digest = exported["scene"], exported["scene_digest"]
    frozen_path = destination / "frozen/scene.sqlite"
    frozen_hash = hashlib.sha256(frozen_path.read_bytes()).hexdigest()
    backup_database(frozen_path, destination / "restart.sqlite")
    setup_ms = (perf_counter() - setup_begin) * 1000
    frozen = json.loads((destination / "frozen/snapshot.json").read_text())
    with Store(destination / "restart.sqlite") as store:
        engine = Recovery(store)
        trial_id = new_id()
        report = engine.handle_notice(trial_id, scene["notice"]["notice_id"], scene, scene_digest)
        write_json(destination / "engine_report.json", report)
        snapshot = store.snapshot_run()
        oracle_begin = perf_counter()
        evaluation = FullRestartOracle().check(task, scene, frozen, snapshot, report)
        oracle_ms = initial_oracle_ms + (perf_counter() - oracle_begin) * 1000
        report = store.attach_evaluation(report["recovery_id"], evaluation,
                                        "correct" if initial_check["passed"] else "incorrect", setup_ms, oracle_ms)
        # An identical notice returns the saved report, without modifying any run data.
        before = store.snapshot_run()
        repeated = engine.handle_notice(trial_id, scene["notice"]["notice_id"], scene, scene_digest)
        duplicate_unchanged = repeated == report and store.snapshot_run() == before
        snapshot = store.snapshot_run()
        integrity = store.connection.execute("PRAGMA integrity_check").fetchone()[0]
    frozen_unchanged = hashlib.sha256(frozen_path.read_bytes()).hexdigest() == frozen_hash
    expected = "failed_conflict" if case == "T04" else "recovered"
    failures = {check["rule_id"] for check in evaluation["checks"] if not check["passed"]}
    safe_refusal = case == "T04" and failures == {"O_CURRENT_METADATA", "O_EFFECT_ACCOUNTING"} and any(
        check["rule_id"] == "S3_CONFLICT_SAFETY" and check["passed"] for check in evaluation["checks"])
    accepted = (report["outcome"] == expected and not initial_check["passed"]
                and (evaluation["passed"] if case != "T04" else safe_refusal)
                and frozen_unchanged and duplicate_unchanged and integrity == "ok")
    integration = {"case": case, "status": "passed" if accepted else "failed", "policy": "full_restart",
                   "expected_outcome": expected, "observed_outcome": report["outcome"],
                   "initial_check": initial_check, "initial_wrong_plan": initial["output_objects"][0]["payload"],
                   "recovery_steps": report["cost"]["recovery_steps_started"],
                   "compensated_groups": report["cost"]["compensated_effect_groups"],
                   "safe_conflict_refusal": safe_refusal, "scene_digest": scene_digest,
                   "frozen_database_sha256": frozen_hash, "frozen_database_unchanged": frozen_unchanged,
                   "duplicate_notice_unchanged": duplicate_unchanged, "database_integrity": integrity,
                   "evaluation_failed_rules": sorted(failures), "report": report,
                   "scope": "S3_full_restart_only", "full_T01_T16_acceptance": False}
    write_json(destination / "report.json", report)
    write_json(destination / "snapshot.json", snapshot)
    write_json(destination / "integration.json", integration)
    return integration


def s3_demo(reference, destination):
    bundle = ReferenceBundle.load(reference)
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    cases = [run_case(bundle.task, case, destination / case) for case in ("T02", "T03", "T04")]
    summary = {"scope": "S3_full_restart_only", "status": "passed" if all(case["status"] == "passed" for case in cases) else "failed",
               "cases": [{key: case[key] for key in ("case", "status", "observed_outcome", "recovery_steps",
                          "compensated_groups", "safe_conflict_refusal")} for case in cases],
               "model_calls": 0, "selective_execution": False,
               "limitations": ["No selective recovery", "No complete T01-T16 acceptance", "No automatic crash resume",
                               "Only one restart round is executed", "No real model or cloud resources"]}
    write_json(destination / "integration.json", summary)
    return summary
