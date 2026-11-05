"""Pair two recovery policies on copies of an existing immutable S3 scene."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from time import perf_counter

from .contracts import STEPS, digest, new_id, require
from .oracle import BasicOracle
from .recovery import Recovery
from .recovery_oracle import RecoveryOracle, adopted_chain
from .recovery_store import backup_database
from .s3_experiment import write_json
from .store import Store

POLICIES = ("full_restart", "selective")


def file_hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def comparable_state(snapshot):
    """Branch-local output writer UUIDs differ; each Oracle checks ownership."""
    return {"source_objects": snapshot["source_objects"], "output_objects": [
        {key: value for key, value in obj.items() if key != "last_writer_id"}
        for obj in snapshot["output_objects"]]}


def run_pair(source, destination, first_policy="full_restart"):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    require(first_policy in POLICIES, "Unknown first policy")
    require(not destination.is_relative_to(source), "Keep paired outputs outside the source scene")
    task = json.loads((source / "task.json").read_text())
    scene = json.loads((source / "frozen/scene.json").read_text())
    frozen = json.loads((source / "frozen/snapshot.json").read_text())
    initial = json.loads((source / "initial_snapshot.json").read_text())
    prior = json.loads((source / "integration.json").read_text())
    frozen_path = source / "frozen/scene.sqlite"
    inputs = [source / name for name in ("task.json", "initial_snapshot.json", "integration.json",
                                        "frozen/scene.json", "frozen/snapshot.json", "frozen/scene.sqlite")]
    hashes = {str(path.relative_to(source)): file_hash(path) for path in inputs}
    scene_digest = digest(scene)
    require(scene_digest == prior["scene_digest"] and digest(task) == scene["task_spec_digest"]
            and hashes["frozen/scene.sqlite"] == prior["frozen_database_sha256"],
            "Source no longer matches its S3 scene receipt", "SCENARIO_ERROR")
    destination.mkdir(parents=True, exist_ok=False)
    write_json(destination / "task.json", task)
    write_json(destination / "scene.json", scene)
    write_json(destination / "frozen_snapshot.json", frozen)
    write_json(destination / "source_identity.json", {"source": str(source), "sha256": hashes})
    initial_begin = perf_counter()
    initial_check = BasicOracle().check("initial", task, initial)
    initial_oracle_ms = (perf_counter() - initial_begin) * 1000
    # Prepare both branches before either policy is run. The SQLite Backup API
    # keeps the original scene read-only and refuses to overwrite a branch.
    setup = {}
    for policy in POLICIES:
        folder = destination / policy
        folder.mkdir()
        begin = perf_counter()
        backup_database(frozen_path, folder / "branch.sqlite")
        with Store(folder / "branch.sqlite") as store:
            require(store.scene_manifest(scene["initial_cost"]) == scene
                    and store.snapshot_run() == frozen, "Backup differs from frozen scene", "SCENARIO_ERROR")
        setup[policy] = (perf_counter() - begin) * 1000
    initial_ids = {row["result_id"] for row in frozen["results"]}
    results, snapshots = {}, {}
    order = (first_policy, next(policy for policy in POLICIES if policy != first_policy))
    case = prior["case"]
    for policy in order:
        folder = destination / policy
        with Store(folder / "branch.sqlite") as store:
            require(store.snapshot_run() == frozen, "Other policy changed this paused branch")
            engine = Recovery(store)
            trial_id = new_id()
            report = engine.handle_notice(trial_id, scene["notice"]["notice_id"], scene, scene_digest, policy)
            write_json(folder / "engine_report.json", report)
            snapshot = store.snapshot_run()
            begin = perf_counter()
            evaluation = RecoveryOracle().check(task, scene, frozen, snapshot, report)
            oracle_ms = initial_oracle_ms + (perf_counter() - begin) * 1000
            report = store.attach_evaluation(report["recovery_id"], evaluation,
                        "correct" if initial_check["passed"] else "incorrect", setup[policy], oracle_ms)
            before = store.snapshot_run()
            repeated = engine.handle_notice(trial_id, scene["notice"]["notice_id"], scene, scene_digest, policy)
            duplicate_unchanged = repeated == report and store.snapshot_run() == before
            snapshot = store.snapshot_run()
            integrity = store.connection.execute("PRAGMA integrity_check").fetchone()[0]
        fresh = [row for row in snapshot["results"] if row["result_id"] not in initial_ids]
        adopted = adopted_chain(snapshot, initial_ids)
        reused = []
        for step in STEPS:
            rid = adopted.get(step)
            if rid not in initial_ids:
                continue
            original = next(row for row in frozen["results"] if row["result_id"] == rid)
            actual = next(row for row in snapshot["results"] if row["result_id"] == rid)
            reused.append({"step_id": step, "result_id": rid, "attempt_no": actual["attempt_no"],
                "original_result_unchanged": actual == original,
                "consumed_by_result_ids": [row["result_id"] for row in snapshot["results"]
                    if row["result_id"] in adopted.values() and rid in row["parent_result_ids"]]})
        failures = sorted(check["rule_id"] for check in evaluation["checks"] if not check["passed"])
        safe_refusal = case == "T04" and set(failures) == {"O_CURRENT_METADATA", "O_EFFECT_ACCOUNTING"} and any(
            check["rule_id"] == "S3_CONFLICT_SAFETY" and check["passed"] for check in evaluation["checks"])
        expected_steps = 0 if case == "T04" else (5 if policy == "full_restart" else (3 if case == "T02" else 4))
        expected_reuse = 0 if case == "T04" or policy == "full_restart" else (2 if case == "T02" else 1)
        actual_attempts = len(snapshot["attempts"]) - len(frozen["attempts"])
        accepted = (report["outcome"] == ("failed_conflict" if case == "T04" else "recovered")
            and (safe_refusal if case == "T04" else evaluation["passed"])
            and not initial_check["passed"] and integrity == "ok" and duplicate_unchanged
            and len(fresh) == actual_attempts == expected_steps and len(reused) == expected_reuse
            and sorted(row["result_id"] for row in reused) == evaluation["verified_reused_results"]
            and report["cost"]["reused_result_count"] == expected_reuse
            and report["cost"]["recovery_steps_started"] == actual_attempts
            and all(row["original_result_unchanged"] and row["consumed_by_result_ids"] for row in reused))
        results[policy] = {"status": "passed" if accepted else "failed", "policy": policy,
            "outcome": report["outcome"], "trial_id": trial_id, "recovery_id": report["recovery_id"],
            "scene_digest": scene_digest, "remaining_budget": scene["remaining_budget"],
            "actual_rerun_steps": [row["step_id"] for row in fresh], "actual_steps_started": actual_attempts,
            "actual_reused_results": reused, "verified_reused_result_ids": evaluation["verified_reused_results"],
            "candidate_result_ids": report["reuse_candidates"], "safe_conflict_refusal": safe_refusal,
            "evaluation_failed_rules": failures, "duplicate_notice_unchanged": duplicate_unchanged,
            "database_integrity": integrity, "final_result_ids": adopted}
        snapshots[policy] = snapshot
        write_json(folder / "report.json", report)
        write_json(folder / "snapshot.json", snapshot)
        write_json(folder / "integration.json", results[policy])
    frozen_unchanged = all(file_hash(path) == hashes[str(path.relative_to(source))] for path in inputs)
    same_state = comparable_state(snapshots["full_restart"]) == comparable_state(snapshots["selective"])
    paired = {"case": case, "scope": "S4_single_round_scripted_pair", "execution_order": list(order),
        "status": "passed" if same_state and frozen_unchanged and all(row["status"] == "passed" for row in results.values()) else "failed",
        "source_run_id": scene["run_id"], "source": str(source), "scene_digest": scene_digest,
        "frozen_database_sha256": hashes["frozen/scene.sqlite"], "source_inputs_unchanged": frozen_unchanged,
        "same_final_business_state_and_versions": same_state,
        "comparison_excludes": ["output last_writer_id: distinct branch execution UUIDs, checked separately by each Oracle"],
        "policies": {policy: results[policy] for policy in POLICIES}}
    write_json(destination / "comparison.json", paired)
    return paired


def s4_demo(scene_root, destination):
    scene_root, destination = Path(scene_root).resolve(), Path(destination).resolve()
    require(not destination.is_relative_to(scene_root), "Keep S4 outputs outside S3 evidence")
    destination.mkdir(parents=True, exist_ok=False)
    pairs = [run_pair(scene_root / case, destination / case,
                      "selective" if case == "T03" else "full_restart") for case in ("T02", "T03", "T04")]
    summary = {"scope": "S4_single_round_scripted_pairs", "status": "passed" if all(row["status"] == "passed" for row in pairs) else "failed",
        "source_scene_root": str(scene_root), "cases": pairs, "real_model_calls": 0, "S5_started": False,
        "limitations": ["Three S3 scenes, not full T01-T16 acceptance", "One recovery round; no automatic crash resume",
            "Scripted CPU steps only; no measured token, model latency, GPU or dollar savings", "Conflict refusal is not successful recovery"]}
    write_json(destination / "integration.json", summary)
    return summary
