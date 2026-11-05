"""Gated CPU-only campaign. The adapter owns execution; this module owns order.

Each invocation advances exactly one requested stage. Completed stages are
returned from disk, failed stages retain all evidence and cannot be silently
restarted in the same output directory. The frozen formal registry is read,
never updated.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import traceback

from sr_recovery_v2.common import digest
from .checker import audit_export

STAGES = ("adult-normal", "adult-n2", "matrix")
CAMPAIGN_ID = "sr-v2-cpu-offline-r1"


class CampaignError(RuntimeError):
    pass


def _now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _write(path, value, *, fresh=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if fresh and path.exists():
        raise CampaignError("EVIDENCE_ALREADY_EXISTS:" + str(path))
    temporary = path.with_name(path.name + ".tmp." + str(os.getpid()))
    with temporary.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _rows(value):
    return list(value.values()) if isinstance(value, dict) else list(value or [])


def _new_registry(v0):
    frozen_path = v0 / "registry/formal_scenes.json"
    formal = _read(frozen_path)
    scenes = []
    items = []
    for dataset in ("adult", "bank"):
        items.append({"item_id": f"v2.cpu.{dataset}.control", "dataset_id": dataset,
                      "kind": "normal", "status": "registered", "run_count": 0})
        for condition in ("N1", "N2", "N3"):
            source = next(s for s in formal["scenes"] if s["domain"] == "macro" and
                          s["task_id"] == f"macro-{dataset}-01" and s["condition"] == condition)
            sid = f"v2.cpu.{dataset}.{condition}"
            scenes.append({"scene_id": sid, "dataset_id": dataset, "condition": condition,
                           "formal_scene_id": source["scene_id"],
                           "strategy_order": source["strategy_order"], "status": "registered"})
            items.append({"item_id": sid + ".prefix", "scene_id": sid, "dataset_id": dataset,
                          "condition": condition, "kind": "prefix", "status": "registered", "run_count": 0})
            for policy in source["strategy_order"]:
                items.append({"item_id": sid + "." + policy, "scene_id": sid, "dataset_id": dataset,
                              "condition": condition, "kind": "recovery", "policy": policy,
                              "status": "registered", "run_count": 0})
    return {"campaign_id": CAMPAIGN_ID, "mode": "real_cpu_fake_llm", "created_at_utc": _now(),
            "formal_registry_read_only": True,
            "formal_scenes_sha256": hashlib.sha256(frozen_path.read_bytes()).hexdigest(),
            "expected_counts": {"normal": 2, "prefix": 6, "recovery": 18},
            "real_api_requests": 0, "actual_cost_nano_usd": 0, "gpu_used": False,
            "scenes": scenes, "items": items}


def _set_item(root, item_id, status, **details):
    path = root / "cpu_registry.json"
    registry = _read(path)
    item = next(row for row in registry["items"] if row["item_id"] == item_id)
    if status == "running":
        if item["status"] != "registered":
            raise CampaignError("ITEM_ALREADY_ATTEMPTED:" + item_id)
        item["run_count"] += 1
        item["started_at_utc"] = _now()
    item.update(details)
    item["status"] = status
    if status in ("passed", "failed"):
        item["finished_at_utc"] = _now()
    _write(path, registry)


def _selected(view, node):
    rid = view["state"]["selected_by_node"].get(node)
    return next((row for row in _rows(view["results"]) if row["result_id"] == rid), None)


def _job_statistics(view):
    initial = view.get("initial_snapshot", {})
    old_receipts = {receipt for row in _rows(initial.get("results")) for receipt in row.get("tool_receipt_ids", [])}
    job_records = []
    for receipt in _rows(view.get("tool_receipts")):
        if receipt["receipt_id"] in old_receipts:
            continue
        evidence = receipt.get("parameters", {}).get("execution", {})
        if evidence:
            job_records.append({"node_id": receipt["node_id"], "receipt_id": receipt["receipt_id"], **evidence})
    fit = [job for job in job_records if job["node_id"] in ("fit_lr", "fit_rf")]
    predict = [job for job in job_records if job["node_id"] in ("predict_lr", "predict_rf")]
    return {"jobs": job_records, "fit_jobs": len(fit), "prediction_jobs": len(predict),
            "workflow_wall_seconds": sum(float(job.get("wall_seconds", 0)) for job in job_records),
            "workflow_cpu_seconds": sum(float(job.get("cpu_seconds", 0)) for job in job_records),
            "fit_wall_seconds": sum(float(job.get("wall_seconds", 0)) for job in fit),
            "fit_cpu_seconds": sum(float(job.get("cpu_seconds", 0)) for job in fit),
            "peak_worker_rss_bytes": max([int(job.get("peak_rss_bytes", 0)) for job in job_records] or [0])}


def _reuse_proof(view, proven_ids):
    initial = view.get("initial_snapshot", {})
    old_results = {r["result_id"]: r for r in _rows(initial.get("results"))}
    old_artifacts = {a["artifact_id"]: a for a in _rows(initial.get("artifacts", initial.get("artifact_manifest")))}
    results = {r["result_id"]: r for r in _rows(view["results"])}
    artifacts = {a["artifact_id"]: a for a in _rows(view.get("artifacts"))}
    old_attempts = {r["attempt_id"] for r in _rows(initial.get("attempts"))}
    new_dispatched = {a["node_id"] for a in _rows(view.get("attempts")) if a["attempt_id"] not in old_attempts}
    proof = []
    for rid in proven_ids:
        result = results[rid]
        bindings = [{"artifact_id": aid, "sha256": artifacts[aid]["sha256"],
                     "same_initial_binding": artifacts[aid] == old_artifacts.get(aid)}
                    for aid in result.get("artifact_refs", [])]
        row = {"result_id": rid, "node_id": result["node_id"],
               "same_initial_result": result == old_results.get(rid),
               "no_new_dispatch_for_node": result["node_id"] not in new_dispatched,
               "artifact_bindings": bindings}
        row["proven"] = row["same_initial_result"] and row["no_new_dispatch_for_node"] and all(a["same_initial_binding"] for a in bindings)
        proof.append(row)
    return proof


def _evaluate(root, v0, label, view, *, prefix=False, save_export=True, recheck_of=None):
    from .adapter import numerical_check
    files = root / "files"
    if save_export:
        _write(root / "exports" / (label + ".json"), view, fresh=True)
    audit = audit_export(view, files, v0)
    _write(root / "audits" / (label + ".json"), audit, fresh=True)
    if not audit.get("passed") or (not prefix and not audit.get("business_correct")):
        raise CampaignError("STRUCTURAL_OR_BUSINESS_AUDIT_FAILED:" + label)
    numerical = numerical_check(view, v0, files, root, label, prefix=prefix)
    _write(root / "numerical" / (label + ".json"), numerical, fresh=True)
    report = (numerical.get("response") or {}).get("payload", {})
    if numerical.get("execution", {}).get("status") != "success" or not report.get("passed"):
        raise CampaignError("NUMERICAL_CHECK_FAILED:" + label)
    statistics = audit.get("statistics", {})
    reused = _reuse_proof(view, statistics.get("actual_reused_result_ids", []))
    if any(not row["proven"] for row in reused):
        raise CampaignError("REUSE_IDENTITY_PROOF_FAILED:" + label)
    jobs = _job_statistics(view)
    selected = _selected(view, "report")
    family_metrics = {family: (_selected(view, "summary_" + family) or {}).get("payload", {}).get("metrics")
                      for family in ("lr", "rf")}
    item = {"item_id": recheck_of or label, "passed": True, "prefix": prefix,
            "terminal_status": view["state"].get("terminal_status"),
            "audit": statistics, "workflow_jobs": jobs,
            "actual_reuse_proof": reused, "family_validation_metrics": family_metrics,
            "selected_report": selected.get("payload") if selected else None,
            "numerical_statistics": report.get("statistics", report.get("stats", {})),
            "independent_checker_resources": numerical.get("execution", {}),
            "real_api_requests": 0, "actual_cost_nano_usd": 0}
    if recheck_of:
        item.update(recheck_of=recheck_of, evidence_label=label, existing_execution_reused=True,
                    new_workflow_dispatches=0)
    _write(root / "summaries" / (label + ".json"), item, fresh=True)
    return item


def _normal(root, v0, dataset):
    from .adapter import initial_run
    label = f"v2.cpu.{dataset}.control"
    _set_item(root, label, "running")
    try:
        outcome = initial_run(v0, root / "files", root, label, dataset, fault=False)
        item = _evaluate(root, v0, label, outcome["view"])
        _set_item(root, label, "passed", summary_path="summaries/" + label + ".json", db_path=outcome["db_path"])
        # Convenient stable aliases do not replace the raw ID-named exports.
        _write(root / "exports" / ("control." + dataset + ".json"), outcome["view"], fresh=True)
        return item
    except Exception as exc:
        _set_item(root, label, "failed", error=str(exc))
        raise


def _expected_recovery_fit(condition, policy):
    return 2 if policy == "FULL" or condition == "N3" else (1 if condition == "N2" else 0)


def _scene(root, v0, dataset, condition):
    from .adapter import initial_run, freeze_scene, recovery_run
    scene_id = f"v2.cpu.{dataset}.{condition}"
    prefix_id = scene_id + ".prefix"
    _set_item(root, prefix_id, "running")
    try:
        initial = initial_run(v0, root / "files", root, prefix_id, dataset, fault=True)
        prefix_summary = _evaluate(root, v0, prefix_id, initial["view"], prefix=True)
        scene = freeze_scene(initial["db_path"], v0, root / "files", condition, scene_id)
        scene_digest = digest(scene)
        _write(root / "scenes" / (scene_id + ".json"), scene, fresh=True)
        _set_item(root, prefix_id, "passed", db_path=initial["db_path"],
                  frozen_scene_digest=scene_digest, summary_path="summaries/" + prefix_id + ".json")
    except Exception as exc:
        _set_item(root, prefix_id, "failed", error=str(exc))
        raise
    registry = _read(root / "cpu_registry.json")
    registered = next(s for s in registry["scenes"] if s["scene_id"] == scene_id)
    summaries = []
    for policy in registered["strategy_order"]:
        branch_id = scene_id + "." + policy
        _set_item(root, branch_id, "running", frozen_scene_digest=scene_digest)
        try:
            branch_scene = copy.deepcopy(scene)
            view = recovery_run(branch_scene, policy, root / "files", root, branch_id)
            if digest(scene) != scene_digest:
                raise CampaignError("FROZEN_SCENE_MUTATED:" + scene_id)
            item = _evaluate(root, v0, branch_id, view)
            expected_fits = _expected_recovery_fit(condition, policy)
            if item["workflow_jobs"]["fit_jobs"] != expected_fits:
                raise CampaignError(f"WRONG_ACTUAL_FIT_COUNT:{branch_id}:expected={expected_fits}:actual={item['workflow_jobs']['fit_jobs']}")
            required_reuse = ([] if condition == "N3" or policy == "FULL" else
                              (["fit_lr", "predict_lr"] if condition == "N2" else ["fit_lr", "predict_lr", "fit_rf", "predict_rf"]))
            reused_nodes = {row["node_id"] for row in item["actual_reuse_proof"] if row["proven"]}
            if not set(required_reuse).issubset(reused_nodes):
                raise CampaignError("REQUIRED_REAL_MODEL_REUSE_MISSING:" + branch_id)
            _set_item(root, branch_id, "passed", summary_path="summaries/" + branch_id + ".json",
                      frozen_scene_digest=scene_digest, expected_fit_jobs=expected_fits)
            summaries.append(item)
        except Exception as exc:
            _set_item(root, branch_id, "failed", error=str(exc))
            raise
    registry = _read(root / "cpu_registry.json")
    registered = next(s for s in registry["scenes"] if s["scene_id"] == scene_id)
    registered.update(status="passed", frozen_scene_digest=scene_digest,
                      successful_branch_count=3, all_branch_prefix_digests_equal=True)
    _write(root / "cpu_registry.json", registry)
    return {"scene_id": scene_id, "frozen_scene_digest": scene_digest,
            "prefix": prefix_summary["item_id"], "branch_ids": [s["item_id"] for s in summaries],
            "strategy_order": registered["strategy_order"], "passed": True}


def _accepted_gate(root, name):
    """An acceptance receipt supplements an immutable failed checker gate."""
    acceptance = root / "gates" / (name + ".acceptance.json")
    original = root / "gates" / (name + ".json")
    if not acceptance.is_file():
        return original, (_read(original) if original.is_file() else None)
    record = _read(acceptance)
    if name != "adult-normal" or not record.get("passed") or record.get("stage") != name:
        raise CampaignError("INVALID_RECHECK_ACCEPTANCE:" + name)
    for binding in record.get("evidence_bindings", []):
        path = (root / binding["path"]).resolve()
        if not path.is_relative_to(root) or not path.is_file() or _sha(path) != binding["sha256"]:
            raise CampaignError("RECHECK_ACCEPTANCE_HASH_MISMATCH:" + binding["path"])
    item_id = record.get("recheck_of")
    if item_id != "v2.cpu.adult.control" or record.get("original_gate_path") != "gates/adult-normal.json":
        raise CampaignError("RECHECK_ACCEPTANCE_WRONG_ITEM")
    required = {"gates/adult-normal.json", "exports/" + item_id + ".json",
                record.get("audit_path"), record.get("numerical_path"), record.get("summary_path")}
    if not required.issubset({binding["path"] for binding in record.get("evidence_bindings", [])}):
        raise CampaignError("RECHECK_ACCEPTANCE_MISSING_BINDINGS")
    failed = _read(original)
    audit = _read(root / record["audit_path"])
    numerical = _read(root / record["numerical_path"])
    summary = _read(root / record["summary_path"])
    exported = _read(root / "exports" / (item_id + ".json"))
    item = next(row for row in _read(root / "cpu_registry.json")["items"] if row["item_id"] == item_id)
    if (failed.get("passed") is not False or failed.get("error") != "NUMERICAL_CHECK_FAILED:" + item_id or
            exported["state"].get("terminal_status") != "completed_correct" or
            not audit.get("passed") or not audit.get("business_correct") or
            numerical.get("execution", {}).get("status") != "success" or
            not (numerical.get("response") or {}).get("payload", {}).get("passed") or
            summary.get("recheck_of") != item_id or not summary.get("passed") or
            item.get("status") != "passed" or item.get("run_count") != 1 or
            item.get("summary_path") != record["summary_path"]):
        raise CampaignError("RECHECK_ACCEPTANCE_EVIDENCE_INVALID")
    return acceptance, record


def _require_gate(root, name):
    _, record = _accepted_gate(root, name)
    if not record or not record.get("passed"):
        raise CampaignError("PREREQUISITE_GATE_NOT_PASSED:" + name)


def _quiescent_completed_export(root, item_id, view):
    state = view["state"]
    if (state.get("terminal_status") != "completed_correct" or state.get("status") != "terminal" or
            state.get("run_id") != item_id or state.get("active_attempt_ids") or
            state.get("unsettled_call_ids") or view.get("pending_decision")):
        raise CampaignError("RECHECK_REQUIRES_QUIESCENT_COMPLETED_EXPORT")
    for attempt in _rows(view.get("attempts")):
        if attempt.get("status") != "completed" or attempt.get("worker_reaped") is not True:
            raise CampaignError("RECHECK_UNREAPED_OR_INCOMPLETE_ATTEMPT")
    for receipt in _rows(view.get("tool_receipts")):
        execution = receipt.get("parameters", {}).get("execution", {})
        if (execution.get("status") != "success" or execution.get("worker_reaped") is not True or
                execution.get("remaining_processes")):
            raise CampaignError("RECHECK_RESOURCE_EXECUTION_NOT_SETTLED")
    dbpath = root / "db" / (item_id + ".sqlite")
    if not dbpath.is_file():
        raise CampaignError("RECHECK_RUNTIME_DATABASE_MISSING")
    database = sqlite3.connect(dbpath.as_uri() + "?mode=ro", uri=True)
    try:
        row = database.execute("SELECT payload FROM document WHERE id=1").fetchone()
    finally:
        database.close()
    if row is None or json.loads(row[0])["state"] != state:
        raise CampaignError("RECHECK_EXPORT_DATABASE_STATE_MISMATCH")


def recheck_existing(item_id, output, v0_root):
    """Recheck one already-successful Adult execution, never dispatch workflow work.

    This is deliberately narrower than a retry or campaign resume: the prior
    numerical checker must be the sole failed acceptance gate. A Bank control
    recheck cannot mark a partly unexecuted matrix complete.
    """
    root, v0 = Path(output).resolve(), Path(v0_root).resolve()
    if item_id != "v2.cpu.adult.control":
        raise CampaignError("RECHECK_ONLY_ADULT_NORMAL_CONTROL_SUPPORTED")
    if not root.is_dir():
        raise CampaignError("CAMPAIGN_ROOT_MISSING")
    with (root / ".campaign.lock").open("a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CampaignError("CAMPAIGN_ALREADY_RUNNING") from exc
        acceptance_path = root / "gates/adult-normal.acceptance.json"
        if acceptance_path.exists():
            _require_gate(root, "adult-normal")
            return {"stage": "adult-normal", "passed": True, "returned_existing": True,
                    "recheck_of": item_id, "gate": str(acceptance_path), "totals": _totals(root)}
        original_gate = root / "gates/adult-normal.json"
        original_export = root / "exports" / (item_id + ".json")
        original_audit = root / "audits" / (item_id + ".json")
        original_numerical = root / "numerical" / (item_id + ".json")
        gate = _read(original_gate)
        registry = _read(root / "cpu_registry.json")
        item = next(row for row in registry["items"] if row["item_id"] == item_id)
        if (item.get("kind") != "normal" or item.get("status") != "failed" or item.get("run_count") != 1 or
                gate.get("passed") is not False or gate.get("error") != "NUMERICAL_CHECK_FAILED:" + item_id or
                item.get("error") != "NUMERICAL_CHECK_FAILED:" + item_id):
            raise CampaignError("RECHECK_NOT_A_NUMERICAL_ONLY_CONTROL_FAILURE")
        audit = _read(original_audit)
        old_numerical = _read(original_numerical)
        if (not audit.get("passed") or not audit.get("business_correct") or
                (old_numerical.get("response") or {}).get("payload", {}).get("passed") is True):
            raise CampaignError("RECHECK_ORIGINAL_EVIDENCE_NOT_ELIGIBLE")
        view = _read(original_export)
        _quiescent_completed_export(root, item_id, view)
        original_paths = [original_gate, original_export, original_audit, original_numerical]
        preserved = {str(path.relative_to(root)): _sha(path) for path in original_paths}
        before_totals = _totals(root)
        number = 1
        while any((root / name / (item_id + f".recheck{number}.json")).exists()
                  for name in ["rechecks", "audits", "numerical", "summaries"]):
            number += 1
        label = item_id + f".recheck{number}"
        receipt_path = root / "rechecks" / (label + ".json")
        started = _now()
        _write(receipt_path, {"recheck_of": item_id, "evidence_label": label,
                             "started_at_utc": started, "status": "running",
                             "preserved_evidence": preserved, "new_workflow_dispatches": 0}, fresh=True)
        try:
            summary = _evaluate(root, v0, label, view, save_export=False, recheck_of=item_id)
            if any(_sha(root / path) != sha for path, sha in preserved.items()):
                raise CampaignError("RECHECK_MODIFIED_ORIGINAL_EVIDENCE")
            after_totals = _totals(root)
            if after_totals["actual_real_training_jobs"] != before_totals["actual_real_training_jobs"]:
                raise CampaignError("RECHECK_UNEXPECTED_TRAINING_DISPATCH")
            previous = copy.deepcopy(item)
            item.setdefault("history", []).append({"event": "independent_checker_recheck_accepted",
                                                    "at_utc": _now(), "previous": previous})
            item.update(status="passed", previous_status=previous["status"],
                        previous_error=previous.get("error"), summary_path="summaries/" + label + ".json",
                        recheck_label=label, finished_at_utc=_now())
            item.pop("error", None)
            _write(root / "cpu_registry.json", registry)
            bindings = [{"path": path, "sha256": sha} for path, sha in preserved.items()]
            for kind in ("audits", "numerical", "summaries"):
                path = root / kind / (label + ".json")
                bindings.append({"path": str(path.relative_to(root)), "sha256": _sha(path)})
            acceptance = {"stage": "adult-normal", "passed": True, "recheck_of": item_id,
                          "evidence_label": label, "started_at_utc": started, "finished_at_utc": _now(),
                          "original_gate_path": "gates/adult-normal.json",
                          "audit_path": "audits/" + label + ".json",
                          "numerical_path": "numerical/" + label + ".json",
                          "summary_path": "summaries/" + label + ".json", "evidence_bindings": bindings,
                          "new_workflow_dispatches": 0, "unchanged_workflow_run_count": 1,
                          "real_api_requests": 0, "actual_cost_nano_usd": 0, "totals": _totals(root)}
            _write(acceptance_path, acceptance, fresh=True)
            _write(receipt_path, {"status": "passed", **acceptance})
            _require_gate(root, "adult-normal")
            return {"stage": "adult-normal", "passed": True, "recheck_of": item_id,
                    "evidence_label": label, "gate": str(acceptance_path), "totals": _totals(root)}
        except Exception as exc:
            _write(receipt_path, {"recheck_of": item_id, "evidence_label": label,
                                 "started_at_utc": started, "finished_at_utc": _now(), "status": "failed",
                                 "error": str(exc), "traceback": traceback.format_exc(),
                                 "preserved_evidence": preserved, "new_workflow_dispatches": 0})
            raise


def _totals(root):
    registry = _read(root / "cpu_registry.json")
    result = {"registered_items": len(registry["items"]), "counts": {},
              "actual_real_training_jobs": 0, "real_api_requests": 0, "actual_cost_nano_usd": 0}
    for kind in ("normal", "prefix", "recovery"):
        items = [row for row in registry["items"] if row["kind"] == kind]
        result["counts"][kind] = {status: sum(row["status"] == status for row in items)
                                  for status in ("registered", "running", "passed", "failed")}
    # Physical job evidence is authoritative even if a later audit refused an
    # item before its summary could be accepted. Failed work is not free.
    training = []
    for path in (root / "files" / "jobs").glob("*/execution.json"):
        execution = _read(path)
        if execution.get("tool") in ("fit_lr", "fit_rf"):
            training.append(execution)
    result["actual_real_training_jobs"] = len(training)
    result["successful_training_jobs"] = sum(job.get("status") == "success" for job in training)
    result["failed_training_jobs"] = len(training) - result["successful_training_jobs"]
    return result


def run_stage(stage, output, v0_root):
    root, v0 = Path(output).resolve(), Path(v0_root).resolve()
    if stage == "adult-normal":
        if not root.exists():
            root.mkdir(parents=True, exist_ok=False)
            (root / "files").mkdir()
            _write(root / "cpu_registry.json", _new_registry(v0), fresh=True)
        elif not (root / "cpu_registry.json").is_file() or not (root / "gates/adult-normal.json").is_file():
            raise CampaignError("ADULT_NORMAL_REQUIRES_NEW_ROOT_OR_FINISHED_GATE")
    elif not root.is_dir():
        raise CampaignError("CAMPAIGN_ROOT_MISSING")
    lock_path = root / ".campaign.lock"
    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CampaignError("CAMPAIGN_ALREADY_RUNNING") from exc
        gate_path, previous = _accepted_gate(root, stage)
        if previous:
            return {"stage": stage, "passed": previous.get("passed", False), "returned_existing": True,
                    "gate": str(gate_path), "totals": _totals(root)}
        if stage == "adult-n2":
            _require_gate(root, "adult-normal")
        elif stage == "matrix":
            _require_gate(root, "adult-normal")
            _require_gate(root, "adult-n2")
        started = _now()
        _write(root / "stage_attempts" / (stage + ".json"),
               {"stage": stage, "started_at_utc": started, "pid": os.getpid()}, fresh=True)
        try:
            if stage == "adult-normal":
                detail = {"normal_item": _normal(root, v0, "adult")["item_id"]}
            elif stage == "adult-n2":
                detail = _scene(root, v0, "adult", "N2")
            else:
                _normal(root, v0, "bank")
                scenes = []
                for dataset, condition in [("adult", "N1"), ("adult", "N3"),
                                           ("bank", "N1"), ("bank", "N2"), ("bank", "N3")]:
                    scenes.append(_scene(root, v0, dataset, condition))
                totals = _totals(root)
                if any(totals["counts"][kind]["passed"] != expected
                       for kind, expected in [("normal", 2), ("prefix", 6), ("recovery", 18)]):
                    raise CampaignError("COMPLETE_MATRIX_COUNTS_MISMATCH")
                if totals["actual_real_training_jobs"] != 40:
                    raise CampaignError("COMPLETE_MATRIX_TRAINING_COUNT_MISMATCH")
                detail = {"additional_scenes": scenes, "adult_n2_reused_from_gate": True}
            gate = {"stage": stage, "passed": True, "started_at_utc": started,
                    "finished_at_utc": _now(), "detail": detail, "totals": _totals(root),
                    "real_api_requests": 0, "actual_cost_nano_usd": 0}
        except Exception as exc:
            gate = {"stage": stage, "passed": False, "started_at_utc": started,
                    "finished_at_utc": _now(), "error": str(exc), "exception_type": type(exc).__name__,
                    "traceback": traceback.format_exc(), "totals": _totals(root),
                    "real_api_requests": 0, "actual_cost_nano_usd": 0}
        _write(gate_path, gate, fresh=True)
        return {"stage": stage, "passed": gate["passed"], "gate": str(gate_path),
                "error": gate.get("error"), "totals": gate["totals"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Gated real-CPU / fake-LLM V2 campaign")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--stage", choices=STAGES)
    action.add_argument("--recheck-existing", metavar="ITEM_ID")
    parser.add_argument("--output", required=True)
    parser.add_argument("--v0-root", default=str(Path(__file__).resolve().parents[2] / "sr_v2/v0"))
    args = parser.parse_args(argv)
    try:
        result = (recheck_existing(args.recheck_existing, args.output, args.v0_root)
                  if args.recheck_existing else run_stage(args.stage, args.output, args.v0_root))
    except Exception as exc:
        result = {"stage": args.stage, "passed": False, "error": str(exc), "exception_type": type(exc).__name__}
    print(json.dumps(result, sort_keys=True, ensure_ascii=False, allow_nan=False))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
