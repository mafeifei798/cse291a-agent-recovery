"""V1 deterministic offline adapters. No HTTP, sklearn or real dataset loading.

Outputs are fake evidence of controller execution, never trained models or model
quality. Every response is computed from a serialized, permission-scoped input
projection. Private scenario choices belong only to the prefix harness.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import time
from pathlib import Path

REVISION = "sr-v2-v0-r1"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _by_id(values, key):
    return values if isinstance(values, dict) else {v[key]: v for v in values}


def _sources(view):
    return _by_id(view.get("sources", view.get("current_sources", [])), "object_key")


def _results(view):
    return _by_id(view.get("results", []), "result_id")


def _artifacts(view):
    return _by_id(view.get("artifacts", view.get("artifact_manifest", [])), "artifact_id")


def _node(view, node_id):
    return next(n for n in view["dag"]["nodes"] if n["node_id"] == node_id)


def _selected(view):
    return view.get("state", view.get("run_state", {}))["selected_by_node"]


def _artifact_value(artifact_id, artifacts, artifact_root):
    binding = artifacts[artifact_id]
    root = Path(artifact_root).resolve()
    path = (root / binding["uri"]).resolve()
    if not path.is_relative_to(root):
        raise ValueError("artifact path escapes root")
    body = path.read_bytes()
    if len(body) != binding["size_bytes"] or hashlib.sha256(body).hexdigest() != binding["sha256"]:
        raise ValueError("artifact size/hash mismatch")
    return json.loads(body)


def input_projection(view, node_id, artifact_root):
    """Only request, direct current bindings and actual parent ancestry enter IO.

    Ancestor artifacts are explicitly cited: report needs the model/prediction
    identities stored in summary's real ancestry. Unrelated RF source keys never
    appear in profile, prepare, LR planning or LR tools.
    """
    node = _node(view, node_id)
    results, artifacts, sources = _results(view), _artifacts(view), _sources(view)
    selected = _selected(view)
    direct_keys = [view.get("source_aliases", {}).get(k, k) for k in node["direct_source_keys"]]
    direct = [copy.deepcopy(sources[k]) for k in direct_keys]
    parents = [results[selected[p]] for p in node["parents"]]
    ancestor_ids, artifact_ids = set(), set()

    def visit(result):
        if result["result_id"] in ancestor_ids:
            return
        ancestor_ids.add(result["result_id"])
        artifact_ids.update(result["artifact_refs"])
        for source in result.get("input_snapshot", {}).get("direct_source_inputs", []):
            artifact_ids.update(source.get("artifact_refs", []))
        for parent_id in result["parent_result_ids"]:
            visit(results[parent_id])

    for parent in parents:
        visit(parent)
    for source in direct:
        artifact_ids.update(source.get("artifact_refs", []))
    projected_parents = [{"result_id": p["result_id"], "node_id": p["node_id"],
        "payload": copy.deepcopy(p["payload"]), "payload_digest": digest(p["payload"]),
        "artifact_refs": copy.deepcopy(p["artifact_refs"]),
        "effective_reads": copy.deepcopy(p["effective_reads"])} for p in parents]
    snapshot = {"fixture_only": True, "run_id": view["state"]["run_id"], "node_id": node_id,
        "request": copy.deepcopy(view["task"]["request"]), "parent_inputs": projected_parents,
        "direct_source_inputs": direct,
        "artifact_bindings": [copy.deepcopy(artifacts[a]) for a in sorted(artifact_ids)]}
    # Bytes are consumed by the deterministic adapter and linked to their binding.
    snapshot["artifact_values"] = {a: _artifact_value(a, artifacts, artifact_root) for a in sorted(artifact_ids)}
    message = canonical(snapshot).decode("utf-8")
    snapshot["rendered_messages"] = [{"role": "system", "content": "Offline deterministic fake adapter. Emit the fixed node JSON contract from the cited inputs only."},
                                     {"role": "user", "content": message}]
    return snapshot


def fake_metrics(labels, probabilities):
    """Small tied-score aware metric arithmetic, without a model/library."""
    if len(labels) != len(probabilities) or not labels:
        raise ValueError("bad fake predictions")
    labels = [int(y) for y in labels]
    if set(labels) - {0, 1} or not all(math.isfinite(p) and 0 <= p <= 1 for p in probabilities):
        raise ValueError("non binary/non finite fake predictions")
    positives, negatives = sum(labels), len(labels) - sum(labels)
    ordered = sorted(zip(probabilities, labels), reverse=True)
    tp, seen, ap = 0, 0, 0.0
    for score in sorted(set(probabilities), reverse=True):
        group = [y for p, y in ordered if p == score]
        tp += sum(group)
        seen += len(group)
        if positives:
            ap += sum(group) / positives * (tp / seen)
    auc = sum((pa > pb) + .5 * (pa == pb) for pa, ya in zip(probabilities, labels) if ya
              for pb, yb in zip(probabilities, labels) if not yb) / (positives * negatives) if positives and negatives else None
    pred = [int(p >= .5) for p in probabilities]
    tp = sum(y == p == 1 for y, p in zip(labels, pred))
    fp = sum(y == 0 and p == 1 for y, p in zip(labels, pred))
    fn = sum(y == 1 and p == 0 for y, p in zip(labels, pred))
    return {"accuracy": sum(y == p for y, p in zip(labels, pred)) / len(labels),
            "average_precision": ap, "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0., "roc_auc": auc}


def execute_fake(view, node_id, attempt, artifact_root, fault=None):
    """Return immutable evidence package; Store alone accepts/publishes it.

    ``fault`` is harness-only and applied after raw response/tool result exists.
    No source outside ``input_snapshot`` can influence adapter output.
    """
    wall_start, cpu_start = time.monotonic(), time.process_time()
    node = _node(view, node_id)
    snapshot = input_projection(view, node_id, artifact_root)
    # Round trip ensures fake client consumes the actual serialized projection.
    request_input = json.loads(snapshot["rendered_messages"][1]["content"])
    request = request_input["request"]
    parents = {p["node_id"]: p for p in request_input["parent_inputs"]}
    source_inputs = {s["object_key"]: s for s in request_input["direct_source_inputs"]}
    values = request_input["artifact_values"]
    attempt_id = attempt["attempt_id"]
    result_id = attempt.get("result_id") or attempt_id + ".result"
    run_id = view["state"]["run_id"]
    made, contents = [], {}

    def artifact(label, value):
        artifact_id = result_id + "." + label
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in artifact_id)
        body = json_bytes(value)
        record = {"record_type": "Artifact", "revision": REVISION, "fixture_only": True,
            "artifact_id": artifact_id, "producer_result_id": result_id,
            "uri": "artifacts/v1/" + safe + ".json", "sha256": hashlib.sha256(body).hexdigest(),
            "size_bytes": len(body), "media_type": "application/json"}
        made.append(record)
        contents[artifact_id] = body
        return artifact_id

    def find_value(predicate):
        for artifact_id, value in values.items():
            if predicate(value):
                return artifact_id, value
        raise ValueError("required input artifact missing")

    params = {"fixture_evidence_kind": "executed_deterministic_fake", "training_performed": False,
              "actual_model_prediction_performed": False}
    domain = view.get("domain", "micro" if "read_metadata" in view["dag"]["topological_order"] else "macro")
    if domain == "micro":
        if node_id.startswith("read_"):
            source = next(iter(source_inputs.values()))
            payload = copy.deepcopy(source["payload"])
        elif node_id == "plan":
            metadata, permission, resources = (parents[n]["payload"] for n in ("read_metadata", "read_permission", "read_resources"))
            n, batch, epochs = metadata["num_examples"], request["batch_size"], request["epochs"]
            payload = {**copy.deepcopy(request), "num_examples": n, "steps": ((n + batch - 1) // batch) * epochs,
                       "workers": min(request["requested_workers"], resources["max_workers"]),
                       "allowed": permission["allowed"], "policy_revision": permission["policy_revision"]}
        elif node_id == "execute":
            command = copy.deepcopy(parents["plan"]["payload"])
            payload = {**command, "command": command, "config": copy.deepcopy(command), "action": "commit_config_and_draft"}
            artifact("config", command)
            artifact("draft", {"fixture_only": True, "command": command, "training_performed": False})
        else:
            raise ValueError("unknown micro node")
    elif node_id == "profile":
        train_source = source_inputs["data:train"]
        train_ids = train_source["payload"]["row_ids"]
        train_artifact_id = train_source["artifact_refs"][0]
        val_id, val = find_value(lambda v: v.get("kind") == "synthetic_input_rows" and
                                 all(".val." in r["row_id"] for r in v.get("rows", [])) and bool(v.get("rows")))
        profile_id = artifact("profile", {"fixture_only": True, "kind": "synthetic_profile", "numeric_columns": ["x0", "x1"],
            "categorical_columns": [], "train_count": len(train_ids), "validation_count": len(val["rows"]), "missing_values": 0})
        payload = {"fixture_only": True, "profile_artifact_id": profile_id, "train_count": len(train_ids),
            "validation_count": len(val["rows"]), "train_rows_artifact_id": train_artifact_id,
            "validation_rows_artifact_id": val_id, "training_row_ids": train_ids}
    elif node_id == "inspect":
        profile = values[parents["profile"]["payload"]["profile_artifact_id"]]
        payload = {"fixture_only": True, "approved_numeric_columns": profile["numeric_columns"],
                   "fit_preprocessing_on": "training_rows_only", "status": "ready"}
    elif node_id == "prepare":
        profile = parents["profile"]["payload"]
        # Frozen V0 profile only cites counts; its direct source bindings remain
        # actual ancestors, so the referenced row artifacts are in the projection.
        train_id = profile.get("train_rows_artifact_id")
        if train_id is None:
            train_id, _ = find_value(lambda v: v.get("kind") == "synthetic_input_rows" and any(".train." in r["row_id"] for r in v.get("rows", [])))
        val_id = profile.get("validation_rows_artifact_id")
        if val_id is None:
            val_id, _ = find_value(lambda v: v.get("kind") == "synthetic_input_rows" and any(".val." in r["row_id"] for r in v.get("rows", [])))
        all_train, val_rows = values[train_id]["rows"], values[val_id]["rows"]
        train_ids = profile.get("training_row_ids", [r["row_id"] for r in all_train])
        train_rows = [r for r in all_train if r["row_id"] in train_ids]
        families = {}
        for family in ("lr", "rf"):
            processor = artifact(family + ".preprocessor", {"fixture_only": True, "kind": "fake_preprocessor_placeholder",
                "training_row_ids": train_ids, "feature_columns": ["x0", "x1"], "numeric_columns": ["x0", "x1"],
                "categorical_columns": [], "can_transform_real_data": False, "scaled": family == "lr", "was_fitted": False})
            matrix = artifact(family + ".matrices", {"fixture_only": True, "kind": "synthetic_small_matrices",
                "feature_columns": ["x0", "x1"], "train_row_ids": train_ids,
                "train_x": [r["x"] for r in train_rows], "train_y": [r["y"] for r in train_rows],
                "val_row_ids": [r["row_id"] for r in val_rows], "val_x": [r["x"] for r in val_rows],
                "val_y": [r["y"] for r in val_rows]})
            families[family] = {"preprocessor_artifact_id": processor, "matrix_artifact_id": matrix}
        payload = {"fixture_only": True, "families": families, "training_row_ids": train_ids,
                   "validation_row_ids": [r["row_id"] for r in val_rows]}
    elif node_id.startswith("plan_"):
        family = node_id[-2:]
        recipe = source_inputs["recipe:" + family]["payload"]
        payload = {"fixture_only": True, "family": family.upper(), "parameters": copy.deepcopy(recipe["parameters"]),
                   "matrix_artifact_id": parents["prepare"]["payload"]["families"][family]["matrix_artifact_id"]}
    elif node_id.startswith("fit_"):
        family = node_id[-2:]
        plan, prepare = parents["plan_" + family]["payload"], parents["prepare"]["payload"]
        model_id = artifact("model", {"fixture_only": True, "not_a_real_experiment": True, "kind": "fake_model_placeholder",
            "family": family.upper(), "classes": [0, 1], "has_predict_method": False, "was_trained": False,
            "parameters": plan["parameters"], "matrix_artifact_id": plan["matrix_artifact_id"],
            "training_row_ids": prepare["training_row_ids"]})
        params["model_parameters"] = copy.deepcopy(plan["parameters"])
        payload = {"fixture_only": True, "model_artifact_id": model_id, "training_performed": False,
                   "synthetic_success_status_only": True}
    elif node_id.startswith("predict_"):
        family = node_id[-2:]
        model_id = parents["fit_" + family]["payload"]["model_artifact_id"]
        model, prepare = values[model_id], parents["prepare"]["payload"]
        matrix = values[prepare["families"][family]["matrix_artifact_id"]]
        if family == "lr":
            scores = [.9, .8, .7, .6, .5]
        elif model["parameters"]["max_depth"] == 12:
            scores = [.8, .2, .3, .1, .9]
        else:
            scores = [.9, .8, .7, .5, .6]
        if len(scores) != len(matrix["val_row_ids"]):
            raise ValueError("V1 fake adapter only supports five synthetic validation rows")
        prediction_id = artifact("prediction", {"fixture_only": True, "not_a_real_experiment": True,
            "kind": "synthetic_probabilities_not_model_output", "classes": [0, 1],
            "model_artifact_id": model_id, "preprocessor_artifact_id": prepare["families"][family]["preprocessor_artifact_id"],
            "positive_probabilities": scores, "row_ids": matrix["val_row_ids"]})
        payload = {"fixture_only": True, "actual_model_prediction_performed": False, "prediction_artifact_id": prediction_id}
    elif node_id.startswith("summary_"):
        family = node_id[-2:]
        prediction_id = parents["predict_" + family]["payload"]["prediction_artifact_id"]
        prediction, prepare = values[prediction_id], parents["prepare"]["payload"]
        matrix = values[prepare["families"][family]["matrix_artifact_id"]]
        metrics = fake_metrics(matrix["val_y"], prediction["positive_probabilities"])
        params["unmodified_metrics"] = copy.deepcopy(metrics)
        metrics_id = artifact("metrics", {"fixture_only": True, "kind": "synthetic_metrics_arithmetic_fixture",
            "not_a_real_experiment": True, "metrics": metrics, "positive_label": 1,
            "prediction_artifact_id": prediction_id, "probability_threshold": .5})
        payload = {"fixture_only": True, "family": family.upper(), "metrics": copy.deepcopy(metrics), "metrics_artifact_id": metrics_id}
    elif node_id == "report":
        summaries = {f: parents["summary_" + f.lower()]["payload"] for f in ("LR", "RF")}
        scores = {f: s["metrics"]["average_precision"] for f, s in summaries.items()}
        choice = "LR" if scores["LR"] + request["tie_break"]["epsilon"] >= scores["RF"] else "RF"
        summary_artifact = values[summaries[choice]["metrics_artifact_id"]]
        prediction_id = summary_artifact["prediction_artifact_id"]
        prediction = values[prediction_id]
        payload = {"fixture_only": True, "chosen_family": choice, "validation_average_precision": scores,
            "model_artifact_id": prediction["model_artifact_id"], "prediction_artifact_id": prediction_id,
            "report_text": "Offline synthetic comparison from the delivered summaries."}
        payload["report_artifact_id"] = artifact("report", copy.deepcopy(payload))
    elif node_id == "publish":
        report = parents["report"]["payload"]
        report_artifact_id = report.get("report_artifact_id") or parents["report"]["artifact_refs"][0]
        candidate_id = artifact("manifest", {"fixture_only": True, "not_a_real_experiment": True,
            "kind": "unpublished_synthetic_manifest_candidate", "model_artifact_id": report["model_artifact_id"],
            "prediction_artifact_id": report["prediction_artifact_id"], "report_artifact_id": report_artifact_id,
            "would_publish": False})
        payload = {"fixture_only": True, "action": "publish_manifest", "candidate_artifact_id": candidate_id,
                   "business_effect_created": False}
    else:
        raise ValueError("unknown macro node")

    raw_payload = copy.deepcopy(payload)
    if fault:
        if fault == "metadata_plus_batch" and node_id == "read_metadata":
            payload["num_examples"] += request["batch_size"]
        elif fault == "summary_ap_flip" and node_id == "summary_lr":
            payload["metrics"]["average_precision"] = 0. if payload["metrics"]["average_precision"] >= .5 else 1.
        elif fault == "steps_plus_one" and node_id == "plan":
            payload["steps"] += 1
        elif fault == "report_ap_wrong" and node_id == "report":
            payload["validation_average_precision"]["LR"] += .125
        else:
            raise ValueError("fault does not match node")
    direct_reads = sorted([{ "object_key": s["object_key"], "version": s["version"]} for s in request_input["direct_source_inputs"]], key=lambda r: r["object_key"])
    read_set = {(r["object_key"], r["version"]) for p in request_input["parent_inputs"] for r in p["effective_reads"]}
    read_set.update((r["object_key"], r["version"]) for r in direct_reads)
    input_digest = digest(snapshot)
    calls, receipts = [], []
    if node["llm_calls_per_execution"]:
        calls.append({"record_type": "CallEvidence", "revision": REVISION, "fixture_only": True,
            "call_id": attempt.get("call_id", attempt_id + ".call"), "run_id": run_id, "node_id": node_id,
            "attempt_id": attempt_id, "mode": "fixture", "status": "completed", "provider_request_id": None,
            "usage": None, "cost_nano_usd": 0, "input_digest": input_digest, "request_sent": False,
            "http_status": None, "endpoint": None, "model": "deterministic_offline_fake",
            "worker_started": False, "evidence_kind": "executed_deterministic_fake",
            "raw_response_payload": raw_payload, "note": "Local fake client consumed serialized scoped inputs; no HTTP request."})
    if node["cpu_jobs_per_execution"]:
        receipts.append({"record_type": "ToolReceipt", "revision": REVISION, "fixture_only": True,
            "receipt_id": attempt.get("receipt_id", attempt_id + ".receipt"), "run_id": run_id, "node_id": node_id,
            "attempt_id": attempt_id, "producer_result_id": result_id, "tool": "v1.fake." + node_id,
            "input_digest": input_digest, "parameters": params, "artifact_refs": [a["artifact_id"] for a in made],
            "cpu_seconds": time.process_time() - cpu_start, "wall_seconds": time.monotonic() - wall_start,
            "exit_code": 0, "warnings": ["V1 synthetic adapter only; no training or real model prediction."]})
    result = {"record_type": "NodeResult", "revision": REVISION, "fixture_only": True,
        "run_id": run_id, "node_id": node_id, "attempt_id": attempt_id, "result_id": result_id,
        "producer": node["role"], "execution_status": "success", "parent_result_ids": [p["result_id"] for p in request_input["parent_inputs"]],
        "direct_reads": direct_reads, "effective_reads": [{"object_key": k, "version": v} for k, v in sorted(read_set)],
        "input_digest": input_digest, "input_snapshot": snapshot, "payload": payload,
        "artifact_refs": [a["artifact_id"] for a in made], "call_ids": [c["call_id"] for c in calls],
        "tool_receipt_ids": [r["receipt_id"] for r in receipts]}
    return {"result": result, "artifacts": made, "artifact_contents": contents, "calls": calls, "tool_receipts": receipts}


def materialize_package(package, artifact_root):
    """Prefix harness helper, never a substitute for Store branch acceptance."""
    root = Path(artifact_root).resolve()
    for binding in package["artifacts"]:
        path = (root / binding["uri"]).resolve()
        if not path.is_relative_to(root):
            raise ValueError("unsafe artifact path")
        path.parent.mkdir(parents=True, exist_ok=True)
        body = package["artifact_contents"][binding["artifact_id"]]
        if path.exists() and path.read_bytes() != body:
            raise ValueError("attempt to rewrite immutable artifact")
        path.write_bytes(body)


def load_n2_scene(v0_root, artifact_root):
    """Import only frozen synthetic runtime fixture and its cited artifacts."""
    base = Path(v0_root) / "fixtures/n2"
    scene = json.loads((base / "runtime/initial_state.json").read_text())
    root = Path(artifact_root)
    for artifact in scene["artifact_manifest"]:
        source, target = base / artifact["uri"], root / artifact["uri"]
        body = source.read_bytes()
        if hashlib.sha256(body).hexdigest() != artifact["sha256"]:
            raise ValueError("frozen N2 artifact mismatch")
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.read_bytes() != body:
            raise ValueError("immutable destination mismatch")
        target.write_bytes(body)
    scene.update({"domain": "macro", "workflow_id": "sr-v2.macro.cpu-model-selection", "source_aliases": {}})
    return scene


def _prefix_view(scene, dag):
    from .common import source_fingerprint
    state = {**scene["run_state"], "source_fingerprint": source_fingerprint(scene["current_sources"]),
             "invalidated_result_ids": [], "branch_id": scene["run_state"]["run_id"] + ".fixture_build", "state_version": 0}
    return {"state": state, "dag": dag, "results": scene["results"],
            "sources": scene["current_sources"], "source_history": scene["source_history"], "task": scene["task"], "artifacts": scene["artifact_manifest"],
            "source_aliases": scene.get("source_aliases", {}), "domain": scene["domain"],
            "notice": scene.get("notice"), "tool_receipts": scene["tool_receipts"], "calls": scene["call_evidence"]}


def build_scene(v0_root, domain, task_id, condition, artifact_root):
    """Fresh fake fault prefix, semantic refusal, then a legal source change.

    Prefix nodes are deterministic local computations with durable input/result
    files in the returned package. Formal registry and V0 are never mutated.
    No already-completed normal/control output is edited into a fault scene.
    """
    if condition not in {"N1", "N2", "N3"} or domain not in {"micro", "macro"}:
        raise ValueError("unregistered fake domain/condition")
    base = Path(v0_root)
    dag = json.loads((base / "dags" / (domain + ".json")).read_text())
    task_label = "eval" + task_id.rsplit("-", 1)[-1] if domain == "micro" else "graph"
    scene_id = f"sr-v2.fake.{domain}.{task_label}.{condition}"
    run_id = scene_id + ".prefix"
    scene = {"revision": REVISION, "fixture_only": True, "domain": domain, "workflow_id": dag["workflow_id"],
        "prefix_mode": "fake_adapter_fixture_not_transactional_initial_runner",
        "results": [], "artifact_manifest": [], "call_evidence": [], "tool_receipts": [], "attempts": [],
        "input_producers": [], "source_aliases": {}, "current_sources": [], "source_history": [],
        "run_state": {"run_id": run_id, "scene_id": scene_id, "task_id": task_id, "lifecycle": "prefix_building",
            "selected_by_node": {n: None for n in dag["topological_order"]}, "active_attempt_ids": [],
            "unsettled_call_ids": [], "business_effects": [], "published_manifest": None, "published_report_index": None,
            "failed_candidate_result_ids": []}}
    if domain == "micro":
        task = next(t for t in json.loads((base / "tasks/micro_tasks.json").read_text())["tasks"] if t["task_id"] == task_id)
        sources = json.loads((base / "tasks/authority" / (task_id + ".sources.json")).read_text())["sources"]
        scene["current_sources"] = copy.deepcopy([s for s in sources if s["version"] == 1])
        scene["source_history"] = copy.deepcopy(scene["current_sources"])
        scene["source_aliases"] = task["resolved_source_aliases"]
        scene["task"] = {"task_id": task_id, "request": copy.deepcopy(task["public_request"]),
                         "revision": REVISION, "limits": dag["branch_caps"], "nodes": dag["nodes"],
                         "resolved_source_aliases": copy.deepcopy(task["resolved_source_aliases"])}
        target = "read_metadata"
    else:
        # Only V0 synthetic rows, never the Adult/Bank raw files.
        frozen_base = base / "fixtures/n2"
        frozen = json.loads((frozen_base / "runtime/initial_state.json").read_text())
        scene["task"] = copy.deepcopy(frozen["task"])
        scene["task"]["task_id"] = task_id
        scene["task"]["nodes"] = dag["nodes"]
        initial = [s for s in frozen["source_history"] if s["version"] == 1]
        scene["current_sources"] = copy.deepcopy(initial)
        scene["source_history"] = copy.deepcopy(initial)
        external_ids = set(a for s in initial for a in s["artifact_refs"])
        scene["artifact_manifest"] = [a for a in frozen["artifact_manifest"] if a["artifact_id"] in external_ids]
        for binding in scene["artifact_manifest"]:
            body = (frozen_base / binding["uri"]).read_bytes()
            if hashlib.sha256(body).hexdigest() != binding["sha256"]:
                raise ValueError("frozen synthetic input mismatch")
            materialize_package({"artifacts": [binding], "artifact_contents": {binding["artifact_id"]: body}}, artifact_root)
        scene["input_producers"] = frozen["input_producers"]
        target = "summary_lr"
    terminal = dag["topological_order"][-1]
    target_result = None
    for index, node_id in enumerate(dag["topological_order"]):
        attempt = {"attempt_id": f"{run_id}.attempt.{index:02d}.{node_id}"}
        fault = ("metadata_plus_batch" if domain == "micro" else "summary_ap_flip") if node_id == target else None
        package = execute_fake(_prefix_view(scene, dag), node_id, attempt, artifact_root, fault=fault)
        materialize_package(package, artifact_root)
        result = package["result"]
        scene["results"].append(result)
        scene["artifact_manifest"].extend(package["artifacts"])
        scene["call_evidence"].extend(package["calls"])
        scene["tool_receipts"].extend(package["tool_receipts"])
        scene["attempts"].append({"attempt_id": attempt["attempt_id"], "node_id": node_id,
            "result_id": result["result_id"], "status": "closed", "fixture_only": True})
        scene["run_state"]["selected_by_node"][node_id] = result["result_id"]
        if node_id == target:
            target_result = result["result_id"]
    # Same runtime guard as all recovery policies; this initial refusal does not
    # tell the controller which future source changes the harness will apply.
    from .guard import diagnose
    prefix_guard = diagnose(_prefix_view(scene, dag), terminal, checkpoint="precommit", candidate=scene["results"][-1],
                            full=True, artifact_root=artifact_root)
    if prefix_guard["classification"] != "semantic":
        raise ValueError("fake prefix did not exhibit the injected semantic fault: " + prefix_guard["classification"])
    scene["prefix_candidate_result"] = copy.deepcopy(scene["results"][-1])
    scene["prefix_refusal"] = prefix_guard
    scene["results"][-1]["execution_status"] = "validation_rejected"
    scene["run_state"]["selected_by_node"][terminal] = None
    scene["run_state"]["failed_candidate_result_ids"] = [scene["results"][-1]["result_id"]]
    for receipt in scene["tool_receipts"]:
        if receipt["producer_result_id"] == scene["results"][-1]["result_id"]:
            receipt["exit_code"] = 65
    scene["notice"] = {"record_type": "Notice", "revision": REVISION, "fixture_only": True,
        "run_id": run_id, "notice_id": scene_id + ".notice", "faulty_result_id": target_result}
    if domain == "micro":
        history = json.loads((base / "tasks/authority" / (task_id + ".sources.json")).read_text())["sources"]
        updated_keys = {scene["source_aliases"]["resources"]} if condition == "N2" else set(scene["source_aliases"].values()) if condition == "N3" else set()
        updates = [copy.deepcopy(s) for s in history if s["object_key"] in updated_keys and s["version"] == 2]
    else:
        updates = []
        if condition == "N2":
            update = copy.deepcopy(next(s for s in scene["current_sources"] if s["object_key"] == "recipe:rf"))
            update["version"] = 2
            update["payload"]["binding_id"] = "fake.rf.recipe.v2"
            update["payload"]["parameters"]["max_depth"] = 12
            update["payload_digest"] = digest(update["payload"])
            updates = [update]
        elif condition == "N3":
            update = copy.deepcopy(next(s for s in scene["current_sources"] if s["object_key"] == "data:train"))
            train_artifact = next(a for a in scene["artifact_manifest"] if a["artifact_id"] == update["artifact_refs"][0])
            train = _artifact_value(train_artifact["artifact_id"], _by_id(scene["artifact_manifest"], "artifact_id"), artifact_root)
            train = copy.deepcopy(train)
            train["rows"].append({"row_id": "fake.train.row.06", "x": [6, 0], "y": 0})
            artifact_id = run_id + ".external.train.v2"
            body = json_bytes(train)
            binding = {"record_type": "Artifact", "revision": REVISION, "fixture_only": True,
                "artifact_id": artifact_id, "producer_result_id": "fake.external.input.01", "uri": "artifacts/v1/" + artifact_id + ".json",
                "sha256": hashlib.sha256(body).hexdigest(), "size_bytes": len(body), "media_type": "application/json"}
            materialize_package({"artifacts": [binding], "artifact_contents": {artifact_id: body}}, artifact_root)
            scene["artifact_manifest"].append(binding)
            update["version"] = 2
            update["artifact_refs"] = [artifact_id]
            update["payload"].update({"binding_id": "fake.train.binding.v2", "row_count": len(train["rows"]), "row_ids": [r["row_id"] for r in train["rows"]]})
            update["payload_digest"] = digest(update["payload"])
            updates = [update]
    for update in updates:
        scene["current_sources"] = [update if s["object_key"] == update["object_key"] else s for s in scene["current_sources"]]
        scene["source_history"].append(update)
    scene["run_state"]["lifecycle"] = "frozen_recoverable"
    scene["prefix_evidence"] = {"kind": "fresh_offline_fake_prefix", "fault_node": target,
        "faulty_result_id": target_result, "request_sent": False, "real_api_calls": 0,
        "source_update_after_refusal": True, "condition": condition}
    return scene
