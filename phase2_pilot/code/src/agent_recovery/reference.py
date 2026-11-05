"""Extraction and integrity checks for the eight static documentation blocks."""

from __future__ import annotations

import json
import re
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path

from .contracts import (
    canonical_json, digest, exact_fields, require, validate_id, validate_object,
    validate_result, validate_task,
)
from .trace import build_graph

FILES = (
    "task.json", "initial_results.jsonl", "replay_results.jsonl", "write_receipts.jsonl",
    "operation_digest_inputs.json", "frozen_scene.json", "audit_records.json",
    "expected_recovery_report.json",
)
RECEIPT_FIELDS = {
    "schema_version", "effect_id", "operation_id", "operation_digest", "run_id",
    "owner_result_id", "step_id", "attempt_no", "source_read_set", "targets",
    "committed_at", "state", "compensation_attempts",
}


@dataclass
class ReferenceBundle:
    task: dict
    initial: list[dict]
    replay: list[dict]
    receipts: list[dict]
    commands: list[dict]
    scene: dict
    audit: dict
    expected_report: dict

    @property
    def results(self):
        return self.initial + self.replay

    @classmethod
    def load(cls, folder: str | Path):
        folder = Path(folder)
        values = []
        for name in FILES:
            content = (folder / name).read_text(encoding="utf-8")
            values.append([json.loads(line) for line in content.splitlines() if line.strip()]
                          if name.endswith(".jsonl") else json.loads(content))
        return cls(*values)

    def initial_snapshot(self) -> dict:
        """Pre-update snapshot, independent of the expected report's verdict."""
        effect = deepcopy(self.receipts[0])
        effect.update(state="applied", compensation_attempts=[])
        return {
            "request": deepcopy(self.task["request"]), "run_state": "initial",
            "source_objects": deepcopy(self.task["initial_objects"]),
            "output_objects": [deepcopy(target["after"]) for target in effect["targets"]],
            "attempts": [], "results": deepcopy(self.initial), "result_status_events": [],
            "effects": [effect], "event_log": deepcopy([e for e in self.audit["event_log"] if e["event_seq"] <= 11]),
            "notices": [],
        }

    def final_snapshot(self) -> dict:
        """Reconstruct static object history; this does not run recovery."""
        objects = {obj["object_key"]: deepcopy(obj) for obj in self.task["initial_objects"]}
        for event in self.audit["event_log"]:
            for after in event["after_objects"]:
                objects[after["object_key"]] = deepcopy(after)
        source_keys = {o["object_key"] for o in self.task["initial_objects"]}
        return {
            "request": deepcopy(self.task["request"]), "run_state": "terminal",
            "source_objects": [objects[key] for key in sorted(source_keys)],
            "output_objects": [objects[key] for key in sorted(objects.keys() - source_keys)],
            "attempts": [], "results": deepcopy(self.results),
            "result_status_events": deepcopy(self.audit["result_status_events"]),
            "effects": deepcopy(self.receipts), "event_log": deepcopy(self.audit["event_log"]),
            "notices": [deepcopy(self.scene["notice"])],
        }


def check_reference(bundle: ReferenceBundle) -> dict:
    validate_task(bundle.task)
    require(len(bundle.initial) == 5 and len(bundle.replay) == 4, "Reference must have 5 initial and 4 replay results")
    graph = build_graph(bundle.results)
    byid = graph.nodes
    require(len(byid) == 9, "Reference result identities are not unique")
    require([r["step_id"] for r in bundle.initial] ==
            ["read_metadata", "read_permission", "read_resources", "plan", "execute"], "Wrong initial order")
    run_id = bundle.initial[0]["run_id"]
    require(len(bundle.receipts) == len(bundle.commands) == 2, "Reference needs two receipts/commands")
    for receipt, command in zip(bundle.receipts, bundle.commands):
        exact_fields(receipt, RECEIPT_FIELDS, "WriteReceipt")
        require(receipt["schema_version"] == "1.1", "Unsupported receipt schema")
        for field in ("effect_id", "operation_id", "owner_result_id", "run_id"):
            validate_id(receipt[field])
        owner = byid[receipt["owner_result_id"]]
        require(owner["step_id"] == receipt["step_id"] == "execute", "Wrong effect owner")
        require(owner["attempt_no"] == receipt["attempt_no"], "Wrong effect attempt")
        require(owner["effect_ids"] == [receipt["effect_id"]], "Effect identity mismatch")
        require(receipt["source_read_set"] == owner["effective_read_set"], "Write source lineage mismatch")
        require(receipt["committed_at"] == owner["finished_at"], "Commit time mismatch")
        require(receipt["operation_digest"] == digest(command), "Operation digest mismatch")
        require(command["run_id"] == receipt["run_id"] == run_id, "Command belongs to a different run")
        require(command["arguments"] == byid[owner["parent_result_ids"][0]]["payload"], "Command differs from input plan")
        require(command["target_keys"] == [t["object_key"] for t in receipt["targets"]], "Wrong target keys")
        for target in receipt["targets"]:
            validate_object(target["before"])
            validate_object(target["after"])
            require(target["before"]["object_key"] == target["object_key"] == target["after"]["object_key"], "Target identity mismatch")
            require(target["after"]["version"] == target["before"]["version"] + 1, "Write version did not advance")
            require(target["after"]["last_writer_id"] == owner["result_id"], "Wrong output writer")
    scene = bundle.scene
    require(scene["task_spec_digest"] == digest(bundle.task), "Task digest mismatch")
    require(scene["initial_results_digest"] == digest(bundle.initial), "Initial-results digest mismatch")
    core = {key: value for key, value in bundle.receipts[0].items()
            if key not in ("state", "compensation_attempts")}
    require(scene["write_receipt_cores_digest"] == digest([core]), "Receipt core digest mismatch")
    require(scene["effect_states"] == [{"effect_id": bundle.receipts[0]["effect_id"], "state": "applied"}], "Frozen effect has wrong lifecycle state")
    objects = {obj["object_key"]: deepcopy(obj) for obj in bundle.task["initial_objects"]}
    seq = 0
    for event in bundle.audit["event_log"]:
        require(event["event_seq"] > seq, "Event sequence must increase")
        seq = event["event_seq"]
        require(len(event["before_objects"]) == len(event["after_objects"]), "Partial write group")
        for before, after in zip(event["before_objects"], event["after_objects"]):
            validate_object(before)
            validate_object(after)
            current = objects.get(before["object_key"], {
                "object_key": before["object_key"], "exists": False,
                "payload": None, "version": 0, "last_writer_id": None})
            require(current == before, "Event before-image differs from actual static history")
            require(before["object_key"] == after["object_key"] and after["version"] == before["version"] + 1, "Invalid event version change")
            objects[after["object_key"]] = after
    report = bundle.expected_report
    require(report["schema_version"] == "1.1" and report["case_id"] == bundle.task["case_id"], "Report task mismatch")
    require(report["scene_digest"] == digest(scene), "Scene digest mismatch")
    require(report["run_id"] == run_id and report["notice_id"] == scene["notice"]["notice_id"], "Report identity mismatch")
    require(report["faulty_result_ids"] == [scene["notice"]["faulty_result_id"]], "Fault identity mismatch")
    for step, rid in report["final_result_ids"].items():
        require(rid in byid and byid[rid]["step_id"] == step, "Report references the wrong final result")
    final = bundle.final_snapshot()
    require(report["final_objects"] == final["output_objects"], "Report final objects differ from raw journal")
    require(all(objects[obj["object_key"]] == obj for obj in scene["source_objects"]), "Legal source update was lost")
    invalidated = {row["result_id"] for row in bundle.audit["result_status_events"]}
    require(invalidated == {row["result_id"] for row in report["invalidation_rounds"][0]["invalidated"]}, "Report invalidation differs from raw state events")
    require(not invalidated.intersection(report["final_result_ids"].values()), "Final chain retained an invalid result")
    require(report["reused_results"] == report["evaluation"]["verified_reused_results"] == [bundle.initial[1]["result_id"]], "Unexpected reference reuse")
    require([row["result_id"] for row in report["reexecutions"]] == [row["result_id"] for row in bundle.replay], "Replay reference mismatch")
    cost = report["cost"]
    require(cost["initial_steps"] == 5 and cost["recovery_steps_started"] == 4 and cost["reused_result_count"] == 1, "Reference count mismatch")
    require(cost["total_wall_ms"] == cost["initial_wall_ms"] + cost["recovery_wall_ms"], "Latency accounting mismatch")
    return {"status": "passed", "scope": "static_reference_integrity", "files": 8,
            "initial_results": 5, "replay_results": 4, "write_receipts": 2,
            "input_hashes_checked": 9, "scene_digest": digest(scene),
            "workflow_or_recovery_executed": False}


def extract_reference(document: str | Path, destination: str | Path) -> dict:
    text = Path(document).read_text(encoding="utf-8")
    section = text.split("## 15.", 1)[1].split("## 16.", 1)[0]
    values = [json.loads(block) for block in re.findall(r"```json\n(.*?)\n```", section, re.S)]
    require(len(values) == 8, "Expected exactly eight reference blocks")
    result = check_reference(ReferenceBundle(*values))
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    for name, value in zip(FILES, values):
        body = "".join(canonical_json(row) + "\n" for row in value) if name.endswith(".jsonl") else json.dumps(value, ensure_ascii=False, indent=2) + "\n"
        (destination / name).write_text(body, encoding="utf-8")
    return result
