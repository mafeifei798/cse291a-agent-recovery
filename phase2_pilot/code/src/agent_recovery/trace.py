"""Pure provenance analysis. This module performs no writes or recovery actions."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass

from .contracts import (
    PARENTS, STEPS, ContractError, require, source_keys, validate_reads, validate_result,
)


def derive_read_set(direct_reads: list, parents: list[dict]) -> list[dict]:
    validate_reads(direct_reads)
    versions = {}
    for refs in [direct_reads, *[parent["effective_read_set"] for parent in parents]]:
        validate_reads(refs)
        for ref in refs:
            key, version = ref["object_key"], ref["version"]
            require(key not in versions or versions[key] == version,
                    f"Two versions of {key} occur in the same input", "INCONSISTENT_READ_SET")
            versions[key] = version
    return [{"object_key": key, "version": version} for key, version in sorted(versions.items())]


@dataclass(frozen=True)
class ResultGraph:
    nodes: dict[str, dict]
    children: dict[str, set[str]]

    def descendants(self, seeds: set[str]) -> set[str]:
        require(seeds <= self.nodes.keys(), "Unknown result in graph", "INVALID_PARENT")
        found, pending = set(seeds), list(seeds)
        while pending:
            for child in self.children[pending.pop()]:
                if child not in found:
                    found.add(child)
                    pending.append(child)
        return found


def build_graph(results: list[dict]) -> ResultGraph:
    all_ids, run_ids, attempts = set(), set(), set()
    nodes = {}
    for result in results:
        validate_result(result)
        rid = result["result_id"]
        require(rid not in all_ids, "Duplicate result ID", "INVALID_PARENT")
        all_ids.add(rid)
        run_ids.add(result["run_id"])
        attempt = (result["step_id"], result["attempt_no"])
        require(attempt not in attempts, "Duplicate logical attempt", "INVALID_PARENT")
        attempts.add(attempt)
        if result["execution_status"] == "success":
            nodes[rid] = deepcopy(result)
    require(len(run_ids) <= 1, "Graph mixes different runs", "INVALID_PARENT")
    requests = [result["input_snapshot"]["request"] for result in nodes.values()]
    require(not requests or all(request == requests[0] for request in requests),
            "Graph mixes task requests in one run", "INVALID_PARENT")
    children = {rid: set() for rid in nodes}
    for rid, result in nodes.items():
        snapshot = result["input_snapshot"]
        tools = snapshot["tool_snapshots"]
        allowed = dict(zip(STEPS[:3], source_keys(snapshot["request"])))
        if result["step_id"] in allowed:
            require(len(tools) == 1 and tools[0]["exists"]
                    and tools[0]["object_key"] == allowed[result["step_id"]],
                    "Query did not record its declared source", "INVALID_PARENT")
        else:
            require(tools == [], "Non-query step recorded an undeclared tool read", "INVALID_PARENT")
        captured_reads = sorted(
            [{"object_key": obj["object_key"], "version": obj["version"]} for obj in tools],
            key=lambda ref: ref["object_key"],
        )
        require(result["direct_reads"] == captured_reads,
                "Direct reads differ from captured tool snapshots", "INVALID_PARENT")
        parents = []
        for pid in result["parent_result_ids"]:
            require(pid in nodes, "Missing or failed successful-result parent", "INVALID_PARENT")
            children[pid].add(rid)
            parents.append(nodes[pid])
        require(tuple(p["step_id"] for p in parents) == PARENTS[result["step_id"]],
                "Parents do not match fixed workflow", "INVALID_PARENT")
        require([p["payload"] for p in parents] ==
                [p["payload"] for p in result["input_snapshot"]["parents"]],
                "Stored parent differs from delivered input", "INVALID_PARENT")
        require(derive_read_set(result["direct_reads"], parents) == result["effective_read_set"],
                "Effective read set omitted or changed a source", "INVALID_PARENT")
    visiting, visited = set(), set()

    def visit(rid):
        require(rid not in visiting, "Cyclic result graph", "INVALID_PARENT")
        if rid in visited:
            return
        visiting.add(rid)
        for pid in nodes[rid]["parent_result_ids"]:
            visit(pid)
        visiting.remove(rid)
        visited.add(rid)

    for rid in nodes:
        visit(rid)
    return ResultGraph(nodes, children)


def project_states(graph: ResultGraph, events: list[dict]) -> dict[str, dict]:
    states = {rid: {"validity": "usable", "reasons": []} for rid in graph.nodes}
    for event in events:
        rid = event["result_id"]
        require(rid in states, "State references an unknown successful result", "INVALID_PARENT")
        validity = event["validity"]
        require(validity in ("usable", "invalidated"), "Unknown result state")
        if states[rid]["validity"] == "invalidated" and validity == "usable":
            raise ContractError("INVALID_PARENT", "Invalidated results cannot become usable again")
        reasons = event.get("reasons", event.get("invalid_reasons", []))
        require(isinstance(reasons, list), "Reasons must be an array")
        states[rid]["validity"] = validity
        states[rid]["reasons"] = sorted(set(states[rid]["reasons"]) | set(reasons))
    return states


def find_invalidated(graph: ResultGraph, selected: dict[str, str], faulty_result_id: str,
                     current_versions: dict[str, dict], state_events: list[dict] | None = None,
                     policy: str = "selective") -> dict:
    require(policy in ("selective", "full_restart"), "Unknown policy")
    require(faulty_result_id in graph.nodes, "Unknown faulty result", "INVALID_NOTICE")
    require(set(selected) <= set(STEPS), "Unknown selected step", "INVALID_PARENT")
    for step, rid in selected.items():
        require(rid in graph.nodes and graph.nodes[rid]["step_id"] == step,
                "Selected result has wrong identity", "INVALID_PARENT")
    # A current consumer must reference the chosen producer, not a different generation.
    for step, rid in selected.items():
        require(graph.nodes[rid]["parent_result_ids"] ==
                [selected[parent] for parent in PARENTS[step] if parent in selected]
                and all(parent in selected for parent in PARENTS[step]),
                "Selected results do not form one execution chain", "INVALID_PARENT")
    states = project_states(graph, state_events or [])
    reasons = {rid: set(state["reasons"]) for rid, state in states.items()
               if state["validity"] == "invalidated"}
    fault_closure = graph.descendants({faulty_result_id})
    for rid in fault_closure:
        reasons.setdefault(rid, set()).add("known_fault" if rid == faulty_result_id else "depends_on_invalid")
    stale_seeds = set()
    for rid in selected.values():
        if rid in reasons:
            continue
        for ref in graph.nodes[rid]["effective_read_set"]:
            actual = current_versions.get(ref["object_key"])
            if actual is None or not actual["exists"] or actual["version"] != ref["version"]:
                stale_seeds.add(rid)
                reasons.setdefault(rid, set()).add("stale_source")
                break
    for rid in graph.descendants(set(reasons)) if reasons else set():
        if rid not in reasons:
            reasons[rid] = {"depends_on_invalid"}
    if policy == "full_restart":
        for rid in selected.values():
            reasons.setdefault(rid, set()).add("full_restart")
    candidates = sorted(rid for rid in selected.values() if rid not in reasons)
    return {
        "fault_closure": sorted(fault_closure), "stale_seeds": sorted(stale_seeds),
        "invalidated": [{"result_id": rid, "reasons": sorted(why)}
                        for rid, why in sorted(reasons.items())],
        "reuse_candidates": candidates,
        "replay_steps": [step for step in STEPS
                         if step not in selected or selected[step] in reasons],
    }


def build_input_bundle(step: str, request: dict, parents: list[dict],
                       tool_snapshots: list[dict]) -> dict:
    require(step in STEPS, "Unknown step")
    require(tuple(parent["step_id"] for parent in parents) == PARENTS[step],
            "Wrong actual parent order", "INVALID_PARENT")
    require(all(p["execution_status"] == "success" for p in parents),
            "Failed parent is not consumable", "INVALID_PARENT")
    return deepcopy({
        "request": request,
        "parents": [{"result_id": p["result_id"], "payload": p["payload"]} for p in parents],
        "tool_snapshots": tool_snapshots,
    })
