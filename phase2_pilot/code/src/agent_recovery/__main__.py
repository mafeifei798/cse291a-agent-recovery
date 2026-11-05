"""Offline S1-S5 entry points; no real model or cloud access."""

import argparse
import json
from pathlib import Path

from .contracts import utc_now
from .oracle import BasicOracle, NormalRunOracle
from .reference import ReferenceBundle, check_reference, extract_reference
from .store import Store
from .trace import build_graph, find_invalidated
from .workflow import PrefixWorkflow, Workflow


def s1_demo(reference: Path, destination: Path) -> dict:
    bundle = ReferenceBundle.load(reference)
    static_check = check_reference(bundle)
    destination.mkdir(parents=True, exist_ok=False)
    with Store(destination / "prefix.sqlite") as store:
        run_id = store.initialize_run(bundle.task)
        prefix = PrefixWorkflow(store).run_prefix()
        snapshot = store.snapshot_run()
        graph = build_graph(snapshot["results"])
        assert prefix["status"] == "planner_complete" and len(graph.nodes) == 4
        assert not snapshot["output_objects"] and not snapshot["effects"]
        assert all(row["status"] == "closed" for row in snapshot["attempts"])
        plan = store.get_result(prefix["selected"]["plan"])["payload"]
    initial_graph = build_graph(bundle.initial)
    current = {obj["object_key"]: obj for obj in bundle.scene["source_objects"]}
    analysis = find_invalidated(
        initial_graph, {r["step_id"]: r["result_id"] for r in bundle.initial},
        bundle.scene["notice"]["faulty_result_id"], current,
        bundle.scene["result_states"],
    )
    assert analysis["reuse_candidates"] == [bundle.initial[1]["result_id"]]
    assert analysis["replay_steps"] == ["read_metadata", "read_resources", "plan", "execute"]
    oracle = BasicOracle()
    initial_check = oracle.check("initial", bundle.task, bundle.initial_snapshot())
    final_check = oracle.check("final", bundle.task, bundle.final_snapshot())
    assert not initial_check["passed"] and final_check["passed"]
    report = {
        "scope": "S1_first_integration", "status": "passed",
        "reference": static_check,
        "live_store_prefix": {**prefix, "run_id": run_id, "completed_steps": 4,
                              "planner_payload": plan, "active_attempts": 0,
                              "business_output_objects": 0, "effects": 0},
        "dependency_analysis": {"input": "static frozen reference", **analysis},
        "independent_checker": {"input": "static journal snapshots, not expected report",
                                "initial": initial_check, "final": final_check},
        "not_implemented": ["executor", "business writes", "event injection",
                            "compensation", "recovery execution", "real model", "cloud jobs"],
    }
    (destination / "snapshot.json").write_text(json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n")
    (destination / "integration.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    return report


def s2_demo(reference: Path, destination: Path) -> dict:
    bundle = ReferenceBundle.load(reference)
    static = check_reference(bundle)
    destination.mkdir(parents=True, exist_ok=False)
    started = utc_now()
    with Store(destination / "normal.sqlite") as store:
        run_id = store.initialize_run(bundle.task)
        workflow = Workflow(store).run_initial()
        snapshot = store.snapshot_run()
        integrity = store.connection.execute("PRAGMA integrity_check").fetchone()[0]
    evaluation = NormalRunOracle().check(bundle.task, snapshot)
    passed = workflow["status"] == "completed" and evaluation["passed"] and integrity == "ok"
    report = {"scope": "S2_normal_workflow", "status": "passed" if passed else "failed",
              "started_at": started, "finished_at": utc_now(), "run_id": run_id,
              "reference": static, "workflow": workflow, "evaluation": evaluation,
              "database_integrity": integrity, "result_count": len(snapshot["results"]),
              "active_attempts": sum(row["status"] == "active" for row in snapshot["attempts"]),
              "output_objects": len(snapshot["output_objects"]), "effects": len(snapshot["effects"]),
              "planner_payload": next((r["payload"] for r in snapshot["results"] if r["step_id"] == "plan"), None),
              "scenario_events_applied": 0,
              "not_implemented": ["event injection", "compensation", "recovery execution", "real model", "cloud jobs"]}
    (destination / "snapshot.json").write_text(json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (destination / "integration.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description="Offline foundations; no model or cloud access")
    sub = parser.add_subparsers(dest="command", required=True)
    extract = sub.add_parser("extract-reference")
    extract.add_argument("--document", type=Path, required=True)
    extract.add_argument("--destination", type=Path, required=True)
    check = sub.add_parser("check-reference")
    check.add_argument("--reference", type=Path, default=Path("fixtures/reference"))
    demo = sub.add_parser("s1-demo")
    demo.add_argument("--reference", type=Path, default=Path("fixtures/reference"))
    demo.add_argument("--destination", type=Path, required=True)
    normal = sub.add_parser("s2-demo")
    normal.add_argument("--reference", type=Path, default=Path("fixtures/reference"))
    normal.add_argument("--destination", type=Path, required=True)
    restart = sub.add_parser("s3-demo")
    restart.add_argument("--reference", type=Path, default=Path("fixtures/reference"))
    restart.add_argument("--destination", type=Path, required=True)
    selective = sub.add_parser("s4-demo")
    selective.add_argument("--scene-root", type=Path, required=True)
    selective.add_argument("--destination", type=Path, required=True)
    acceptance = sub.add_parser("s5-demo")
    acceptance.add_argument("--scene-root", type=Path, required=True)
    acceptance.add_argument("--destination", type=Path, required=True)
    offline = sub.add_parser("s6-offline-demo")
    offline.add_argument("--reference", type=Path, default=Path("fixtures/reference"))
    offline.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "extract-reference":
        result = extract_reference(args.document, args.destination)
    elif args.command == "check-reference":
        result = check_reference(ReferenceBundle.load(args.reference))
    elif args.command == "s1-demo":
        result = s1_demo(args.reference, args.destination)
    elif args.command == "s2-demo":
        result = s2_demo(args.reference, args.destination)
    elif args.command == "s3-demo":
        from .s3_experiment import s3_demo
        result = s3_demo(args.reference, args.destination)
    elif args.command == "s4-demo":
        from .s4_experiment import s4_demo
        result = s4_demo(args.scene_root, args.destination)
    elif args.command == "s5-demo":
        from .s5_experiment import s5_demo
        result = s5_demo(args.scene_root, args.destination)
    else:
        from .s6_experiment import s6_offline_demo
        result = s6_offline_demo(args.reference, args.destination)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if result.get("status") == "failed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
