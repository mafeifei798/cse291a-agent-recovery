"""S5 finite, offline acceptance: real SQLite histories, including safe failures.

The subclasses below are private test doubles for transport/storage faults. They
are never model context and do not change the recovery engine's decisions.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from time import perf_counter, sleep

from .contracts import (STEPS, ContractError, canonical_json, digest, new_id,
                        output_keys, require, utc_now)
from .gateway import ScriptedGateway
from .oracle import NormalRunOracle
from .recovery import Recovery
from .recovery_store import backup_database
from .reference import ReferenceBundle
from .s3_experiment import make_task, write_json
from .s4_experiment import comparable_state, file_hash, run_pair
from .s5_oracle import S5RecoveryOracle
from .scenario import Scenario
from .store import Store
from .trace import build_input_bundle
from .workflow import PrefixWorkflow, Workflow

REFERENCE = Path(__file__).resolve().parents[2] / "fixtures/reference"


def clean_task(base):
    task = deepcopy(base)
    task.update(case_id="s5_t01", events=[], tags=["S5", "scripted", "clean"])
    return task


def prepare_scene(base, destination, case="T02", rounds=None, dynamic=False):
    """Build test-owned scenes; production acceptance uses the pinned S3 scenes."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    run_id = new_id()
    task = make_task(base, case, run_id)
    if rounds is not None:
        task["execution_settings"]["max_recovery_rounds"] = rounds
    if dynamic:
        task["case_id"] = "s5_dynamic_resource_update"
        task["events"].append({"event_id": new_id(), "kind": "external_update",
            "trigger": {"boundary": "before_executor_commit", "step_id": "execute", "attempt_no": 2},
            "order": 1, "parameters": {"object_key": "resource_policy:default",
            "expected_version": 1, "new_payload": {"max_workers": 4}}})
    write_json(destination / "task.json", task)
    with Store(destination / "initial.sqlite") as store:
        store.initialize_run(task, run_id)
        prepared = Scenario(store, task).run_to_notice()
        require(prepared["status"] == "ready", "Acceptance fixture did not pause")
        write_json(destination / "initial_snapshot.json", prepared["initial_snapshot"])
        exported = store.export_scene(destination / "frozen", prepared["initial_cost"])
    write_json(destination / "integration.json", {"case": case, "scene_digest": exported["scene_digest"],
        "frozen_database_sha256": file_hash(destination / "frozen/scene.sqlite")})
    return destination


def load_scene(source):
    source = Path(source)
    return tuple(json.loads((source / name).read_text()) for name in
                 ("task.json", "frozen/scene.json", "frozen/snapshot.json"))


def execution_candidate(store, template, plan_id, recovery_id=None):
    """Prepare a real admitted execute token without invoking a model."""
    view = store.runtime_view()
    plan = store.get_result(plan_id)
    attempt = store.begin_attempt(view["run_id"], "execute", [plan_id], recovery_id)
    inputs = {**build_input_bundle("execute", view["request"], [plan], []),
              "prompt_revision": "scripted-v1", "rendered_messages": []}
    result = deepcopy(template)
    result.update(run_id=view["run_id"], attempt_no=attempt["attempt_no"], result_id=attempt["result_id"],
        execution_status="success", payload=None, parent_result_ids=[plan_id], direct_reads=[],
        effective_read_set=deepcopy(plan["effective_read_set"]), input_snapshot=inputs,
        input_digest=digest(inputs), effect_ids=[], model_calls=[], started_at=attempt["started_at"],
        finished_at=utc_now(), duration_ms=0, error=None)
    command = {"run_id": view["run_id"], "step_id": "execute", "attempt_no": attempt["attempt_no"],
               "action": "save_job", "arguments": deepcopy(plan["payload"]),
               "target_keys": list(output_keys(view["run_id"]))}
    return [attempt["token"], result, command, store.read_objects(command["target_keys"]), new_id()]


class RecordingStore(Store):
    def commit_execution(self, *args, **kwargs):
        self.last_commit = deepcopy(args)
        return super().commit_execution(*args, **kwargs)


class TransportFaultStore(RecordingStore):
    """Only replay execute attempt 2 is affected, not the initial frozen scene."""
    fault_mode = None
    fault_attempt_no = 2

    def commit_execution(self, *args, **kwargs):
        self.last_commit = deepcopy(args)
        if args[1]["attempt_no"] != self.fault_attempt_no:
            return super().commit_execution(*args, **kwargs)
        if self.fault_mode == "absent_readable":
            raise OSError("S5 precommit transport/storage failure")
        if self.fault_mode == "absent_unreadable":
            # Fail after the first target write: real SQLite rollback must remove it.
            self.connection.executescript("""CREATE TRIGGER s5_abort_commit BEFORE INSERT ON effects
                BEGIN SELECT RAISE(ABORT, 'S5 rollback before receipt'); END;""")
            try:
                return super().commit_execution(*args, **kwargs)
            finally:
                self.connection.execute("DROP TRIGGER s5_abort_commit")
        value = super().commit_execution(*args, **kwargs)
        if self.fault_mode in ("applied_lost", "applied_unreadable"):
            raise OSError("S5 committed, acknowledgement lost")
        return value

    def get_operation(self, run_id, operation_id):
        if self.fault_mode in ("applied_unreadable", "absent_unreadable"):
            raise OSError("S5 operation lookup unavailable")
        return super().get_operation(run_id, operation_id)


def run_recovery(source, destination, policy="selective", store_type=Store, scenario_type=Scenario,
                 transport_mode=None, delay_before_ms=0):
    source, destination = Path(source), Path(destination)
    task, scene, frozen = load_scene(source)
    before_hash = file_hash(source / "frozen/scene.sqlite")
    destination.mkdir(parents=True, exist_ok=False)
    backup_database(source / "frozen/scene.sqlite", destination / "branch.sqlite")
    waited_begin = perf_counter()
    if delay_before_ms:
        sleep(delay_before_ms / 1000)
    wait_ms = (perf_counter() - waited_begin) * 1000
    begin = perf_counter()
    with store_type(destination / "branch.sqlite") as store:
        if transport_mode:
            store.fault_mode = transport_mode
        scenario = scenario_type(store, task)
        engine = Recovery(store, scenario=scenario)
        trial_id = new_id()
        if hasattr(scenario, "bind"):
            scenario.bind(engine, trial_id, scene, policy)
        engine_begin = perf_counter()
        report = engine.handle_notice(trial_id, scene["notice"]["notice_id"], scene, digest(scene), policy)
        engine_observed_wall_ms = (perf_counter() - engine_begin) * 1000
        write_json(destination / "engine_report.json", report)
        snapshot = store.snapshot_run()
        evaluation = S5RecoveryOracle().check(task, scene, frozen, snapshot, report)
        report = store.attach_evaluation(report["recovery_id"], evaluation, "incorrect", 0, 0)
        before_repeat = store.snapshot_run()
        repeated = engine.handle_notice(trial_id, scene["notice"]["notice_id"], scene, digest(scene), policy)
        repeat_unchanged = repeated == report and before_repeat == store.snapshot_run()
        evidence = {"duplicate_notice_unchanged": repeat_unchanged,
                    "engine_observed_wall_ms": engine_observed_wall_ms,
                    "database_integrity": store.connection.execute("PRAGMA integrity_check").fetchone()[0]}
        if hasattr(scenario, "duplicate_evidence"):
            evidence["during_recovery_duplicate"] = scenario.duplicate_evidence
        if transport_mode:
            # Bypass fault injection only for an external, read-only investigator.
            operation = Store.get_operation(store, scene["run_id"], store.last_commit[-1])
            evidence.update(operation_id=store.last_commit[-1], result_id=store.last_commit[1]["result_id"],
                            reconciled_readonly_operation_state=operation["state"])
            try:
                store.begin_attempt(scene["run_id"], "read_metadata", [], report["recovery_id"])
                evidence["later_attempt_rejected"] = False
            except ContractError as exc:
                evidence.update(later_attempt_rejected=True, later_attempt_error=exc.code)
        snapshot = store.snapshot_run()
    evidence.update(source_unchanged=file_hash(source / "frozen/scene.sqlite") == before_hash,
                    delay_before_recovery_ms=wait_ms, branch_execution_wall_ms=(perf_counter() - begin) * 1000,
                    scene_digest=digest(scene), remaining_budget=scene["remaining_budget"])
    write_json(destination / "report.json", report)
    write_json(destination / "snapshot.json", snapshot)
    write_json(destination / "evidence.json", evidence)
    return task, scene, frozen, snapshot, report, evaluation, evidence


class DuplicateDuringRecovery(Scenario):
    def bind(self, engine, trial_id, scene, policy):
        self.binding = (engine, trial_id, scene, policy)
        self.duplicate_evidence = []

    def on_boundary(self, boundary, step_id, attempt_no):
        super().on_boundary(boundary, step_id, attempt_no)
        if boundary == "before_executor_commit" and attempt_no == 2:
            engine, trial, scene, policy = self.binding
            before = self.store.snapshot_run()
            duplicate = engine.handle_notice(trial, scene["notice"]["notice_id"], scene, digest(scene), policy)
            self.duplicate_evidence.append({"snapshot_unchanged": before == self.store.snapshot_run(),
                "same_recovery_id": duplicate["recovery_id"] == self.store.recovery_progress(scene["notice"]["notice_id"])["recovery_id"],
                "phase": duplicate.get("phase"), "engine_status": duplicate.get("engine_status")})


class AcceptanceSuite:
    def __init__(self, scene_root, destination, reference=REFERENCE):
        self.scene_root, self.destination = Path(scene_root), Path(destination)
        self.bundle = ReferenceBundle.load(reference)
        self.base = self.bundle.task
        self.pairs = {}

    def verdict(self, case, checks, evidence=None):
        folder = self.destination / case
        folder.mkdir(parents=True, exist_ok=True)
        row = {"case": case, "status": "passed" if all(checks.values()) else "failed",
               "checks": checks, "evidence": evidence or {}}
        write_json(folder / "acceptance.json", row)
        return row

    def paired(self, case):
        if case not in self.pairs:
            self.pairs[case] = run_pair(self.scene_root / case, self.destination / case / "pair",
                                       "selective" if case == "T03" else "full_restart")
        return self.pairs[case]

    def t01(self):
        folder = self.destination / "T01"
        folder.mkdir(parents=True)
        task = clean_task(self.base)
        with Store(folder / "normal.sqlite") as store:
            store.initialize_run(task)
            report = Workflow(store).run_initial()
            snapshot = store.snapshot_run()
        evaluation = NormalRunOracle().check(task, snapshot)
        write_json(folder / "task.json", task)
        write_json(folder / "snapshot.json", snapshot)
        write_json(folder / "evaluation.json", evaluation)
        return self.verdict("T01", {"normal_oracle_passed": evaluation["passed"],
            "five_actual_steps": len(snapshot["results"]) == len(snapshot["attempts"]) == 5,
            "one_live_group": len(snapshot["effects"]) == 1 and snapshot["effects"][0]["state"] == "applied",
            "completed": report["status"] == "completed"})

    def t02(self):
        pair = self.paired("T02")
        return self.verdict("T02", {"same_frozen_pair_passed": pair["status"] == "passed",
            "selective_three_steps_two_original_results": pair["policies"]["selective"]["actual_steps_started"] == 3
                and len(pair["policies"]["selective"]["verified_reused_result_ids"]) == 2}, pair)

    def t03(self):
        pair = self.paired("T03")
        return self.verdict("T03", {"same_frozen_pair_passed": pair["status"] == "passed",
            "selective_four_steps_one_original_result": pair["policies"]["selective"]["actual_steps_started"] == 4
                and len(pair["policies"]["selective"]["verified_reused_result_ids"]) == 1}, pair)

    def t04(self):
        pair = self.paired("T04")
        return self.verdict("T04", {"safe_refusal_verified": pair["status"] == "passed" and all(
            row["safe_conflict_refusal"] and row["outcome"] == "failed_conflict"
            and row["actual_steps_started"] == 0 and row["verified_reused_result_ids"] == []
            for row in pair["policies"].values())}, pair)

    def t05(self):
        folder = self.destination / "T05"
        folder.mkdir(parents=True)
        with RecordingStore(folder / "duplicate_write.sqlite") as store:
            store.initialize_run(clean_task(self.base))
            Workflow(store).run_initial()
            args = deepcopy(store.last_commit)
            before = store.snapshot_run()
            exact = store.commit_execution(*args)
            duplicate_write = before == store.snapshot_run() and exact["result"] == before["results"][-1]
            changed = list(deepcopy(args))
            changed[2]["arguments"]["workers"] = 2
            changed_code = None
            try:
                store.commit_execution(*changed)
            except ContractError as exc:
                changed_code = exc.code
            late = list(deepcopy(args)); late[-1] = new_id()
            late_code = None
            try:
                store.commit_execution(*late)
            except ContractError as exc:
                late_code = exc.code
            query = deepcopy(before["results"][0])
            token = store.connection.execute("SELECT token FROM attempts WHERE result_id=?", (query["result_id"],)).fetchone()[0]
            query["payload"]["num_examples"] += 1
            query_code = None
            try:
                store.append_result(token, query)
            except ContractError as exc:
                query_code = exc.code
            write_json(folder / "write_snapshot.json", store.snapshot_run())
            write_unchanged = before == store.snapshot_run()
        _, scene, _, snapshot, report, evaluation, evidence = run_recovery(self.scene_root / "T02",
            folder / "recovery", scenario_type=DuplicateDuringRecovery)
        with Store(folder / "recovery/branch.sqlite") as store:
            before = store.snapshot_run()
            old_effect = before["effects"][0]["effect_id"]
            comp = store.compensate(old_effect, report["recovery_id"])
            duplicate_comp = before == store.snapshot_run() and comp["status"] == "already_compensated"
            params_code = None
            try:
                Recovery(store).handle_notice(new_id(), scene["notice"]["notice_id"], scene, digest(scene), "selective")
            except ContractError as exc:
                params_code = exc.code
        evidence.update(changed_operation_error=changed_code, late_execute_error=late_code,
                        late_query_error=query_code, changed_trial_error=params_code)
        return self.verdict("T05", {"duplicate_write_identical": duplicate_write,
            "changed_operation_rejected": changed_code == "IDEMPOTENCY_MISMATCH",
            "closed_execute_new_operation_rejected": late_code == "STALE_ATTEMPT",
            "closed_query_novel_response_rejected": query_code in ("IDEMPOTENCY_MISMATCH", "STALE_ATTEMPT"),
            "no_mutation_from_late_responses": write_unchanged,
            "duplicate_compensation_no_version_bump": duplicate_comp,
            "duplicate_notice_no_new_work": evidence["duplicate_notice_unchanged"],
            "duplicate_during_running_is_readonly": bool(evidence.get("during_recovery_duplicate")) and all(
                row["snapshot_unchanged"] and row["same_recovery_id"] for row in evidence["during_recovery_duplicate"]),
            "changed_trial_rejected": params_code == "IDEMPOTENCY_MISMATCH",
            "recovery_still_correct": report["outcome"] == "recovered" and evaluation["passed"]}, evidence)

    def dynamic(self, rounds, policy, folder):
        source = prepare_scene(self.base, folder / "source", rounds=rounds, dynamic=True)
        return run_recovery(source, folder / policy, policy)

    def t06(self):
        folder = self.destination / "T06"
        folder.mkdir(parents=True)
        _, _, frozen, final, report, evaluation, evidence = self.dynamic(1, "selective", folder)
        failed = [row for row in final["results"][5:] if row["step_id"] == "execute"]
        checks = {"execute_attempt2_stale_source": len(failed) == 1 and failed[0]["attempt_no"] == 2
                    and failed[0]["execution_status"] == "stale_input" and failed[0]["error"]["code"] == "STALE_SOURCE",
            "no_phantom_effect": len(final["effects"]) == 1 and final["effects"][0]["state"] == "compensated",
            "only_undo_versions_remain": all(not obj["exists"] and obj["version"] == 2 for obj in final["output_objects"]),
            "new_resource_kept": next(obj for obj in final["source_objects"] if obj["object_key"] == "resource_policy:default")["version"] == 2,
            "explicit_budget_failure": report["outcome"] == "failed_budget" and report["failure"]["code"] == "RECOVERY_ROUND_LIMIT",
            "single_round_only": len(report["invalidation_rounds"]) == 1,
            "no_active_attempt": not any(row["status"] == "active" for row in final["attempts"]),
            "independent_budget_stop_safety": rule_passed(evaluation, "S5_BUDGET_STOP_SAFETY"),
            "not_counted_as_recovered": not evaluation["passed"] and report["cost"]["reused_result_count"] == 0}
        return self.verdict("T06", checks, {**evidence, "failure": report["failure"],
            "failed_execute": failed, "evaluation_failed_rules": failed_rules(evaluation)})

    def _prefix(self, folder):
        folder.mkdir(parents=True)
        store = Store(folder / "branch.sqlite")
        task = clean_task(self.base)
        store.initialize_run(task)
        selected = PrefixWorkflow(store).run_prefix()["selected"]
        return store, task, selected

    def t07(self):
        folder = self.destination / "T07"
        store, _, selected = self._prefix(folder)
        with store:
            args = execution_candidate(store, self.bundle.initial[-1], selected["plan"])
            old = deepcopy(args[1]["effective_read_set"])
            # A new-version claim cannot overwrite the old parent-derived version.
            for ref in args[1]["effective_read_set"]:
                if ref["object_key"] == "resource_policy:default":
                    ref["version"] = 2
            write_json(folder / "rejected_candidate.json", args[1])
            result = store.commit_execution(*args)["result"]
            store.finish_run(store.runtime_view()["run_id"])
            final = store.snapshot_run()
            write_json(folder / "snapshot.json", final)
        return self.verdict("T07", {"inconsistent_new_vs_parent_version_rejected": result["execution_status"] != "success"
                and result["error"]["code"] == "INVALID_PARENT",
            "saved_old_source_not_silently_replaced": old != args[1]["effective_read_set"],
            "no_job_or_effect": final["output_objects"] == [] and final["effects"] == [],
            "attempt_closed": all(row["status"] == "closed" for row in final["attempts"])},
            {"parent_read_set": old, "candidate_read_set": args[1]["effective_read_set"], "error": result["error"]})

    def t08(self):
        pair = self.paired("T03")
        folder = self.destination / "T03/pair/selective"
        final = json.loads((folder / "snapshot.json").read_text())
        report = json.loads((folder / "report.json").read_text())
        byid = {row["result_id"]: row for row in final["results"]}
        invalid = {row["result_id"] for row in final["result_status_events"] if row["validity"] == "invalidated"}
        rows = [byid[report["final_result_ids"][step]] for step in ("plan", "execute")]
        inputs = [{"step_id": row["step_id"], "result_id": row["result_id"],
                   "parent_result_ids": row["parent_result_ids"], "input_snapshot": row["input_snapshot"]} for row in rows]
        return self.verdict("T08", {"pair_passed": pair["status"] == "passed",
            "no_invalid_parent_in_actual_replay_inputs": all(not invalid.intersection(row["parent_result_ids"]) for row in rows),
            "parents_match_actual_input_payloads": all(row["input_snapshot"]["parents"] == [
                {"result_id": rid, "payload": byid[rid]["payload"]} for rid in row["parent_result_ids"]] for row in rows)},
            {"inputs": inputs, "invalidated_ids": sorted(invalid)})

    def t09(self):
        rows = {case: self.paired(case)["policies"]["full_restart"] for case in ("T02", "T03")}
        return self.verdict("T09", {"both_full_restarts_recovered": all(row["outcome"] == "recovered" for row in rows.values()),
            "five_steps_no_old_reuse": all(row["actual_steps_started"] == 5 and row["actual_reused_results"] == [] for row in rows.values()),
            "both_pairs_same_state_and_source_preserved": all(self.paired(case)["same_final_business_state_and_versions"]
                and self.paired(case)["source_inputs_unchanged"] for case in rows)}, rows)

    def t10(self):
        self.paired("T02")
        final = json.loads((self.destination / "T02/pair/selective/snapshot.json").read_text())
        old, new = final["effects"]
        histories = {key: [obj["version"] for event in final["event_log"] for obj in event["after_objects"]
                          if obj["object_key"] == key] for key in output_keys(old["run_id"])}
        return self.verdict("T10", {"stable_output_keys": [row["object_key"] for row in old["targets"]] == [row["object_key"] for row in new["targets"]],
            "versions_strictly_1_2_3": all(versions == [1, 2, 3] for versions in histories.values()),
            "old_receipt_and_result_retained": old["state"] == "compensated" and old["owner_result_id"] in {row["result_id"] for row in final["results"]},
            "one_live_draft": sum(row["state"] == "applied" for row in final["effects"]) == 1 and all(row["exists"] for row in final["output_objects"])},
            {"object_versions_in_raw_journal": histories, "effect_states": [{"effect_id": row["effect_id"], "state": row["state"]} for row in final["effects"]]})

    def t11(self):
        folder = self.destination / "T11"
        store, _, selected = self._prefix(folder)
        with store:
            notice = {"notice_id": new_id(), "run_id": store.runtime_view()["run_id"],
                      "faulty_result_id": selected["read_metadata"]}
            store.record_notice_and_pause(notice)
            identity = store.start_recovery(new_id(), notice["notice_id"], "selective")
            recovery_id = identity["recovery_id"]
            args = execution_candidate(store, self.bundle.initial[-1], selected["plan"], recovery_id)
            sources = store.snapshot_run()["source_objects"]
            # Exercise the real storage interface after execute admission. Its
            # invalidation and matching journal event are committed together.
            store.mark_unusable([{"result_id": selected["plan"], "reasons": ["known_fault"]}], recovery_id)
            status = store.snapshot_run()["result_status_events"][-1]
            committed = store.commit_execution(*args)
            store.finish_run(store.runtime_view()["run_id"])
            final = store.snapshot_run()
            write_json(folder / "snapshot.json", final)
        return self.verdict("T11", {"invalidated_plan_rejected": committed["result"]["error"]["code"] == "INVALID_PARENT",
            "sources_unchanged": final["source_objects"] == sources,
            "no_objects_receipt_or_live_attempt": final["output_objects"] == final["effects"] == []
                and all(row["status"] == "closed" for row in final["attempts"])},
            {"invalidation": status, "failed_result": committed["result"]})

    def t12(self):
        folder = self.destination / "T12"
        folder.mkdir(parents=True)

        class ReadFailure(Store):
            def read_objects(self, keys, attempt_token=None):
                if attempt_token is not None and self._attempt(attempt_token)["step_id"] == "read_metadata":
                    raise OSError("S5 tool read failure before model invocation")
                return super().read_objects(keys, attempt_token)

        class RenderFailure(ScriptedGateway):
            generate_count = 0
            def render(self, role, bundle):
                if role == "read_metadata":
                    raise ValueError("S5 render failure before model invocation")
                return super().render(role, bundle)
            def generate(self, *args):
                self.generate_count += 1
                return super().generate(*args)

        evidence, checks = {}, {}
        for mode, cls, gateway in (("read", ReadFailure, ScriptedGateway()), ("render", Store, RenderFailure())):
            with cls(folder / (mode + ".sqlite")) as store:
                store.initialize_run(clean_task(self.base))
                workflow = Workflow(store, gateway)
                failed = workflow.run_step("read_metadata", [])
                count_before_followup = getattr(gateway, "generate_count", 0)
                followup = workflow.run_step("read_permission", [])
                store.finish_run(store.runtime_view()["run_id"])
                snapshot = store.snapshot_run()
                write_json(folder / (mode + "_snapshot.json"), snapshot)
            checks[mode + "_saved_closed_failure_before_model"] = (failed["execution_status"] == "runtime_error"
                and failed["input_snapshot"] is None and failed["model_calls"] == [] and count_before_followup == 0
                and all(row["status"] == "closed" for row in snapshot["attempts"]))
            checks[mode + "_later_step_not_blocked"] = followup["execution_status"] == "success"
            evidence[mode] = {"failed_result": failed, "followup_result_id": followup["result_id"]}
        return self.verdict("T12", checks, evidence)

    def t13(self):
        folder = self.destination / "T13"
        folder.mkdir(parents=True)
        checks, evidence = {}, {}
        for mode in ("applied_lost", "absent_readable", "applied_unreadable", "absent_unreadable"):
            _, _, frozen, final, report, evaluation, observed = run_recovery(self.scene_root / "T02", folder / mode,
                store_type=TransportFaultStore, transport_mode=mode)
            applied = mode.startswith("applied")
            uncertain = mode.endswith("unreadable")
            expected_outcome = "failed_uncertain" if uncertain else ("recovered" if applied else "failed_runtime")
            effect_count = 2 if applied else 1
            checks[mode + "_explicit_outcome"] = report["outcome"] == expected_outcome
            checks[mode + "_no_duplicate_write"] = len(final["effects"]) == effect_count and len(final["output_objects"]) == 2
            checks[mode + "_same_operation_resolved_or_fenced"] = (observed["reconciled_readonly_operation_state"] == ("applied" if applied else "absent")
                and observed["later_attempt_rejected"] and observed["duplicate_notice_unchanged"])
            checks[mode + "_no_active_attempt"] = not any(row["status"] == "active" for row in final["attempts"])
            checks[mode + "_version_boundary"] = all(row["version"] == (3 if applied else 2)
                and row["exists"] == applied for row in final["output_objects"])
            if uncertain:
                checks[mode + "_uncertainty_preserved"] = (final["run_state"] == "uncertain"
                    and report["cost"]["reused_result_count"] == 0 and not evaluation["passed"]
                    and evaluation["verified_reused_results"] == []
                    and report["failure"].get("operation_id") == observed["operation_id"]
                    and report["failure"].get("result_id") == observed["result_id"])
                checks[mode + "_independent_uncertain_safety"] = rule_passed(evaluation, "S5_UNCERTAIN_SAFETY")
            elif applied:
                checks[mode + "_independent_success"] = evaluation["passed"]
            evidence[mode] = {**observed, "outcome": report["outcome"], "run_state": final["run_state"],
                "attempts": len(final["attempts"]) - len(frozen["attempts"]), "effects": len(final["effects"]),
                "evaluation_failed_rules": failed_rules(evaluation), "failure": report["failure"]}
        # The same ambiguity can happen before any recovery exists. The run
        # must close admission even when an applied commit already closed its
        # token; an initial mode with no active attempt would otherwise be open.
        for mode in ("applied_unreadable", "absent_unreadable"):
            label = "initial_" + mode
            target = folder / label
            target.mkdir()
            task = clean_task(self.base)
            with TransportFaultStore(target / "branch.sqlite") as store:
                store.fault_attempt_no = 1
                store.fault_mode = mode
                run_id = store.initialize_run(task)
                report = Workflow(store).run_initial()
                before = store.snapshot_run()
                operation_id = store.last_commit[-1]
                operation = Store.get_operation(store, run_id, operation_id)
                rejected = False
                try:
                    store.begin_attempt(run_id, "read_metadata", [])
                except ContractError as exc:
                    rejected = exc.code == "STALE_ATTEMPT"
                final = store.snapshot_run()
            applied = mode.startswith("applied")
            checks[label + "_failed_uncertain_and_fenced"] = (report["status"] == "failed_uncertain"
                and report["log_complete"] is False and final["run_state"] == "uncertain"
                and report["error"]["code"] == "UNKNOWN_COMMIT_OUTCOME")
            checks[label + "_later_work_rejected_without_mutation"] = rejected and final == before
            checks[label + "_actual_operation_accounted_once"] = (operation["state"] == ("applied" if applied else "absent")
                and len(final["attempts"]) == 5 and len(final["results"]) == (5 if applied else 4)
                and len(final["effects"]) == (1 if applied else 0)
                and len(final["output_objects"]) == (2 if applied else 0)
                and all(row["version"] == 1 for row in final["output_objects"]))
            checks[label + "_no_active_token"] = (not any(row["status"] == "active" for row in final["attempts"])
                and final["attempts"][-1]["status"] == ("closed" if applied else "uncertain"))
            write_json(target / "task.json", task)
            write_json(target / "report.json", report)
            write_json(target / "snapshot.json", final)
            evidence[label] = {"outcome": report["status"], "run_state": final["run_state"],
                "operation_id": operation_id, "result_id": store.last_commit[1]["result_id"],
                "reconciled_readonly_operation_state": operation["state"],
                "actual_attempts": len(final["attempts"]), "actual_results": len(final["results"]),
                "actual_effects": len(final["effects"]), "log_complete": report["log_complete"]}
        return self.verdict("T13", checks, evidence)

    def t14(self):
        folder = self.destination / "T14"
        folder.mkdir(parents=True)
        source = prepare_scene(self.base, folder / "source", rounds=2, dynamic=True)
        checks, evidence, states = {}, {}, {}
        for policy in ("full_restart", "selective"):
            _, scene, frozen, final, report, evaluation, observed = run_recovery(source, folder / policy, policy)
            fresh = final["results"][5:]
            stale = [row for row in fresh if row["execution_status"] == "stale_input"]
            journal_rounds = [row for row in final["event_log"] if row["action"] == "begin_recovery_round"]
            checks[policy + "_recovered_second_round"] = report["outcome"] == "recovered" and evaluation["passed"] and len(report["invalidation_rounds"]) == 2
            checks[policy + "_actual_steps"] = report["cost"]["recovery_steps_started"] == len(fresh) == (10 if policy == "full_restart" else 6)
            checks[policy + "_stale_execute_has_no_effect"] = len(stale) == 1 and stale[0]["step_id"] == "execute" and stale[0]["effect_ids"] == []
            checks[policy + "_old_compensation_once"] = len([row for row in final["event_log"] if row["action"] == "compensate_group"]) == 1
            checks[policy + "_monotonic_output_versions"] = all(row["exists"] and row["version"] == 3 for row in final["output_objects"])
            checks[policy + "_two_raw_round_boundaries"] = len(journal_rounds) == 2
            checks[policy + "_new_policy_kept"] = next(row for row in final["source_objects"] if row["object_key"] == "resource_policy:default")["version"] == 2
            states[policy] = comparable_state(final)
            evidence[policy] = {**observed, "actual_reexecutions": [{key: row[key] for key in
                ("step_id", "attempt_no", "result_id", "execution_status")} for row in fresh],
                "reused_result_ids": report["reused_results"], "invalidation_rounds": report["invalidation_rounds"],
                "raw_round_boundaries": journal_rounds, "evaluation_failed_rules": failed_rules(evaluation)}
        checks["same_dynamic_scene_final_business_state"] = states["full_restart"] == states["selective"]
        return self.verdict("T14", checks, evidence)

    def t15(self):
        folder = self.destination / "T15"
        folder.mkdir(parents=True)
        rows = {}
        for policy in ("full_restart", "selective"):
            _, _, _, _, report, evaluation, evidence = run_recovery(self.scene_root / "T03", folder / policy,
                policy, delay_before_ms=50 if policy == "selective" else 0)
            rows[policy] = {**evidence, "recovery_wall_ms": report["cost"]["recovery_wall_ms"],
                            "outcome": report["outcome"], "evaluation_passed": evaluation["passed"]}
        a, b = rows["full_restart"], rows["selective"]
        return self.verdict("T15", {"same_scene_digest_and_independent_budget": a["scene_digest"] == b["scene_digest"]
                and a["remaining_budget"] == b["remaining_budget"],
            "second_branch_deliberately_delayed": b["delay_before_recovery_ms"] >= 45,
            "waiting_excluded_from_recovery_timer": all(row["recovery_wall_ms"] <= row["engine_observed_wall_ms"] for row in rows.values()),
            "both_recovered": all(row["outcome"] == "recovered" and row["evaluation_passed"] for row in rows.values()),
            "source_immutable": all(row["source_unchanged"] for row in rows.values())}, rows)

    def t16(self):
        self.paired("T03")
        source = self.scene_root / "T03"
        task, scene, frozen = load_scene(source)
        folder = self.destination / "T03/pair/selective"
        actual = json.loads((folder / "snapshot.json").read_text())
        original_report = json.loads((folder / "report.json").read_text())
        checks, evidence = {}, {}
        for mode in ("false_reuse", "omitted_compensation", "changed_raw_output", "forged_planner_input"):
            snapshot, report = deepcopy(actual), deepcopy(original_report)
            if mode == "false_reuse":
                report["reused_results"] = [scene["notice"]["faulty_result_id"]]
            elif mode == "omitted_compensation":
                report["compensations"] = []
            elif mode == "changed_raw_output":
                snapshot["output_objects"][0]["payload"]["steps"] += 1
            else:
                plan = next(row for row in snapshot["results"] if row["result_id"] == report["final_result_ids"]["plan"])
                plan["input_snapshot"]["parents"][2]["payload"]["max_workers"] = 99
                plan["input_digest"] = digest(plan["input_snapshot"])
            evaluation = S5RecoveryOracle().check(task, scene, frozen, snapshot, report)
            failures = failed_rules(evaluation)
            checks[mode + "_rejected_from_raw_evidence"] = not evaluation["passed"] and bool(failures) and evaluation["verified_reused_results"] == []
            evidence[mode] = {"failed_rules": failures, "evaluation": evaluation}
        return self.verdict("T16", checks, evidence)


def failed_rules(evaluation):
    return sorted(row["rule_id"] for row in evaluation["checks"] if not row["passed"])


def rule_passed(evaluation, rule_id):
    return any(row["rule_id"] == rule_id and row["passed"] for row in evaluation["checks"])


def s5_demo(scene_root, destination, reference=REFERENCE):
    scene_root, destination = Path(scene_root).resolve(), Path(destination).resolve()
    require(not destination.is_relative_to(scene_root), "Keep S5 output outside pinned source evidence")
    destination.mkdir(parents=True, exist_ok=False)
    suite = AcceptanceSuite(scene_root, destination, reference)
    rows = [getattr(suite, "t" + str(index).zfill(2))() for index in range(1, 17)]
    summary = {"scope": "S5_T01_T16_scripted_SQLite_acceptance", "status": "passed" if all(row["status"] == "passed" for row in rows) else "failed",
        "source_scene_root": str(scene_root), "cases": rows, "real_model_calls": 0,
        "S6_started": False, "cloud_resources": False,
        "limitations": ["Finite deterministic protocol tests; not exhaustive fault interleavings",
            "Uncertain commits are fenced for investigation, not automatically reconciled",
            "At most two recovery rounds in this acceptance; no crash resume",
            "CPU scripted adapter only; no claims about real-model quality or latency savings",
            "Safe refusal and budget exhaustion are expected failures, not recovered tasks"]}
    write_json(destination / "integration.json", summary)
    return summary
