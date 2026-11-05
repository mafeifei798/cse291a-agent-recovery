"""Independent checks from raw journal, receipts and inputs, not engine plans."""

from __future__ import annotations

from .contracts import STEPS, digest, output_keys, source_keys, utc_now, validate_object, validate_result
from .oracle import BasicOracle


def adopted_chain(snapshot, initial_ids):
    """Find the actual new live execution and its ancestors without a report."""
    active = [effect for effect in snapshot["effects"] if effect["state"] == "applied"]
    if not active or (len(active) == 1 and active[0]["owner_result_id"] in initial_ids):
        return {}
    if len(active) != 1:
        raise ValueError("More than one live execution")
    byid = {result["result_id"]: result for result in snapshot["results"]}
    selected, visiting = {}, set()

    def visit(rid):
        if rid in visiting:
            raise ValueError("Cyclic adopted chain")
        result = byid[rid]
        step = result["step_id"]
        if step in selected:
            if selected[step] != rid:
                raise ValueError("Adopted chain mixes step generations")
            return
        visiting.add(rid)
        for parent in result["parent_result_ids"]:
            visit(parent)
        visiting.remove(rid)
        selected[step] = rid

    visit(active[0]["owner_result_id"])
    return {step: selected[step] for step in STEPS if step in selected}


class RecoveryOracle:
    def check(self, task, scene, frozen, final, report):
        checks = list(BasicOracle().check("final", task, final)["checks"])
        initial_ids = {result["result_id"] for result in frozen["results"]}
        fresh = [result for result in final["results"] if result["result_id"] not in initial_ids]
        byid = {result["result_id"]: result for result in final["results"]}
        old_effects = {effect["effect_id"] for effect in frozen["effects"]}
        run_id = scene["run_id"]
        policy = report["policy"]
        # Deliberately independent of trace.find_invalidated: derive closure
        # from raw frozen parent references and authoritative source versions.
        originals = {result["result_id"]: result for result in frozen["results"]}
        fault_closure = {scene["notice"]["faulty_result_id"]}
        while True:
            expanded = fault_closure | {rid for rid, row in originals.items()
                                       if fault_closure.intersection(row["parent_result_ids"])}
            if expanded == fault_closure:
                break
            fault_closure = expanded
        sources = {obj["object_key"]: obj for obj in scene["source_objects"]}
        stale_seeds = {rid for rid, row in originals.items() if rid not in fault_closure and any(
            ref["object_key"] not in sources or not sources[ref["object_key"]]["exists"]
            or sources[ref["object_key"]]["version"] != ref["version"] for ref in row["effective_read_set"])}
        expected_invalid = fault_closure | stale_seeds
        while True:
            expanded = expected_invalid | {rid for rid, row in originals.items()
                                          if expected_invalid.intersection(row["parent_result_ids"])}
            if expanded == expected_invalid:
                break
            expected_invalid = expanded
        if policy == "full_restart":
            expected_invalid = initial_ids
        candidates = sorted(initial_ids - expected_invalid)
        replay_steps = [step for step in STEPS if any(row["step_id"] == step and rid in expected_invalid
                                                    for rid, row in originals.items())]
        try:
            adopted = adopted_chain(final, initial_ids)
            adoption_error = None
        except (ValueError, KeyError) as exc:
            adopted, adoption_error = {}, str(exc)
        actual_reuse = sorted(initial_ids.intersection(adopted.values()))

        def need(condition, message):
            if not condition:
                raise ValueError(message)

        def add(rule, verifier, evidence):
            try:
                verifier()
                passed, error = True, None
            except (ValueError, TypeError, KeyError, IndexError, StopIteration) as exc:
                passed, error = False, str(exc)
            checks.append({"rule_id": rule, "passed": passed, "evidence": {**evidence, "error": error}})

        def journal():
            need(final["event_log"][:len(frozen["event_log"])] == frozen["event_log"], "Frozen journal prefix changed")
            state = {obj["object_key"]: obj for obj in task["initial_objects"]}
            sequence = 0
            for event in final["event_log"]:
                need(event["event_seq"] > sequence, "Journal sequence did not increase")
                sequence = event["event_seq"]
                need(len(event["before_objects"]) == len(event["after_objects"]), "Partial object group")
                if event["before_objects"]:
                    need(event["action"] in ("commit_group", "compensate_group", "external_update"), "Undeclared object mutation")
                    need(len(event["before_objects"]) == (1 if event["action"] == "external_update" else 2), "Wrong group size")
                for before, after in zip(event["before_objects"], event["after_objects"]):
                    validate_object(before)
                    validate_object(after)
                    key = before["object_key"]
                    current = state.get(key, {"object_key": key, "exists": False, "payload": None,
                                              "version": 0, "last_writer_id": None})
                    need(before == current and after["object_key"] == key
                         and after["version"] == before["version"] + 1
                         and after["last_writer_id"] == event["actor_id"], "Before-image, version or writer differs")
                    state[key] = after
            actual = final["source_objects"] + final["output_objects"]
            need(len(actual) == len(state) and {obj["object_key"]: obj for obj in actual} == state,
                 "Actual objects differ from reconstructed journal")
            need(final["run_state"] == "terminal" and not any(row["status"] == "active" for row in final["attempts"]),
                 "Run or attempts are still active")

        def trace():
            need(final["results"][:len(frozen["results"])] == frozen["results"], "Original results were rewritten")
            publications = {}
            for event in final["event_log"]:
                if event["action"] in ("publish_result", "commit_group"):
                    need(event["actor_id"] not in publications and event["actor_type"] == "step", "Duplicate publication")
                    publications[event["actor_id"]] = event
            need(set(publications) == set(byid), "Publication/result identities differ")
            invalid = {event["result_id"] for event in final["result_status_events"] if event["validity"] == "invalidated"}
            need(policy in ("full_restart", "selective") and invalid == expected_invalid,
                 "Actual invalidations differ from independently derived fault/version closure")
            if policy == "full_restart":
                need(all("full_restart" in event["reasons"] for event in final["result_status_events"]), "Missing restart reason")
            for status in final["result_status_events"]:
                event = next(event for event in final["event_log"] if event["event_seq"] == status["event_seq"])
                need(event["action"] == "invalidate_results" and status["result_id"] in event["record_ids"]
                     and event["actor_id"] == report["recovery_id"], "Invalidation has no matching journal event")
            need(adoption_error is None, adoption_error)
            attempts = {row["result_id"]: row for row in final["attempts"]}
            need(len(attempts) == len(final["attempts"]) == len(final["results"]), "Attempt/result identities differ")
            for result in final["results"]:
                validate_result(result)
                attempt = attempts[result["result_id"]]
                need(attempt["status"] == "closed" and all(attempt[key] == result[key] for key in
                     ("run_id", "step_id", "attempt_no", "started_at")), "Actual attempt differs from result")
                need(result["run_id"] == run_id and result["model_calls"] == [], "Foreign run or unexpected model call")
                if result["execution_status"] != "success":
                    continue
                step, snapshot = result["step_id"], result["input_snapshot"]
                need(snapshot["request"] == task["request"], "Input request changed")
                producer_steps = () if step in STEPS[:3] else (STEPS[:3] if step == "plan" else ("plan",))
                parents = [byid[rid] for rid in result["parent_result_ids"]]
                need(tuple(parent["step_id"] for parent in parents) == tuple(producer_steps)
                     and snapshot["parents"] == [{"result_id": parent["result_id"], "payload": parent["payload"]} for parent in parents],
                     "Actual parent inputs differ from saved producers")
                need(all(publications[parent["result_id"]]["event_seq"] < publications[result["result_id"]]["event_seq"]
                         for parent in parents), "Consumer was published before its producer")
                if step in STEPS[:3]:
                    tools = snapshot["tool_snapshots"]
                    need(len(tools) == 1 and tools[0]["exists"] and tools[0]["object_key"] ==
                         dict(zip(STEPS[:3], source_keys(task["request"])))[step], "Query has a different source")
                    authoritative = next(obj for obj in task["initial_objects"] if obj["object_key"] == tools[0]["object_key"])
                    for event in final["event_log"]:
                        if event["event_seq"] > publications[result["result_id"]]["event_seq"]:
                            break
                        for after in event["after_objects"]:
                            if after["object_key"] == tools[0]["object_key"]:
                                authoritative = after
                    need(tools[0] == authoritative, "Recorded query snapshot differs from journal source history")
                    direct = [{"object_key": tools[0]["object_key"], "version": tools[0]["version"]}]
                else:
                    need(snapshot["tool_snapshots"] == [], "Consumer received undeclared tool data")
                    direct = []
                need(result["direct_reads"] == direct, "Direct read references differ")
                versions = {}
                for ref in direct + [ref for parent in parents for ref in parent["effective_read_set"]]:
                    need(ref["object_key"] not in versions or versions[ref["object_key"]] == ref["version"], "Mixed source versions")
                    versions[ref["object_key"]] = ref["version"]
                need(result["effective_read_set"] == [{"object_key": key, "version": value} for key, value in sorted(versions.items())],
                     "Inherited source references differ")
                if result["result_id"] not in initial_ids:
                    need(not expected_invalid.intersection(result["parent_result_ids"]), "Replay consumed invalidated work")
            if fresh:
                need([result["step_id"] for result in fresh] == replay_steps
                     and all(result["attempt_no"] == 2 and result["execution_status"] == "success" for result in fresh),
                     "Actual rerun steps or attempt numbers differ")
                need(set(adopted) == set(STEPS) and not expected_invalid.intersection(adopted.values()),
                     "Final execution has an incomplete or invalid ancestor chain")
                sources = {obj["object_key"]: obj for obj in final["source_objects"]}
                for step in STEPS[:3]:
                    result = byid[adopted[step]]
                    tool = result["input_snapshot"]["tool_snapshots"][0]
                    need(tool == sources[tool["object_key"]] and result["payload"] == tool["payload"], "Adopted query is stale or incorrect")
                need(report["final_result_ids"] == adopted, "Final selection differs from actual committed ancestry")
            else:
                need(report["final_result_ids"] == {}, "Conflict report invented a final selection")

        def effects():
            active = [effect for effect in final["effects"] if effect["state"] == "applied"]
            need(len(active) == 1 and active[0]["effect_id"] not in old_effects, "Unresolved original effect or missing new write")
            old = next(effect for effect in final["effects"] if effect["effect_id"] in old_effects)
            original = frozen["effects"][0]
            need({key: value for key, value in old.items() if key not in ("state", "compensation_attempts")} ==
                 {key: value for key, value in original.items() if key not in ("state", "compensation_attempts")}, "Receipt core was rewritten")
            need(old["state"] == "compensated" and len(old["compensation_attempts"]) == 1
                 and old["compensation_attempts"][0]["status"] == "compensated", "Old write was not compensated")
            compensations = [event for event in final["event_log"] if event["action"] == "compensate_group"]
            need(len(compensations) == 1, "Missing or repeated actual compensation")
            compensation = compensations[0]
            expected = [{**target["before"], "version": target["after"]["version"] + 1,
                         "last_writer_id": compensation["actor_id"]} for target in old["targets"]]
            need(compensation["record_ids"] == [old["effect_id"]] and compensation["after_objects"] == expected
                 and compensation["before_objects"] == [target["after"] for target in old["targets"]]
                 and compensation["actor_type"] == "recovery" and compensation["actor_id"] == report["recovery_id"],
                 "Compensation did not restore the before-values with new versions")
            need(old["compensation_attempts"][0]["recovery_id"] == compensation["actor_id"]
                 and old["compensation_attempts"][0]["conflicts"] == []
                 and old["compensation_attempts"][0]["restored_versions"] ==
                     [{"object_key": obj["object_key"], "version": obj["version"]} for obj in expected],
                 "Compensation projection differs from the raw undo event")
            need([target["before"] for target in active[0]["targets"]] == expected, "Replay did not start from the compensated tombstones")
            outputs = {obj["object_key"]: obj for obj in final["output_objects"]}
            for effect in final["effects"]:
                owner = byid[effect["owner_result_id"]]
                need(owner["step_id"] == "execute" and owner["execution_status"] == "success"
                     and owner["effect_ids"] == [effect["effect_id"]]
                     and effect["source_read_set"] == owner["effective_read_set"]
                     and effect["committed_at"] == owner["finished_at"], "Receipt differs from owning execution")
                keys = list(output_keys(run_id))
                need([target["object_key"] for target in effect["targets"]] == keys, "Wrong write group")
                plan = byid[owner["parent_result_ids"][0]]
                need(effect["operation_digest"] == digest({"run_id": run_id, "step_id": "execute", "attempt_no": owner["attempt_no"],
                     "action": "save_job", "arguments": plan["payload"], "target_keys": keys}), "Wrong operation digest")
                event = next(event for event in final["event_log"] if event["action"] == "commit_group" and event["actor_id"] == owner["result_id"])
                need(event["record_ids"] == [owner["result_id"], effect["effect_id"]]
                     and event["before_objects"] == [target["before"] for target in effect["targets"]]
                     and event["after_objects"] == [target["after"] for target in effect["targets"]], "Commit event is not atomic with receipt")
                if effect["state"] == "applied":
                    need(all(target["after"] == outputs[target["object_key"]] for target in effect["targets"]), "Live objects differ from new receipt")
                    need(outputs[keys[0]]["payload"] == plan["payload"], "Saved configuration differs from actual plan")

        def external():
            need(final["source_objects"] == scene["source_objects"], "Recovery reverted or changed current source state")
            planned = {event["event_id"]: event for event in task["events"] if event["kind"] == "external_update"}
            actual = [event for event in final["event_log"] if event["action"] == "external_update"]
            need(len(actual) == len(planned) and {event["actor_id"] for event in actual} == set(planned), "External events are missing or duplicated")
            for event in actual:
                params = planned[event["actor_id"]]["parameters"]
                need(event["before_objects"][0]["object_key"] == params["object_key"]
                     and event["before_objects"][0]["version"] == params["expected_version"]
                     and event["after_objects"][0]["payload"] == params["new_payload"], "Applied external event differs from TaskSpec")

        def report_check():
            need(report["scene_digest"] == digest(scene) and scene["task_spec_digest"] == digest(task)
                 and policy in ("full_restart", "selective") and report["run_id"] == run_id, "Wrong scene or policy identity")
            need(report["reused_results"] == actual_reuse and report["reuse_candidates"] == candidates,
                 "Reported reuse differs from actual original identities in live execution ancestry")
            expected_count = len(actual_reuse) if report["engine_status"] == "completed" else 0
            need(report["cost"]["reused_result_count"] in (None, expected_count), "Reported verified reuse count differs")
            need(report["reexecutions"] == [{key: result[key] for key in ("step_id", "attempt_no", "result_id", "execution_status")} for result in fresh], "Reported replay differs from actual results")
            actual_compensations = [{"effect_id": effect["effect_id"], **{key: attempt[key] for key in
                ("status", "conflicts", "restored_versions")}} for effect in final["effects"] for attempt in effect["compensation_attempts"]]
            need(report["compensations"] == actual_compensations and report["final_objects"] == final["output_objects"], "Reported compensation or final state differs")
            need(report["cost"]["initial_steps"] == len(frozen["attempts"])
                 and report["cost"]["recovery_steps_started"] == len(final["attempts"]) - len(frozen["attempts"])
                 and report["cost"]["compensated_effect_groups"] == sum(item["status"] == "compensated" for item in actual_compensations),
                 "Reported step/effect counts differ from raw state")
            invalid = {item["result_id"] for item in report["invalidation_rounds"][0]["invalidated"]}
            need(len(report["invalidation_rounds"]) == 1 and invalid == expected_invalid
                 and report["invalidation_rounds"][0]["fault_closure"] == sorted(fault_closure)
                 and report["invalidation_rounds"][0]["stale_seeds"] == sorted(stale_seeds)
                 and report["invalidation_rounds"][0]["replay_steps"] == replay_steps,
                 "Reported recovery plan differs from independent fault/version analysis")

        def fault_delivery():
            planned = [event for event in task["events"] if event["kind"] == "corrupt_result"]
            applied = [event for event in scene["applied_events"] if event["kind"] == "corrupt_result"]
            need(len(planned) == len(applied) == 1, "Missing or repeated corruption event")
            event, saved = planned[0], applied[0]
            target = byid[saved["target_result_id"]]
            publication = next(item for item in frozen["event_log"] if item["actor_id"] == target["result_id"])
            need(saved["event_id"] == event["event_id"] and saved["event_digest"] == digest(event)
                 and target["payload"] == event["parameters"]["replacement_payload"]
                 and event["event_id"] in publication["record_ids"] and saved["event_seq"] == publication["event_seq"],
                 "Corruption was not atomically delivered with the target result")
            exposed = any(target["result_id"] in result["parent_result_ids"] for result in frozen["results"])
            need(report["fault_delivered"] is True and report["fault_exposed"] is exposed and exposed
                 and report["faulty_result_ids"] == [target["result_id"]]
                 and scene["notice"]["faulty_result_id"] == target["result_id"], "Known fault identity/exposure differs")

        def conflict_safety():
            need(not fresh and final["output_objects"] == frozen["output_objects"]
                 and final["source_objects"] == frozen["source_objects"]
                 and len(final["attempts"]) == len(frozen["attempts"]), "Conflict path modified objects or replayed")
            attempts = [attempt for effect in final["effects"] for attempt in effect["compensation_attempts"]]
            need(len(attempts) == 1 and attempts[0]["status"] == "compensation_conflict" and attempts[0]["conflicts"], "No recorded compensation conflict")
            need(len(final["effects"]) == 1 and final["effects"][0]["state"] == "applied", "Conflict falsely closed the old effect")
            objects = {obj["object_key"]: obj for obj in frozen["output_objects"]}
            expected_conflicts = [{"object_key": target["object_key"], "expected_version": target["after"]["version"],
                                  "current_version": objects[target["object_key"]]["version"],
                                  "expected_writer": target["after"]["last_writer_id"],
                                  "current_writer": objects[target["object_key"]]["last_writer_id"]}
                                 for target in frozen["effects"][0]["targets"]
                                 if objects[target["object_key"]] != target["after"]]
            need(expected_conflicts and attempts[0]["conflicts"] == expected_conflicts, "Conflict projection differs from actual target changes")
            need(not any(event["action"] == "compensate_group" for event in final["event_log"])
                 and sum(event["action"] == "compensation_conflict" for event in final["event_log"]) == 1,
                 "Conflict path partially compensated or did not record its refusal")

        add("S3_JOURNAL_AND_TERMINAL", journal, {"run_id": run_id, "events": len(final["event_log"])})
        add("O_TRACE_CONSISTENCY", trace, {"new_result_ids": [result["result_id"] for result in fresh]})
        add("O_EFFECT_ACCOUNTING", effects, {"effect_ids": [effect["effect_id"] for effect in final["effects"]]})
        add("O_EXTERNAL_UPDATES", external, {"object_keys": [obj["object_key"] for obj in scene["source_objects"]]})
        add("O_REUSE_VALIDITY", report_check, {"actual_adopted_reuse": actual_reuse, "reexecuted_steps": len(fresh)})
        add("S3_FAULT_DELIVERY", fault_delivery, {"faulty_result_id": scene["notice"]["faulty_result_id"]})
        if report["engine_status"] == "conflict":
            add("S3_CONFLICT_SAFETY", conflict_safety, {"preserved_output_keys": [obj["object_key"] for obj in frozen["output_objects"]]})
        return {"checked_at": utc_now(), "passed": all(check["passed"] for check in checks), "checks": checks,
                "snapshot_versions": [{"object_key": obj["object_key"], "version": obj["version"]}
                                      for obj in sorted(final["source_objects"] + final["output_objects"], key=lambda obj: obj["object_key"])],
                "verified_reused_results": actual_reuse if all(check["passed"] for check in checks)
                    and report["engine_status"] == "completed" else []}


class FullRestartOracle(RecoveryOracle):
    """Keep the S3 entry point restricted to its original full-restart scope."""

    def check(self, task, scene, frozen, final, report):
        if report["policy"] != "full_restart":
            raise ValueError("FullRestartOracle requires full_restart")
        return super().check(task, scene, frozen, final, report)
