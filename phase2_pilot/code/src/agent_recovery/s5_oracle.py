"""S5 verification reconstructed from raw journal and publication history.

Recovery plans are evidence to compare, never the source of the expected plan.
This module deliberately does not import the recovery engine or trace analysis.
An unsuccessful but safe stop remains a failed recovery; the separate safety
rules describe the narrower property that was actually checked.
"""

from __future__ import annotations

from copy import deepcopy

from .contracts import (
    PARENTS, STEPS, digest, output_keys, source_keys, utc_now,
    validate_object, validate_result,
)
from .oracle import BasicOracle
from .recovery_oracle import adopted_chain


def _need(condition, message):
    if not condition:
        raise ValueError(message)


def _descendants(nodes, seeds):
    _need(set(seeds) <= set(nodes), "Unknown successful fault or invalidation seed")
    found = set(seeds)
    while True:
        expanded = found | {rid for rid, row in nodes.items()
                            if found.intersection(row["parent_result_ids"])}
        if expanded == found:
            return found
        found = expanded


def _derive_round(nodes, selected, faulty, sources, old_reasons, policy):
    """Independent fixed-workflow derivation; no engine-produced collections."""
    _need(policy in ("selective", "full_restart"), "Unknown recovery policy")
    for step, rid in selected.items():
        _need(step in STEPS and rid in nodes and nodes[rid]["step_id"] == step,
              "Selected identity does not match its logical role")
        _need(all(parent in selected for parent in PARENTS[step])
              and nodes[rid]["parent_result_ids"] == [selected[parent] for parent in PARENTS[step]],
              "Round input selection mixes producer generations")
    reasons = {rid: set(why) for rid, why in old_reasons.items()}
    fault = _descendants(nodes, {faulty})
    for rid in fault:
        reasons.setdefault(rid, set()).add("known_fault" if rid == faulty else "depends_on_invalid")
    stale = set()
    for rid in selected.values():
        if rid in reasons:
            continue
        if any(ref["object_key"] not in sources or not sources[ref["object_key"]]["exists"]
               or sources[ref["object_key"]]["version"] != ref["version"]
               for ref in nodes[rid]["effective_read_set"]):
            stale.add(rid)
            reasons.setdefault(rid, set()).add("stale_source")
    for rid in _descendants(nodes, set(reasons)) if reasons else ():
        reasons.setdefault(rid, {"depends_on_invalid"})
    if policy == "full_restart":
        for rid in selected.values():
            reasons.setdefault(rid, set()).add("full_restart")
    return {
        "fault_closure": sorted(fault), "stale_seeds": sorted(stale),
        "invalidated": [{"result_id": rid, "reasons": sorted(why)}
                        for rid, why in sorted(reasons.items())],
        "replay_steps": [step for step in STEPS if step not in selected or selected[step] in reasons],
        "reuse_candidates": sorted(rid for rid in selected.values() if rid not in reasons),
    }


class S5RecoveryOracle:
    """Check one recovery, including bounded source-staleness retry rounds."""

    def check(self, task, scene, frozen_snapshot, final_snapshot, report):
        frozen, final = frozen_snapshot, final_snapshot
        checks = list(BasicOracle().check("final", task, final)["checks"])
        initial_ids = {row["result_id"] for row in frozen["results"]}
        byid = {row["result_id"]: row for row in final["results"]}
        fresh = [row for row in final["results"] if row["result_id"] not in initial_ids]
        old_effect_ids = {row["effect_id"] for row in frozen["effects"]}
        run_id, policy = scene["run_id"], report["policy"]
        events = final["event_log"]
        publications = {event["actor_id"]: event for event in events
                        if event["action"] in ("publish_result", "commit_group")}
        markers = [event for event in events if event["action"] == "begin_recovery_round"]
        reconstructed = {"rounds": [], "invalid": set(), "candidates": []}
        try:
            adopted = adopted_chain(final, initial_ids)
            adoption_error = None
        except (KeyError, TypeError, ValueError) as exc:
            adopted, adoption_error = {}, str(exc)
        actual_reuse = sorted(initial_ids.intersection(adopted.values()))

        def add(rule_id, verifier, evidence=None):
            try:
                verifier()
                passed, error = True, None
            except (KeyError, IndexError, TypeError, ValueError, StopIteration) as exc:
                passed, error = False, str(exc)
            checks.append({"rule_id": rule_id, "passed": passed,
                           "evidence": {**(evidence or {}), "error": error}})

        def journal():
            _need(events[:len(frozen["event_log"])] == frozen["event_log"], "Frozen journal prefix was changed")
            state = {obj["object_key"]: deepcopy(obj) for obj in task["initial_objects"]}
            previous = 0
            for event in events:
                _need(event["event_seq"] > previous, "Journal sequence does not increase")
                previous = event["event_seq"]
                before, after = event["before_objects"], event["after_objects"]
                _need(len(before) == len(after), "Partial mutation group")
                if before:
                    _need(event["action"] in ("external_update", "commit_group", "compensate_group"),
                          "Undeclared object mutation")
                    _need(len(before) == (1 if event["action"] == "external_update" else 2), "Wrong mutation group size")
                for old, new in zip(before, after):
                    validate_object(old)
                    validate_object(new)
                    key = old["object_key"]
                    current = state.get(key, {"object_key": key, "exists": False, "payload": None,
                                              "version": 0, "last_writer_id": None})
                    _need(old == current and new["object_key"] == key
                          and new["version"] == old["version"] + 1
                          and new["last_writer_id"] == event["actor_id"],
                          "Journal before-image, version or writer is wrong")
                    state[key] = new
            actual = final["source_objects"] + final["output_objects"]
            _need(len(actual) == len(state) and {obj["object_key"]: obj for obj in actual} == state,
                  "Final objects differ from journal reconstruction")
            _need(not any(row["status"] == "active" for row in final["attempts"]), "Active attempt survived the stop")
            _need(final["run_state"] in ("terminal", "uncertain"), "Run is neither terminal nor safely fenced")

        def rounds():
            _need(0 < len(markers) <= min(2, task["execution_settings"]["max_recovery_rounds"]),
                  "Recovery round count is absent or exceeds the declared bound")
            _need(len(report["invalidation_rounds"]) == len(markers), "Report omitted or invented a recovery round")
            _need(all(marker["actor_type"] == "recovery" and marker["actor_id"] == report["recovery_id"]
                      and marker["before_objects"] == marker["after_objects"] == [] for marker in markers),
                  "Round marker has a different owner or mutates objects")
            selected = {row["step_id"]: row["result_id"] for row in frozen["results"]
                        if row["execution_status"] == "success"}
            prior_reasons = {}
            status_by_seq = {}
            for status in final["result_status_events"]:
                _need(status["validity"] == "invalidated", "Historical invalidation was revived")
                status_by_seq.setdefault(status["event_seq"], []).append(status)
            seen_status_keys = set()
            for index, marker in enumerate(markers):
                sequence = marker["event_seq"]
                end_sequence = markers[index + 1]["event_seq"] if index + 1 < len(markers) else float("inf")
                _need(marker["record_ids"] == [selected[step] for step in STEPS if step in selected],
                      "Round marker does not contain the independently reconstructed selection")
                nodes = {rid: row for rid, row in byid.items() if row["execution_status"] == "success"
                         and publications[rid]["event_seq"] < sequence}
                sources = {obj["object_key"]: obj for obj in task["initial_objects"]}
                for event in events:
                    if event["event_seq"] >= sequence:
                        break
                    for obj in event["after_objects"]:
                        if obj["object_key"] in sources:
                            sources[obj["object_key"]] = obj
                expected = _derive_round(nodes, selected, scene["notice"]["faulty_result_id"],
                                         sources, prior_reasons, policy)
                expected_report = {"round_no": index + 1, **{key: expected[key] for key in
                    ("fault_closure", "stale_seeds", "invalidated", "replay_steps")}}
                _need(report["invalidation_rounds"][index] == expected_report,
                      "Reported round differs from independent historical fault/version analysis")
                invalid = {row["result_id"] for row in expected["invalidated"]}
                expected_reasons = {row["result_id"]: row["reasons"] for row in expected["invalidated"]}
                # New reasons may append a monotonic event for an already
                # invalid result. An exact duplicate is not a new transition.
                additions = {rid for rid, why in expected_reasons.items()
                             if not set(why) <= prior_reasons.get(rid, set())}
                actual_statuses = [status for seq, statuses in status_by_seq.items()
                                   if sequence < seq < end_sequence for status in statuses]
                _need({status["result_id"] for status in actual_statuses} == additions
                      and len(actual_statuses) == len(additions), "Raw invalidation set is missing, extra or repeated")
                for status in actual_statuses:
                    event = next(event for event in events if event["event_seq"] == status["event_seq"])
                    status_key = (status["event_seq"], status["result_id"])
                    _need(status_key not in seen_status_keys
                          and status["reasons"] == expected_reasons[status["result_id"]]
                          and event["action"] == "invalidate_results"
                          and event["actor_id"] == report["recovery_id"]
                          and status["result_id"] in event["record_ids"], "Invalidation lacks matching journal evidence")
                    seen_status_keys.add(status_key)
                segment = [row for row in fresh if sequence < publications[row["result_id"]]["event_seq"] < end_sequence]
                _need([row["step_id"] for row in segment] == expected["replay_steps"][:len(segment)],
                      "Actual round steps are not a prefix of the derived replay order")
                failures = [row for row in segment if row["execution_status"] != "success"]
                _need(not failures or failures == segment[-1:], "Recovery continued after a failed attempt in one round")
                if index + 1 < len(markers):
                    _need(len(failures) == 1 and failures[0]["step_id"] == "execute"
                          and failures[0]["execution_status"] == "stale_input"
                          and failures[0]["error"]["code"] == "STALE_SOURCE"
                          and failures[0]["effect_ids"] == [], "Another round began without a source-stale commit refusal")
                selected = {step: rid for step, rid in selected.items() if rid not in invalid}
                for result in segment:
                    if result["execution_status"] == "success":
                        selected[result["step_id"]] = result["result_id"]
                reconstructed["rounds"].append(expected_report)
                reconstructed["candidates"] = expected["reuse_candidates"]
                # Historical events stay immutable; an additional reason is
                # represented by a new event with the cumulative reason set.
                for status in actual_statuses:
                    prior_reasons[status["result_id"]] = set(status["reasons"])
                reconstructed["invalid"] = invalid
            _need(seen_status_keys == {(status["event_seq"], status["result_id"])
                                      for status in final["result_status_events"]},
                  "Invalidation was recorded outside a recovery round")
            _need(all(publications[row["result_id"]]["event_seq"] > markers[0]["event_seq"] for row in fresh),
                  "Replay was published before the first recovery round")
            if report["engine_status"] == "completed":
                last = reconstructed["rounds"][-1]
                last_segment = [row for row in fresh if publications[row["result_id"]]["event_seq"] > markers[-1]["event_seq"]]
                _need([row["step_id"] for row in last_segment] == last["replay_steps"]
                      and all(row["execution_status"] == "success" for row in last_segment),
                      "Engine completed before the derived round finished")

        def trace():
            _need(final["results"][:len(frozen["results"])] == frozen["results"]
                  and final["attempts"][:len(frozen["attempts"])] == frozen["attempts"], "Original attempts or results were changed")
            publication_events = [event for event in events if event["action"] in ("publish_result", "commit_group")]
            _need(len(byid) == len(final["results"]) == len(publication_events)
                  and set(publications) == set(byid)
                  and all(event["actor_type"] == "step" for event in publication_events), "Publication/result identities differ")
            attempts = {row["result_id"]: row for row in final["attempts"]}
            _need(len(attempts) == len(final["attempts"]), "Duplicate actual attempt identity")
            counts = {step: 0 for step in STEPS}
            for attempt in final["attempts"]:
                counts[attempt["step_id"]] += 1
                _need(attempt["attempt_no"] == counts[attempt["step_id"]], "Logical attempt counter is not contiguous")
                if attempt["result_id"] not in byid:
                    _need(attempt["status"] == "uncertain" and final["run_state"] == "uncertain",
                          "An attempt has neither a saved result nor an uncertainty fence")
            for result in final["results"]:
                validate_result(result)
                attempt = attempts[result["result_id"]]
                _need(attempt["status"] == "closed" and all(attempt[key] == result[key] for key in
                      ("run_id", "step_id", "attempt_no", "started_at")), "Attempt differs from its result")
                _need(result["run_id"] == run_id and result["model_calls"] == [], "Foreign run or real model call")
                stale_submission = result["execution_status"] == "stale_input"
                if result["execution_status"] != "success":
                    _need(result["effect_ids"] == [], "Failed result owns a write")
                    if not stale_submission:
                        # A tool/render failure can precede input capture.
                        continue
                    _need(result["step_id"] == "execute" and result["error"]["code"] == "STALE_SOURCE",
                          "Stale-input result does not identify a source-stale execution")
                snapshot, step = result["input_snapshot"], result["step_id"]
                _need(snapshot["request"] == task["request"], "Delivered request was changed")
                parents = [byid[rid] for rid in result["parent_result_ids"]]
                _need(tuple(parent["step_id"] for parent in parents) == PARENTS[step]
                      and all(parent["execution_status"] == "success" for parent in parents)
                      and snapshot["parents"] == [{"result_id": parent["result_id"], "payload": parent["payload"]}
                                                   for parent in parents], "Delivered parent identities or values differ")
                sequence = publications[result["result_id"]]["event_seq"]
                _need(all(publications[parent["result_id"]]["event_seq"] < sequence for parent in parents),
                      "Consumer was published before its producer")
                invalid_at_input = {status["result_id"] for status in final["result_status_events"]
                                    if status["event_seq"] < sequence}
                _need(not invalid_at_input.intersection(result["parent_result_ids"]), "Replay consumed an already invalidated parent")
                if step in STEPS[:3]:
                    tools = snapshot["tool_snapshots"]
                    _need(len(tools) == 1 and tools[0]["exists"]
                          and tools[0]["object_key"] == dict(zip(STEPS[:3], source_keys(task["request"])))[step],
                          "Query did not capture its declared source")
                    authoritative = next(obj for obj in task["initial_objects"] if obj["object_key"] == tools[0]["object_key"])
                    for event in events:
                        if event["event_seq"] >= sequence:
                            break
                        for obj in event["after_objects"]:
                            if obj["object_key"] == tools[0]["object_key"]:
                                authoritative = obj
                    _need(tools[0] == authoritative, "Captured query source differs from journal history")
                    direct = [{"object_key": tools[0]["object_key"], "version": tools[0]["version"]}]
                else:
                    _need(snapshot["tool_snapshots"] == [], "Consumer captured undeclared tools")
                    direct = []
                _need(result["direct_reads"] == direct, "Direct source references differ from captured tools")
                inherited = {}
                for ref in direct + [ref for parent in parents for ref in parent["effective_read_set"]]:
                    _need(ref["object_key"] not in inherited or inherited[ref["object_key"]] == ref["version"],
                          "Consumer input contains inconsistent source versions")
                    inherited[ref["object_key"]] = ref["version"]
                _need(result["effective_read_set"] == [{"object_key": key, "version": version}
                      for key, version in sorted(inherited.items())], "Inherited source set was altered")
                if stale_submission:
                    # A diagnostic error code cannot establish why another
                    # round was necessary. Reconstruct the source state at
                    # the actual failed publication and compare the reads
                    # inherited from its real plan, exactly as recorded.
                    current_sources = {obj["object_key"]: obj for obj in task["initial_objects"]}
                    for event in events:
                        if event["event_seq"] >= sequence:
                            break
                        for obj in event["after_objects"]:
                            if obj["object_key"] in current_sources:
                                current_sources[obj["object_key"]] = obj
                    _need(any(key not in current_sources or not current_sources[key]["exists"]
                              or current_sources[key]["version"] != version
                              for key, version in inherited.items()),
                          "Source-stale refusal has no actual source-version or existence mismatch")
                    publication = publications[result["result_id"]]
                    _need(publication["action"] == "publish_result"
                          and publication["before_objects"] == publication["after_objects"] == [],
                          "Source-stale refusal partially mutated the output group")
            _need(adoption_error is None, adoption_error)
            if report["engine_status"] == "completed":
                _need(set(adopted) == set(STEPS) and not reconstructed["invalid"].intersection(adopted.values()),
                      "Final adopted execution is incomplete or invalidated")
                sources = {obj["object_key"]: obj for obj in final["source_objects"]}
                for step in STEPS[:3]:
                    query = byid[adopted[step]]
                    tool = query["input_snapshot"]["tool_snapshots"][0]
                    _need(tool == sources[tool["object_key"]] and query["payload"] == tool["payload"],
                          "Final adopted query is stale or incorrect")
                _need(report["final_result_ids"] == adopted, "Final report selection differs from actual live receipt ancestry")

        def effects():
            outputs = {obj["object_key"]: obj for obj in final["output_objects"]}
            active = [effect for effect in final["effects"] if effect["state"] == "applied"]
            _need(len(active) == 1 and active[0]["effect_id"] not in old_effect_ids,
                  "Original effect remains active or no unique new effect exists")
            compensation_events = [event for event in events if event["action"] == "compensate_group"]
            _need(len(compensation_events) == len(old_effect_ids), "Old write was compensated zero or multiple times")
            for original in frozen["effects"]:
                old = next(effect for effect in final["effects"] if effect["effect_id"] == original["effect_id"])
                core = lambda row: {key: value for key, value in row.items() if key not in ("state", "compensation_attempts")}
                _need(core(old) == core(original) and old["state"] == "compensated"
                      and len(old["compensation_attempts"]) == 1
                      and old["compensation_attempts"][0]["status"] == "compensated", "Original receipt changed or was not compensated exactly once")
                undo = next(event for event in compensation_events if event["record_ids"] == [old["effect_id"]])
                restored = [{**target["before"], "version": target["after"]["version"] + 1,
                             "last_writer_id": report["recovery_id"]} for target in old["targets"]]
                _need(undo["actor_type"] == "recovery" and undo["actor_id"] == report["recovery_id"]
                      and undo["before_objects"] == [target["after"] for target in old["targets"]]
                      and undo["after_objects"] == restored, "Compensation did not restore the full group with new versions")
                attempt = old["compensation_attempts"][0]
                _need(attempt["recovery_id"] == report["recovery_id"] and attempt["conflicts"] == []
                      and attempt["restored_versions"] == [{"object_key": obj["object_key"], "version": obj["version"]}
                                                            for obj in restored], "Compensation projection differs from raw undo")
                _need([target["before"] for target in active[0]["targets"]] == restored,
                      "New execution did not start from the once-compensated tombstones")
            for effect in final["effects"]:
                owner = byid[effect["owner_result_id"]]
                _need(owner["step_id"] == "execute" and owner["execution_status"] == "success"
                      and owner["effect_ids"] == [effect["effect_id"]]
                      and owner["payload"]["effect_id"] == effect["effect_id"]
                      and effect["source_read_set"] == owner["effective_read_set"]
                      and effect["committed_at"] == owner["finished_at"], "Receipt differs from its owning execution")
                keys = list(output_keys(run_id))
                _need([target["object_key"] for target in effect["targets"]] == keys, "Receipt has different logical output keys")
                plan = byid[owner["parent_result_ids"][0]]
                command = {"run_id": run_id, "step_id": "execute", "attempt_no": owner["attempt_no"],
                           "action": "save_job", "arguments": plan["payload"], "target_keys": keys}
                _need(effect["operation_digest"] == digest(command), "Receipt operation digest differs from the real plan")
                event = publications[owner["result_id"]]
                _need(event["action"] == "commit_group" and event["record_ids"] == [owner["result_id"], effect["effect_id"]]
                      and event["before_objects"] == [target["before"] for target in effect["targets"]]
                      and event["after_objects"] == [target["after"] for target in effect["targets"]], "Objects, receipt and result were not published together")
                if effect["state"] == "applied":
                    _need(all(target["after"] == outputs[target["object_key"]] for target in effect["targets"])
                          and outputs[keys[0]]["payload"] == plan["payload"], "Live objects differ from the new receipt or actual plan")
            # A stale attempt has no commit event; version two survives until
            # the next successful commit, which alone creates version three.
            for result in fresh:
                if result["execution_status"] == "stale_input":
                    _need(result["effect_ids"] == [] and publications[result["result_id"]]["action"] == "publish_result"
                          and publications[result["result_id"]]["before_objects"] ==
                              publications[result["result_id"]]["after_objects"] == [], "Stale commit partially mutated the output group")

        def external():
            planned = {event["event_id"]: event for event in task["events"] if event["kind"] == "external_update"}
            actual = [event for event in events if event["action"] == "external_update"]
            _need(len(actual) == len({event["actor_id"] for event in actual})
                  and {event["actor_id"] for event in actual} <= set(planned), "External update was duplicated or undeclared")
            # Events scheduled after an early stop need not have fired. Every
            # event whose declared boundary was reached must be present.
            reached = set()
            for event_id, event in planned.items():
                trigger = event["trigger"]
                matching = [row for row in final["results"] if row["step_id"] == trigger["step_id"]
                            and row["attempt_no"] == trigger["attempt_no"]]
                if trigger["boundary"] == "after_commit" and any(row["execution_status"] == "success" for row in matching):
                    reached.add(event_id)
                elif trigger["boundary"] == "before_executor_commit" and any(row["step_id"] == "execute"
                        and row["input_snapshot"] is not None and row["execution_status"] in ("success", "stale_input") for row in matching):
                    reached.add(event_id)
            _need(reached <= {event["actor_id"] for event in actual}, "A reached external update was skipped")
            for event in actual:
                spec = planned[event["actor_id"]]
                params, trigger = spec["parameters"], spec["trigger"]
                _need(event["before_objects"][0]["object_key"] == params["object_key"]
                      and event["before_objects"][0]["version"] == params["expected_version"]
                      and event["after_objects"][0]["payload"] == params["new_payload"], "Applied external update differs from TaskSpec")
                matching = [row for row in final["results"] if row["step_id"] == trigger["step_id"]
                            and row["attempt_no"] == trigger["attempt_no"]]
                if matching:
                    publication = publications[matching[0]["result_id"]]["event_seq"]
                    _need((event["event_seq"] > publication) if trigger["boundary"] == "after_commit"
                          else (event["event_seq"] < publication), "External update occurred on the wrong side of its declared boundary")

        def report_check():
            _need(report["scene_digest"] == digest(scene) and scene["task_spec_digest"] == digest(task)
                  and report["run_id"] == run_id and report["notice_id"] == scene["notice"]["notice_id"], "Scene/task/run/notice identity differs")
            _need(report["reuse_candidates"] == reconstructed["candidates"], "Reported candidates differ from the latest independently derived round")
            expected_reuse = actual_reuse if report["engine_status"] == "completed" else []
            _need(report["reused_results"] == expected_reuse
                  and report["cost"]["reused_result_count"] in (None, len(expected_reuse)), "Reported reuse is not original identity adoption")
            actual_rows = [{key: row[key] for key in ("step_id", "attempt_no", "result_id", "execution_status")} for row in fresh]
            _need(report["reexecutions"] == actual_rows, "Reported replay results differ from actual saved publications")
            actual_compensations = [{"effect_id": effect["effect_id"], **{key: attempt[key] for key in
                ("status", "conflicts", "restored_versions")}} for effect in final["effects"] for attempt in effect["compensation_attempts"]]
            _need(report["compensations"] == actual_compensations and report["final_objects"] == final["output_objects"],
                  "Reported compensation or final objects differ from raw state")
            _need(report["cost"]["initial_steps"] == len(frozen["attempts"])
                  and report["cost"]["recovery_steps_started"] == len(final["attempts"]) - len(frozen["attempts"])
                  and report["cost"]["recovery_model_calls"] == sum(len(row["model_calls"]) for row in fresh)
                  and report["cost"]["compensated_effect_groups"] == sum(row["status"] == "compensated" for row in actual_compensations),
                  "Reported attempt, model or compensation counts differ")

        def fault_delivery():
            planned = [event for event in task["events"] if event["kind"] == "corrupt_result"]
            applied = [event for event in scene["applied_events"] if event["kind"] == "corrupt_result"]
            _need(len(planned) == len(applied) == 1, "Missing or duplicated scripted corruption")
            spec, saved = planned[0], applied[0]
            target = byid[saved["target_result_id"]]
            publication = publications[target["result_id"]]
            _need(saved["event_id"] == spec["event_id"] and saved["event_digest"] == digest(spec)
                  and target["payload"] == spec["parameters"]["replacement_payload"]
                  and spec["event_id"] in publication["record_ids"]
                  and saved["event_seq"] == publication["event_seq"], "Corruption does not match its atomic delivery evidence")
            exposed = any(target["result_id"] in row["parent_result_ids"] for row in frozen["results"])
            _need(report["fault_delivered"] is True and report["fault_exposed"] is exposed and exposed
                  and report["faulty_result_ids"] == [target["result_id"]]
                  and scene["notice"]["faulty_result_id"] == target["result_id"], "Fault identity or actual exposure differs")

        def conflict_safety():
            _need(not fresh and final["output_objects"] == frozen["output_objects"]
                  and final["source_objects"] == frozen["source_objects"]
                  and final["attempts"] == frozen["attempts"], "Conflict path overwrote objects or began replay")
            attempts = [attempt for effect in final["effects"] for attempt in effect["compensation_attempts"]]
            _need(len(attempts) == 1 and attempts[0]["status"] == "compensation_conflict"
                  and len(final["effects"]) == len(frozen["effects"]) == 1
                  and final["effects"][0]["state"] == "applied", "Conflict path hid or closed the original effect")
            objects = {obj["object_key"]: obj for obj in frozen["output_objects"]}
            conflicts = [{"object_key": target["object_key"], "expected_version": target["after"]["version"],
                          "current_version": objects[target["object_key"]]["version"],
                          "expected_writer": target["after"]["last_writer_id"],
                          "current_writer": objects[target["object_key"]]["last_writer_id"]}
                         for target in frozen["effects"][0]["targets"] if objects[target["object_key"]] != target["after"]]
            _need(conflicts and attempts[0]["conflicts"] == conflicts
                  and not any(event["action"] == "compensate_group" for event in events)
                  and sum(event["action"] == "compensation_conflict" for event in events) == 1,
                  "Conflict report differs from the actual changed targets or partial compensation occurred")

        def uncertain_safety():
            _need(report["failure"] and report["failure"]["code"] == "UNKNOWN_COMMIT_OUTCOME"
                  and report["engine_status"] != "completed" and final["run_state"] == "uncertain",
                  "Uncertain submission was not fenced and reported as a failure")
            _need(next(row for row in checks if row["rule_id"] == "S5_JOURNAL_AND_STOP")["passed"],
                  "Uncertainty safety requires a consistent raw object journal")
            _need(not any(row["status"] == "active" for row in final["attempts"]), "Uncertain attempt is still active")
            uncertain = [row for row in final["attempts"] if row["status"] == "uncertain"]
            _need(len(uncertain) <= 1 and not report["reused_results"], "Uncertain path invented reuse or multiple pending attempts")
            fresh_executions = [row for row in final["attempts"][len(frozen["attempts"]):] if row["step_id"] == "execute"]
            _need(fresh_executions and fresh_executions[-1] == final["attempts"][-1], "Recovery replayed after an uncertain execution")
            last = fresh_executions[-1]
            failure = report["failure"]
            _need(failure.get("operation_id") and failure.get("result_id") == last["result_id"],
                  "Unknown submission report does not identify the actual final execute attempt")
            fences = [event for event in events if event["action"] == "fence_uncertain_recovery"]
            _need(len(fences) == 1 and fences[0] == events[-1]
                  and fences[0]["actor_type"] == "recovery" and fences[0]["actor_id"] == report["recovery_id"]
                  and fences[0]["before_objects"] == fences[0]["after_objects"] == []
                  and len(fences[0]["record_ids"]) == 2
                  and set(fences[0]["record_ids"]) == {failure["result_id"], failure["operation_id"]},
                  "Unknown operation has no matching immutable fence or work continued after fencing")
            new_effects = [effect for effect in final["effects"] if effect["effect_id"] not in old_effect_ids]
            _need(len(new_effects) <= 1, "Uncertain execution was submitted more than once")
            if new_effects:
                effect = new_effects[0]
                _need(effect["operation_id"] == failure["operation_id"]
                      and effect["owner_result_id"] == last["result_id"]
                      and last["status"] == "closed" and not uncertain,
                      "Already committed unknown operation has different ownership")
                effects()
            else:
                _need(uncertain == [last] and last["result_id"] not in byid,
                      "Absent unknown operation invented a completed result")
                undos = [event for event in events if event["action"] == "compensate_group"]
                _need(len(undos) == 1 and final["output_objects"] == undos[0]["after_objects"]
                      and all(effect["state"] == "compensated" for effect in final["effects"]),
                      "Absent unknown operation changed the once-compensated output group")

        def budget_safety():
            _need(report["engine_status"] == "budget_exceeded"
                  and report["failure"] and report["failure"]["code"] == "RECOVERY_ROUND_LIMIT"
                  and final["run_state"] == "terminal", "Round limit did not produce an explicit failed terminal state")
            _need(next(row for row in checks if row["rule_id"] == "S5_JOURNAL_AND_STOP")["passed"]
                  and next(row for row in checks if row["rule_id"] == "S5_INDEPENDENT_ROUNDS")["passed"],
                  "Budget safety requires consistent journal and independently verified rounds")
            _need(len(markers) == min(2, task["execution_settings"]["max_recovery_rounds"])
                  and fresh and fresh[-1]["step_id"] == "execute"
                  and fresh[-1]["execution_status"] == "stale_input"
                  and fresh[-1]["error"]["code"] == "STALE_SOURCE" and fresh[-1]["effect_ids"] == [],
                  "Round limit did not stop immediately after the final source-stale execute")
            _need(not report["final_result_ids"] and not report["reused_results"]
                  and not any(effect["effect_id"] not in old_effect_ids for effect in final["effects"]),
                  "Budget stop invented an adopted final chain or new committed operation")
            undos = [event for event in events if event["action"] == "compensate_group"]
            _need(len(undos) == 1 and final["output_objects"] == undos[0]["after_objects"]
                  and all(effect["state"] == "compensated" for effect in final["effects"]),
                  "Budget stop changed the once-compensated output group")

        add("S5_JOURNAL_AND_STOP", journal, {"events": len(events), "run_state": final["run_state"]})
        add("S5_INDEPENDENT_ROUNDS", rounds, {"actual_rounds": len(markers)})
        add("O_TRACE_CONSISTENCY", trace, {"new_result_ids": [row["result_id"] for row in fresh]})
        add("O_EFFECT_ACCOUNTING", effects, {"effect_ids": [effect["effect_id"] for effect in final["effects"]]})
        add("O_EXTERNAL_UPDATES", external)
        add("O_REUSE_VALIDITY", report_check, {"actual_adopted_original_ids": actual_reuse})
        add("S5_FAULT_DELIVERY", fault_delivery)
        add("S5_ENGINE_SUCCESS", lambda: _need(report["engine_status"] == "completed"
            and final["run_state"] == "terminal", "Stopped recovery is not a successfully recovered task"))
        if report["engine_status"] == "conflict":
            add("S5_CONFLICT_SAFETY", conflict_safety)
        if report.get("failure") and report["failure"]["code"] == "UNKNOWN_COMMIT_OUTCOME":
            add("S5_UNCERTAIN_SAFETY", uncertain_safety)
        if report["engine_status"] == "budget_exceeded":
            add("S5_BUDGET_STOP_SAFETY", budget_safety)
        passed = all(row["passed"] for row in checks)
        return {"checked_at": utc_now(), "passed": passed, "checks": checks,
                "snapshot_versions": [{"object_key": obj["object_key"], "version": obj["version"]}
                                      for obj in sorted(final["source_objects"] + final["output_objects"], key=lambda obj: obj["object_key"])],
                "verified_reused_results": actual_reuse if passed and report["engine_status"] == "completed" else []}
