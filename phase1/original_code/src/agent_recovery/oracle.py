"""Independent S1 business checks over read-only snapshots.

Does not import ScriptedGateway, the graph algorithm or an expected report.
Effect compensation and recovery-validity checks are explicitly deferred.
"""

from __future__ import annotations

from .contracts import (
    BUSINESS_RULES, STEPS, ContractError, digest, exact_fields, output_keys, source_keys,
    validate_id, validate_object, validate_payload, validate_request, validate_result,
)


class BasicOracle:
    def check(self, stage: str, task: dict, snapshot: dict) -> dict:
        if stage not in ("initial", "final"):
            raise ValueError("stage must be initial or final")
        request = task["request"]
        validate_request(request)
        sources = {obj["object_key"]: obj for obj in snapshot["source_objects"] if obj["exists"]}
        metadata_key, permission_key, resource_key = source_keys(request)
        outputs = [obj for obj in snapshot["output_objects"] if obj["exists"]]
        configs = [obj for obj in outputs if obj["object_key"].startswith("job_config:")]
        drafts = [obj for obj in outputs if obj["object_key"].startswith("job_draft:")]
        run_ids = {result["run_id"] for result in snapshot["results"]}
        expected_keys = output_keys(next(iter(run_ids))) if len(run_ids) == 1 else (None, None)
        config = configs[0]["payload"] if len(configs) == 1 else {}
        checks = []
        structure_error = None
        try:
            for obj in snapshot["source_objects"] + snapshot["output_objects"]:
                validate_object(obj)
            for step, key in zip(
                ("read_metadata", "read_permission", "read_resources"),
                (metadata_key, permission_key, resource_key),
            ):
                if key in sources:
                    validate_payload(step, sources[key]["payload"])
            validate_payload("plan", config)
            for draft in drafts:
                # Dict equality alone treats True as 1 in nested draft configs.
                validate_payload("plan", draft["payload"].get("config"))
        except ContractError as exc:
            structure_error = str(exc)

        def add(rule_id, predicate, evidence):
            try:
                passed = structure_error is None and bool(predicate())
                error = structure_error
            except (KeyError, TypeError, ValueError, ZeroDivisionError) as exc:
                passed, error = False, type(exc).__name__
            checks.append({"rule_id": rule_id, "passed": passed,
                           "evidence": {**evidence, "malformed_input": error}})

        add("O_REQUEST_MATCH", lambda: all(config[k] == request[k] for k in
            ("dataset_id", "purpose", "batch_size", "epochs")),
            {"config_keys": [o["object_key"] for o in configs]})

        def check_metadata():
            n = sources[metadata_key]["payload"]["num_examples"]
            batch, epochs = request["batch_size"], request["epochs"]
            whole, remainder = divmod(n, batch)
            expected_steps = (whole + int(remainder != 0)) * epochs
            return sources[metadata_key]["payload"]["dataset_id"] == request["dataset_id"] \
                and config["num_examples"] == n and config["steps"] == expected_steps

        add("O_CURRENT_METADATA", check_metadata, {"source_key": metadata_key})
        add("O_CURRENT_PERMISSION", lambda:
            sources[permission_key]["payload"]["allowed"] is True
            and all(sources[permission_key]["payload"][key] == request[key]
                    for key in ("dataset_id", "purpose"))
            and config["permission_allowed"] is True, {"source_key": permission_key})
        add("O_CURRENT_RESOURCES", lambda:
            config["workers"] == min(request["requested_workers"],
                                     sources[resource_key]["payload"]["max_workers"]),
            {"source_key": resource_key})
        add("O_SINGLE_DRAFT", lambda:
            len(configs) == len(drafts) == 1 and len(outputs) == 2
            and configs[0]["object_key"] == expected_keys[0]
            and drafts[0]["object_key"] == expected_keys[1]
            and drafts[0]["payload"]["config_key"] == configs[0]["object_key"]
            and drafts[0]["payload"]["config"] == config
            and drafts[0]["payload"]["status"] == "draft",
            {"config_count": len(configs), "draft_count": len(drafts)})
        remaining = [rule for rule in task["oracle_rules"] if rule not in BUSINESS_RULES]
        return {"scope": "S1_business_checks_only", "stage": stage,
                "passed": all(item["passed"] for item in checks),
                "complete_recovery_verification": False, "checks": checks,
                "not_implemented_rules": remaining}


class NormalRunOracle:
    """Independent T01 checks over actual snapshots; not a recovery verifier."""

    def check(self, task: dict, snapshot: dict) -> dict:
        business = BasicOracle().check("initial", task, snapshot)
        checks = list(business["checks"])

        def add(rule_id, verifier):
            try:
                verifier()
                passed, error = True, None
            except (KeyError, IndexError, TypeError, ValueError, StopIteration) as exc:
                passed, error = False, str(exc)
            checks.append({"rule_id": rule_id, "passed": passed, "evidence": {"error": error}})

        def need(value, message):
            if not value:
                raise ValueError(message)

        def trace_check():
            results = snapshot["results"]
            need(len(results) == 5, "Normal run needs five actual results")
            bystep = {result["step_id"]: result for result in results}
            need(set(bystep) == set(STEPS), "Normal run is missing or duplicating a step")
            run_id = results[0]["run_id"]
            sources = {obj["object_key"]: obj for obj in snapshot["source_objects"]}
            reads = [{"object_key": key, "version": sources[key]["version"]}
                     for key in sorted(source_keys(task["request"]))]
            for step in STEPS:
                result = bystep[step]
                validate_result(result)
                need(result["run_id"] == run_id and result["attempt_no"] == 1
                     and result["execution_status"] == "success" and result["model_calls"] == [],
                     "Unexpected run, retry, failure or model call")
                actual = result["input_snapshot"]
                need(actual["request"] == task["request"], "Input request differs from TaskSpec")
                if step in STEPS[:3]:
                    source = sources[dict(zip(STEPS[:3], source_keys(task["request"])))[step]]
                    need(result["parent_result_ids"] == [] and actual["parents"] == []
                         and actual["tool_snapshots"] == [source] and result["payload"] == source["payload"],
                         "Query differs from actual source snapshot")
                    expected_reads = [{"object_key": source["object_key"], "version": source["version"]}]
                    need(result["direct_reads"] == result["effective_read_set"] == expected_reads,
                         "Query read references differ from its source")
                else:
                    producer_steps = STEPS[:3] if step == "plan" else ("plan",)
                    producers = [bystep[name] for name in producer_steps]
                    need(result["parent_result_ids"] == [parent["result_id"] for parent in producers]
                         and actual["parents"] == [{"result_id": parent["result_id"], "payload": parent["payload"]}
                                                   for parent in producers]
                         and actual["tool_snapshots"] == [] and result["direct_reads"] == []
                         and result["effective_read_set"] == reads,
                         "Consumer inputs or inherited sources differ from saved producers")
            config_key, draft_key = output_keys(run_id)
            outputs = {obj["object_key"]: obj for obj in snapshot["output_objects"]}
            need(bystep["plan"]["payload"] == outputs[config_key]["payload"], "Saved config differs from plan")
            execute = bystep["execute"]
            need(execute["payload"]["config_key"] == config_key
                 and execute["payload"]["draft_key"] == draft_key, "Executor output identity differs")

        def effect_check():
            need(len(snapshot["effects"]) == 1, "Normal run needs exactly one receipt")
            receipt = snapshot["effects"][0]
            exact_fields(receipt, {"schema_version", "effect_id", "operation_id", "operation_digest", "run_id",
                                  "owner_result_id", "step_id", "attempt_no", "source_read_set", "targets",
                                  "committed_at", "state", "compensation_attempts"}, "WriteReceipt")
            for key in ("effect_id", "operation_id", "run_id", "owner_result_id"):
                validate_id(receipt[key])
            execute = next(result for result in snapshot["results"] if result["result_id"] == receipt["owner_result_id"])
            plan = next(result for result in snapshot["results"] if result["result_id"] == execute["parent_result_ids"][0])
            need(receipt["schema_version"] == "1.1" and receipt["state"] == "applied"
                 and receipt["compensation_attempts"] == [] and receipt["run_id"] == execute["run_id"]
                 and receipt["step_id"] == execute["step_id"] == "execute"
                 and receipt["attempt_no"] == execute["attempt_no"]
                 and execute["effect_ids"] == [receipt["effect_id"]]
                 and execute["payload"]["effect_id"] == receipt["effect_id"]
                 and receipt["source_read_set"] == execute["effective_read_set"]
                 and receipt["committed_at"] == execute["finished_at"], "Receipt identity or lifecycle differs")
            keys = list(output_keys(execute["run_id"]))
            need([target["object_key"] for target in receipt["targets"]] == keys, "Receipt has wrong target group")
            outputs = {obj["object_key"]: obj for obj in snapshot["output_objects"]}
            for target in receipt["targets"]:
                before, after = target["before"], target["after"]
                validate_object(before)
                validate_object(after)
                need(before == {"object_key": target["object_key"], "exists": False,
                                "payload": None, "version": 0, "last_writer_id": None},
                     "Fresh normal run did not create from absent version zero")
                need(after == outputs[target["object_key"]] and after["exists"]
                     and after["version"] == 1 and after["last_writer_id"] == execute["result_id"],
                     "Receipt after-image differs from actual objects")
            command = {"run_id": execute["run_id"], "step_id": "execute", "attempt_no": execute["attempt_no"],
                       "action": "save_job", "arguments": plan["payload"], "target_keys": keys}
            need(receipt["operation_digest"] == digest(command), "Operation digest differs from actual plan")
            events = snapshot["event_log"]
            need(len(events) == 5 and [event["event_seq"] for event in events] ==
                 sorted({event["event_seq"] for event in events}), "Missing, duplicate or unordered publish events")
            commits = [event for event in events if event["action"] == "commit_group"]
            need(len(commits) == 1, "Normal run needs one atomic commit event")
            event = commits[0]
            need(event["actor_type"] == "step" and event["actor_id"] == execute["result_id"]
                 and event["record_ids"] == [execute["result_id"], receipt["effect_id"]]
                 and event["before_objects"] == [target["before"] for target in receipt["targets"]]
                 and event["after_objects"] == [target["after"] for target in receipt["targets"]],
                 "Atomic event does not bind objects, receipt and result")
            published = [event for event in events if event["action"] == "publish_result"]
            need(len(published) == 4 and {event["actor_id"] for event in published} ==
                 {result["result_id"] for result in snapshot["results"] if result["step_id"] != "execute"}
                 and all(item["actor_type"] == "step" and item["event_seq"] < event["event_seq"]
                         and item["record_ids"] == [item["actor_id"]] and item["before_objects"] ==
                         item["after_objects"] == [] for item in published),
                 "Non-writing events differ from results or occur after the commit")

        def final_state_check():
            results = snapshot["results"]
            need(snapshot["run_state"] == "terminal" and len(snapshot["attempts"]) == 5
                 and all(attempt["status"] == "closed" for attempt in snapshot["attempts"])
                 and {attempt["result_id"] for attempt in snapshot["attempts"]} ==
                     {result["result_id"] for result in results}, "Run or attempts are not closed consistently")
            need(snapshot["result_status_events"] == [] and snapshot["notices"] == [],
                 "Normal run unexpectedly has recovery state")

        def unchanged_sources():
            need(len(snapshot["source_objects"]) == 3 and
                 {obj["object_key"]: obj for obj in snapshot["source_objects"]} ==
                 {obj["object_key"]: obj for obj in task["initial_objects"]}, "Normal source state changed")

        add("O_TRACE_CONSISTENCY", trace_check)
        add("O_EFFECT_ACCOUNTING", effect_check)
        add("S2_CLOSED_RUN", final_state_check)
        add("S2_SOURCE_UNCHANGED", unchanged_sources)
        return {"scope": "S2_normal_workflow_only", "passed": all(row["passed"] for row in checks),
                "checks": checks, "complete_recovery_verification": False,
                "not_implemented_rules": ["O_REUSE_VALIDITY", "O_EXTERNAL_UPDATES"],
                "limitation": "Effect and trace checks cover normal creation only, not compensation or replay."}
