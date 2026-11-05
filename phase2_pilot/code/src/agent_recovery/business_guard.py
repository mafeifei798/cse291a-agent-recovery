"""Authoritative business admission for a model-proposed job write.

The guard does not repair or regenerate model output.  Its Store mixin hooks
the saved ancestry lookup that the existing commit already performs inside
BEGIN IMMEDIATE.  Validation, the guard record, failed-attempt publication and
any successful business write therefore share one transaction.
"""
from __future__ import annotations

from copy import deepcopy
import json

from .contracts import ContractError, canonical_json, require, source_keys, utc_now


GUARD_REVISION = "authoritative-precommit-business-v1"
READ_STEPS = ("read_metadata", "read_permission", "read_resources")


def evaluate_business(request, source_objects, chain, command):
    """Return exact differences against trusted state, retaining proposed values.

    ``chain`` contains the actual Executor ancestors, rather than every result
    ever produced in the run.  Lifecycle, command schema, source CAS and write
    preconditions remain the original Store's responsibility.
    """
    sources = {obj["object_key"]: obj for obj in source_objects}
    keys = source_keys(request)
    metadata, permission, resource = [sources[key]["payload"] for key in keys]
    n, batch = metadata["num_examples"], request["batch_size"]
    expected = {key: deepcopy(request[key]) for key in
                ("dataset_id", "purpose", "batch_size", "epochs")}
    expected.update(num_examples=n, steps=((n + batch - 1) // batch) * request["epochs"],
                    workers=min(request["requested_workers"], resource["max_workers"]),
                    permission_allowed=permission["allowed"])
    differences = []

    def compare(location, actual, truth):
        # JSON equality distinguishes booleans from integer values (True != 1).
        if canonical_json(actual) != canonical_json(truth):
            if isinstance(actual, dict) and isinstance(truth, dict):
                for key in sorted(set(actual) | set(truth)):
                    if key not in actual or key not in truth:
                        differences.append(dict(location=location + "." + key,
                            expected=deepcopy(truth.get(key)), actual=deepcopy(actual.get(key))))
                    else:
                        compare(location + "." + key, actual[key], truth[key])
            else:
                differences.append(dict(location=location, expected=deepcopy(truth), actual=deepcopy(actual)))

    for step, key in zip(READ_STEPS, keys):
        matches = [r for r in chain.values() if r["step_id"] == step]
        if len(matches) != 1:
            differences.append(dict(location=step + ".count", expected=1, actual=len(matches)))
            continue
        reader = matches[0]
        compare(step + ".payload", reader["payload"], sources[key]["payload"])
        compare(step + ".tool_snapshots", reader["input_snapshot"]["tool_snapshots"], [sources[key]])
        compare(step + ".direct_reads", reader["direct_reads"],
                [dict(object_key=key, version=sources[key]["version"])])
    # Even a reader/plan pair that consistently copied a wrong value must fail.
    plans = [r for r in chain.values() if r["step_id"] == "plan"]
    if len(plans) == 1:
        compare("plan.payload", plans[0]["payload"], expected)
    else:
        differences.append(dict(location="plan.count", expected=1, actual=len(plans)))
    compare("command.action", command.get("action"), "save_job")
    compare("command.arguments", command.get("arguments"), expected)
    compare("metadata.dataset_id", metadata["dataset_id"], request["dataset_id"])
    compare("permission.dataset_id", permission["dataset_id"], request["dataset_id"])
    compare("permission.purpose", permission["purpose"], request["purpose"])
    denied = permission["allowed"] is not True
    error = "PERMISSION_DENIED" if denied else ("BUSINESS_VALIDATION_FAILED" if differences else None)
    return dict(guard_revision=GUARD_REVISION, expected_config=expected, mismatches=differences,
                passed=not differences, allowed_to_commit=not denied and not differences, error_code=error)


class BusinessGuardMixin:
    """Install one atomic, policy-independent guard without altering the core."""

    def __init__(self, path):
        super().__init__(path)
        self._business_guard_context = None
        self.connection.execute("CREATE TABLE IF NOT EXISTS business_guard_checks "
                                "(result_id TEXT PRIMARY KEY, body TEXT NOT NULL)")

    def commit_execution(self, attempt_token, result, command, expected_outputs, operation_id):
        require(self._business_guard_context is None, "Nested guarded commit", "INTERNAL_ERROR")
        self._business_guard_context = dict(attempt_token=attempt_token, raw_candidate=deepcopy(result),
                                            raw_command=deepcopy(command), operation_id=operation_id)
        try:
            return super().commit_execution(attempt_token, result, command, expected_outputs, operation_id)
        finally:
            self._business_guard_context = None

    def _parent_chain(self, parent_ids, run_id):
        chain = super()._parent_chain(parent_ids, run_id)
        context = self._business_guard_context
        if context is None:
            return chain
        require(self.connection.in_transaction, "Business guard needs commit transaction", "INTERNAL_ERROR")
        run = self._run(run_id)
        request = json.loads(run["public_view"])["request"]
        sources = [json.loads(self.connection.execute("SELECT body FROM objects WHERE object_key=?",
                   (key,)).fetchone()[0]) for key in source_keys(request)]
        decision = evaluate_business(request, sources, chain, context["raw_command"])
        record = dict(schema_version="precommit-business-check-v1", **deepcopy(context),
            result_id=context["raw_candidate"]["result_id"], checked_at=utc_now(),
            source_objects=sources, **decision)
        self.connection.execute("INSERT INTO business_guard_checks VALUES(?,?)",
                                (record["result_id"], canonical_json(record)))
        if decision["error_code"]:
            message = ("Current authoritative permission denies this job" if
                       decision["error_code"] == "PERMISSION_DENIED" else
                       "Proposed job differs from authoritative data or business arithmetic")
            raise ContractError(decision["error_code"], message)
        return chain

    def snapshot_run(self, run_id=None):
        snapshot = super().snapshot_run(run_id)
        snapshot["business_guard_checks"] = [json.loads(row[0]) for row in
            self.connection.execute("SELECT body FROM business_guard_checks ORDER BY rowid")]
        return snapshot
