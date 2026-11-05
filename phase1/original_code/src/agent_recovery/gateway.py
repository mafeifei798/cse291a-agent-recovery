"""A deterministic, offline adapter. There is intentionally no real-model client."""

from copy import deepcopy

from .contracts import StageNotImplemented, require, validate_action, validate_payload


class ScriptedGateway:
    prompt_revision = "scripted-v1"
    model_call_count = 0

    def render(self, role: str, input_bundle: dict) -> list:
        return []

    def generate(self, step_id: str, messages: list, input_bundle: dict) -> dict:
        require(messages == [], "Scripted adapter expects no rendered model messages")
        if step_id in ("read_metadata", "read_permission", "read_resources"):
            require(len(input_bundle["tool_snapshots"]) == 1, "Query needs one source snapshot")
            payload = deepcopy(input_bundle["tool_snapshots"][0]["payload"])
        elif step_id == "plan":
            request = input_bundle["request"]
            require(len(input_bundle["parents"]) == 3, "Planner needs three actual parents")
            metadata, permission, resources = [p["payload"] for p in input_bundle["parents"]]
            n, batch = metadata["num_examples"], request["batch_size"]
            payload = {
                "dataset_id": request["dataset_id"], "purpose": request["purpose"],
                "batch_size": batch, "epochs": request["epochs"], "num_examples": n,
                "steps": ((n + batch - 1) // batch) * request["epochs"],
                "workers": min(request["requested_workers"], resources["max_workers"]),
                "permission_allowed": permission["allowed"],
            }
        elif step_id == "execute":
            require(len(input_bundle["parents"]) == 1, "Executor needs its actual plan")
            action = {"action": "save_job", "arguments": deepcopy(input_bundle["parents"][0]["payload"])}
            validate_action(action)
            return action
        else:
            raise StageNotImplemented("Unknown workflow step")
        validate_payload(step_id, payload)
        return payload
