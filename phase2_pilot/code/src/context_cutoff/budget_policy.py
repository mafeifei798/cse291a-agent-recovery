"""Versioned internal spending caps. A budget policy grants no live activity."""
from agent_recovery.contracts import digest, require

LEGACY_BUDGET_REVISION = "bank-budget-20261024-r1"
CURRENT_BUDGET_REVISION = "bank-budget-20261024-r2"
R6_RESUME_BUDGET_REVISION = "bank-budget-20261024-r3"


def budget_policy(revision):
    caps = {
        LEGACY_BUDGET_REVISION: (5_000_000_000, 1_000_000_000, 200_000_000),
        CURRENT_BUDGET_REVISION: (20_000_000_000, 3_000_000_000, 1_000_000_000),
        R6_RESUME_BUDGET_REVISION: (20_000_000_000, 3_000_000_000, 2_000_000_000),
    }
    require(isinstance(revision, str) and revision in caps,
            "Unknown spending-policy revision", "BUDGET_REVISION_INVALID")
    project, pilot, batch = caps[revision]
    policy = dict(schema_version="bank-budget-policy-v1", revision=revision,
                  project_cap_nano=project, pilot_cap_nano=pilot,
                  batch_cap_nano=batch, budget_only=True,
                  real_api_authorized=False, key_read_authorized=False,
                  training_authorized=False, cloud_authorized=False)
    return {**policy, "policy_sha256": digest(policy)}
