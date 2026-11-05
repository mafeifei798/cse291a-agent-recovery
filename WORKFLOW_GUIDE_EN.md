# Workflows and tasks

## Configuration baseline

The user specifies a dataset, batch size, epochs, and requested workers. Tools
provide dataset size, permission, and the current worker limit.

1. Analyst calls produce three structured summaries of these snapshots.
2. The Planner calculates steps and permitted workers from those summaries.
3. The Executor proposes a write, which Python applies to SQLite.

This task saves a configuration; it does not train a model. Recorded LLM calls
and database writes were real. Offline mode substitutes scripted model
responses while running the same controller, faults, and database operations.

Correct steps are `ceil(num_examples / batch_size) * epochs`. Workers must
respect the request and current limit. Permission must remain valid.

| Task | Examples | Batch | Epochs | Requested workers / limit | Steps / workers |
|---|---:|---:|---:|---:|---:|
| eval01 | 4096 | 64 | 2 | 2 / 8 | 128 / 2 |
| eval02 | 4097 | 64 | 2 | 8 / 3 | 130 / 3 |
| eval03 | 17 | 128 | 3 | 1 / 4 | 3 / 1 |
| eval08 | 2049 | 256 | 3 | 5 / 2 | 27 / 2 |

Each task is repeated three times. Tasks, fault schedules, and the 168-row
registration are in `phase1/original_code/phase1/p0/manifests/`. Schemas and
message templates are in `contracts/` beside that directory.

| Condition | Injection |
|---|---|
| CLEAN | No injected fault; natural failures still count |
| ERR | Wrong dataset size or step count in an intermediate result |
| ADV | An instruction in low-trust source text or a handoff |
| TMO | A local tool times out; its late response is drained and rejected |
| STL | A source changes after an earlier version was read |

BASE checks structure and source versions. VERIFY_STOP additionally checks
intermediate business values and stops on an error. FULL_RESTART receives the
faulty output identity, conditionally compensates owned writes, and reruns once
from current sources. A stopped task is not a completed task.

The original entry is `phase1/original_code/scripts/run_p4_formal.py`. The root
`run_offline.py` handles its staged checkpoints and independent checks.

## Bank recovery pilot

The Analyst reads data facts, the Planner selects a feature bundle and a fixed
LR or RF recipe, and the Reviewer accepts the result or requests one adjustment.
Sklearn tools perform real CPU training and prediction.

The saved pilot corrupts an Analyst row-count summary without changing data.
Its checkpoint follows an approved adjustment. After correction, initial and
adjusted training specifications match their originals. CUTOFF reuses three
artifacts after source, binding, hash, and numeric checks. FULL and CONSERVATIVE
each retrain three times. Every method checks its artifacts: CUTOFF avoids
training but still pays verification cost. This is one checkpoint, not a
repeated evaluation.

Comparison logic is in `phase2_pilot/code/src/agent_l_compare` and
`src/agent_l_compare_entry`. Role and CPU tools are in `src/agent_l_v3` and
`src/context_cutoff`; the historical comparison entry is
`phase2_pilot/code/scripts/run_l_compare_entry.py`. The root `reproduce.py`
rebuilds Table 3 from saved results. The later source-update attempt remains
incomplete and is not counted as a successful recovery.

## Planned Phase 2 evaluation: detailed rules

The report describes a planned repeated evaluation, distinct from the saved
one-checkpoint pilot. Its matrix has three scenarios, six repetitions per
scenario, and three recovery methods: 18 shared failure states and 54 recovery
runs, plus six clean runs and six repeated-input model calls. These are planned
deliverables, not additional completed Phase 1 measurements.

- N changes only the Analyst's reported row count by one. The model may still
  choose a different plan; equivalence is measured rather than assumed.
- D preserves the Planner's raw response but replaces the delivered choice
  with D0/LR: the existing five-feature bundle and logistic-regression recipe.
  If the original choice was already D0/LR, record the injection as ineffective
  and keep that scheduled run rather than drawing a replacement.
- U combines N with increasing the first training row's age by one in a shared
  copy of the data. Labels and validation rows stay unchanged. Every method
  receives the same update and must respect its new data binding.

Each method starts after the first training result, before Reviewer feedback,
with the same faulty-result identity, sources, checks, and remaining time.
The workflow allows one normal Reviewer-requested adjustment. Recovery inherits
the consumed allowance and deadline; it does not replenish either. A cutoff
point may be rechecked only once in a recovery round.

For D, a permitted recipe can still be an injected change to the agent's actual
decision. Recovery is judged against the newly checked plan, current data,
quality rules, and publication permission. The independent checker verifies
that the final artifacts and report match those inputs and their saved numeric
results. A separate clean model call is not an exact-output oracle: it can make
a different valid choice. When the corrected training specification changes,
the old dependent training output cannot be admitted.

Count correct completion, quality stops, safety stops, wrong completion,
infrastructure failures, ineffective injections, and runs that never reached
the shared failure state separately. Report changed training specifications
over valid rechecks, with failed rechecks listed separately. The six model
consistency calls repeat exact saved inputs once each; they are used only for
analysis, never to choose a recovery output or obtain another cutoff attempt.

Planned continuation after a service interruption retains every failed attempt
and its cost. Only unstarted work may enter a later batch, after access,
accounting, budget, and independent checks permit it. A started or failed run
is not reopened, its deadline is not reset, and a failed sample is not replaced.
Unknown effects or charges remain recorded until evidence resolves them.
Completed business results keep their outcomes if later accounting fails.

The deterministic runtime tests will use fake tools and separate external-state
namespaces for each method. They cover an action completing before its local
receipt is durable, duplicate delivery, conflicting data under the same
operation ID, and a source changing before a resumed write. Targets are zero
duplicate effects, zero accepted stale writes, and preservation of adjustment
and time limits. If an external effect cannot be established by ID, stop and
report it as unresolved rather than blindly repeating it. These new tests and
continuation paths are plans; this submission does not claim they are complete.
