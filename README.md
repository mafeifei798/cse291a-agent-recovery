# Failure propagation and recovery in stateful agent workflows

CSE 291A, Fall 2026 — Phase 1
Hongyi Ding · Yang Zeng · Beijie Cheng

Start with [report.pdf](report.pdf). It combines the controlled configuration experiment, live PostgreSQL experiment, and a small Bank training recovery pilot.

## Recompute the saved results

Use Python 3.11 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m zipfile -e supplements/cse291a_phase1_safety_supplement_20261102_r15.zip supplements
python3 -B reproduce.py --output runs/configuration_bank_safety
python3 -B database/check_traces.py --output runs/database_check
```

These commands check the existing records without model calls, PostgreSQL, training, or prediction. Use a new output directory each time. The safety archive is already included in this package; no separate download is needed.

The first checker produces the configuration outcomes, calls and timing, safety proposal counts, and Bank pilot results. The second reconstructs the database branch scores, dependencies, usage, operation outcomes, restart pairs and cleanup checks from the raw traces. In the current report, `table1_outcomes.csv` supports Table 1, `database_branches_recomputed.csv` supports Table 2, and `table3_pilot.csv` supports Table 3.

## Run the configuration workflow offline

```bash
python3 -B run_offline.py --output runs/offline
python3 -B check_offline.py --run runs/offline/campaign --output runs/offline_check
```

This executes all 168 trials with scripted model responses and real SQLite operations. Expected counts: 84 correct completions, 24 verification stops, 36 runs with no output, 12 wrong writes, and 12 cases where restart is unnecessary. These differ from the report's real-model results because the scripted model does not introduce natural errors. Add `--stop-after 14` for a short run.

## Contents

| Path | Contents |
| --- | --- |
| `report.pdf` | Final report |
| `phase1/original_code/` | Configuration workflow, prompts, tasks and faults |
| `phase1/evaluation_code/`, `analysis/` | Independent checks and saved-result analysis |
| `phase1/evidence/p4/` | Original configuration results |
| `database/code/` | Supplied PostgreSQL workflow implementation |
| `database/raw/`, `database/results/` | Database traces and summary tables |
| `phase2_pilot/` | Bank pilot code, decisions, databases, data and saved arrays |
| `supplements/` | Safety experiment source, records and checker |

`WORKFLOW_GUIDE_EN.md` documents the configuration workflow and archived Bank pilot; the current Phase 2 plan is in the report. `DATA.md` gives the Bank data source. Database source/version limitations are described in `database/README.md`.

## Live execution

The commands above are the offline evaluation path. New configuration API runs need a TritonAI key and a permit; database runs additionally need PostgreSQL 16 and the dependencies in `database/code/requirements.txt`. See the respective source instructions before running them. No credential is included. New stochastic runs are not expected to match the saved responses exactly.

## Report versions

Table 2 reports the original v0.3.0 database results. The v0.3.1 clean-handoff follow-up is reported separately.
