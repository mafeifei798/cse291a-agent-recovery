# Failure propagation and recovery in an agent workflow

CSE 291A, Fall 2026 — Phase 1  
Hongyi Ding · Yang Zeng · Beijie Cheng

[Report](report.pdf) · [Workflow and experiment details](WORKFLOW_GUIDE_EN.md)

We study how an incorrect agent result affects later steps, and what a full
restart throws away. The main workflow has three LLM roles: an Analyst reads
dataset, permission, and resource information; a Planner produces a job
configuration; and an Executor requests a SQLite write. Python tools perform
the reads, writes, and checks. This task saves a configuration; it does not
launch a training job.

The report covers clean runs, four injected faults, intermediate verification,
and full restart. It also includes one Bank Marketing recovery pilot with real
CPU training. The files needed to check both are included here.

## Run the workflow offline

Use Python 3.11 or newer. The commands below were checked with Python 3.13.1
and the versions in `requirements.txt`.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -B run_offline.py --output runs/offline
```

This runs all 168 registered trials with scripted model responses, real SQLite
writes, fault injection, verification, and restart. It takes about two minutes
on a laptop and needs no API key or GPU. For a short check, add `--stop-after 14`.
Use a new output directory for each run.

The expected offline counts are 84 correct completions, 24 verification stops,
36 runs with no output, 12 wrong writes, and 12 cases where restart is not
needed. These differ from the report's real-LLM results because the scripted
model does not introduce natural copying or arithmetic errors.

The summary is `runs/offline/OFFLINE_RUN.json`; per-trial results are in
`runs/offline/audit168/trials.csv`. To check the run separately:

```bash
python3 -B check_offline.py --run runs/offline/campaign --output runs/offline_check
```

## Reproduce the report tables

```bash
python3 -B reproduce.py --output runs/report_tables
```

This reads the saved real responses, database records, and prediction arrays.
It recomputes the four tables without API calls, training, or prediction.
The output directory contains:

- `table1_outcomes.csv`: correct completions, wrong writes, and stops.
- `table2_calls.csv`: model calls and usage-based cost estimates.
- `table3_pilot.csv`: training, checking, and reuse in the Bank pilot.
- `tableA1_timing.csv`: baseline and recovery timing.
- `verification_summary.json`: extra reads, checking time, and clean-run stops.
- `REPRODUCTION_RECEIPT.json`: the check results.

The main experiment contains 168 scheduled trials, 156 executed workflows,
and 602 real model calls. Full restart completed 26 of 36 recovery attempts
correctly; the other 10 saved incorrect configurations. Of 135 calls discarded
by restart, 63 still had valid results at the checkpoint. This is potential
reuse, not measured savings. The Bank pilot is a single paired comparison;
its three methods share the same saved state.

## Check the safety supplement

The report's additional permission and resource checks are stored in a separate
archive to keep the main code easy to browse. The archive includes its source,
raw results, and checker.

```bash
python3 -m zipfile -e supplements/cse291a_phase1_safety_supplement_20261102_r15.zip supplements
python3 -B reproduce.py --output runs/report_with_safety
```

The second command checks the supplement as well as the four report tables.
It also writes `safety_proposals.csv`, separating unsafe proposals from actual writes.
Without extraction, it checks the main experiment and Bank pilot only.
The extracted supplement is ignored by Git.

## Files

| Path | Contents |
| --- | --- |
| `phase1/original_code/` | Runnable workflow, prompts, task and fault definitions |
| `phase1/evaluation_code/`, `analysis/` | Independent checks and table calculations |
| `phase1/evidence/p4/` | Saved real-API records and per-trial results |
| `phase2_pilot/code/`, `phase2_pilot/records/` | Bank pilot source, decisions, databases, and arrays |
| `supplements/` | Additional safety experiment and its checksum information |
| `typesetting/` | LaTeX source for the report |

`records.json.gz` is a lossless copy of the original records. The reproduction
script checks its uncompressed hash. `MANIFEST.json` lists the other file
checksums. Bank data and its train/validation row selections are included with
the pilot; see [DATA.md](DATA.md) for the source.

## Live runs

The commands above are the intended evaluation path. The original real-API
producer is `phase1/original_code/scripts/run_p4_formal.py`; it requires a
TritonAI credential, model/pricing configuration, and an explicit run permit.
The Bank pilot additionally needs its training dependencies. Live runs incur
costs and will not reproduce the saved stochastic responses exactly. No
credential is included in this repository.
