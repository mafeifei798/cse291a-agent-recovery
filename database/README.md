# Database experiment

`raw/` contains the supplied model requests and responses, artifacts, event logs, branch receipts and cleanup results for 66 started runs and 83 branches. `RUN_INDEX.json` maps run IDs to their directories. `results/` contains the supplied summary CSV files.

Check the saved evidence without PostgreSQL or API access:

```bash
python3 -B database/check_traces.py --output runs/database_check
```

`code/` contains the supplied v0.3.1 implementation and its usage instructions. The measured configuration uses `--diagnostic-experts 1 --role-policy separated`: four roles without Reviewer, five with it. The source also supports other configurations that were not evaluated in the report.

The main campaign used v0.3.0; the separate follow-up used v0.3.1. Their records remain labeled separately. An exact v0.3.0 source snapshot was not supplied. The checker independently reconstructs outcomes from saved records rather than rerunning either version. Database-state checks rely on the recorded evaluator observations; no independent database dump is included.
