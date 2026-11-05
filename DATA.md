# Data

The configuration workflow uses synthetic task definitions in
`phase1/original_code/phase1/p0/`. Its saved model responses and SQLite records
are in `phase1/evidence/p4/`; the four task specifications are also summarized
in `WORKFLOW_GUIDE_EN.md`.

The CPU training pilot uses **bank-additional-full.csv** (41,188 rows) from
the UCI Bank Marketing dataset. The source data, selected row IDs, training
specifications, and saved predictions are included with the pilot. The report
describes the feature restrictions and fixed split.

Source: S. Moro, P. Rita, and P. Cortez (2014), *Bank Marketing*, UCI Machine
Learning Repository. <https://doi.org/10.24432/C5K306>.

UCI distributes the data under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
The source CSV is unmodified; train/validation row selections and predictions
are products of our experiment.
