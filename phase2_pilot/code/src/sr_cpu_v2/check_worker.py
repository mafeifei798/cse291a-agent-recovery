"""Independent numerical audit worker for trusted CPU artifacts.

This module deliberately imports no production runner, tools, Store, guard or
policy. It may transform data and predict with verified fitted objects, but it
never calls fit and does not write a test matrix or reveal test labels.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import itertools
import os
from pathlib import Path
import sys
import time


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


class _Audit:
    def __init__(self):
        self.checks = 0
        self.issues = []

    def require(self, condition, code, ref="", detail=None):
        self.checks += 1
        if not condition:
            self.issues.append({"code": code, "ref": ref, "detail": detail})
            raise ValueError(code + (": " + ref if ref else ""))


class _Files:
    def __init__(self, spec, audit):
        self.root = Path(spec["artifact_root"]).resolve()
        self.audit = audit
        artifacts = spec.get("artifacts", [])
        if isinstance(artifacts, dict):
            artifacts = list(artifacts.values())
        self.manifest = {x["artifact_id"]: x for x in artifacts}
        audit.require(len(self.manifest) == len(artifacts), "ARTIFACT_IDS_UNIQUE")
        self.verified = {}

    def path(self, artifact_id):
        self.audit.require(artifact_id in self.manifest, "ARTIFACT_MANIFEST_MISSING", artifact_id)
        item = self.manifest[artifact_id]
        path = Path(item["uri"])
        path = (self.root / path).resolve() if not path.is_absolute() else path.resolve()
        self.audit.require(path != self.root and self.root in path.parents,
                           "ARTIFACT_PATH_OUTSIDE_ALLOW_ROOT", artifact_id)
        self.audit.require(path.is_file(), "ARTIFACT_FILE_MISSING", artifact_id)
        stat = path.stat()
        self.audit.require(stat.st_size <= 128 * 1024 ** 2, "ARTIFACT_SIZE_CAP", artifact_id)
        self.audit.require(not (stat.st_mode & 0o222), "ARTIFACT_NOT_IMMUTABLE", artifact_id)
        raw = path.read_bytes()
        self.audit.require(len(raw) == item["size_bytes"], "ARTIFACT_SIZE", artifact_id)
        self.audit.require(hashlib.sha256(raw).hexdigest() == item["sha256"],
                           "ARTIFACT_SHA256", artifact_id)
        self.verified[artifact_id] = item["sha256"]
        return path

    def json(self, artifact_id):
        return json.loads(self.path(artifact_id).read_text())


def _locked_json(v0, relative, manifest, audit):
    path = v0 / "data" / relative
    entry = manifest[relative]
    raw = path.read_bytes()
    audit.require(len(raw) == entry["bytes"] and hashlib.sha256(raw).hexdigest() == entry["sha256"],
                  "FROZEN_DATA_DIGEST", relative)
    return json.loads(raw)


def _read_rows(v0, dataset, schema, required_ids, manifest, audit):
    """Parse raw sources independently, keeping the frozen row-ID order."""
    import numpy as np
    import pandas as pd

    row_index_path = "rows/" + dataset + ".jsonl"
    raw_index = (v0 / "data" / row_index_path).read_bytes()
    entry = manifest[row_index_path]
    audit.require(hashlib.sha256(raw_index).hexdigest() == entry["sha256"], "ROW_INDEX_DIGEST", dataset)
    frozen_rows = {r["row_id"]: r for r in (json.loads(line) for line in raw_index.splitlines())}
    audit.require(len(required_ids) == len(set(required_ids)), "ROW_IDS_UNIQUE", dataset)
    audit.require(all(x in frozen_rows for x in required_ids), "ROWS_IN_FROZEN_INDEX", dataset)
    wanted = set(required_ids)
    needed_files = {frozen_rows[x]["raw_file"] for x in required_ids}
    normalized = {}
    columns = schema["raw_column_order"]
    for relative in sorted(needed_files):
        raw = (v0 / "data" / relative).read_bytes()
        record = manifest[relative]
        sha = hashlib.sha256(raw).hexdigest()
        audit.require(sha == record["sha256"] and len(raw) == record["bytes"], "RAW_SOURCE_DIGEST", relative)
        texts = raw.decode().splitlines()
        if dataset == "bank":
            reader = csv.reader(texts, delimiter=";")
            audit.require(next(reader) == columns, "RAW_COLUMNS", dataset)
            parsed = ((i + 2, row) for i, row in enumerate(reader))
        else:
            parsed = ((physical, [x.strip() for x in next(csv.reader([line]))])
                      for physical, line in enumerate(texts, 1)
                      if line.strip() and not line.lstrip().startswith("|"))
        largest = max(frozen_rows[rid]["data_row_1based"] for rid in required_ids
                      if frozen_rows[rid]["raw_file"] == relative)
        counter = 0
        for physical, row in itertools.islice(parsed, largest):
            counter += 1
            if dataset == "adult" and relative.endswith("adult.test"):
                audit.require(row[-1].endswith("."), "ADULT_TEST_LABEL_PERIOD")
                row[-1] = row[-1][:-1]
            rid = f"sha256:{sha}:row:{counter}"
            if rid not in wanted:
                continue
            audit.require(len(row) == len(columns), "RAW_ROW_WIDTH", rid)
            index = frozen_rows[rid]
            audit.require(index["physical_line_1based"] == physical and
                          index["normalized_record_sha256"] == _digest(row), "RAW_ROW_PROVENANCE", rid)
            normalized[rid] = row
    audit.require(set(normalized) == wanted, "ALL_REQUESTED_ROWS_RECOVERED", dataset)
    frame = pd.DataFrame([normalized[rid] for rid in required_ids], columns=columns)
    labels = (frame[schema["label_column"]] == schema["positive_label"]).to_numpy(dtype=np.int8)
    frame = frame[schema["input_column_order"]].copy()
    for column in schema["numeric_column_order"]:
        frame[column] = pd.to_numeric(frame[column].replace("?", np.nan), errors="raise").astype(float)
    for column in schema["categorical_column_order"]:
        frame[column] = frame[column].astype(object)
        if schema.get("missing_literal") is not None:
            frame[column] = frame[column].replace(schema["missing_literal"], schema["missing_category"])
    return frame, labels


def _metrics(labels, probabilities):
    from sklearn.metrics import average_precision_score, roc_auc_score, f1_score, accuracy_score
    predicted = probabilities >= 0.5
    return {"average_precision": float(average_precision_score(labels, probabilities)),
            "roc_auc": float(roc_auc_score(labels, probabilities)),
            "f1": float(f1_score(labels, predicted)),
            "accuracy": float(accuracy_score(labels, predicted))}


def _same_array(actual, expected, audit, code, ref, atol=1e-8):
    import numpy as np
    audit.require(actual.shape == expected.shape, code + "_SHAPE", ref)
    audit.require(np.isfinite(actual).all() and np.isfinite(expected).all(), code + "_FINITE", ref)
    difference = float(np.max(np.abs(actual - expected))) if actual.size else 0.0
    audit.require(difference <= atol, code, ref, {"max_absolute_error": difference})
    return difference


def _same_sparse(actual, expected, audit, code, ref):
    import numpy as np
    from scipy import sparse
    audit.require(sparse.isspmatrix_csr(actual) and actual.dtype == np.float64,
                  code + "_CSR_FLOAT64", ref)
    audit.require(actual.shape == expected.shape, code + "_SHAPE", ref)
    delta = actual - expected
    error = float(np.max(np.abs(delta.data))) if delta.nnz else 0.0
    audit.require(np.isfinite(actual.data).all() and error <= 1e-8,
                  code, ref, {"max_absolute_error": error})


def _pipeline_named(transformer, kind):
    """Identify steps by sklearn type rather than production-selected names."""
    from sklearn.impute import SimpleImputer
    from sklearn.preprocessing import OneHotEncoder, StandardScaler
    from sklearn.pipeline import Pipeline
    groups = []
    for name, fitted, columns in transformer.transformers_:
        if name == "remainder":
            continue
        steps = fitted.steps if isinstance(fitted, Pipeline) else [(name, fitted)]
        classes = (SimpleImputer, StandardScaler) if kind == "numeric" else (OneHotEncoder,)
        if any(isinstance(step, classes) for _, step in steps):
            groups.append((columns, [step for _, step in steps]))
    if len(groups) != 1:
        raise ValueError("TRANSFORMER_GROUP_AMBIGUOUS: " + kind)
    return groups[0]


def _check_transformer(transformer, train_x, schema, family, audit):
    import numpy as np
    from sklearn.compose import ColumnTransformer
    from sklearn.impute import SimpleImputer
    from sklearn.preprocessing import StandardScaler, OneHotEncoder

    audit.require(isinstance(transformer, ColumnTransformer), "TRUSTED_COLUMN_TRANSFORMER", family)
    audit.require(list(transformer.feature_names_in_) == schema["input_column_order"], "FEATURE_COLUMNS", family)
    numeric, cat = schema["numeric_column_order"], schema["categorical_column_order"]
    nc, ns = _pipeline_named(transformer, "numeric")
    cc, cs = _pipeline_named(transformer, "categorical")
    audit.require(list(nc) == numeric and list(cc) == cat and
                  [list(cols) for name, _, cols in transformer.transformers_ if name != "remainder"] == [numeric, cat],
                  "TRANSFORMER_BLOCK_ORDER", family)
    imputer = next((x for x in ns if isinstance(x, SimpleImputer)), None)
    audit.require(imputer is not None and imputer.strategy == "median", "TRAIN_MEDIAN_IMPUTER", family)
    raw = train_x[numeric].to_numpy(dtype=np.float64)
    medians = np.nanmedian(raw, axis=0)
    _same_array(np.asarray(imputer.statistics_, dtype=float), medians, audit, "TRAIN_MEDIANS", family)
    filled = np.where(np.isnan(raw), medians, raw)
    scalers = [x for x in ns if isinstance(x, StandardScaler)]
    audit.require(len(scalers) == (1 if family == "LR" else 0), "FAMILY_SCALER", family)
    if scalers:
        scaler = scalers[0]
        audit.require(scaler.with_mean and scaler.with_std, "STANDARD_SCALER_CONFIGURATION", family)
        _same_array(np.asarray(scaler.mean_), filled.mean(axis=0), audit, "TRAIN_SCALER_MEAN", family)
        _same_array(np.asarray(scaler.var_), filled.var(axis=0), audit, "TRAIN_SCALER_VARIANCE", family,
                    atol=max(1e-8, float(np.max(np.abs(filled.var(axis=0)))) * 1e-12))
        expected_scale = np.sqrt(filled.var(axis=0))
        expected_scale[expected_scale == 0] = 1.0
        _same_array(np.asarray(scaler.scale_), expected_scale, audit, "TRAIN_SCALER_SCALE", family,
                    atol=max(1e-8, float(np.max(expected_scale)) * 1e-12))
        audit.require(int(np.min(scaler.n_samples_seen_)) == len(train_x), "SCALER_TRAIN_ROW_COUNT", family)
    encoder = next((x for x in cs if isinstance(x, OneHotEncoder)), None)
    audit.require(encoder is not None and encoder.handle_unknown == "ignore" and encoder.sparse_output,
                  "CATEGORY_ENCODER_CONFIGURATION", family)
    cat_imputer = next((x for x in cs if isinstance(x, SimpleImputer)), None)
    audit.require(cat_imputer is None or (cat_imputer.strategy == "constant" and
                  cat_imputer.fill_value == schema["missing_category"]), "CATEGORY_MISSING_NORMALIZATION", family)
    audit.require(len(encoder.categories_) == len(cat), "CATEGORY_COLUMNS", family)
    for column, categories in zip(cat, encoder.categories_):
        expected = sorted(train_x[column].fillna(schema["missing_category"]).unique().tolist())
        audit.require(categories.tolist() == expected, "TRAIN_ONLY_CATEGORIES", family + ":" + column)
    audit.require(transformer.sparse_threshold == schema["column_transformer_sparse_threshold"], "SPARSE_THRESHOLD", family)


def run_check(spec):
    """No fitting, no model prompts, no network, and test metrics remain private."""
    started = time.monotonic()
    audit = _Audit()
    statistics = {"models_loaded": 0, "model_fits": 0, "prediction_max_absolute_error": {},
                  "test_evaluated": False, "test_matrix_written": False, "real_api_requests": 0}
    try:
        import numpy as np
        import joblib
        from scipy import sparse
        from sklearn.linear_model import LogisticRegression
        from sklearn.ensemble import RandomForestClassifier

        audit.require(spec.get("tool") == "independent_check", "CHECK_TOOL_ID")
        files = _Files(spec, audit)
        v0 = Path(spec["v0_root"]).resolve()
        freeze_raw = (v0 / "FREEZE.json").read_bytes()
        audit.require(hashlib.sha256(freeze_raw).hexdigest() ==
                      "643acd951eb135d484e4b32ff63de4e670d66a7f50a7da5f304505a6f471f6b2", "V0_FREEZE_PIN")
        frozen = {x["path"]: x for x in json.loads(freeze_raw)["files"]}
        manifest_raw = (v0 / "data/manifest.json").read_bytes()
        audit.require(hashlib.sha256(manifest_raw).hexdigest() == frozen["sr_v2/v0/data/manifest.json"]["sha256"], "V0_DATA_MANIFEST_PIN")
        manifest_doc = json.loads(manifest_raw)
        manifest = {x["path"]: x for x in manifest_doc["files"]}
        schemas = _locked_json(v0, "schema_and_preprocessing.json", manifest, audit)
        inputs = spec["inputs"]
        dataset = inputs["dataset_id"]
        audit.require(dataset in ("adult", "bank"), "DATASET_ID")
        schema = schemas["datasets"][dataset]
        train_version = inputs["train_version"]
        train_name = train_version if isinstance(train_version, str) and train_version.startswith("train_") else "train_v" + str(train_version)
        audit.require(train_name in ("train_v1", "train_v2"), "TRAIN_VERSION")
        train_split = _locked_json(v0, f"splits/{dataset}/{train_name}.json", manifest, audit)
        val_split = _locked_json(v0, f"splits/{dataset}/validation.json", manifest, audit)
        train_ids, val_ids = train_split["row_ids"], val_split["row_ids"]
        audit.require(set(train_ids).isdisjoint(val_ids), "TRAIN_VALIDATION_DISJOINT")
        all_x, all_y = _read_rows(v0, dataset, schema, train_ids + val_ids, manifest, audit)
        train_x, val_x = all_x.iloc[:len(train_ids)].copy(), all_x.iloc[len(train_ids):].copy()
        train_y, val_y = all_y[:len(train_ids)], all_y[len(train_ids):]
        payloads = inputs["selected_payloads"]
        prepare = payloads["prepare"]
        audit.require(prepare["dataset_id"] == dataset and str(prepare["train_version"]) == train_name.rsplit("v", 1)[1], "PREPARE_DATASET_VERSION")
        audit.require(prepare["training_row_ids_digest"] == _digest(train_ids) and
                      prepare["validation_row_ids_digest"] == _digest(val_ids), "PREPARE_ROW_PROVENANCE")
        source_path = f"tasks/authority/macro-{dataset}-01.sources.json"
        source_raw = (v0 / source_path).read_bytes()
        audit.require(hashlib.sha256(source_raw).hexdigest() == frozen["sr_v2/v0/" + source_path]["sha256"], "V0_RECIPE_AUTHORITY_PIN")
        source_doc = json.loads(source_raw)
        recipe_options = {}
        for source in source_doc["sources"]:
            if source["object_key"] in ("recipe:lr", "recipe:rf"):
                recipe_options.setdefault(source["object_key"].split(":")[1], []).append(source["payload"]["parameters"])
        models, preprocessors, recomputed = {}, {}, {}
        for lower, family in (("lr", "LR"), ("rf", "RF")):
            pf = prepare["families"][lower]
            fit, prediction, summary = payloads["fit_" + lower], payloads["predict_" + lower], payloads["summary_" + lower]
            plan = payloads["plan_" + lower]
            parameters = plan.get("parameters", plan.get("model_parameters"))
            audit.require(parameters in recipe_options[lower] and fit["parameters"] == parameters,
                          "LOCKED_RECIPE_PARAMETERS", family)
            expected_recipes = inputs.get("expected_parameters", {})
            if lower in expected_recipes or family in expected_recipes:
                audit.require(parameters == expected_recipes.get(lower, expected_recipes.get(family)), "CURRENT_RECIPE_PARAMETERS", family)
            rows = files.json(pf["rows_artifact_id"])
            audit.require(rows["train_row_ids"] == train_ids and rows["validation_row_ids"] == val_ids,
                          "PERSISTED_ROW_IDS", family)
            audit.require(fit["training_row_ids_digest"] == _digest(train_ids) and
                          fit["matrix_artifact_id"] == pf["train_matrix_artifact_id"], "FIT_TRAIN_PROVENANCE", family)
            selected_ids = inputs["selected_result_ids"]
            audit.require(files.manifest[pf["preprocessor_artifact_id"]]["producer_result_id"] == selected_ids["prepare"] and
                          files.manifest[fit["model_artifact_id"]]["producer_result_id"] == selected_ids["fit_" + lower],
                          "TRUSTED_CURRENT_RUN_FITTED_PRODUCERS", family)
            preprocessor = joblib.load(files.path(pf["preprocessor_artifact_id"]))
            _check_transformer(preprocessor, train_x, schema, family, audit)
            transformed_train = preprocessor.transform(train_x).tocsr()
            transformed_val = preprocessor.transform(val_x).tocsr()
            train_matrix = sparse.load_npz(files.path(pf["train_matrix_artifact_id"]))
            val_matrix = sparse.load_npz(files.path(pf["val_matrix_artifact_id"]))
            _same_sparse(train_matrix, transformed_train, audit, "TRAIN_MATRIX", family)
            _same_sparse(val_matrix, transformed_val, audit, "VALIDATION_MATRIX", family)
            saved_train_y = np.load(files.path(pf["train_y_artifact_id"]), allow_pickle=False)
            saved_val_y = np.load(files.path(pf["val_y_artifact_id"]), allow_pickle=False)
            audit.require(saved_train_y.dtype == np.int8 and saved_val_y.dtype == np.int8 and
                          np.array_equal(saved_train_y, train_y) and np.array_equal(saved_val_y, val_y), "LABELS_FROM_LOCKED_ROWS", family)
            stats = files.json(pf["transform_stats_artifact_id"])
            audit.require(stats.get("feature_names", stats.get("feature_names_out")) == preprocessor.get_feature_names_out().tolist(), "TRANSFORM_STATS_FEATURE_NAMES", family)
            audit.require(stats["input_columns"] == schema["input_column_order"] and
                          stats["numeric_columns"] == schema["numeric_column_order"] and
                          stats["categorical_columns"] == schema["categorical_column_order"] and
                          stats["excluded_columns"] == schema["excluded_columns"] and
                          stats["fit_on"] == "training_only" and stats["test_rows_used"] is False,
                          "TRANSFORM_STATS_COLUMNS_SCOPE", family)
            audit.require(stats["training_row_ids_digest"] == _digest(train_ids) and
                          stats["validation_row_ids_digest"] == _digest(val_ids) and
                          stats["train_shape"] == list(transformed_train.shape) and
                          stats["validation_shape"] == list(transformed_val.shape), "TRANSFORM_STATS_ROW_MATRIX_PROVENANCE", family)
            medians = np.nanmedian(train_x[schema["numeric_column_order"]].to_numpy(dtype=float), axis=0)
            _same_array(np.asarray(stats["numeric_imputer_medians"], dtype=float), medians, audit, "TRANSFORM_STATS_MEDIANS", family)
            expected_categories = [sorted(train_x[c].fillna(schema["missing_category"]).unique().tolist())
                                   for c in schema["categorical_column_order"]]
            audit.require(stats["category_values"] == expected_categories, "TRANSFORM_STATS_CATEGORIES", family)
            if family == "LR":
                _, numeric_steps = _pipeline_named(preprocessor, "numeric")
                from sklearn.preprocessing import StandardScaler
                fitted_scaler = next(x for x in numeric_steps if isinstance(x, StandardScaler))
                for stat_key, fitted_value in (("mean", fitted_scaler.mean_), ("var", fitted_scaler.var_), ("scale", fitted_scaler.scale_)):
                    _same_array(np.asarray(stats["scaler"][stat_key], dtype=float), np.asarray(fitted_value), audit,
                                "TRANSFORM_STATS_SCALER", family + ":" + stat_key)
            else:
                audit.require(stats["scaler"] is None, "RF_HAS_NO_SCALER_STATS")
            model = joblib.load(files.path(fit["model_artifact_id"]))
            audit.require(isinstance(model, LogisticRegression if lower == "lr" else RandomForestClassifier), "MODEL_CLASS", family)
            audit.require(model.get_params(deep=False) == parameters, "FITTED_MODEL_PARAMETERS", family)
            audit.require(model.classes_.tolist() == [0, 1] and model.n_features_in_ == transformed_val.shape[1], "MODEL_CLASSES_FEATURES", family)
            audit.require(prediction["model_artifact_id"] == fit["model_artifact_id"] and
                          prediction["validation_row_ids_digest"] == _digest(val_ids), "PREDICT_PROVENANCE", family)
            saved_probs = np.load(files.path(prediction["prediction_artifact_id"]), allow_pickle=False)
            probabilities = model.predict_proba(transformed_val)[:, 1]
            audit.require(saved_probs.dtype == np.float64 and saved_probs.shape == (len(val_y),) and
                          np.isfinite(saved_probs).all() and np.all((saved_probs >= 0) & (saved_probs <= 1)), "PROBABILITY_CONSTRAINTS", family)
            statistics["prediction_max_absolute_error"][family] = _same_array(saved_probs, probabilities, audit, "PREDICTIONS_RECOMPUTED", family)
            metrics = _metrics(val_y, probabilities)
            raw_receipt = files.json(summary["metrics_artifact_id"])
            audit.require(raw_receipt["prediction_artifact_id"] == prediction["prediction_artifact_id"] and
                          raw_receipt["model_artifact_id"] == fit["model_artifact_id"] and
                          raw_receipt["validation_row_ids_digest"] == _digest(val_ids) and
                          raw_receipt["row_count"] == len(val_ids) and raw_receipt["threshold"] == 0.5,
                          "RAW_METRICS_PROVENANCE", family)
            audit.require(summary["prediction_artifact_id"] == prediction["prediction_artifact_id"] and
                          summary["model_artifact_id"] == fit["model_artifact_id"] and
                          summary["validation_row_ids_digest"] == _digest(val_ids), "SUMMARY_PROVENANCE", family)
            raw_metrics = raw_receipt["metrics"]
            for key, value in metrics.items():
                audit.require(abs(raw_metrics[key] - value) <= 1e-8, "RAW_METRICS_RECOMPUTED", family + ":" + key)
                if inputs.get("allow_delivered_summary_fault") and family == "LR" and key == "average_precision":
                    audit.require(abs(summary["metrics"][key] - value) > 1e-8, "DELIVERED_AP_FAULT_REALLY_PRESENT", family)
                else:
                    audit.require(abs(summary["metrics"][key] - value) <= 1e-8, "DELIVERED_METRICS", family + ":" + key)
            recomputed[family] = metrics
            models[family], preprocessors[family] = model, preprocessor
            statistics["models_loaded"] += 1
        expected_family = "LR" if recomputed["LR"]["average_precision"] >= recomputed["RF"]["average_precision"] - 1e-6 else "RF"
        statistics["validation_metrics"] = recomputed
        statistics["expected_selected_family"] = expected_family
        report, publish = payloads.get("report", {}), payloads.get("publish", {})
        if inputs.get("allow_delivered_summary_fault"):
            audit.require(inputs.get("prefix_publish_status") == "validation_rejected" and
                          inputs.get("prefix_refusal", {}).get("classification") == "semantic", "PREFIX_FAULT_GUARD_REJECTED")
        if not inputs.get("allow_delivered_summary_fault"):
            audit.require(report.get("selected_family") == expected_family, "REPORT_SELECTION")
            chosen = expected_family.lower()
            expected_references = {"model_artifact_id": payloads["fit_" + chosen]["model_artifact_id"],
                                   "prediction_artifact_id": payloads["predict_" + chosen]["prediction_artifact_id"]}
            for key, value in expected_references.items():
                audit.require(report.get(key) == value, "REPORT_CHOSEN_ARTIFACT_REFERENCE", key)
            audit.require(report.get("validation_row_ids_digest") == _digest(val_ids), "REPORT_VALIDATION_ROW_PROVENANCE")
            for key, value in recomputed[expected_family].items():
                audit.require(abs(report["metrics"][key] - value) <= 1e-8, "REPORT_CHOSEN_METRICS", key)
            report_artifact = report.get("report_artifact_id")
            if report_artifact is not None:
                saved_report = files.json(report_artifact)
                audit.require(saved_report == {k: v for k, v in report.items() if k != "report_artifact_id"}, "SAVED_REPORT_EQUALS_DELIVERED_REPORT")
                for key, value in expected_references.items():
                    audit.require(saved_report.get(key) == value, "SAVED_REPORT_ARTIFACT_REFERENCE", key)
                audit.require(saved_report.get("selected_family") == expected_family, "SAVED_REPORT_SELECTION")
            if publish:
                publish_manifest = files.json(publish["candidate_artifact_id"])
                audit.require(publish.get("publish_manifest") == publish_manifest, "PUBLISH_PAYLOAD_EQUALS_MANIFEST_BYTES")
                audit.require(publish_manifest.get("selected_family") == expected_family, "PUBLISH_SELECTION")
                for key, value in expected_references.items():
                    audit.require(publish.get(key) == value and publish_manifest.get(key) == value, "PUBLISHED_ARTIFACT_REFERENCE", key)
                audit.require(publish_manifest.get("report_artifact_id") == report_artifact and
                              publish_manifest.get("validation_row_ids_digest") == _digest(val_ids), "PUBLISHED_REPORT_PROVENANCE")
                for key, value in recomputed[expected_family].items():
                    audit.require(abs(publish_manifest["metrics"][key] - value) <= 1e-8, "PUBLISHED_METRICS", key)
        if inputs.get("evaluate_test"):
            audit.require(bool(publish) and not inputs.get("allow_delivered_summary_fault"), "TEST_ONLY_AFTER_VALID_PUBLISH")
            test_split = _locked_json(v0, f"splits/{dataset}/test.json", manifest, audit)
            test_ids = test_split["row_ids"]
            audit.require(set(test_ids).isdisjoint(train_ids) and set(test_ids).isdisjoint(val_ids), "TEST_DISJOINT")
            test_x, test_y = _read_rows(v0, dataset, schema, test_ids, manifest, audit)
            probabilities = []
            for at in range(0, len(test_ids), 1024):
                matrix = preprocessors[expected_family].transform(test_x.iloc[at:at + 1024])
                probabilities.append(models[expected_family].predict_proba(matrix)[:, 1])
            statistics["private_test_metrics"] = _metrics(test_y, np.concatenate(probabilities))
            statistics["test_evaluated"] = True
            statistics["test_rows"] = len(test_ids)
        statistics["verified_artifact_count"] = len(files.verified)
        statistics["dataset_id"] = dataset
        statistics["train_rows"] = len(train_ids)
        statistics["validation_rows"] = len(val_ids)
    except Exception as exc:
        if not audit.issues:
            audit.issues.append({"code": "CHECK_EXCEPTION", "ref": "", "detail": f"{type(exc).__name__}: {exc}"})
    statistics["elapsed_seconds"] = time.monotonic() - started
    return {"passed": not audit.issues, "checks": audit.checks, "issues": audit.issues, "statistics": statistics}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True)
    parser.add_argument("--response", required=True)
    args = parser.parse_args(argv)
    spec = json.loads(Path(args.spec).read_text())
    report = run_check(spec)
    result = {"status": "success" if report["passed"] else "failed", "tool": "independent_check",
              "job_id": spec.get("job_id"), "payload": report, "artifacts": []}
    path = Path(args.response)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(_canonical(result) + b"\n")
    os.replace(temporary, path)
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    sys.exit(main())
