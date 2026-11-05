"""Locked, CPU-only model tools. This module never starts a worker or a network client.

Only ``execute`` is public. Its input and output are JSON; all large arrays and
fitted objects live in immutable, hash-addressed local artifacts. Model loading
is limited to artifacts explicitly registered by the controller for this run.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import warnings
from pathlib import Path
from typing import Any

REV = "sr-v2-v0-r1"
ALLOWED_TOOLS = frozenset({"profile", "prepare", "fit_lr", "fit_rf", "predict_lr", "predict_rf", "summary_lr", "summary_rf", "publish"})
MAX_ARTIFACT = 128 * 1024 * 1024


class ToolError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def file_sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _inside(root: Path, path: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise ToolError("PATH_ESCAPE", str(path)) from exc
    return resolved


class Context:
    def __init__(self, spec: dict):
        self.spec = spec
        self.root = Path(spec["artifact_root"]).resolve()
        self.output = _inside(self.root, Path(spec["output_dir"]))
        self.output.mkdir(parents=True, exist_ok=True)
        self.v0 = Path(spec["v0_root"]).resolve()
        self.inputs = spec["inputs"]
        self.result_id = spec["result_id"]
        self.artifacts: list[dict] = []
        registry = spec.get("artifacts", [])
        if isinstance(registry, dict):
            registry = list(registry.values())
        self.registry = {item["artifact_id"]: item for item in registry}
        if len(self.registry) != len(registry):
            raise ToolError("DUPLICATE_ARTIFACT_ID", "Artifact registry has repeated IDs")

    def input_path(self, artifact_id: str) -> Path:
        if artifact_id not in self.registry:
            raise ToolError("UNREGISTERED_ARTIFACT", artifact_id)
        entry = self.registry[artifact_id]
        uri = entry["uri"]
        if Path(uri).is_absolute():
            raise ToolError("ABSOLUTE_ARTIFACT_URI", uri)
        path = _inside(self.root, self.root / uri)
        if not path.is_file() or path.stat().st_size != entry["size_bytes"] or file_sha(path) != entry["sha256"]:
            raise ToolError("ARTIFACT_INTEGRITY", artifact_id)
        if path.stat().st_size > MAX_ARTIFACT:
            raise ToolError("ARTIFACT_TOO_LARGE", artifact_id)
        return path

    def destination(self, label: str, suffix: str) -> Path:
        if not re.fullmatch(r"[a-z0-9_.-]+", label):
            raise ToolError("INVALID_ARTIFACT_LABEL", label)
        path = self.output / (label + suffix)
        if path.exists():
            raise ToolError("OUTPUT_EXISTS", str(path))
        return path

    def register(self, path: Path, label: str, media_type: str) -> str:
        path = _inside(self.output, path)
        size = path.stat().st_size
        limit = min(MAX_ARTIFACT, int(self.spec.get("limits", {}).get("max_artifact_bytes", MAX_ARTIFACT)))
        if size > limit:
            raise ToolError("ARTIFACT_TOO_LARGE", str(path))
        with path.open("rb") as handle:
            os.fsync(handle.fileno())
        # The controller still verifies this hash before accepting the package.
        artifact_id = self.result_id + "." + label
        self.artifacts.append({"record_type": "Artifact", "revision": REV,
                               "artifact_id": artifact_id, "producer_result_id": self.result_id,
                               "uri": path.relative_to(self.root).as_posix(), "sha256": file_sha(path),
                               "size_bytes": size, "media_type": media_type, "fixture_only": False})
        path.chmod(0o444)
        return artifact_id

    def save_json(self, label: str, value: Any) -> str:
        path = self.destination(label, ".json")
        with path.open("x", encoding="utf-8") as handle:
            handle.write(canonical(value) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return self.register(path, label, "application/json")

    def save_npy(self, label: str, value: Any) -> str:
        import numpy as np
        path = self.destination(label, ".npy")
        with path.open("xb") as handle:
            np.save(handle, value, allow_pickle=False)
            handle.flush()
            os.fsync(handle.fileno())
        return self.register(path, label, "application/x-npy")

    def save_sparse(self, label: str, value: Any) -> str:
        from scipy import sparse
        path = self.destination(label, ".npz")
        sparse.save_npz(path, value, compressed=True)
        return self.register(path, label, "application/x-scipy-sparse-npz")

    def save_fitted(self, label: str, value: Any) -> str:
        import joblib
        path = self.destination(label, ".joblib")
        joblib.dump(value, path, compress=3, protocol=4)
        return self.register(path, label, "application/x-joblib")

    def load_fitted(self, artifact_id: str, expected_role: str):
        import joblib
        entry = self.registry.get(artifact_id, {})
        if entry.get("media_type") != "application/x-joblib" or not artifact_id.endswith("." + expected_role):
            raise ToolError("UNTRUSTED_FITTED_ARTIFACT", artifact_id)
        # Hash/size and root containment are checked before deserializing a
        # controller-supplied own-run artifact. External pickles are unsupported.
        return joblib.load(self.input_path(artifact_id))


def _locked_data(ctx: Context, dataset: str, version: int) -> dict:
    """Read only the allowed training/validation rows, independently of fixtures."""
    import numpy as np
    import pandas as pd
    if dataset not in {"adult", "bank"} or version not in {1, 2}:
        raise ToolError("DATA_BINDING", "Expected adult/bank and training version 1/2")
    data = ctx.v0 / "data"
    manifest = {item["path"]: item for item in _json(data / "manifest.json")["files"]}

    def locked(path: str) -> Path:
        value = _inside(data, data / path)
        entry = manifest.get(path)
        if not entry or value.stat().st_size != entry["bytes"] or file_sha(value) != entry["sha256"]:
            raise ToolError("FROZEN_DATA_INTEGRITY", path)
        return value

    schemas = _json(locked("schema_and_preprocessing.json"))
    schema = schemas["datasets"][dataset]
    train = _json(locked(f"splits/{dataset}/train_v{version}.json"))
    validation = _json(locked(f"splits/{dataset}/validation.json"))
    for split in [train, validation]:
        if split["row_count"] != len(split["row_ids"]) or digest(split["row_ids"]) != split["row_ids_digest"]:
            raise ToolError("SPLIT_DIGEST", dataset)
    if set(train["row_ids"]) & set(validation["row_ids"]):
        raise ToolError("ROW_LEAKAGE", "Training and validation overlap")
    raw_name = "raw/adult/adult.data" if dataset == "adult" else "raw/bank/bank-additional-full.csv"
    raw = locked(raw_name)
    raw_digest = manifest[raw_name]["sha256"]
    wanted = set(train["row_ids"]) | set(validation["row_ids"])
    values: dict[str, list[str]] = {}
    # Rows beyond validation are not parsed into feature/label arrays.
    largest = max(int(row_id.rsplit(":", 1)[1]) for row_id in wanted)
    with raw.open(encoding="utf-8", newline="") as handle:
        if dataset == "bank":
            reader = csv.reader(handle, delimiter=";")
            if next(reader) != schema["raw_column_order"]:
                raise ToolError("RAW_COLUMNS", dataset)
        else:
            reader = csv.reader((line for line in handle if line.strip() and not line.lstrip().startswith("|")))
        for at, row in enumerate(reader, 1):
            if at > largest:
                break
            row = [value.strip() for value in row]
            if len(row) != len(schema["raw_column_order"]):
                raise ToolError("RAW_ROW_WIDTH", f"{dataset}:{at}")
            row_id = f"sha256:{raw_digest}:row:{at}"
            if row_id in wanted:
                values[row_id] = row
    if set(values) != wanted:
        raise ToolError("MISSING_ROWS", dataset)
    labels = {schema["positive_label"]: 1}
    expected_labels = {">50K", "<=50K"} if dataset == "adult" else {"yes", "no"}

    def frame(row_ids: list[str]):
        rows = [values[row_id] for row_id in row_ids]
        if any(row[-1] not in expected_labels for row in rows):
            raise ToolError("RAW_LABEL", dataset)
        result = pd.DataFrame(rows, columns=schema["raw_column_order"])
        y = np.asarray([labels.get(value, 0) for value in result[schema["label_column"]]], dtype=np.int8)
        result = result[schema["input_column_order"]].copy()
        for name in schema["numeric_column_order"]:
            result[name] = pd.to_numeric(result[name].replace("?", np.nan), errors="raise").astype(np.float64)
        missing = schema["missing_literal"]
        if missing is not None:
            for name in schema["categorical_column_order"]:
                result[name] = result[name].replace(missing, schema["missing_category"])
        return result, y

    train_x, train_y = frame(train["row_ids"])
    val_x, val_y = frame(validation["row_ids"])
    return {"schema": schema, "dataset_id": dataset, "train_version": version,
            "train_x": train_x, "train_y": train_y, "val_x": val_x, "val_y": val_y,
            "train_ids": train["row_ids"], "val_ids": validation["row_ids"],
            "training_row_ids_digest": train["row_ids_digest"],
            "validation_row_ids_digest": validation["row_ids_digest"],
            "raw_sha256": raw_digest}


def _binding(inputs: dict) -> tuple[str, int]:
    dataset = inputs["dataset_id"]
    version = int(inputs.get("train_version", 1))
    return dataset, version


def _profile(ctx: Context) -> tuple[dict, dict]:
    import numpy as np
    dataset, version = _binding(ctx.inputs)
    data = _locked_data(ctx, dataset, version)
    profile = {"dataset_id": dataset, "train_version": version,
               "row_counts": {"training": len(data["train_ids"]), "validation": len(data["val_ids"])},
               "training_row_ids_digest": data["training_row_ids_digest"],
               "validation_row_ids_digest": data["validation_row_ids_digest"],
               "feature_columns": data["schema"]["input_column_order"],
               "excluded_columns": data["schema"]["excluded_columns"],
               "training_class_counts": [int(x) for x in np.bincount(data["train_y"], minlength=2)],
               "raw_sha256": data["raw_sha256"], "test_rows_used": False}
    profile["profile_artifact_id"] = ctx.save_json("profile", profile)
    return profile, {"dataset_id": dataset, "train_version": version, "test_rows_used": False}


def _prepare(ctx: Context) -> tuple[dict, dict]:
    import numpy as np
    from scipy import sparse
    from sklearn.compose import ColumnTransformer
    from sklearn.impute import SimpleImputer
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import OneHotEncoder, StandardScaler
    dataset, version = _binding(ctx.inputs)
    data = _locked_data(ctx, dataset, version)
    schema = data["schema"]
    rows_id = ctx.save_json("rows", {"dataset_id": dataset, "train_version": version,
                                   "train_row_ids": data["train_ids"], "validation_row_ids": data["val_ids"],
                                   "training_row_ids_digest": data["training_row_ids_digest"],
                                   "validation_row_ids_digest": data["validation_row_ids_digest"]})
    train_y_id = ctx.save_npy("train_y", data["train_y"])
    val_y_id = ctx.save_npy("val_y", data["val_y"])
    families = {}
    for family in ["lr", "rf"]:
        steps = [("imputer", SimpleImputer(strategy="median"))]
        if family == "lr":
            steps.append(("scaler", StandardScaler()))
        transformer = ColumnTransformer(
            [("numeric", Pipeline(steps), schema["numeric_column_order"]),
             ("categorical", OneHotEncoder(handle_unknown="ignore", sparse_output=True, dtype=np.float64), schema["categorical_column_order"])],
            sparse_threshold=1.0, remainder="drop")
        train_matrix = sparse.csr_matrix(transformer.fit_transform(data["train_x"]), dtype=np.float64)
        val_matrix = sparse.csr_matrix(transformer.transform(data["val_x"]), dtype=np.float64)
        transformer_id = ctx.save_fitted(family + ".preprocessor", transformer)
        train_matrix_id = ctx.save_sparse(family + ".train_matrix", train_matrix)
        val_matrix_id = ctx.save_sparse(family + ".val_matrix", val_matrix)
        numeric = transformer.named_transformers_["numeric"]
        encoder = transformer.named_transformers_["categorical"]
        stats = {"dataset_id": dataset, "train_version": version, "family": family,
                 "fit_on": "training_only", "input_columns": schema["input_column_order"],
                 "numeric_columns": schema["numeric_column_order"],
                 "categorical_columns": schema["categorical_column_order"],
                 "excluded_columns": schema["excluded_columns"],
                 "training_row_ids_digest": data["training_row_ids_digest"],
                 "validation_row_ids_digest": data["validation_row_ids_digest"],
                 "numeric_imputer_medians": numeric.named_steps["imputer"].statistics_.tolist(),
                 "category_values": [value.tolist() for value in encoder.categories_],
                 "feature_names": transformer.get_feature_names_out().tolist(),
                 "scaler": ({"mean": numeric.named_steps["scaler"].mean_.tolist(),
                              "scale": numeric.named_steps["scaler"].scale_.tolist(),
                              "var": numeric.named_steps["scaler"].var_.tolist()} if family == "lr" else None),
                 "matrix_format": "csr", "matrix_dtype": "float64",
                 "train_shape": list(train_matrix.shape), "validation_shape": list(val_matrix.shape),
                 "train_nnz": int(train_matrix.nnz), "validation_nnz": int(val_matrix.nnz),
                 "test_rows_used": False}
        stats_id = ctx.save_json(family + ".transform_stats", stats)
        families[family] = {"preprocessor_artifact_id": transformer_id,
                            "matrix_artifact_id": train_matrix_id, "train_matrix_artifact_id": train_matrix_id,
                            "val_matrix_artifact_id": val_matrix_id,
                            "train_y_artifact_id": train_y_id, "val_y_artifact_id": val_y_id,
                            "rows_artifact_id": rows_id, "transform_stats_artifact_id": stats_id}
    payload = {"dataset_id": dataset, "train_version": version, "families": families,
               "training_row_ids_digest": data["training_row_ids_digest"],
               "validation_row_ids_digest": data["validation_row_ids_digest"],
               "row_counts": {"training": len(data["train_ids"]), "validation": len(data["val_ids"])}}
    return payload, {"fit_on": "training_only", "dataset_id": dataset, "train_version": version,
                     "training_row_ids_digest": data["training_row_ids_digest"],
                     "validation_row_ids_digest": data["validation_row_ids_digest"], "test_rows_used": False}


def _family(ctx: Context, expected_prefix: str) -> tuple[str, dict]:
    family = str(ctx.inputs["family"]).lower()
    if family not in {"lr", "rf"} or ctx.spec["tool"] != expected_prefix + "_" + family:
        raise ToolError("FAMILY_TOOL_MISMATCH", family)
    prepared = ctx.inputs["prepare"]
    if prepared["dataset_id"] not in {"adult", "bank"} or prepared["train_version"] not in {1, 2}:
        raise ToolError("PREPARE_BINDING", "Unrecognized prepared data binding")
    return family, prepared


def _prepared_rows(ctx: Context, prepared: dict, family: str) -> dict:
    rows = _json(ctx.input_path(prepared["families"][family]["rows_artifact_id"]))
    if rows["dataset_id"] != prepared["dataset_id"] or rows["train_version"] != prepared["train_version"]:
        raise ToolError("PREPARED_ROWS_BINDING", family)
    for field, digest_field in [("train_row_ids", "training_row_ids_digest"),
                                ("validation_row_ids", "validation_row_ids_digest")]:
        if digest(rows[field]) != rows[digest_field] or rows[digest_field] != prepared[digest_field]:
            raise ToolError("PREPARED_ROWS_DIGEST", family)
    if set(rows["train_row_ids"]) & set(rows["validation_row_ids"]):
        raise ToolError("PREPARED_ROWS_OVERLAP", family)
    return rows


def _fit(ctx: Context) -> tuple[dict, dict]:
    import numpy as np
    from scipy import sparse
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    family, prepared = _family(ctx, "fit")
    requested = ctx.inputs["parameters"]
    recipes = _json(ctx.v0 / "environment" / "model_recipes.json")
    allowed = [recipes["lr_v1"]] if family == "lr" else [recipes["rf_v1"], recipes["rf_v2"]]
    if requested not in allowed:
        raise ToolError("RECIPE_NOT_LOCKED", family)
    bindings = prepared["families"][family]
    rows = _prepared_rows(ctx, prepared, family)
    matrix = sparse.load_npz(ctx.input_path(bindings["train_matrix_artifact_id"]))
    labels = np.load(ctx.input_path(bindings["train_y_artifact_id"]), allow_pickle=False)
    if matrix.format != "csr" or matrix.dtype != np.dtype("float64") or labels.dtype != np.dtype("int8"):
        raise ToolError("TRAIN_ARRAY_FORMAT", family)
    if matrix.shape[0] != len(labels) or len(labels) != len(rows["train_row_ids"]) or set(labels.tolist()) != {0, 1}:
        raise ToolError("TRAIN_ARRAY_SHAPE", family)
    model = LogisticRegression(**requested) if family == "lr" else RandomForestClassifier(**requested)
    model.fit(matrix, labels)
    if model.classes_.tolist() != [0, 1] or model.get_params(deep=False) != requested:
        raise ToolError("MODEL_PARAMETERS", family)
    model_id = ctx.save_fitted(family + ".model", model)
    parameters = {"family": family, "model_parameters": model.get_params(deep=False),
                  "training_row_ids_digest": prepared["training_row_ids_digest"],
                  "model_artifact_id": model_id, "matrix_artifact_id": bindings["train_matrix_artifact_id"],
                  "preprocessor_artifact_id": bindings["preprocessor_artifact_id"],
                  "rows_artifact_id": bindings["rows_artifact_id"],
                  "training_samples": int(matrix.shape[0]), "training_features": int(matrix.shape[1]),
                  "actual_model_fit": True, "sample_weight_used": False,
                  "n_iter": model.n_iter_.tolist() if family == "lr" else None}
    payload = {"dataset_id": prepared["dataset_id"], "train_version": prepared["train_version"],
               "family": family, "model_artifact_id": model_id, "parameters": requested,
               "training_row_ids_digest": prepared["training_row_ids_digest"],
               "matrix_artifact_id": bindings["train_matrix_artifact_id"],
               "preprocessor_artifact_id": bindings["preprocessor_artifact_id"]}
    return payload, parameters


def _predict(ctx: Context) -> tuple[dict, dict]:
    import numpy as np
    from scipy import sparse
    family, prepared = _family(ctx, "predict")
    fitted = ctx.inputs["fit"]
    if fitted["family"] != family or fitted["training_row_ids_digest"] != prepared["training_row_ids_digest"]:
        raise ToolError("FIT_PREPARE_MISMATCH", family)
    bindings = prepared["families"][family]
    rows = _prepared_rows(ctx, prepared, family)
    matrix = sparse.load_npz(ctx.input_path(bindings["val_matrix_artifact_id"]))
    if matrix.format != "csr" or matrix.dtype != np.dtype("float64"):
        raise ToolError("PREDICT_ARRAY_FORMAT", family)
    model = ctx.load_fitted(fitted["model_artifact_id"], family + ".model")
    if model.classes_.tolist() != [0, 1] or model.get_params(deep=False) != fitted["parameters"]:
        raise ToolError("MODEL_BINDING", family)
    probabilities = np.asarray(model.predict_proba(matrix)[:, 1], dtype=np.float64)
    if probabilities.ndim != 1 or len(probabilities) != matrix.shape[0] or len(probabilities) != len(rows["validation_row_ids"]) or not np.all(np.isfinite(probabilities)) or np.any((probabilities < 0) | (probabilities > 1)):
        raise ToolError("INVALID_PROBABILITIES", family)
    prediction_id = ctx.save_npy(family + ".predictions", probabilities)
    payload = {"dataset_id": prepared["dataset_id"], "train_version": prepared["train_version"],
               "family": family, "prediction_artifact_id": prediction_id,
               "model_artifact_id": fitted["model_artifact_id"],
               "preprocessor_artifact_id": bindings["preprocessor_artifact_id"],
               "validation_row_ids_digest": prepared["validation_row_ids_digest"],
               "training_row_ids_digest": prepared["training_row_ids_digest"],
               "row_count": int(len(probabilities))}
    return payload, {"positive_class": 1, "prediction_dtype": "float64", "validation_row_ids_digest": prepared["validation_row_ids_digest"],
                     "model_artifact_id": fitted["model_artifact_id"], "prediction_artifact_id": prediction_id,
                     "preprocessor_artifact_id": bindings["preprocessor_artifact_id"],
                     "rows_artifact_id": bindings["rows_artifact_id"], "actual_model_predict": True}


def _summary(ctx: Context) -> tuple[dict, dict]:
    import numpy as np
    from sklearn.metrics import accuracy_score, average_precision_score, f1_score, roc_auc_score
    family, prepared = _family(ctx, "summary")
    prediction = ctx.inputs["predict"]
    rows = _prepared_rows(ctx, prepared, family)
    if prediction["family"] != family or prediction["validation_row_ids_digest"] != prepared["validation_row_ids_digest"]:
        raise ToolError("PREDICT_PREPARE_MISMATCH", family)
    probabilities = np.load(ctx.input_path(prediction["prediction_artifact_id"]), allow_pickle=False)
    labels = np.load(ctx.input_path(prepared["families"][family]["val_y_artifact_id"]), allow_pickle=False)
    if labels.shape != probabilities.shape or len(labels) != len(rows["validation_row_ids"]) or probabilities.dtype != np.dtype("float64") or labels.dtype != np.dtype("int8") or not np.all(np.isfinite(probabilities)) or np.any((probabilities < 0) | (probabilities > 1)):
        raise ToolError("SUMMARY_ARRAY_FORMAT", family)
    hard = (probabilities >= 0.5).astype(np.int8)
    metrics = {"average_precision": float(average_precision_score(labels, probabilities)),
               "roc_auc": float(roc_auc_score(labels, probabilities)),
               "f1": float(f1_score(labels, hard, zero_division=0)),
               "accuracy": float(accuracy_score(labels, hard))}
    raw = {"family": family, "metrics": metrics, "threshold": 0.5,
           "row_count": len(labels), "validation_row_ids_digest": prepared["validation_row_ids_digest"],
           "prediction_artifact_id": prediction["prediction_artifact_id"],
           "model_artifact_id": prediction["model_artifact_id"]}
    metrics_id = ctx.save_json(family + ".metrics", raw)
    payload = {"dataset_id": prepared["dataset_id"], "train_version": prepared["train_version"],
               "family": family, "metrics": metrics, "metrics_artifact_id": metrics_id,
               "prediction_artifact_id": prediction["prediction_artifact_id"],
               "model_artifact_id": prediction["model_artifact_id"],
               "matrix_artifact_id": prepared["families"][family]["matrix_artifact_id"],
               "validation_row_ids_digest": prepared["validation_row_ids_digest"]}
    return payload, {"unmodified_metrics": metrics, "threshold": 0.5, "validation_row_ids_digest": prepared["validation_row_ids_digest"],
                     "prediction_artifact_id": prediction["prediction_artifact_id"], "model_artifact_id": prediction["model_artifact_id"],
                     "matrix_artifact_id": prepared["families"][family]["matrix_artifact_id"], "raw_metrics_artifact_id": metrics_id}


def _publish(ctx: Context) -> tuple[dict, dict]:
    report = ctx.inputs["report"]
    if ctx.inputs.get("action") != "publish_manifest":
        raise ToolError("PUBLISH_ACTION", "Expected publish_manifest")
    # This tool prepares a candidate only. The controller's transaction guard
    # authorizes the manifest + report-index business effect together.
    references = {key: report[key] for key in ["model_artifact_id", "prediction_artifact_id", "report_artifact_id"]}
    for artifact_id in references.values():
        ctx.input_path(artifact_id)
    candidate = {"action": "publish_manifest", **references,
                 "selected_family": report.get("selected_family", report.get("family")),
                 "validation_row_ids_digest": report.get("validation_row_ids_digest"),
                 "metrics": report.get("metrics"), "fixture_only": False}
    candidate_id = ctx.save_json("candidate_manifest", candidate)
    return {"action": "publish_manifest", "candidate_artifact_id": candidate_id, **references}, {"candidate_only": True, "business_effect_in_controller_transaction": True}


def execute(spec: dict) -> dict:
    """Execute one allowlisted trusted CPU tool in the already-limited worker."""
    tool = spec.get("tool")
    if tool not in ALLOWED_TOOLS:
        raise ToolError("TOOL_NOT_ALLOWED", str(tool))
    if not isinstance(spec.get("result_id"), str) or not spec["result_id"]:
        raise ToolError("RESULT_ID_REQUIRED", "result_id is required")
    ctx = Context(spec)
    dispatch = {"profile": _profile, "prepare": _prepare,
                "fit_lr": _fit, "fit_rf": _fit,
                "predict_lr": _predict, "predict_rf": _predict,
                "summary_lr": _summary, "summary_rf": _summary, "publish": _publish}
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        payload, parameters = dispatch[tool](ctx)
    return {"payload": payload, "artifacts": ctx.artifacts, "parameters": parameters,
            "warnings": [{"category": type(item.message).__name__, "message": str(item.message)} for item in captured]}
