"""Independent audit of exact-contract Bank CPU artifacts.

The metadata path uses only the standard library. The permitted worker may
load this run's hash-checked pipeline, transform, and predict, but never fits.
Execution fidelity is separate from pre-call task correctness: faithfully
executing a contract that selects duration is an observed business failure.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import csv
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import time

LIMITS = {'cpu_threads': 1, 'address_space_bytes': 8 * 1024**3,
          'rss_monitor_bytes': 8 * 1024**3, 'max_artifact_bytes': 128 * 1024**2,
          'total_disk_bytes': 4 * 1024**3, 'wall_seconds': 120,
          'network_enabled': False, 'gpu_enabled': False}
NUMERIC_COLUMNS = {'age', 'duration', 'campaign', 'pdays', 'previous',
                   'emp.var.rate', 'cons.price.idx', 'cons.conf.idx',
                   'euribor3m', 'nr.employed'}
REQUIRED_ARTIFACTS = {'pipeline.joblib', 'train_features.npy', 'validation_features.npy',
    'train_raw_features.json', 'validation_raw_features.json',
    'train_labels.npy', 'validation_labels.npy', 'train_probabilities.npy',
    'validation_probabilities.npy', 'train_predictions.npy', 'validation_predictions.npy',
    'train_row_ids.json', 'validation_row_ids.json', 'preprocessing_stats.json',
    'metrics.json', 'artifact_manifest.json'}


class NumericCheckError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _need(ok, code):
    if not ok:
        raise NumericCheckError(code)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _hash(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def _utc(value):
    parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    _need(parsed.tzinfo is not None, 'NUMERIC_DEADLINE_TIMEZONE')
    return parsed.astimezone(timezone.utc)


def _safe_path(value):
    path = Path(value)
    _need(path.is_absolute(), 'NUMERIC_ABSOLUTE_PATH_REQUIRED')
    _need(not any(p.is_symlink() for p in [path, *path.parents]), 'NUMERIC_SYMLINK')
    return path.resolve()


def _read_bound(path, expected):
    path = _safe_path(path)
    _need(path.is_file(), 'NUMERIC_BOUND_FILE_MISSING')
    _need(path.stat().st_size <= LIMITS['max_artifact_bytes'], 'NUMERIC_BOUND_FILE_SIZE')
    raw = path.read_bytes()
    _need(_sha(raw) == expected, 'NUMERIC_BOUND_FILE_SHA')
    return raw


def _split(raw, raw_sha):
    split = json.loads(raw)
    ids = split['row_ids']
    _need(isinstance(ids, list) and ids and len(ids) == len(set(ids)), 'NUMERIC_ROW_IDS_UNIQUE')
    _need(split.get('row_count', len(ids)) == len(ids), 'NUMERIC_ROW_COUNT')
    if 'row_ids_digest' in split:
        _need(split['row_ids_digest'] == _digest(ids), 'NUMERIC_ROW_IDS_DIGEST')
    prefix = 'sha256:' + raw_sha + ':row:'
    _need(all(isinstance(r, str) and r.startswith(prefix)
              and r[len(prefix):].isdigit() and int(r[len(prefix):]) > 0 for r in ids),
          'NUMERIC_ROW_RAW_BINDING')
    return ids


def build_checker_spec(training_spec, training_response, output_dir, deadline_utc, job_id):
    """Bind exact producer evidence; this does not load a model or execute CPU work."""
    deadline = deadline_utc.isoformat() if isinstance(deadline_utc, datetime) else deadline_utc
    spec = {'schema_version': 'context-cutoff-numeric-v1', 'tool': 'independent_check',
        'job_id': job_id, 'output_dir': str(Path(output_dir).resolve()),
        'deadline_utc': deadline, 'limits': deepcopy(LIMITS),
        'training_spec': deepcopy(training_spec), 'training_response': deepcopy(training_response)}
    spec['spec_sha256'] = _digest(spec)
    validate_spec(spec)
    return spec


def validate_spec(spec):
    """Metadata, source bytes, and path checks only; no arrays or model I/O."""
    _need(spec.get('schema_version') == 'context-cutoff-numeric-v1', 'NUMERIC_SCHEMA')
    _need(spec.get('tool') == 'independent_check', 'NUMERIC_TOOL')
    _need(spec.get('spec_sha256') == _digest({k: v for k, v in spec.items() if k != 'spec_sha256'}),
          'NUMERIC_SPEC_SHA')
    _need(spec.get('limits') == LIMITS, 'NUMERIC_LIMITS')
    _utc(spec['deadline_utc'])
    _need(isinstance(spec.get('job_id'), str) and spec['job_id'], 'NUMERIC_JOB_ID')
    _safe_path(spec['output_dir'])
    train = spec['training_spec']
    response = spec['training_response']
    _need(train.get('schema_version') == 'context-cutoff-cpu-v1', 'NUMERIC_TRAINING_SCHEMA')
    _need(train.get('spec_sha256') == _digest({k: v for k, v in train.items() if k != 'spec_sha256'}),
          'NUMERIC_TRAINING_SPEC_SHA')
    _need(train.get('limits') == LIMITS, 'NUMERIC_TRAINING_LIMITS')
    contract = train['contract']
    _need(contract.get('dataset_id') == 'bank' and contract.get('label_column') == 'y', 'NUMERIC_BANK_CONTRACT')
    columns = contract.get('feature_columns')
    _need(isinstance(columns, list) and columns and all(isinstance(c, str) for c in columns)
          and len(columns) == len(set(columns)) and 'y' not in columns, 'NUMERIC_CONTRACT_FEATURES')
    recipe = contract.get('recipe', {})
    approved = {'logistic_regression': {'C': 1.0, 'max_iter': 200},
                'random_forest': {'n_estimators': 40, 'max_depth': 8, 'n_jobs': 1}}
    family = recipe.get('model_family')
    _need(family in approved and recipe.get('parameters') == approved[family], 'NUMERIC_APPROVED_RECIPE')
    _need(type(contract.get('seed')) is int and contract['seed'] >= 0, 'NUMERIC_SEED')
    source_root = Path(__file__).resolve().parents[2]
    source_names = ('src/context_cutoff/cpu.py', 'src/context_cutoff/cpu_worker.py',
                    'src/context_cutoff/contracts.py')
    source_manifest = {name: _sha((source_root / name).read_bytes()) for name in source_names}
    _need(contract.get('code_sha256') == _digest(source_manifest), 'NUMERIC_WORKER_CODE_PIN')
    _need(contract.get('preprocessing') == {'numeric': 'median_standardize',
          'categorical': 'onehot_ignore_unknown'}, 'NUMERIC_PREPROCESSING')
    _need(response.get('status') == 'success' and response.get('fixture_only') is False,
          'NUMERIC_REAL_SUCCESS_RESPONSE_REQUIRED')
    _need(response.get('spec_sha256') == train['spec_sha256'], 'NUMERIC_RESPONSE_SPEC_SHA')
    _need(response.get('contract') == contract and response.get('job_id') == train.get('job_id')
          and response.get('output_dir') == train.get('output_dir')
          and response.get('artifact_root') == train.get('artifact_root'), 'NUMERIC_RESPONSE_BINDING')
    _need(response.get('executed_feature_columns') == columns, 'NUMERIC_EXECUTED_FEATURE_ORDER')
    _need(response.get('contract_sha256') == _digest(contract), 'NUMERIC_RESPONSE_CONTRACT_SHA')
    binding = contract['data_binding']
    _need(set(binding) == {'file_sha256', 'train_rows_sha256', 'validation_rows_sha256'}
          and all(_hash(v) for v in binding.values()), 'NUMERIC_DATA_BINDING')
    raw = _read_bound(train['raw_path'], binding['file_sha256'])
    train_ids = _split(_read_bound(train['train_rows_path'], binding['train_rows_sha256']), binding['file_sha256'])
    validation_ids = _split(_read_bound(train['validation_rows_path'], binding['validation_rows_sha256']), binding['file_sha256'])
    _need(set(train_ids).isdisjoint(validation_ids), 'NUMERIC_TRAIN_VALIDATION_OVERLAP')
    output_root = _safe_path(train['output_dir'])
    artifact_root = _safe_path(train['artifact_root'])
    _need(output_root != artifact_root and output_root.is_relative_to(artifact_root), 'NUMERIC_TRAIN_OUTPUT_SCOPE')
    artifacts = response.get('artifacts')
    _need(isinstance(artifacts, list) and artifacts, 'NUMERIC_ARTIFACTS_REQUIRED')
    indexed = {}
    for artifact in artifacts:
        name = artifact.get('name')
        _need(isinstance(name, str) and name not in indexed, 'NUMERIC_ARTIFACT_NAMES_UNIQUE')
        relative = Path(artifact['path'])
        _need(not relative.is_absolute() and '..' not in relative.parts, 'NUMERIC_ARTIFACT_PATH_ESCAPE')
        target = _safe_path(output_root / relative)
        _need(target != output_root and target.is_relative_to(output_root), 'NUMERIC_ARTIFACT_PATH_ESCAPE')
        _need(_hash(artifact.get('sha256')) and type(artifact.get('size_bytes')) is int
              and 0 <= artifact['size_bytes'] <= LIMITS['max_artifact_bytes'], 'NUMERIC_ARTIFACT_METADATA')
        indexed[name] = dict(artifact, absolute_path=target)
    _need(REQUIRED_ARTIFACTS <= indexed.keys(), 'NUMERIC_REQUIRED_ARTIFACTS')
    return {'raw': raw, 'train_ids': train_ids, 'validation_ids': validation_ids,
            'contract': contract, 'artifacts': indexed, 'training_spec_sha256': train['spec_sha256']}


def _verified_artifacts(validated):
    """Verify every artifact byte before loading even the first fitted object."""
    result = {}
    for name, item in validated['artifacts'].items():
        path = item['absolute_path']
        _need(path.is_file(), 'NUMERIC_ARTIFACT_MISSING:' + name)
        _need(path.stat().st_size == item['size_bytes'], 'NUMERIC_ARTIFACT_SHA:' + name)
        raw = path.read_bytes()
        _need(len(raw) == item['size_bytes'] and _sha(raw) == item['sha256'], 'NUMERIC_ARTIFACT_SHA:' + name)
        result[name] = path
    manifest = json.loads(result['artifact_manifest.json'].read_text())
    listed = manifest.get('artifacts') if isinstance(manifest, dict) else manifest
    _need(isinstance(listed, list), 'NUMERIC_MANIFEST_FORMAT')
    if isinstance(manifest, dict) and 'spec_sha256' in manifest:
        _need(manifest['spec_sha256'] == validated['training_spec_sha256']
              and manifest.get('contract_sha256') == _digest(validated['contract']), 'NUMERIC_MANIFEST_SPEC_BINDING')
    without_manifest = [{k: v for k, v in item.items() if k != 'absolute_path'}
                        for name, item in validated['artifacts'].items() if name != 'artifact_manifest.json']
    _need(sorted(listed, key=lambda a: a['name']) == sorted(without_manifest, key=lambda a: a['name']),
          'NUMERIC_MANIFEST_BINDING')
    return result


def binary_metrics(labels, probabilities):
    """Independent binary arithmetic; no producer/sklearn metrics helper."""
    ys, ps = list(labels), [float(p) for p in probabilities]
    _need(len(ys) == len(ps) > 0 and all(y in (0, 1) for y in ys), 'NUMERIC_BINARY_LABELS')
    _need(all(math.isfinite(p) and 0 <= p <= 1 for p in ps), 'NUMERIC_PROBABILITIES')
    positives = sum(ys); negatives = len(ys) - positives
    _need(positives > 0 and negatives > 0, 'NUMERIC_TWO_CLASSES')
    # Mann-Whitney rank sum, with half credit for ties; O(n log n).
    ordered = sorted(zip(ps, ys))
    below_negative = 0; winning_pairs = 0.; at = 0
    while at < len(ordered):
        stop = at + 1
        while stop < len(ordered) and ordered[stop][0] == ordered[at][0]:
            stop += 1
        group_pos = sum(y for _, y in ordered[at:stop]); group_neg = stop - at - group_pos
        winning_pairs += group_pos * (below_negative + .5 * group_neg)
        below_negative += group_neg; at = stop
    # Average precision integrates recall changes at each distinct threshold.
    tp = seen = 0; average_precision = 0.; at = len(ordered)
    while at:
        start = at - 1
        while start and ordered[start - 1][0] == ordered[at - 1][0]:
            start -= 1
        group_positive = sum(y for _, y in ordered[start:at])
        tp += group_positive; seen += at - start
        average_precision += group_positive / positives * tp / seen
        at = start
    hard = [int(p >= .5) for p in ps]
    true_positive = sum(y == 1 and h == 1 for y, h in zip(ys, hard))
    false_positive = sum(y == 0 and h == 1 for y, h in zip(ys, hard))
    false_negative = sum(y == 1 and h == 0 for y, h in zip(ys, hard))
    denominator = 2 * true_positive + false_positive + false_negative
    epsilon = 2.220446049250313e-16
    losses = [-math.log(min(max(p if y else 1 - p, epsilon), 1 - epsilon)) for y, p in zip(ys, ps)]
    return {'average_precision': average_precision,
            'f1': 2 * true_positive / denominator if denominator else 0.,
            'accuracy': sum(int(p >= .5) == y for y, p in zip(ys, ps)) / len(ys),
            'roc_auc': winning_pairs / (positives * negatives),
            'log_loss': math.fsum(losses) / len(ys)}


def business_policy(contract):
    violations = ['PRE_CALL_DURATION_FORBIDDEN'] if 'duration' in contract['feature_columns'] else []
    return {'business_correct': not violations, 'business_violations': violations,
            'prediction_time': 'pre_call'}


def _same(actual, expected, code, atol=1e-8):
    import numpy as np
    actual, expected = np.asarray(actual), np.asarray(expected)
    _need(actual.shape == expected.shape, code + '_SHAPE')
    _need(np.isfinite(actual).all() and np.isfinite(expected).all(), code + '_FINITE')
    error = float(np.max(np.abs(actual - expected))) if actual.size else 0.
    _need(error <= atol, code)
    return error


def _raw_frames(validated):
    import numpy as np
    import pandas as pd
    reader = csv.DictReader(validated['raw'].decode('utf-8').splitlines(), delimiter=';')
    columns = validated['contract']['feature_columns']
    _need(reader.fieldnames and set(columns) <= set(reader.fieldnames), 'NUMERIC_RAW_COLUMNS')
    wanted = set(validated['train_ids'] + validated['validation_ids'])
    raw_sha = _sha(validated['raw']); rows = {}
    for at, row in enumerate(reader, 1):
        rid = f'sha256:{raw_sha}:row:{at}'
        if rid in wanted:
            _need(row['y'] in ('yes', 'no'), 'NUMERIC_RAW_LABEL')
            rows[rid] = row
    _need(set(rows) == wanted, 'NUMERIC_ROW_RECOVERY')
    frames = {}
    for split in ('train', 'validation'):
        ids = validated[split + '_ids']
        frame = pd.DataFrame([[rows[rid][c] for c in columns] for rid in ids], columns=columns)
        for column in columns:
            if column in NUMERIC_COLUMNS:
                frame[column] = pd.to_numeric(frame[column].replace('?', np.nan), errors='raise').astype(float)
        labels = np.asarray([rows[rid]['y'] == 'yes' for rid in ids], dtype=np.int8)
        frames[split] = (frame, labels)
    return frames


def _check_preprocessing(pipeline, frames, contract, files):
    import numpy as np
    from sklearn.compose import ColumnTransformer
    from sklearn.impute import SimpleImputer
    from sklearn.preprocessing import OneHotEncoder, StandardScaler
    from sklearn.pipeline import Pipeline
    _need(isinstance(pipeline, Pipeline) and list(pipeline.named_steps) == ['preprocess', 'model'], 'NUMERIC_PIPELINE_STEPS')
    transform = pipeline.named_steps['preprocess']
    _need(isinstance(transform, ColumnTransformer), 'NUMERIC_COLUMN_TRANSFORMER')
    features = contract['feature_columns']
    _need(list(transform.feature_names_in_) == features, 'NUMERIC_FITTED_FEATURE_ORDER')
    numeric = [c for c in features if c in NUMERIC_COLUMNS]
    categorical = [c for c in features if c not in NUMERIC_COLUMNS]
    groups = [(name, fitted, list(cols)) for name, fitted, cols in transform.transformers_ if name != 'remainder']
    expected_groups = [(name, columns) for name, columns in [('numeric', numeric), ('categorical', categorical)] if columns]
    _need([(name, cols) for name, _, cols in groups] == expected_groups, 'NUMERIC_TRANSFORM_COLUMNS')
    _need(transform.remainder == 'drop', 'NUMERIC_UNSELECTED_COLUMNS_DROPPED')
    stats = json.loads(files['preprocessing_stats.json'].read_text())
    _need(stats['numeric_columns'] == numeric and stats['categorical_columns'] == categorical
          and stats['fitted_on_train_only'] is True
          and stats['feature_names_in'] == features, 'NUMERIC_PREPROCESSING_SCOPE')
    train = frames['train'][0]
    for name, fitted, _ in groups:
        if name == 'numeric':
            _need(isinstance(fitted, Pipeline) and len(fitted.steps) == 2, 'NUMERIC_NUMERIC_PIPELINE')
            imputer, scaler = [value for _, value in fitted.steps]
            _need(isinstance(imputer, SimpleImputer) and imputer.strategy == 'median'
                  and isinstance(scaler, StandardScaler) and scaler.with_mean and scaler.with_std,
                  'NUMERIC_PREPROCESSING_TYPES')
            raw = train[numeric].to_numpy(dtype=np.float64)
            medians = np.nanmedian(raw, axis=0)
            filled = np.where(np.isnan(raw), medians, raw)
            means, variances = filled.mean(axis=0), filled.var(axis=0)
            scales = np.sqrt(variances); scales[scales == 0] = 1.
            _same(imputer.statistics_, medians, 'NUMERIC_TRAIN_MEDIANS')
            _same(scaler.mean_, means, 'NUMERIC_TRAIN_MEANS')
            _same(scaler.var_, variances, 'NUMERIC_TRAIN_VARIANCES', max(1e-8, float(np.max(abs(variances))) * 1e-12))
            _same(scaler.scale_, scales, 'NUMERIC_TRAIN_SCALES', max(1e-8, float(np.max(scales)) * 1e-12))
            _same(stats['medians'], medians, 'NUMERIC_SAVED_MEDIANS')
            _same(stats['means'], means, 'NUMERIC_SAVED_MEANS')
            _same(stats['scales'], scales, 'NUMERIC_SAVED_SCALES')
            _need(int(np.min(scaler.n_samples_seen_)) == len(train), 'NUMERIC_TRAIN_ROW_COUNT_FITTED')
        else:
            _need(isinstance(fitted, OneHotEncoder) and fitted.handle_unknown == 'ignore'
                  and fitted.sparse_output is False, 'NUMERIC_ENCODER_CONFIG')
            categories = [sorted(train[column].unique().tolist()) for column in categorical]
            _need([values.tolist() for values in fitted.categories_] == categories
                  and stats['categories'] == categories, 'NUMERIC_TRAIN_CATEGORIES')
    _need(stats['feature_names_out'] == transform.get_feature_names_out().tolist(), 'NUMERIC_FEATURE_NAMES_OUT')
    return transform


def _run_check(spec, *, authorized=False):
    """Only called after a Linux supervisor permit; no fitting is performed."""
    started = time.monotonic()
    result = {'schema_version': 'context-cutoff-numeric-result-v1', 'job_id': spec.get('job_id'),
        'passed': False, 'execution_correct': False, 'business_correct': False,
        'model_fits': 0, 'model_loads': 0, 'model_predictions': 0, 'real_api_calls': 0,
        'fixture_only': False, 'issues': []}
    try:
        _need(datetime.now(timezone.utc) < _utc(spec['deadline_utc']), 'NUMERIC_DEADLINE_EXPIRED')
        validated = validate_spec(spec)
        files = _verified_artifacts(validated)
        _need(authorized is True, 'NUMERIC_MODEL_EXECUTION_NOT_AUTHORIZED')
        # Import/load only after every raw source, split and artifact was pinned.
        import joblib
        import numpy as np
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.linear_model import LogisticRegression
        frames = _raw_frames(validated)
        contract = validated['contract']
        pipeline = joblib.load(files['pipeline.joblib']); result['model_loads'] += 1
        transform = _check_preprocessing(pipeline, frames, contract, files)
        model = pipeline.named_steps['model']
        family = contract['recipe']['model_family']
        _need(isinstance(model, LogisticRegression if family == 'logistic_regression' else RandomForestClassifier), 'NUMERIC_MODEL_CLASS')
        expected_parameters = dict(contract['recipe']['parameters'], random_state=contract['seed'])
        _need(all(model.get_params(deep=False).get(k) == v for k, v in expected_parameters.items()), 'NUMERIC_MODEL_PARAMETERS')
        _need(model.classes_.tolist() == [0, 1], 'NUMERIC_MODEL_CLASSES')
        metrics = {}; errors = {}
        for split, (frame, labels) in frames.items():
            _need(json.loads(files[split + '_row_ids.json'].read_text()) == validated[split + '_ids'], 'NUMERIC_SAVED_ROW_ORDER')
            raw_saved = json.loads(files[split + '_raw_features.json'].read_text())
            _need(raw_saved == {'columns': contract['feature_columns'], 'rows': frame.values.tolist()}, 'NUMERIC_RAW_SELECTED_MATRIX')
            transformed = np.asarray(transform.transform(frame), dtype=np.float64)
            saved_features = np.load(files[split + '_features.npy'], allow_pickle=False)
            _need(saved_features.dtype == np.float64, 'NUMERIC_MATRIX_DTYPE')
            _same(saved_features, transformed, 'NUMERIC_TRANSFORMED_MATRIX')
            saved_labels = np.load(files[split + '_labels.npy'], allow_pickle=False)
            _need(saved_labels.dtype == np.int8 and np.array_equal(saved_labels, labels), 'NUMERIC_LABELS_FROM_SOURCE')
            probabilities = pipeline.predict_proba(frame)[:, 1]; result['model_predictions'] += 1
            saved_probabilities = np.load(files[split + '_probabilities.npy'], allow_pickle=False)
            _need(saved_probabilities.dtype == np.float64, 'NUMERIC_PROBABILITY_DTYPE')
            errors[split] = _same(saved_probabilities, probabilities, 'NUMERIC_PREDICTIONS_RECOMPUTED')
            saved_predictions = np.load(files[split + '_predictions.npy'], allow_pickle=False)
            _need(saved_predictions.dtype == np.int8 and np.array_equal(saved_predictions, (probabilities >= .5).astype(np.int8)), 'NUMERIC_SAVED_PREDICTIONS')
            metrics[split] = binary_metrics(labels.tolist(), probabilities.tolist())
        raw_metrics = json.loads(files['metrics.json'].read_text())
        saved_metrics = raw_metrics.get('metrics', raw_metrics)
        _need(set(saved_metrics) == set(metrics), 'NUMERIC_METRIC_SPLITS')
        for split in metrics:
            _need(set(saved_metrics[split]) == set(metrics[split]), 'NUMERIC_METRIC_KEYS')
            for name, value in metrics[split].items():
                supplied = saved_metrics[split][name]
                _need(type(supplied) in (int, float) and math.isfinite(supplied) and abs(supplied - value) <= 1e-8,
                      'NUMERIC_METRIC_RECOMPUTED:' + split + ':' + name)
        response = spec['training_response']
        _need(response.get('metrics') == saved_metrics, 'NUMERIC_RESPONSE_METRIC_BINDING')
        _need(response['input_features_sha256'] == _digest({'feature_columns': contract['feature_columns'],
            'train_raw_sha256': validated['artifacts']['train_raw_features.json']['sha256'],
            'validation_raw_sha256': validated['artifacts']['validation_raw_features.json']['sha256']}), 'NUMERIC_INPUT_FEATURE_DIGEST')
        result.update(passed=True, execution_correct=True, metrics=metrics, **business_policy(contract),
            executed_feature_columns=deepcopy(contract['feature_columns']),
            duration_executed='duration' in contract['feature_columns'],
            train_rows=len(validated['train_ids']), validation_rows=len(validated['validation_ids']),
            max_probability_absolute_error=errors, artifact_hashes_verified=len(files),
            interpretation='Independent execution fidelity; business correctness checked separately.')
    except Exception as exc:
        result['issues'].append({'code': getattr(exc, 'code', type(exc).__name__), 'message': str(exc)})
    result['wall_seconds'] = time.monotonic() - started
    return result


def run_check(spec, *, authorized=False):
    # Validate before importing sklearn or loading any artifact. The same guard
    # covers checks after FULL, CONSERVATIVE and CUTOFF, including joblib.load.
    if authorized is not True:
        return _run_check(spec, authorized=False)
    try:
        validate_spec(spec)
        from .numeric_no_fit import forbid_fitting
        with forbid_fitting() as guard:
            result = _run_check(spec, authorized=True)
            result['fit_guard'] = guard
            if guard['rejected_calls']:
                result.update(passed=False, execution_correct=False, business_correct=False)
            return result
    except Exception as exc:
        return dict(schema_version='context-cutoff-numeric-result-v1',job_id=spec.get('job_id'),
                    passed=False,execution_correct=False,business_correct=False,model_fits=0,
                    model_loads=0,model_predictions=0,real_api_calls=0,fixture_only=False,
                    issues=[dict(code=getattr(exc,'code',type(exc).__name__),message=str(exc))])


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec', required=True); parser.add_argument('--response', required=True)
    parser.add_argument('--supervisor-permit', required=True)
    args = parser.parse_args(argv)
    spec = json.loads(Path(args.spec).read_text())
    destination = Path(args.response).resolve()
    _need(destination == Path(spec['output_dir']).resolve() / 'job_response.json', 'NUMERIC_RESPONSE_PATH')
    from phase2_unified.supervisor import validate_worker_permit
    validate_worker_permit(spec, json.loads(Path(args.supervisor_permit).read_text()))
    def deny_network(event, details):
        if event.startswith('socket.'):
            raise RuntimeError('NUMERIC_WORKER_NETWORK_DISABLED')
    sys.addaudithook(deny_network)
    response = run_check(spec, authorized=True)
    response['status'] = 'success' if response['passed'] else 'failed'
    temporary = destination.with_name(destination.name + '.tmp.' + str(os.getpid()))
    with temporary.open('x') as handle:
        json.dump(response, handle, sort_keys=True, allow_nan=False); handle.write('\n'); handle.flush(); os.fsync(handle.fileno())
    os.replace(temporary, destination)
    return 0 if response['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
