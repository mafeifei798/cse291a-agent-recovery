"""Supervised Bank training/prediction with the exact Planner contract.

Numerical imports happen only after a valid Linux supervisor permit. There is
no reuse of the old Bank loader, whose fixed schema excludes duration.
"""
from datetime import datetime, timezone
import csv
import json
import os
from pathlib import Path
import sys
import time

from sr_recovery_v2.common import canonical, digest
from .contracts import contract_digest, require
from .cpu import NUMERIC_COLUMNS, file_sha256, verify_spec


def _raw_selected(spec, row_ids):
    """Trusted row selector; the contract alone selects and orders columns."""
    with Path(spec['raw_path']).open(newline='') as handle:
        reader = csv.DictReader(handle, delimiter=';')
        wanted = {int(r.rsplit(':', 1)[1]) for r in row_ids}
        selected = {index: row for index, row in enumerate(reader, 1) if index in wanted}
    require(len(selected) == len(row_ids), 'CTX_CPU_SELECTED_ROWS_MISSING')
    columns = spec['contract']['feature_columns']
    rows, labels = [], []
    for row_id in row_ids:
        row = selected[int(row_id.rsplit(':', 1)[1])]
        require(row['y'] in ('yes', 'no'), 'CTX_CPU_LABEL')
        labels.append(int(row['y'] == 'yes'))
        values = []
        for column in columns:
            value = row[column].strip()
            # JSON uses null for genuinely missing numeric values. Bank's
            # literal "unknown" remains a categorical level.
            values.append((float(value) if value else None) if column in NUMERIC_COLUMNS else value)
        rows.append(values)
    return {'columns': list(columns), 'rows': rows}, labels


def execute(spec, *, supervisor_permit=None):
    from phase2_unified.supervisor import validate_worker_permit
    require(supervisor_permit is not None, 'CTX_CPU_SUPERVISOR_PERMIT_REQUIRED')
    validate_worker_permit(spec, supervisor_permit)
    bound = verify_spec(spec)
    require(datetime.now(timezone.utc) < datetime.fromisoformat(spec['deadline_utc'].replace('Z', '+00:00')),
            'CTX_CPU_DEADLINE_EXPIRED')
    # Only trusted, explicitly supervised execution reaches model imports.
    import joblib
    import numpy as np
    import pandas as pd
    import scipy
    import sklearn
    from sklearn.compose import ColumnTransformer
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import accuracy_score, average_precision_score, f1_score, log_loss, roc_auc_score
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import OneHotEncoder, StandardScaler

    began = time.monotonic()
    contract = bound['contract']
    train_raw, train_y = _raw_selected(spec, bound['train']['row_ids'])
    validation_raw, validation_y = _raw_selected(spec, bound['validation']['row_ids'])
    features = contract['feature_columns']
    numeric = [c for c in features if c in NUMERIC_COLUMNS]
    categorical = [c for c in features if c not in NUMERIC_COLUMNS]

    def frame(raw):
        result = pd.DataFrame(raw['rows'], columns=features)
        for column in numeric:
            result[column] = pd.to_numeric(result[column], errors='raise').astype(np.float64)
        return result

    train_frame, validation_frame = frame(train_raw), frame(validation_raw)
    train_labels, validation_labels = np.asarray(train_y, dtype=np.int8), np.asarray(validation_y, dtype=np.int8)
    require(len(np.unique(train_labels)) == 2 and len(np.unique(validation_labels)) == 2, 'CTX_CPU_BOTH_CLASSES')
    transformers = []
    if numeric:
        transformers.append(('numeric', Pipeline([('imputer', SimpleImputer(strategy='median')),
                                                  ('scaler', StandardScaler())]), numeric))
    if categorical:
        transformers.append(('categorical', OneHotEncoder(handle_unknown='ignore', sparse_output=False,
                                                           dtype=np.float64), categorical))
    preprocess = ColumnTransformer(transformers, remainder='drop', sparse_threshold=0.)
    params = contract['recipe']['parameters']
    if contract['recipe']['model_family'] == 'logistic_regression':
        model = LogisticRegression(C=params['C'], max_iter=params['max_iter'],
                                   random_state=contract['seed'], solver='lbfgs')
    else:
        model = RandomForestClassifier(**params, random_state=contract['seed'])
    pipeline = Pipeline([('preprocess', preprocess), ('model', model)])
    fit_start = time.monotonic()
    pipeline.fit(train_frame, train_labels)
    fit_seconds = time.monotonic() - fit_start
    require(list(preprocess.feature_names_in_) == features, 'CTX_CPU_FEATURE_ORDER_CHANGED')
    train_features = np.asarray(preprocess.transform(train_frame), dtype=np.float64)
    validation_features = np.asarray(preprocess.transform(validation_frame), dtype=np.float64)
    predict_start = time.monotonic()
    train_probabilities = np.asarray(pipeline.predict_proba(train_frame)[:, 1], dtype=np.float64)
    validation_probabilities = np.asarray(pipeline.predict_proba(validation_frame)[:, 1], dtype=np.float64)
    predict_seconds = time.monotonic() - predict_start
    train_predictions = (train_probabilities >= .5).astype(np.int8)
    validation_predictions = (validation_probabilities >= .5).astype(np.int8)

    def metrics(labels, probabilities, predictions):
        return {'average_precision': float(average_precision_score(labels, probabilities)),
                'roc_auc': float(roc_auc_score(labels, probabilities)),
                'log_loss': float(log_loss(labels, probabilities, labels=[0, 1])),
                'f1': float(f1_score(labels, predictions, zero_division=0)),
                'accuracy': float(accuracy_score(labels, predictions))}

    all_metrics = {'train': metrics(train_labels, train_probabilities, train_predictions),
                   'validation': metrics(validation_labels, validation_probabilities, validation_predictions)}
    stats = {'numeric_columns': numeric, 'categorical_columns': categorical,
             'feature_names_in': list(preprocess.feature_names_in_),
             'feature_names_out': list(preprocess.get_feature_names_out()),
             'fitted_on_train_only': True, 'train_row_ids_digest': digest(bound['train']['row_ids']),
             'medians': [], 'means': [], 'scales': [], 'categories': []}
    if numeric:
        fitted = preprocess.named_transformers_['numeric']
        stats.update(medians=fitted.named_steps['imputer'].statistics_.tolist(),
                     means=fitted.named_steps['scaler'].mean_.tolist(),
                     scales=fitted.named_steps['scaler'].scale_.tolist())
    if categorical:
        stats['categories'] = [values.tolist() for values in preprocess.named_transformers_['categorical'].categories_]
    output = Path(spec['output_dir'])
    require(output.is_dir(), 'CTX_CPU_SUPERVISOR_STAGE_REQUIRED')
    artifacts = []

    def register(name):
        path = output / name
        require(path.is_file() and path.stat().st_size <= spec['limits']['max_artifact_bytes'], 'CTX_CPU_ARTIFACT_SIZE')
        path.chmod(0o444)
        artifacts.append({'name': name, 'path': name, 'sha256': file_sha256(path), 'size_bytes': path.stat().st_size})

    def save_json(name, value):
        with (output / name).open('x') as handle:
            handle.write(canonical(value) + '\n')
        register(name)

    def save_array(name, value):
        with (output / name).open('xb') as handle:
            np.save(handle, value, allow_pickle=False)
        register(name)

    # Arrays and JSON never require pickle. Only the trusted own fitted
    # pipeline is joblib, and the independent checker verifies hashes first.
    save_json('train_raw_features.json', train_raw)
    save_json('validation_raw_features.json', validation_raw)
    save_json('train_row_ids.json', bound['train']['row_ids'])
    save_json('validation_row_ids.json', bound['validation']['row_ids'])
    for name, value in [('train_features.npy', train_features), ('validation_features.npy', validation_features),
                        ('train_labels.npy', train_labels), ('validation_labels.npy', validation_labels),
                        ('train_probabilities.npy', train_probabilities), ('validation_probabilities.npy', validation_probabilities),
                        ('train_predictions.npy', train_predictions), ('validation_predictions.npy', validation_predictions)]:
        save_array(name, value)
    save_json('preprocessing_stats.json', stats)
    save_json('metrics.json', all_metrics)
    require(not (output / 'pipeline.joblib').exists(), 'CTX_CPU_ARTIFACT_EXISTS')
    joblib.dump(pipeline, output / 'pipeline.joblib', compress=3, protocol=4)
    register('pipeline.joblib')
    input_hashes = {a['name']: a['sha256'] for a in artifacts}
    input_features_sha256 = digest({'feature_columns': features,
        'train_raw_sha256': input_hashes['train_raw_features.json'],
        'validation_raw_sha256': input_hashes['validation_raw_features.json']})
    save_json('artifact_manifest.json', {'schema_version': 'context-cutoff-cpu-artifacts-v1',
              'spec_sha256': spec['spec_sha256'], 'contract_sha256': contract_digest(contract),
              'artifacts': list(artifacts)})
    return {'schema_version': 'context-cutoff-cpu-response-v1', 'job_id': spec['job_id'],
            'status': 'success', 'settled': True, 'fixture_only': False,
            'actual_training': 1, 'actual_prediction': 1, 'actual_model_prediction': 1,
            'predict_proba_calls': 2, 'real_api_calls': 0, 'spec_sha256': spec['spec_sha256'],
            'contract': contract, 'contract_sha256': contract_digest(contract),
            'executed_feature_columns': list(features), 'input_features_sha256': input_features_sha256,
            'artifact_root': spec['artifact_root'], 'output_dir': spec['output_dir'], 'artifacts': artifacts,
            'metrics': all_metrics, 'train_rows': len(train_labels), 'validation_rows': len(validation_labels),
            'transformed_feature_count': train_features.shape[1], 'estimator_parameters': model.get_params(),
            'versions': {'python': sys.version.split()[0], 'numpy': np.__version__, 'pandas': pd.__version__,
                         'scipy': scipy.__version__, 'sklearn': sklearn.__version__, 'joblib': joblib.__version__},
            'timing': {'fit_wall_seconds': fit_seconds, 'predict_wall_seconds': predict_seconds,
                       'worker_wall_seconds': time.monotonic() - began},
            'finished_utc': datetime.now(timezone.utc).isoformat()}


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec', required=True)
    parser.add_argument('--response', required=True)
    parser.add_argument('--supervisor-permit', required=True)
    args = parser.parse_args(argv)
    spec = json.loads(Path(args.spec).read_text())
    response_path = Path(args.response).resolve()
    require(response_path == Path(spec['output_dir']).resolve() / 'job_response.json', 'CTX_CPU_RESPONSE_PATH')
    permit = json.loads(Path(args.supervisor_permit).read_text())
    from phase2_unified.supervisor import validate_worker_permit
    validate_worker_permit(spec, permit)

    def deny_network(event, details):
        if event.startswith('socket.'):
            raise RuntimeError('CTX_CPU_NETWORK_DISABLED')

    sys.addaudithook(deny_network)
    try:
        response, exit_code = execute(spec, supervisor_permit=permit), 0
    except Exception as exc:
        response = {'schema_version': 'context-cutoff-cpu-response-v1', 'status': 'failed',
                    'settled': False, 'spec_sha256': spec['spec_sha256'],
                    'error': {'code': getattr(exc, 'code', type(exc).__name__), 'message': str(exc)}}
        exit_code = 1
    temporary = response_path.with_name(response_path.name + '.tmp.' + str(os.getpid()))
    with temporary.open('x') as handle:
        handle.write(canonical(response) + '\n')
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, response_path)
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
