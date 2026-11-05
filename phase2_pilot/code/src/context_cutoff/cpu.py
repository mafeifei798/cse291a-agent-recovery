"""Exact Planner-contract CPU binding; construction never imports ML libraries.

This backend intentionally has no business-policy feature filter. A contract
containing Bank's duration column is executed verbatim and can then fail the
separate pre-call-prediction business check.
"""
from copy import deepcopy
from datetime import datetime, timezone
import csv
import hashlib
import json
from pathlib import Path
import re

from phase2_unified.cpu import LIMITS
from sr_recovery_v2.common import canonical, digest
from .contracts import normalize_contract, require

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = 'context-cutoff-cpu-v1'
NUMERIC_COLUMNS = ('age', 'duration', 'campaign', 'pdays', 'previous',
                   'emp.var.rate', 'cons.price.idx', 'cons.conf.idx',
                   'euribor3m', 'nr.employed')
BANK_COLUMNS = ('age', 'job', 'marital', 'education', 'default', 'housing',
                'loan', 'contact', 'month', 'day_of_week', 'duration',
                'campaign', 'pdays', 'previous', 'poutcome', 'emp.var.rate',
                'cons.price.idx', 'cons.conf.idx', 'euribor3m', 'nr.employed', 'y')


def file_sha256(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def worker_code_text():
    """Canonical source-hash bundle stored as a versioned runtime code input."""
    names = ('src/context_cutoff/cpu.py', 'src/context_cutoff/cpu_worker.py',
             'src/context_cutoff/contracts.py')
    return canonical({name: file_sha256(ROOT / name) for name in names})


def worker_code_sha256():
    """Pin the exact numerical/contract source, independent of checkout path."""
    return hashlib.sha256(worker_code_text().encode()).hexdigest()


def _absolute_no_symlink(value):
    path = Path(value)
    require(path.is_absolute(), 'CTX_CPU_ABSOLUTE_PATH')
    require('..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)),
            'CTX_CPU_SYMLINK_OR_ESCAPE')
    require(str(path) == str(path.resolve()), 'CTX_CPU_CANONICAL_PATH')
    return path


def _rows(path, raw_sha, maximum_row):
    document = json.loads(path.read_text())
    require(isinstance(document, dict) and isinstance(document.get('row_ids'), list),
            'CTX_CPU_ROW_DOCUMENT')
    ids = document['row_ids']
    require(ids and document.get('row_count') == len(ids) == len(set(ids)), 'CTX_CPU_ROW_COUNT')
    require(document.get('row_ids_digest') == digest(ids), 'CTX_CPU_ROW_DIGEST')
    require(document.get('dataset', 'bank') == 'bank', 'CTX_CPU_ROW_DATASET')
    prefix = 'sha256:' + raw_sha + ':row:'
    for row in ids:
        require(isinstance(row, str) and row.startswith(prefix), 'CTX_CPU_ROW_RAW_BINDING')
        suffix = row[len(prefix):]
        require(suffix.isdigit() and str(int(suffix)) == suffix and 1 <= int(suffix) <= maximum_row,
                'CTX_CPU_ROW_INDEX')
    return document


def build_spec(contract, raw_path, train_rows_path, validation_rows_path,
               output_dir, artifact_root, deadline_utc, job_id):
    contract = normalize_contract(contract)
    deadline = deadline_utc.isoformat() if isinstance(deadline_utc, datetime) else deadline_utc
    spec = {'schema_version': SCHEMA, 'job_id': job_id,
            'tool': 'fit_lr' if contract['recipe']['model_family'] == 'logistic_regression' else 'fit_rf',
            'contract': contract, 'raw_path': str(Path(raw_path).absolute()),
            'train_rows_path': str(Path(train_rows_path).absolute()),
            'validation_rows_path': str(Path(validation_rows_path).absolute()),
            'output_dir': str(Path(output_dir).absolute()),
            'artifact_root': str(Path(artifact_root).absolute()),
            'deadline_utc': deadline, 'limits': deepcopy(LIMITS)}
    spec['spec_sha256'] = digest(spec)
    verify_spec(spec)
    return spec


def verify_spec(spec):
    require(isinstance(spec, dict) and spec.get('schema_version') == SCHEMA, 'CTX_CPU_SCHEMA')
    fields = {'schema_version', 'job_id', 'tool', 'contract', 'raw_path', 'train_rows_path',
              'validation_rows_path', 'output_dir', 'artifact_root', 'deadline_utc', 'limits', 'spec_sha256'}
    require(set(spec) == fields, 'CTX_CPU_SPEC_FIELDS')
    require(spec['spec_sha256'] == digest({k: v for k, v in spec.items() if k != 'spec_sha256'}),
            'CTX_CPU_SPEC_SHA')
    c = normalize_contract(spec['contract'])
    require(c == spec['contract'], 'CTX_CPU_NORMALIZED_CONTRACT')
    require(c['code_sha256'] == worker_code_sha256(), 'CTX_CPU_WORKER_CODE_PIN')
    require(spec['tool'] == ('fit_lr' if c['recipe']['model_family'] == 'logistic_regression' else 'fit_rf'),
            'CTX_CPU_TOOL_BINDING')
    require(isinstance(spec['job_id'], str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,180}', spec['job_id']),
            'CTX_CPU_JOB_ID')
    require(spec['limits'] == LIMITS, 'CTX_CPU_RESOURCE_LIMITS')
    deadline = datetime.fromisoformat(str(spec['deadline_utc']).replace('Z', '+00:00'))
    require(deadline.tzinfo is not None and deadline.utcoffset().total_seconds() == 0,
            'CTX_CPU_UTC_DEADLINE')
    inputs = [_absolute_no_symlink(spec[k]) for k in ('raw_path', 'train_rows_path', 'validation_rows_path')]
    root, output = (_absolute_no_symlink(spec[k]) for k in ('artifact_root', 'output_dir'))
    require(output != root and output.is_relative_to(root), 'CTX_CPU_OUTPUT_ESCAPE')
    require(len(set(inputs)) == 3 and all(p.is_file() and not p.is_relative_to(output) for p in inputs),
            'CTX_CPU_INPUT_PATHS')
    bindings = c['data_binding']
    require([file_sha256(p) for p in inputs] == [bindings[k] for k in
            ('file_sha256', 'train_rows_sha256', 'validation_rows_sha256')], 'CTX_CPU_INPUT_HASH')
    with inputs[0].open(newline='') as handle:
        reader = csv.reader(handle, delimiter=';')
        require(next(reader, None) == list(BANK_COLUMNS), 'CTX_CPU_RAW_COLUMNS')
        row_count = sum(1 for _ in reader)
    require(all(f in BANK_COLUMNS[:-1] for f in c['feature_columns']), 'CTX_CPU_UNKNOWN_FEATURE')
    train = _rows(inputs[1], bindings['file_sha256'], row_count)
    validation = _rows(inputs[2], bindings['file_sha256'], row_count)
    require(not set(train['row_ids']).intersection(validation['row_ids']), 'CTX_CPU_SPLIT_LEAKAGE')
    return {'contract': c, 'train': train, 'validation': validation, 'raw_row_count': row_count,
            'worker_code_sha256': c['code_sha256']}
