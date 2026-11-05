"""Pilot contracts and source preparation; no estimator imports or inference."""
from copy import deepcopy
import csv
import hashlib
import json
from pathlib import Path

from context_cutoff.contracts import normalize_contract, require
from context_cutoff.cpu import worker_code_sha256
from context_cutoff.store import FileProvenanceStore
from sr_recovery_v2.common import canonical, digest

REVISION = 'agent-l-v1'
D0 = ['age', 'job', 'education', 'housing', 'loan']
BUNDLES = {'D0': D0, 'D8': D0 + ['contact', 'month', 'day_of_week'],
           'D1': D0 + ['contact', 'month', 'day_of_week', 'pdays', 'previous', 'poutcome']}
RECIPES = {
    'LR': {'model_family': 'logistic_regression', 'parameters': {'C': 1., 'max_iter': 200}},
    'RF': {'model_family': 'random_forest', 'parameters': {'n_estimators': 40, 'max_depth': 8, 'n_jobs': 1}},
}
DATA, SCHEMA, PROFILE, REGISTRY, CODE = ('inputs/data.json', 'inputs/schema.json',
    'inputs/profile.json', 'inputs/registry.json', 'inputs/code.json')
PERMISSION, TASK, CHOICE, REVIEW, MODEL, PUBLICATION = ('inputs/permission.json', 'inputs/task.json',
    'work/choice.json', 'work/review.json', 'work/model.json', 'external/report.json')


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''): h.update(b)
    return h.hexdigest()


def save(path, value):
    path = Path(path)
    with path.open('x') as f: f.write(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n')


def ref(document):
    return {k: document[k] for k in FileProvenanceStore.REF_FIELDS}


def prepare_inputs(source_root, destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    raw = (Path(source_root) / 'sr_v2/v0/data/raw/bank/bank-additional-full.csv').resolve()
    raw_sha = sha(raw)
    require(raw_sha == '74adfc578bf77a7ff4bb1ba4a9f8709d9e3c6907342959c2c8416847e0afb4d8', 'L_RAW_PIN')
    paths = {}
    for name, first, last in [('screen_train', 1, 24712), ('screen_validation', 24713, 28831),
                              ('final_train', 1, 28831), ('final_validation', 28832, 32950)]:
        ids = [f'sha256:{raw_sha}:row:{i}' for i in range(first, last + 1)]
        path = (destination / (name + '.json')).resolve()
        save(path, {'dataset': 'bank', 'row_count': len(ids), 'row_ids': ids, 'row_ids_digest': digest(ids)})
        paths[name] = {'path': str(path), 'sha256': sha(path)}
    selected = []
    with raw.open(newline='') as f:
        for index, row in enumerate(csv.DictReader(f, delimiter=';'), 1):
            if index <= 28831: selected.append(row)
    train, feedback = selected[:24712], selected[24712:]
    profile = {'training_rows': len(train), 'training_positive_fraction': sum(r['y'] == 'yes' for r in train) / len(train),
        'training_history_records': sum(int(r['previous']) > 0 for r in train),
        'feedback_rows': len(feedback), 'feedback_constant_AP': sum(r['y'] == 'yes' for r in feedback) / len(feedback)}
    data = {'raw': {'path': str(raw), 'sha256': raw_sha}, **paths}
    return {'data': data, 'schema': {'columns': BUNDLES['D1'], 'label': 'y', 'row_count': 41188,
        'prediction_time': 'pre_call', 'excluded': ['duration', 'campaign']}, 'profile': profile,
        'registry': {'bundles': BUNDLES, 'recipes': RECIPES}, 'code': {'sha256': worker_code_sha256()}}


def contract_pair(selection, data, code, task):
    require(set(selection) == {'bundle', 'recipe'}, 'L_SELECTION_FIELDS')
    require(selection['bundle'] in BUNDLES and selection['recipe'] in RECIPES, 'L_SELECTION_MENU')
    features = BUNDLES[selection['bundle']]
    require(len(features) <= task['feature_cap'], 'L_FEATURE_BUDGET')
    results = {}
    for kind in ('screen', 'final'):
        results[kind] = normalize_contract({'dataset_id': 'bank', 'data_binding': {
            'file_sha256': data['raw']['sha256'], 'train_rows_sha256': data[kind + '_train']['sha256'],
            'validation_rows_sha256': data[kind + '_validation']['sha256']},
            'feature_columns': deepcopy(features), 'label_column': 'y',
            'preprocessing': {'numeric': 'median_standardize', 'categorical': 'onehot_ignore_unknown'},
            'recipe': deepcopy(RECIPES[selection['recipe']]), 'seed': 17,
            'code_sha256': code['sha256'], 'output_schema': 'binary-probability-v1'})
    return results


class ScriptedLLM:
    """Explicit protocol fixture; exercise feedback, never claim learned decisions."""
    fixture_only = True

    def __init__(self, force_recovery_bundle=None): self.force_recovery_bundle = force_recovery_bundle

    def respond(self, role, messages):
        task = json.loads(messages[0]['content'])['task']
        tools = [json.loads(m['content']) for m in messages if m['role'] == 'tool']
        if role == 'Analyst':
            if not tools: return {'tool': 'read_schema', 'arguments': {}}
            if len(tools) == 1: return {'tool': 'read_profile', 'arguments': {}}
            schema = tools[0]['value']
            return {'final': {'row_count': schema['row_count'], 'eligible_features': schema['columns'],
                              'prediction_time': schema['prediction_time'], 'profile': tools[1]['value']}}
        if role == 'Planner':
            if not tools: return {'tool': 'list_recipes', 'arguments': {}}
            feedback = next((json.loads(m['content'])['payload'] for m in messages
                             if m.get('input_kind') == 'feedback'), None)
            bundle = feedback['requested_bundle'] if feedback else ('D0' if task['optimization_remaining'] else 'D1')
            if self.force_recovery_bundle and task['phase'] == 'recovery': bundle = self.force_recovery_bundle
            if len(BUNDLES[bundle]) > task['feature_cap']: bundle = 'D8'
            facts = next(json.loads(m['content'])['payload'] for m in messages if m.get('input_kind') == 'facts')
            eligible = set(facts['eligible_features'])
            if not set(BUNDLES[bundle]) <= eligible:
                choices = [key for key, columns in BUNDLES.items()
                           if set(columns) <= eligible and len(columns) <= task['feature_cap']]
                require(bool(choices), 'L_NO_ELIGIBLE_BUNDLE')
                bundle = max(choices, key=lambda key: len(BUNDLES[key]))
            return {'final': {'bundle': bundle, 'recipe': 'LR'}}
        if role == 'Reviewer':
            evidence = next(json.loads(m['content'])['payload'] for m in messages if m.get('input_kind') == 'screen')
            if task['optimization_remaining'] and evidence['selection']['bundle'] == 'D0':
                return {'final': {'action': 'adjust', 'requested_bundle': 'D1' if task['feature_cap'] >= 11 else 'D8',
                    'reason': 'scripted exercise of one legal feedback adjustment; not a model-quality claim',
                    'evidence_id': evidence['receipt_id']}}
            return {'final': {'action': 'accept', 'reason': 'scripted final review', 'evidence_id': evidence['receipt_id']}}
        raise ValueError(role)
