"""Small integration interfaces, not a frozen scientific evaluation protocol."""
from copy import deepcopy
import hashlib
import math

from sr_recovery_v2.common import ProtocolError, canonical, digest

REVISION = 'ctx-bank-dev-r1'
MODES = ('FULL_HISTORY', 'SCOPED')
METHODS = ('FULL', 'CONSERVATIVE', 'CUTOFF')
ROLES = ('Analyst', 'Planner', 'Executor')
CONTRACT_FIELDS = {'dataset_id', 'data_binding', 'feature_columns', 'label_column',
                   'preprocessing', 'recipe', 'seed', 'code_sha256', 'output_schema'}


def require(ok, code):
    if not ok:
        raise ProtocolError(code)


def byte_hash(content):
    return hashlib.sha256(content.encode() if isinstance(content, str) else content).hexdigest()


def identity(run_id, kind, number):
    require(isinstance(run_id, str) and run_id and kind in ('node', 'llm', 'tool', 'msg', 'event', 'receipt'), 'BAD_ID_SCOPE')
    require(type(number) is int and number >= 0, 'BAD_ID_SEQUENCE')
    return f'{run_id}.{kind}.{number:04d}'


def normalize_contract(contract):
    """Normalize JSON representation, never erase execution-significant order."""
    require(isinstance(contract, dict) and set(contract) == CONTRACT_FIELDS, 'CONTRACT_FIELDS')
    c = deepcopy(contract)
    require(c['dataset_id'] == 'bank' and c['label_column'] == 'y', 'CONTRACT_DATASET')
    require(isinstance(c['data_binding'], dict) and set(c['data_binding']) == {
        'file_sha256', 'train_rows_sha256', 'validation_rows_sha256'}, 'CONTRACT_BINDING')
    require(all(isinstance(v, str) and len(v) == 64 for v in c['data_binding'].values()), 'CONTRACT_HASH')
    require(isinstance(c['feature_columns'], list) and c['feature_columns']
            and all(isinstance(v, str) and v for v in c['feature_columns'])
            and len(set(c['feature_columns'])) == len(c['feature_columns']), 'CONTRACT_FEATURES')
    require(c['preprocessing'] == {'numeric': 'median_standardize', 'categorical': 'onehot_ignore_unknown'}, 'CONTRACT_PREPROCESSING')
    require(isinstance(c['recipe'], dict) and set(c['recipe']) == {'model_family', 'parameters'}, 'CONTRACT_RECIPE')
    family = c['recipe']['model_family']
    require(family in ('logistic_regression', 'random_forest'), 'CONTRACT_MODEL')
    parameters = c['recipe']['parameters']
    approved = {'logistic_regression': {'C': 1.0, 'max_iter': 200},
                'random_forest': {'n_estimators': 40, 'max_depth': 8, 'n_jobs': 1}}
    require(isinstance(parameters, dict) and set(parameters) == set(approved[family]), 'CONTRACT_PARAMETERS')
    for key, value in parameters.items():
        require(type(value) in (int, float) and math.isfinite(value) and value == approved[family][key], 'CONTRACT_PARAMETER_VALUE')
        parameters[key] = float(value) if key == 'C' else int(value)
    require(type(c['seed']) is int and c['seed'] >= 0, 'CONTRACT_SEED')
    require(isinstance(c['code_sha256'], str) and len(c['code_sha256']) == 64, 'CONTRACT_CODE')
    require(c['output_schema'] == 'binary-probability-v1', 'CONTRACT_OUTPUT_SCHEMA')
    # Feature order affects the matrix and fitted model; retain it. Object keys
    # and approved numeric types are the only normalization performed here.
    return c


def contract_digest(contract):
    return digest(normalize_contract(contract))


def message_ref(message):
    return {'message_id': message['message_id'], 'sha256': digest(message)}
