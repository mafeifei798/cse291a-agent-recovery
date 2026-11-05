"""Explicit legacy-worker bridge with current-input admission and no-fit audit."""
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from context_cutoff.contracts import require
from context_cutoff.cpu import build_spec, worker_code_sha256
from context_cutoff.numeric_checker import build_checker_spec
from phase2_unified.supervisor import LiveSupervisorPermit, run_job
from sr_recovery_v2.common import digest
from .core import save, sha


def binding_matches(contract, kind, data):
    require(contract['data_binding'] == {
        'file_sha256': data['raw']['sha256'], 'train_rows_sha256': data[kind + '_train']['sha256'],
        'validation_rows_sha256': data[kind + '_validation']['sha256']}, 'L_ADMISSION_DATA_STALE')
    for key in ('raw', kind + '_train', kind + '_validation'):
        require(sha(data[key]['path']) == data[key]['sha256'], 'L_INPUT_BYTES_CHANGED')
    require(contract['code_sha256'] == worker_code_sha256(), 'L_ADMISSION_CODE_STALE')


class FakeCPU:
    fixture_only = True

    def __init__(self): self.fit_count = 0; self.admissions = 0; self.records = []

    def fit(self, contract, kind, data, deadline):
        binding_matches(contract, kind, data)
        self.fit_count += 1
        ap = .23 if len(contract['feature_columns']) >= 8 else .14
        return {'fixture_only': True, 'producer_id': 'fixture-fit-' + str(self.fit_count),
            'kind': kind, 'contract': deepcopy(contract),
            'metrics': {'validation': {'average_precision': ap, 'roc_auc': .67,
                        'log_loss': .36, 'f1': 0., 'accuracy': .88}}}

    def admit(self, model, desired, kind, data, deadline):
        self.validate(model, desired, kind, data)
        self.admissions += 1
        return {**deepcopy(model), 'admission_fixture': True}

    def validate(self, model, desired, kind, data):
        require(model['contract'] == desired, 'L_ADMISSION_CONTRACT_STALE')
        binding_matches(desired, kind, data)


class ActualCPU:
    fixture_only = False

    def __init__(self, directory, *, authorized=False, fit_limit=10):
        require(authorized is True, 'L_REAL_CPU_PERMISSION')
        self.root = Path(directory).resolve()
        (self.root / 'jobs').mkdir(parents=True, exist_ok=False)
        self.fit_count, self.fit_limit, self.admissions, self.records = 0, fit_limit, 0, []

    def _run(self, spec):
        record_path = self.root / 'jobs' / (spec['job_id'] + '.record.json')
        save(record_path.with_suffix('.intent.json'), {'spec': spec, 'authorized_cpu': True,
            'real_model_API': False, 'automatic_retry': False})
        record = run_job(spec, self.root, permit=LiveSupervisorPermit(True))
        save(record_path, record)
        self.records.append({'record_rel': str(record_path.relative_to(self.root)), 'record': record})
        execution = record['execution']
        require(execution['status'] == 'success' and execution['worker_reaped']
                and not execution['remaining_processes'] and not execution['inherited_credentials'], 'L_CPU_EXECUTION_FAILED')
        return record, str(record_path.relative_to(self.root))

    def _check(self, train, deadline):
        job_id = 'check-' + str(len(self.records) + 1).zfill(4)
        spec = build_checker_spec(train['spec'], train['response'], self.root / 'jobs' / job_id,
                                  deadline, job_id)
        checked, rel = self._run(spec)
        response = checked['response']
        require(response['passed'] and response['business_correct'] and response['model_fits'] == 0
                and response['fit_guard']['installed'] and not response['fit_guard']['rejected_calls'], 'L_NUMERIC_CHECK_FAILED')
        return rel

    def fit(self, contract, kind, data, deadline):
        require(self.fit_count < self.fit_limit, 'L_TOTAL_FIT_CAP')
        binding_matches(contract, kind, data)
        self.fit_count += 1
        job_id = 'fit-' + str(self.fit_count).zfill(4)
        save(self.root / 'jobs' / (job_id + '.reserved.json'), {'fit_ordinal': self.fit_count,
            'fit_limit': self.fit_limit, 'kind': kind, 'contract_sha256': digest(contract)})
        spec = build_spec(contract, data['raw']['path'], data[kind + '_train']['path'],
            data[kind + '_validation']['path'], self.root / 'jobs' / job_id, self.root / 'jobs', deadline, job_id)
        trained, rel = self._run(spec)
        response = trained['response']
        require(response['actual_training'] == 1 and response['predict_proba_calls'] == 2
                and response['executed_feature_columns'] == contract['feature_columns'], 'L_REAL_FIT_RECEIPT')
        check_rel = self._check(trained, deadline)
        return {'fixture_only': False, 'producer_id': job_id, 'record_rel': rel,
            'producer_record_sha256': sha(self.root / rel), 'kind': kind,
            'contract': deepcopy(contract), 'metrics': response['metrics'], 'numeric_record_rel': check_rel}

    def validate(self, model, desired, kind, data):
        # Reject stale binding before deserializing a model or launching any checker.
        require(model['contract'] == desired, 'L_ADMISSION_CONTRACT_STALE')
        binding_matches(desired, kind, data)
        path = (self.root / model['record_rel']).resolve()
        require(path.is_relative_to(self.root) and sha(path) == model['producer_record_sha256'], 'L_PRODUCER_RECORD_CHANGED')
        import json
        train = json.loads(path.read_text())
        for artifact in train['response']['artifacts']:
            file = Path(train['spec']['output_dir']) / artifact['name']
            require(file.is_file() and file.stat().st_size == artifact['size_bytes']
                    and sha(file) == artifact['sha256'], 'L_ADMISSION_ARTIFACT_CHANGED')
        require(train['response']['contract'] == desired, 'L_ADMISSION_PRODUCER_CONTRACT')
        return train

    def admit(self, model, desired, kind, data, deadline):
        train = self.validate(model, desired, kind, data)
        check_rel = self._check(train, deadline)
        self.admissions += 1
        return {**deepcopy(model), 'admission_numeric_record_rel': check_rel}
