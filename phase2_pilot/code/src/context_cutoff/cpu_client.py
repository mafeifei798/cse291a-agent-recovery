"""Explicit server CPU bridge; model inference remains separately disabled."""
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import json

from .contracts import require, byte_hash, contract_digest


@dataclass(frozen=True)
class ServerCPUPermit:
    authorized: bool = False


class ContractCPUClient:
    fixture_only = False

    def __init__(self, campaign_root, *, deadline_utc, permit=None):
        require(isinstance(permit, ServerCPUPermit) and permit.authorized,
                'SERVER_CPU_NOT_AUTHORIZED')
        self.server_cpu_authorized = True
        self.root = Path(campaign_root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.deadline_utc = deadline_utc
        self.records = []

    def code_text(self):
        from .cpu import worker_code_text
        return worker_code_text()

    def execute(self, contract):
        from .cpu import build_spec
        from phase2_unified.supervisor import run_job, LiveSupervisorPermit
        root = Path(__file__).resolve().parents[2]
        name = f'{self.root.parent.name}.cpu-{len(self.records):04d}'
        stage = self.root / name
        require(not stage.exists(), 'CPU_STAGE_ALREADY_EXISTS')
        spec = build_spec(contract,
            raw_path=root / 'sr_v2/v0/data/raw/bank/bank-additional-full.csv',
            train_rows_path=root / 'sr_v2/v0/data/splits/bank/train_v1.json',
            validation_rows_path=root / 'sr_v2/v0/data/splits/bank/validation.json',
            output_dir=stage, artifact_root=self.root, deadline_utc=self.deadline_utc, job_id=name)
        intent = self.root / (name + '.intent.json')
        with intent.open('x') as handle:
            json.dump({'spec': spec, 'authorized_server_cpu': True, 'real_api_allowed': False}, handle, indent=2)
        record = run_job(spec, self.root, permit=LiveSupervisorPermit(authorized=True))
        # Save failures as well as successes, without retry or replacement.
        with (self.root / (name + '.execution.json')).open('x') as handle:
            json.dump(record, handle, indent=2)
        self.records.append(record)
        require(record['execution']['status'] == 'success' and record['response'] is not None,
                'SERVER_CPU_WORKER_FAILED')
        response = record['response']
        require(response.get('status') == 'success' and response.get('fixture_only') is False
                and response.get('actual_training') == 1 and response.get('actual_prediction') == 1,
                'CPU_ACTUAL_EXECUTION_RECEIPT')
        require(response['executed_feature_columns'] == contract['feature_columns'], 'CPU_DROPPED_OR_REORDERED_FEATURES')
        return {'fixture_only': False, 'actual_training': 1, 'actual_prediction': 1,
            'contract_sha256': contract_digest(contract),
            'executed_feature_columns': response['executed_feature_columns'],
            'metrics': response['metrics'], 'artifact': str(stage / 'job_response.json'),
            'artifact_receipt_sha256': byte_hash((stage / 'job_response.json').read_bytes()),
            'job_id': name, 'spec_sha256': spec['spec_sha256']}
