"""Bound numerical artifacts and explicit fake/live CPU adapters.

The offline adapter only hashes saved C02 bytes or writes symbolic fixtures.
It never loads a model, imports numerical libraries, trains or predicts.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from agent_recovery.contracts import digest,require
from .contracts import normalize_contract,contract_digest
from .bank_fault_protocol import write_new
from .cpu_client import ContractCPUClient

ENV_KEY='inputs/execution-environment.json'
NUMERIC_NAMES={'train_raw_features.json','validation_raw_features.json','train_row_ids.json',
 'validation_row_ids.json','train_features.npy','validation_features.npy','train_labels.npy',
 'validation_labels.npy','train_probabilities.npy','validation_probabilities.npy',
 'train_predictions.npy','validation_predictions.npy','preprocessing_stats.json','metrics.json',
 'pipeline.joblib','artifact_manifest.json','symbolic.json'}


def file_pin(path):
    path=Path(path)
    for p in (path,*path.parents):
        alias=str(p) in ('/var','/tmp','/etc') and p.resolve()==Path('/private')/p.name
        require(not p.is_symlink() or alias,'Artifact symlink refused','BF_ARTIFACT_PATH')
    require(path.is_file() and path.stat().st_size<=134217728,'Artifact missing or too large','BF_ARTIFACT')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_bundle(path,contract,environment_sha256):
    bundle=json.loads(Path(path).read_text());unsigned={k:v for k,v in bundle.items() if k!='sha256'}
    require(bundle.get('sha256')==digest(unsigned),'Artifact receipt changed','BF_ARTIFACT_RECEIPT')
    require(bundle.get('contract')==normalize_contract(contract)
            and bundle.get('contract_sha256')==contract_digest(contract)
            and bundle.get('environment_sha256')==environment_sha256,
            'Artifact contract or environment differs','BF_ARTIFACT_BINDING')
    files=bundle.get('files',[])
    require(bool(files) and len({f['name'] for f in files})==len(files),
            'Artifact manifest missing or duplicated','BF_ARTIFACT')
    root=Path(bundle['artifact_directory'])
    for entry in files:
        require(entry['name'] in NUMERIC_NAMES and Path(entry['path']).name==entry['name']
                and Path(entry['path']).parent==root,
                'Artifact path escapes its exact stage','BF_ARTIFACT_PATH')
        require(file_pin(entry['path'])==entry['sha256'],'Artifact content changed','BF_ARTIFACT_TAMPERED')
    return bundle


def save_bundle(root,contract,environment_sha256,stage,names,*,fixture_only,origin,job=None):
    root=Path(root);root.mkdir(parents=True,exist_ok=True)
    body=dict(schema_version='bank-fault-artifact-bundle-v1',contract=normalize_contract(contract),
        contract_sha256=contract_digest(contract),environment_sha256=environment_sha256,
        artifact_directory=str(Path(stage).resolve()),fixture_only=fixture_only,origin=origin,
        files=[dict(name=n,path=str((Path(stage)/n).resolve()),sha256=file_pin(Path(stage)/n)) for n in names])
    if job is not None:body['numerical_job']=job
    body['sha256']=digest(body)
    path=root/'bundle.json';write_new(path,body)
    return path,body


class OfflineArtifactCPU:
    fixture_only=True

    def __init__(self,root,environment_sha256,*,saved_stage=None):
        self.root=Path(root).resolve();self.environment_sha256=environment_sha256
        self.saved_stage=Path(saved_stage) if saved_stage else None
        self.records=[];self.training_requests=0;self.bundle_paths=[]

    def execute(self,contract):
        require(self.training_requests==0,'One training request per unit','BF_CPU_CAP')
        self.training_requests+=1
        output=self.root/'request-0000';output.mkdir(parents=True,exist_ok=False)
        saved=(json.loads((self.saved_stage/'job_response.json').read_text()) if self.saved_stage else None)
        if saved is not None and normalize_contract(saved['contract'])==normalize_contract(contract):
            names=[f['name'] for f in saved['artifacts']]
            path,bundle=save_bundle(output,contract,self.environment_sha256,self.saved_stage,names,
                fixture_only=True,origin='saved-real-C02-bytes-hash-only-replay')
        else:
            # A duration contract cannot borrow the clean model's receipt.
            write_new(output/'symbolic.json',dict(fixture_only=True,not_a_model=True,
                contract_sha256=contract_digest(contract),features=contract['feature_columns']))
            path,bundle=save_bundle(output,contract,self.environment_sha256,output,['symbolic.json'],
                fixture_only=True,origin='symbolic-contract-fixture-no-training')
        self.bundle_paths.append(str(path))
        return dict(fixture_only=True,actual_training=0,actual_prediction=0,
            contract_sha256=contract_digest(contract),executed_feature_columns=contract['feature_columns'],
            artifact=str(path),artifact_receipt_sha256=file_pin(path),artifact_bundle_sha256=bundle['sha256'])

    def validate(self,path,contract):
        bundle=verify_bundle(path,contract,self.environment_sha256)
        return dict(passed=True,fixture_only=True,scope='hash-and-contract-only-not-new-numerical-execution',
            bundle_sha256=bundle['sha256'],model_loads=0,model_fits=0,model_predictions=0)


class LiveArtifactCPU(ContractCPUClient):
    fixture_only=False

    def __init__(self,root,environment_sha256,*,deadline_utc,permit):
        from .cpu_client import ContractCPUClient
        self.client=ContractCPUClient(Path(root)/'numeric',deadline_utc=deadline_utc,permit=permit)
        self.root=Path(root);self.environment_sha256=environment_sha256
        self.deadline_utc=deadline_utc;self.records=self.client.records
        self.training_requests=0;self.bundle_paths=[]

    def code_text(self):
        return self.client.code_text()

    def execute(self,contract):
        require(self.training_requests==0,'One training request per unit','BF_CPU_CAP')
        self.training_requests+=1
        result=self.client.execute(contract);job=self.records[-1]
        stage=Path(job['spec']['output_dir'])
        path,bundle=save_bundle(self.root/'receipt',contract,self.environment_sha256,stage,
            [f['name'] for f in job['response']['artifacts']],fixture_only=False,
            origin='new-permitted-live-CPU-execution',job=job)
        self.bundle_paths.append(str(path))
        # Keep the interface seen by the agent bounded; the manifest is audit data.
        return {**result,'artifact':str(path),'artifact_receipt_sha256':file_pin(path),
                'artifact_bundle_sha256':bundle['sha256']}

    def validate(self,path,contract):
        bundle=verify_bundle(path,contract,self.environment_sha256)
        require(bundle['fixture_only'] is False and 'numerical_job' in bundle,
                'A live branch cannot accept a fixture artifact','BF_ARTIFACT_BINDING')
        from .numeric_checker import build_checker_spec
        from phase2_unified.supervisor import run_job,LiveSupervisorPermit
        job=bundle['numerical_job']
        spec=build_checker_spec(job['spec'],job['response'],self.root/'independent-check',
            self.deadline_utc,self.root.name+'.independent')
        checked=run_job(spec,self.root,permit=LiveSupervisorPermit(authorized=True))
        write_new(self.root/'NUMERIC_EXECUTION.json',checked)
        value=checked.get('response') or {}
        require(value.get('passed') is True and value.get('business_correct') is True
                and value.get('model_fits') == 0
                and value.get('fit_guard', {}).get('installed') is True
                and bool(value.get('fit_guard', {}).get('protected_methods'))
                and value.get('fit_guard', {}).get('rejected_calls') == []
                and checked['execution'].get('worker_reaped') is True
                and not checked['execution'].get('remaining_processes'),
                'Independent numerical check or cleanup failed','BF_NUMERIC_CHECK')
        # Prediction-only validation must not mutate the retained bytes.
        verify_bundle(path,contract,self.environment_sha256)
        return value
