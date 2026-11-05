"""Concrete future CPU backend for the explicit new evaluation task.

Building the backend is inert. Executing it requires a Linux supervisor permit
and separate live CPU authorization; offline tests never execute this path.
The unchanged numerical implementation reads this spec's new pack, not V0.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import os
import sys

from .cpu import CPUContractError, LIMITS, verify_spec, verify_artifacts, utc, digest, require


@dataclass(frozen=True)
class WorkerPermit:
    authorized: bool = False
    supervisor_limits_applied: bool = False
    network_disabled: bool = False
    process_group_owned: bool = False
    fixed_deadline_enforced: bool = False


def prepare_backend(spec):
    """Return a real executable binding without importing/loading an estimator."""
    binding = verify_spec(spec)
    return BoundCPUBackend(spec, binding)


class BoundCPUBackend:
    def __init__(self, spec, binding):
        from copy import deepcopy
        self.spec=deepcopy(spec)
        self.binding=binding
        self.required_environment={'os':'Linux','python':'pinned sklearn CPU environment',
            'resource_supervisor':'process group + prctl subreaper + /proc monitoring + fixed deadline',
            'limits':dict(LIMITS),'worker_implementation':'sr_cpu_v2.tools.execute',
            'network_boundary':'trusted Python socket audit hook; not an OS network namespace',
            'data_root':binding.document()['pack_root'],'live_execution_tested':False}

    def execute(self, *, permit=None):
        if not isinstance(permit,WorkerPermit) or not all((permit.authorized,
                permit.supervisor_limits_applied,permit.network_disabled,
                permit.process_group_owned,permit.fixed_deadline_enforced)):
            raise CPUContractError('CPU_LIVE_EXECUTION_NOT_AUTHORIZED')
        if sys.platform!='linux':
            raise CPUContractError('CPU_LINUX_SUPERVISOR_REQUIRED')
        if utc(datetime.now(timezone.utc))>=utc(self.spec['deadline_utc']):
            raise CPUContractError('CPU_DEADLINE_BEFORE_WORKER')
        if os.environ.get('CUDA_VISIBLE_DEVICES')!='' or any(os.environ.get(k)!='1' for k in (
                'OMP_NUM_THREADS','OPENBLAS_NUM_THREADS','MKL_NUM_THREADS','NUMEXPR_NUM_THREADS')):
            raise CPUContractError('CPU_THREAD_ENV_NOT_APPLIED')
        verify_spec(self.spec); verify_artifacts(self.spec['artifact_root'],self.spec['artifacts'])
        prepared=self.spec['inputs'].get('prepare')
        if self.spec['tool'].startswith(('fit_','predict_','summary_')):
            require(isinstance(prepared,dict) and prepared.get('dataset_id')==self.spec['dataset_id']
                and prepared.get('train_version')==self.spec['train_version']
                and prepared.get('training_row_ids_digest')==self.spec['train_row_ids_digest']
                and prepared.get('validation_row_ids_digest')==self.spec['validation_row_ids_digest'],
                'CPU_REAL_PREPARE_BINDING')
        # No dataset-only task selection: exact Phase 2 task and row manifests
        # were validated above. _locked_data in the old numerical tools uses
        # ctx.v0/data/{manifest,splits,schema}; this root is explicitly new.
        from sr_cpu_v2.tools import execute as execute_numerical_tool
        legacy={**self.spec,'v0_root':self.binding.document()['pack_root']}
        response=execute_numerical_tool(legacy)
        result={key:self.spec[key] for key in ('job_id','attempt_id','result_id','node_id','task_id','dataset_id',
            'evaluation_pack_sha256','protocol_sha256','data_manifest_sha256','train_version','train_row_ids_digest',
            'validation_row_ids_digest','input_digest','selected_parent_ids','spec_sha256')}
        result.update(response,status='success',settled=True,fixture_only=False,
            actual_training=int(self.spec['tool'] in ('prepare','fit_lr','fit_rf')),
            actual_model_prediction=int(self.spec['tool'] in ('predict_lr','predict_rf')),
            evaluation_dataset_rows_executed=True,bound_inputs_are_execution_evidence=True,
            model_loads=int(self.spec['tool'] in ('predict_lr','predict_rf')),worker_started=True,
            finished_utc=datetime.now(timezone.utc).isoformat(),
            actual_parameters_from_projection=self.spec['inputs'].get('parameters'),
            payload_sha256=digest(response['payload']),
            produced_artifact_sha256={a['artifact_id']:a['sha256'] for a in response['artifacts']})
        return result


def execute(spec, *, permit=None):
    return prepare_backend(spec).execute(permit=permit)


def main(argv=None):
    """Only the explicitly permitted new supervisor may invoke this CLI."""
    import argparse
    import json
    from pathlib import Path
    parser=argparse.ArgumentParser()
    parser.add_argument('--spec',required=True);parser.add_argument('--response',required=True)
    parser.add_argument('--supervisor-permit',required=True)
    args=parser.parse_args(argv)
    spec=json.loads(Path(args.spec).read_text())
    response_path=Path(args.response).resolve()
    require(response_path==Path(spec['output_dir']).resolve()/'job_response.json','CPU_RESPONSE_PATH_BINDING')
    from .supervisor import validate_worker_permit
    validate_worker_permit(spec,json.loads(Path(args.supervisor_permit).read_text()))
    def deny_network(event,details):
        if event.startswith('socket.'):raise RuntimeError('CPU_WORKER_NETWORK_DISABLED')
    sys.addaudithook(deny_network)
    try:
        response=execute(spec,permit=WorkerPermit(True,True,True,True,True));exit_code=0
    except Exception as exc:
        response={'status':'failed','settled':False,'error':{'code':getattr(exc,'code',type(exc).__name__),'message':str(exc)}};exit_code=1
    temporary=response_path.with_name(response_path.name+'.tmp.'+str(os.getpid()))
    with temporary.open('x') as handle:
        json.dump(response,handle,sort_keys=True,allow_nan=False);handle.write('\n');handle.flush();os.fsync(handle.fileno())
    os.replace(temporary,response_path)
    return exit_code


if __name__=='__main__':raise SystemExit(main())
