"""Explicit Phase 2 CPU contracts; dispatch requires an injected client.

No process, estimator or numerical library is started/imported by this module.
FakeWorkerClient is an interface test, not a real Adult/Bank experiment.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
EVAL_PACK_SHA256 = '401830a27619259a184aaf9c488587eddd565e6d7f95b93122b0a1afab68a5a1'
PROTOCOL_SHA256 = '3d66f337dde6cd6aebda205584c4c7b8cade8d06f614f105056e496f49b4ef2a'
TOOLS = ('profile','prepare','fit_lr','predict_lr','summary_lr','fit_rf','predict_rf','summary_rf','publish')
LIMITS = {'cpu_threads':1, 'address_space_bytes':8*1024**3, 'rss_monitor_bytes':8*1024**3,
          'max_artifact_bytes':128*1024**2, 'total_disk_bytes':4*1024**3,
          'wall_seconds':120, 'network_enabled':False, 'gpu_enabled':False}


class CPUContractError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(ok, code):
    if not ok:
        raise CPUContractError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',',':'), ensure_ascii=False, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda:handle.read(1024**2), b''):
            h.update(block)
    return h.hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def utc(value):
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(str(value).replace('Z','+00:00'))
    require(parsed.tzinfo is not None, 'CPU_DEADLINE_TIMEZONE')
    return parsed.astimezone(timezone.utc)


def _path(root, relative):
    rel = Path(relative)
    require(not rel.is_absolute() and '..' not in rel.parts, 'CPU_PATH_ESCAPE')
    path = root / rel
    require(path.resolve().is_relative_to(root.resolve()), 'CPU_PATH_ESCAPE')
    require(not any(p.is_symlink() for p in [path,*path.parents] if p==root or root in p.parents), 'CPU_SYMLINK')
    return path


@dataclass(frozen=True)
class ExplicitEvalBinding:
    """Serialized immutable binding; properties return copies, never live state."""
    encoded: str

    def document(self):
        return json.loads(self.encoded)


def load_eval_binding(*, task_id, dataset_id, expected_pack_sha256=EVAL_PACK_SHA256,
                      pack_path=None, protocol_sha256=None):
    from phase2.p0.pack import load_pack
    base = Path(pack_path or ROOT/'phase2/p0/frozen').resolve()
    require(expected_pack_sha256 == EVAL_PACK_SHA256 and sha(base/'FREEZE.json') == EVAL_PACK_SHA256, 'CPU_EVALUATION_PACK_PIN')
    pack = load_pack(base)
    matches = [t for t in read(base/'tasks/macro_tasks.json')['tasks'] if t['task_id']==task_id]
    require(len(matches)==1, 'CPU_EXACT_TASK_REQUIRED')
    task = matches[0]
    require(dataset_id in ('adult','bank') and task_id==f'phase2-{dataset_id}-eval-01'
            and task['public_request']['dataset_id']==dataset_id, 'CPU_TASK_DATASET_MISMATCH')
    require(task['public_request']['test_labels_available'] is False, 'CPU_TEST_LABELS_EXPOSED')
    manifest = read(base/'data/manifest.json')
    require(sha(base/'data/manifest.json')==task['data_binding']['manifest_sha256'], 'CPU_DATA_MANIFEST_PIN')
    files = {e['path']:e for e in manifest['files']}
    relative = ['schema_and_preprocessing.json', f'raw/{dataset_id}/'+('adult.data' if dataset_id=='adult' else 'bank-additional-full.csv')]
    relative += [f'splits/{dataset_id}/{s}.json' for s in ('train_v1','train_v2','validation')]
    records = []
    for name in relative:
        p = _path(base/'data',name); e=files[name]
        require(p.stat().st_size==e['bytes'] and sha(p)==e['sha256'], 'CPU_INPUT_FILE_PIN')
        records.append({'relative_path':'data/'+name, 'sha256':e['sha256'], 'size_bytes':e['bytes']})
    splits = {s:read(base/f'data/splits/{dataset_id}/{s}.json') for s in ('train_v1','train_v2','validation')}
    for name,s in splits.items():
        require(s['row_count']==len(s['row_ids'])==len(set(s['row_ids'])) and digest(s['row_ids'])==s['row_ids_digest'], 'CPU_ROW_MANIFEST_DIGEST')
        if name!='validation':
            require(s['row_ids_digest']==task['data_binding'][name+'_row_digest'], 'CPU_TASK_ROWS_PIN')
            require(not(set(s['row_ids']) & set(splits['validation']['row_ids'])), 'CPU_SPLIT_LEAKAGE')
    binding = {'schema_version':'phase2-explicit-eval-binding-v1','pack_root':str(base),'task_id':task_id,
        'dataset_id':dataset_id,'evaluation_pack_sha256':EVAL_PACK_SHA256,
        'protocol_sha256':protocol_sha256 or PROTOCOL_SHA256,'task_sha256':digest(task),
        'data_manifest_sha256':task['data_binding']['manifest_sha256'],
        'input_files':records,'splits':{n:{'row_count':s['row_count'],'row_ids_digest':s['row_ids_digest']} for n,s in splits.items()},
        'dag':deepcopy(pack['dag']),'recipes':read(base/'environment/model_recipes.json'),
        'test_labels_available_to_agent':False,'raw_access_policy':'trusted row-selector; no agent file access'}
    require(binding['protocol_sha256']==PROTOCOL_SHA256,'CPU_PROTOCOL_SHA')
    require(sha(ROOT/'phase2/unified_r1/frozen/FREEZE.json')==PROTOCOL_SHA256,'CPU_PROTOCOL_BYTES_CHANGED')
    return ExplicitEvalBinding(canonical(binding).decode())


def _training_version(projection):
    reads=[]
    for parent in projection.get('parent_inputs',[]):
        reads.extend(parent.get('effective_reads',[]))
    reads += [{'object_key':s['object_key'],'version':s['version']} for s in projection.get('direct_source_inputs',[])]
    versions={r['version'] for r in reads if r['object_key']=='data:train'}
    require(len(versions)==1 and versions <= {1,2}, 'CPU_TRAIN_SOURCE_REQUIRED')
    return versions.pop()


def build_tool_spec(binding, node_id, attempt, projection, artifacts, deadline, output, artifact_root=None):
    b=binding.document(); require(node_id in TOOLS,'CPU_TOOL_NOT_ALLOWED')
    require(projection.get('node_id')==node_id and projection.get('request',{}).get('dataset_id')==b['dataset_id'], 'CPU_PROJECTION_IDENTITY')
    if 'task_id' in projection:
        require(projection['task_id']==b['task_id'],'CPU_PROJECTION_TASK')
    node={n['node_id']:n for n in b['dag']['nodes']}[node_id]
    parents=projection.get('parent_inputs',[])
    require([p['node_id'] for p in parents]==node['parents'],'CPU_SELECTED_PARENT_SET')
    require(len({p['result_id'] for p in parents})==len(parents),'CPU_PARENT_ID_DUPLICATE')
    for p in parents:
        require(p.get('payload_digest')==digest(p['payload']),'CPU_PARENT_PAYLOAD_DIGEST')
    version=_training_version(projection)
    inputs={'dataset_id':b['dataset_id'],'train_version':version}
    payloads={p['node_id']:p['payload'] for p in parents}
    if node_id.startswith(('fit_','predict_','summary_')):
        family=node_id[-2:]; inputs.update(family=family,prepare=deepcopy(payloads['prepare']))
        if node_id.startswith('fit_'):
            plan=payloads['plan_'+family]
            inputs['parameters']=deepcopy(plan.get('parameters',plan.get('model_parameters')))
            require(inputs['parameters'] in [r for key,r in b['recipes'].items() if key.startswith(family+'_')], 'CPU_UNAPPROVED_RECIPE')
        elif node_id.startswith('predict_'):
            inputs['fit']=deepcopy(payloads['fit_'+family])
        else:
            inputs['predict']=deepcopy(payloads['predict_'+family])
    elif node_id=='publish':
        inputs.update(report=deepcopy(payloads['report']),action='publish_manifest')
    root=Path(artifact_root or Path(output).parent).resolve(); out=Path(output).resolve()
    require(out != root and out.is_relative_to(root),'CPU_OUTPUT_ROOT')
    require(not any('.test' in a['artifact_id'] or a.get('access')=='checker_only' for a in artifacts),'CPU_PRIVATE_ARTIFACT_EXPOSED')
    refs=[a['artifact_id'] for a in artifacts]
    require(len(refs)==len(set(refs)), 'CPU_DUPLICATE_ARTIFACT')
    spec={'schema_version':'phase2-cpu-spec-v1','tool':node_id,'node_id':node_id,
        'job_id':attempt['attempt_id'],'attempt_id':attempt['attempt_id'],'result_id':attempt['attempt_id']+'.result',
        'task_id':b['task_id'],'dataset_id':b['dataset_id'],'evaluation_pack_sha256':b['evaluation_pack_sha256'],
        'protocol_sha256':b['protocol_sha256'],'task_sha256':b['task_sha256'],
        'data_manifest_sha256':b['data_manifest_sha256'],'train_version':version,
        'train_row_ids_digest':b['splits'][f'train_v{version}']['row_ids_digest'],
        'validation_row_ids_digest':b['splits']['validation']['row_ids_digest'],
        'input_files':deepcopy(b['input_files']),'evaluation_pack_root':b['pack_root'],
        'projection':deepcopy(projection),'selected_parent_ids':[p['result_id'] for p in parents],
        'input_digest':digest(projection),'inputs':inputs,'artifacts':deepcopy(artifacts),
        'deadline_utc':utc(deadline).isoformat(),'limits':deepcopy(LIMITS),
        'artifact_root':str(root),'output_dir':str(out),
        'test_labels_available_to_agent':False,'worker_entrypoint':'phase2_unified.cpu_worker.execute'}
    spec['spec_sha256']=digest(spec)
    return spec


def verify_spec(spec):
    require(spec.get('schema_version')=='phase2-cpu-spec-v1','CPU_SPEC_SCHEMA')
    require(spec.get('spec_sha256')==digest({k:v for k,v in spec.items() if k!='spec_sha256'}),'CPU_SPEC_SHA')
    b=load_eval_binding(task_id=spec['task_id'],dataset_id=spec['dataset_id'],
        expected_pack_sha256=spec['evaluation_pack_sha256'],pack_path=spec['evaluation_pack_root'],
        protocol_sha256=spec['protocol_sha256'])
    rebuilt=build_tool_spec(b,spec['node_id'],{'attempt_id':spec['attempt_id']},spec['projection'],
        spec['artifacts'],spec['deadline_utc'],spec['output_dir'],spec['artifact_root'])
    require(rebuilt==spec,'CPU_SPEC_BINDING_MISMATCH')
    return b


def verify_artifacts(root, artifacts):
    root=Path(root).resolve()
    for a in artifacts:
        path=_path(root,a['uri']); require(path.is_file(),'CPU_ARTIFACT_MISSING')
        require(not(path.stat().st_mode & 0o222),'CPU_ARTIFACT_MUTABLE')
        require(path.stat().st_size==a['size_bytes'] and sha(path)==a['sha256'],'CPU_ARTIFACT_SHA')
        require(path.stat().st_size<=LIMITS['max_artifact_bytes'],'CPU_ARTIFACT_TOO_LARGE')


class FakeWorkerClient:
    """Consumes validated contracts; output remains explicitly synthetic."""
    def __init__(self, *, payload=None, artifacts=None, parameters=None, case=None, finished_utc=None):
        self.payload=deepcopy(payload or {}); self.artifacts=deepcopy(artifacts or [])
        self.parameters=deepcopy(parameters or {}); self.case=case; self.finished_utc=finished_utc
        self.calls=[]

    def execute(self,spec):
        verify_spec(spec); self.calls.append(deepcopy(spec))
        finished=self.finished_utc or datetime.now(timezone.utc).isoformat()
        receipt={k:deepcopy(spec[k]) for k in ('job_id','attempt_id','result_id','node_id','task_id','dataset_id',
            'evaluation_pack_sha256','protocol_sha256','data_manifest_sha256','train_version','train_row_ids_digest',
            'validation_row_ids_digest','input_digest','selected_parent_ids','spec_sha256')}
        receipt.update(status='unknown' if self.case=='unknown' else 'success',settled=self.case!='unknown',
            fixture_only=True,actual_training=0,actual_model_prediction=0,model_loads=0,worker_started=False,
            evaluation_dataset_rows_executed=False, bound_inputs_are_execution_evidence=False,
            payload=deepcopy(self.payload),artifacts=deepcopy(self.artifacts),parameters=deepcopy(self.parameters),
            actual_parameters_from_projection=deepcopy(spec['inputs'].get('parameters')),
            payload_sha256=digest(self.payload),
            finished_utc=finished,produced_artifact_sha256={a['artifact_id']:a['sha256'] for a in self.artifacts})
        if self.case=='wrong_identity': receipt['task_id']='macro-'+spec['dataset_id']+'-01'
        return receipt


def dispatch(spec, *, client, now=None):
    verify_spec(spec); verify_artifacts(spec['artifact_root'],spec['artifacts'])
    moment=utc(now or datetime.now(timezone.utc))
    require(moment<utc(spec['deadline_utc']),'CPU_DEADLINE_BEFORE_DISPATCH')
    response=client.execute(deepcopy(spec))
    require(response.get('settled') is True and response.get('status')=='success','CPU_UNSETTLED_OR_FAILED')
    for key in ('job_id','attempt_id','result_id','node_id','task_id','dataset_id','evaluation_pack_sha256','protocol_sha256',
                'data_manifest_sha256','train_version','train_row_ids_digest','validation_row_ids_digest',
                'input_digest','selected_parent_ids','spec_sha256'):
        require(response.get(key)==spec[key],'CPU_RECEIPT_IDENTITY_'+key.upper())
    require(utc(response['finished_utc'])<utc(spec['deadline_utc']),'CPU_LATE_RESPONSE')
    require(response.get('actual_parameters_from_projection')==spec['inputs'].get('parameters'),'CPU_RECEIPT_RECIPE')
    require(response.get('payload_sha256')==digest(response.get('payload')),'CPU_RECEIPT_PAYLOAD_SHA')
    require(all(a.get('producer_result_id')==spec['result_id'] for a in response.get('artifacts',[])), 'CPU_OUTPUT_PRODUCER_IDENTITY')
    verify_artifacts(spec['artifact_root'],response.get('artifacts',[]))
    require(response.get('produced_artifact_sha256')=={a['artifact_id']:a['sha256'] for a in response.get('artifacts',[])},'CPU_RECEIPT_ARTIFACT_HASHES')
    return response


class SupervisedWorkerClient:
    """Gateway client using the new routed supervisor; live mode stays gated."""
    def __init__(self,campaign_root,*,backend=None,permit=None,at_utc=None):
        self.campaign_root=campaign_root;self.backend=backend;self.permit=permit;self.at_utc=at_utc
        self.executions=[]

    def execute(self,spec):
        from .supervisor import run_job,FakeSupervisor
        result=run_job(spec,self.campaign_root,backend=self.backend,permit=self.permit,at_utc=self.at_utc)
        self.executions.append(deepcopy(result['execution']))
        execution=result['execution']
        require(execution['status']=='success' and execution['worker_reaped'] is True
            and not execution['remaining_processes'],'CPU_SUPERVISOR_UNSETTLED_OR_FAILED')
        response=deepcopy(result['response'])
        require(isinstance(response,dict),'CPU_SUPERVISOR_RESPONSE_REQUIRED')
        response['parameters']={**response.get('parameters',{}),'execution':deepcopy(execution)}
        if isinstance(self.backend,FakeSupervisor):
            response.update(fixture_only=True,actual_training=0,actual_model_prediction=0,model_loads=0,
                worker_started=False,evaluation_dataset_rows_executed=False,bound_inputs_are_execution_evidence=False)
        return response


def assemble_cpu_package(view,node_id,attempt,projection,receipt,*,calls=()):
    """Put injected/real worker output in the actual candidate, not a sidecar.

    A real numerical result still requires the real-artifact guard and checker;
    this packaging contract alone makes no numerical-correctness claim.
    """
    from sr_recovery_v2.common import REV,merge_reads
    node={n['node_id']:n for n in view['dag']['nodes']}[node_id]
    require(node_id in TOOLS and node['cpu_jobs_per_execution']==1,'CPU_PACKAGE_TOOL_REQUIRED')
    require(receipt.get('node_id')==node_id and receipt.get('attempt_id')==attempt['attempt_id']
        and receipt.get('result_id')==attempt['attempt_id']+'.result'
        and receipt.get('input_digest')==digest(projection),'CPU_PACKAGE_IDENTITY')
    parents=projection['parent_inputs'];require(receipt.get('selected_parent_ids')==[p['result_id'] for p in parents],'CPU_PACKAGE_PARENTS')
    require(receipt.get('payload_sha256')==digest(receipt.get('payload')) and receipt.get('settled') is True
        and receipt.get('status')=='success','CPU_PACKAGE_UNSETTLED')
    require(receipt.get('task_id')==view['task']['task_id'],'CPU_PACKAGE_TASK')
    require(len(calls)==node['llm_calls_per_execution'],'CPU_LLM_CALL_EVIDENCE_REQUIRED')
    made=deepcopy(receipt.get('artifacts',[]));rid=receipt['result_id'];aid=attempt['attempt_id']
    require(all(a.get('producer_result_id')==rid for a in made),'CPU_PACKAGE_ARTIFACT_PRODUCER')
    require(receipt.get('produced_artifact_sha256')=={a['artifact_id']:a['sha256'] for a in made},'CPU_PACKAGE_ARTIFACT_HASH')
    fixture=receipt.get('fixture_only') is True
    direct=sorted([{'object_key':s['object_key'],'version':s['version']} for s in projection['direct_source_inputs']],key=lambda s:s['object_key'])
    params=deepcopy(receipt.get('parameters',{}));execution=params.get('execution',{})
    tool_receipt={'record_type':'ToolReceipt','revision':REV,'fixture_only':fixture,
        'receipt_id':aid+'.receipt','run_id':view['state']['run_id'],'node_id':node_id,'attempt_id':aid,
        'producer_result_id':rid,'tool':('phase2.fake.' if fixture else 'phase2.cpu.')+node_id,
        'input_digest':digest(projection),'parameters':params,'artifact_refs':[a['artifact_id'] for a in made],
        'cpu_seconds':execution.get('cpu_seconds',0),'wall_seconds':execution.get('wall_seconds',0),
        'exit_code':0,'warnings':deepcopy(receipt.get('warnings',[]))}
    result={'record_type':'NodeResult','revision':REV,'fixture_only':fixture,'run_id':view['state']['run_id'],
        'node_id':node_id,'attempt_id':aid,'result_id':rid,'producer':node['role'],'execution_status':'success',
        'parent_result_ids':[p['result_id'] for p in parents],'direct_reads':direct,
        'effective_reads':merge_reads([direct]+[p['effective_reads'] for p in parents]),
        'input_digest':digest(projection),'input_snapshot':deepcopy(projection),'payload':deepcopy(receipt['payload']),
        'artifact_refs':[a['artifact_id'] for a in made],'call_ids':[c['call_id'] for c in calls],
        'tool_receipt_ids':[tool_receipt['receipt_id']]}
    return {'result':result,'artifacts':made,'calls':deepcopy(list(calls)),
        'tool_receipts':[tool_receipt],'cpu_gateway_receipt':deepcopy(receipt)}
