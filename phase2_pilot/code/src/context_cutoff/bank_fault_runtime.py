"""Permitted Bank workflow: shared pre-publication freeze and three recoveries.

Faults alter delivered Analyst facts, never the saved HTTP response. Billing
authority, in-flight calls and deadlines are outside the copied workspace.
"""
from copy import deepcopy
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import shutil
from time import monotonic_ns,time

from agent_recovery.contracts import require,digest,canonical_json
from sr_recovery_v2.common import closure_ids
from .runtime import (AgentRun,ScriptedAgent,initial_inputs,reference,DOC_KEY,DATA_KEY,CODE_KEY,
                      CONFIG_KEY,MODEL_KEY,REPORT_KEY,PUBLICATION_KEY)
from .bank_runtime import BankAgentRun
from .bank_gateway import BankPilotGateway
from .bank_fault_protocol import BankFaultConfig,BankFaultPermit,REGISTRY_SHA,write_new
from .bank_fault_artifacts import ENV_KEY,verify_bundle,file_pin
from .contracts import contract_digest
from .checker import check_contract
from .cpu import worker_code_text


class BeforePublication(Exception):
    def __init__(self,node):self.node=deepcopy(node)


class BusinessStop(Exception):
    def __init__(self,code):self.code=code


class BankFaultRun(BankAgentRun):
    def __init__(self,directory,unit_id,mode,gateway,cpu,environment_sha256,*,
                 deadline_epoch,document=None,cpu_permit=None,prefix=False):
        require(isinstance(gateway,BankPilotGateway) and isinstance(gateway.config,BankFaultConfig)
                and isinstance(gateway.permit,BankFaultPermit),
                'Independent fault gateway required','BF_ENTRY')
        gateway.validate()
        unit=gateway.ledger.connection.execute('SELECT state,deadline FROM bf_units WHERE unit_id=?',(unit_id,)).fetchone()
        require(unit and unit['state']=='running' and unit['deadline']==deadline_epoch,
                'Deadline differs from durable unit grant','BF_UNIT_DEADLINE')
        require(dict(gateway.config.runs).get(unit_id)==mode
                and Path(directory).resolve()==Path(gateway.config.runs_root)/unit_id,
                'Unit path differs from fixed registration','BF_REGISTRY')
        require((not Path(directory).exists()) if document is None else Path(directory).is_dir(),
                'Never rerun a saved unit','BF_UNIT_STATE')
        require(cpu.fixture_only is gateway.fixture_only,
                'Model and CPU evidence classification differs','BF_CPU_PERMISSION')
        if not gateway.fixture_only:
            require(gateway.permit.training_authorized,'Live CPU permission missing','BF_CPU_PERMISSION')
        AgentRun.__init__(self,directory,unit_id,mode,gateway.ledger,model=ScriptedAgent(),
                          cpu=cpu,cpu_permit=cpu_permit,document=document)
        self.doc['run_id']=unit_id
        self.gateway=gateway;self.environment_sha256=environment_sha256
        self.initial_real_request_count=gateway.model.real_request_count
        # The durable unit deadline is allocated once; copying a checkpoint,
        # fallback and repeated notifications cannot refresh it.
        remaining=deadline_epoch-time()
        require(0<remaining<=120,'Unit deadline expired','BF_UNIT_DEADLINE')
        self.started=monotonic_ns()-int((120-remaining)*1e9)
        self.prefix=prefix;self.unit_tools=[];self.retained_ids=[];self.current_bundle=None
        self.call_phase='initial' if prefix else 'replay'
        self.doc.update(bank_fault_pilot=True,registry_sha256=REGISTRY_SHA,
            llm_fixture_only=gateway.fixture_only,fixture_only=cpu.fixture_only,
            unit_id=unit_id,reuse_receipts=[],bank_launch_config_sha256=gateway.config.config_sha256)
        self.doc['registry_sha256']=gateway.config.registry_sha256
        self.store.db.execute('CREATE TABLE IF NOT EXISTS bf_reuse (receipt_id TEXT PRIMARY KEY,body TEXT NOT NULL)')

    def initialize(self):
        description,binding,_=initial_inputs();code=worker_code_text()
        for key,value in ((DOC_KEY,description),(DATA_KEY,binding),(CODE_KEY,code),
                          (ENV_KEY,{'sha256':self.environment_sha256}),
                          ('inputs/directory.json',[DOC_KEY,DATA_KEY,'inputs/permission.json']),
                          ('inputs/permission.json',{'publish_allowed':True})):
            self.store.initialize(key,value if isinstance(value,str) else canonical_json(value))
        self.doc['audit_policy']=dict(allowed_features=[f for f in description['feature_columns']
            if f not in description['unavailable_before_call']],data_binding=binding,
            code_sha256=hashlib.sha256(code.encode()).hexdigest(),prediction_time='pre_call')

    def _tool(self,role,request_node,name,arguments,contract):
        if role=='Executor':
            expected=('write_config','train','write_report','publish')
            require(len(self.unit_tools)<4 and name==expected[len(self.unit_tools)],
                    'Unit tool order or repeated training refused','BF_TOOL_ORDER')
            if name=='publish':
                if self.prefix:raise BeforePublication(request_node)
                verdict=self.business_guard(contract)
                if not verdict['passed']:raise BusinessStop('BF_PUBLICATION_GUARD')
                self.doc['numeric_check']=self.cpu.validate(self.current_bundle,contract)
            key={'write_config':CONFIG_KEY,'train':MODEL_KEY,'write_report':REPORT_KEY,'publish':PUBLICATION_KEY}[name]
            current=self.store.snapshot()['files'].get(key)
            if current and (current['writer_id']=='external' or current['writer_id'].startswith('external-')):
                raise BusinessStop('BF_EXTERNAL_OUTPUT_OWNER')
        if name=='publish':
            reads=[self.store.read(k) for k in (CONFIG_KEY,MODEL_KEY,REPORT_KEY)]
            actual_contract=json.loads(reads[0]['content']);artifact=json.loads(reads[1]['content'])
            report=json.loads(reads[2]['content'])
            require(contract_digest(actual_contract)==contract_digest(contract)
                    and artifact['artifact']==self.current_bundle
                    and artifact['artifact_receipt_sha256']==file_pin(self.current_bundle)
                    and artifact['contract_sha256']==contract_digest(contract)
                    and report=={'contract_sha256':contract_digest(contract),'artifact':artifact},
                    'Publication content differs from checked computation','BF_REPORT_BINDING')
            payload={'status':'published','report_sha256':digest(report),'fixture_only':True,'compensatable':True}
            read_refs=[reference(r) for r in reads]+verdict['source_refs']
            current=self.store.snapshot()['files'].get(PUBLICATION_KEY)
            write=self.store.write_checked(PUBLICATION_KEY,canonical_json(payload),current,
                request_node['result_id'],read_refs)
            known={n['result_id'] for n in self.store.snapshot()['nodes']}
            parents={request_node['result_id']}|{r['writer_id'] for r in read_refs if r['writer_id'] in known}
            tool_id=self.id_scope+'.tool.'+str(len(self.doc['tool_calls'])).zfill(4)
            node=self._node('tool',role,{'tool':name,**payload},sorted(parents),read_refs,tool_call_id=tool_id)
            self.doc['tool_calls'].append(dict(tool_call_id=tool_id,node_id=node['result_id'],name=name,
                reads=read_refs,writes=[write],fixture_only=True))
            self._message('tool',role,{'tool':name,**payload},node['result_id'])
        elif name!='train':
            node=AgentRun._tool(self,role,request_node,name,arguments,contract)
        else:
            require(role=='Executor' and arguments=={},'Invalid training request','BF_TOOL_ORDER')
            reads=[self.store.read(k) for k in (CONFIG_KEY,DATA_KEY,CODE_KEY,ENV_KEY)]
            saved=json.loads(reads[0]['content'])
            require(contract_digest(saved)==contract_digest(contract)
                    and saved['data_binding']==json.loads(reads[1]['content'])
                    and saved['code_sha256']==hashlib.sha256(reads[2]['content'].encode()).hexdigest()
                    and json.loads(reads[3]['content'])=={'sha256':self.environment_sha256},
                    'Actual inputs differ from contract/environment','BF_TRAIN_BINDING')
            payload=self.cpu.execute(saved)
            self.current_bundle=payload['artifact']
            current=self.store.snapshot()['files'].get(MODEL_KEY)
            write=self.store.write(MODEL_KEY,canonical_json(payload),expected=current,writer_id=request_node['result_id'])
            parents={request_node['result_id']};known={n['result_id'] for n in self.store.snapshot()['nodes']}
            parents.update(r['writer_id'] for r in reads if r['writer_id'] in known)
            tool_id=self.id_scope+'.tool.'+str(len(self.doc['tool_calls'])).zfill(4)
            node=self._node('tool',role,{'tool':name,**payload},sorted(parents),
                [reference(r) for r in reads],tool_call_id=tool_id)
            self.doc['tool_calls'].append(dict(tool_call_id=tool_id,node_id=node['result_id'],name=name,
                reads=[reference(r) for r in reads],writes=[write],fixture_only=self.cpu.fixture_only))
            self._message('tool',role,{'tool':name,**payload},node['result_id'])
        if role=='Executor':self.unit_tools.append(name)
        return node

    def business_guard(self,contract):
        files=self.store.snapshot()['files']
        truth=json.loads(self.store.read(DOC_KEY)['content'])
        facts=json.loads(self.latest['Analyst']['content'])['final']
        expected_binding=initial_inputs()[1]
        expected_code=hashlib.sha256(worker_code_text().encode()).hexdigest()
        contract_check=check_contract(contract,self.doc['audit_policy']['allowed_features'],
            expected_binding,expected_code)
        checks=dict(analyst_facts_current=facts==truth,
            current_feature_eligibility=set(contract['feature_columns']).issubset(
                set(truth['feature_columns'])-set(truth['unavailable_before_call'])),
            current_data_binding=json.loads(self.store.read(DATA_KEY)['content'])==expected_binding,
            current_code_binding=self.store.read(CODE_KEY)['content']==worker_code_text(),
            environment_current=json.loads(self.store.read(ENV_KEY)['content'])=={'sha256':self.environment_sha256},
            current_permission=json.loads(self.store.read('inputs/permission.json')['content'])=={'publish_allowed':True},
            contract_business_valid=contract_check['passed'])
        return dict(passed=all(checks.values()),checks=checks,contract_check=contract_check,
            source_refs=[files[k] for k in (DOC_KEY,DATA_KEY,CODE_KEY,ENV_KEY,'inputs/permission.json')])

    def role(self,role,**kwargs):
        # Preserve the same messages/tools, with no legacy C01 business error
        # allowed to quarantine the campaign's shared monetary authority.
        result=AgentRun.role(self,role,**kwargs)
        if role=='Analyst':
            ids={n['result_id'] for n in self.store.snapshot()['nodes'] if n['role']=='Analyst'
                 and n.get('tool_call_id') and any(r['file_id']==DOC_KEY for r in n.get('file_reads',[]))}
            require(bool(ids),'Analyst must read the current source','BF_SOURCE_NOT_READ')
        return result

    def finish(self,contract,*,safe_stop=False):
        if not safe_stop:
            require(self.unit_tools==['write_config','train','write_report','publish'],
                    'A complete execution or valid reacceptance is required','BF_EXECUTOR_INCOMPLETE')
            require(self.business_guard(contract)['passed'],'Final business guard failed','BF_FINAL_GUARD')
        result=AgentRun.finish(self,contract,retained=self.retained_ids,safe_stop=safe_stop)
        result.update(training_requests_this_unit=self.cpu.training_requests,
            real_api_calls=self.gateway.model.real_request_count-self.initial_real_request_count,
            reuse_receipts=deepcopy(self.doc.get('reuse_receipts',[])))
        write_new(self.directory/'UNIT_RESULT.json',result)
        return result


def freeze_prefix(run,fault,frozen_root):
    require(run.prefix,'Only a prefix may freeze','BF_FREEZE')
    run.id_scope=run.run_id;run.episode_messages=[];run.role_messages={};run.latest={}
    analyst=run.role('Analyst',fault=fault);planner=run.role('Planner')
    try:
        run.role('Executor')
    except BeforePublication as barrier:
        pending=barrier.node
    else:
        raise RuntimeError('BF_MISSING_FREEZE_BARRIER')
    require(PUBLICATION_KEY not in run.store.snapshot()['files']
            and all(c['status']=='settled' for c in run.ledger.calls()),
            'Freeze must precede publication with no unsettled HTTP','BF_FREEZE')
    guard=run.business_guard(planner['payload'])
    require(not guard['passed'] and len(run.doc['faults'])==1,
            'Expected injected fact mismatch at common barrier','BF_FREEZE')
    run.doc.update(run.store.snapshot())
    run.doc['final']={'outcome':'safe_stop','reason':'known-fault-pre-publication-freeze'}
    run.doc['elapsed_ns']=monotonic_ns()-run.started
    registry_sha=run.gateway.config.registry_sha256
    checkpoint=dict(schema_version='bank-fault-checkpoint-v1',registry_sha256=registry_sha,
        scene_id=run.run_id.split('.')[0],mode=run.mode,fault=fault,
        faulty_result_id=analyst['result_id'],planner_result_id=planner['result_id'],
        pending_publication_request=pending,document=deepcopy(run.doc),
        role_messages=deepcopy(run.role_messages),episode_messages=deepcopy(run.episode_messages),
        latest=deepcopy(run.latest),bundle_path=run.current_bundle,bundle_file_sha256=file_pin(run.current_bundle),
        guard=guard,environment_sha256=run.environment_sha256,
        publication_executed=False,all_http_settled=True,
        ledger_authority_path=str(run.ledger.path.resolve()))
    root=Path(frozen_root);root.mkdir(parents=True,exist_ok=False)
    run.store.save_to(root/'state');write_new(root/'CHECKPOINT.json',checkpoint)
    pins={str(p.relative_to(root)):file_pin(p) for p in sorted(root.rglob('*')) if p.is_file()}
    manifest=dict(files=pins,checkpoint_sha256=digest(checkpoint),registry_sha256=registry_sha)
    manifest['freeze_sha256']=digest(manifest);write_new(root/'MANIFEST.json',manifest)
    return manifest


def load_frozen(root,*,expected_registry_sha256=REGISTRY_SHA):
    root=Path(root);manifest=json.loads((root/'MANIFEST.json').read_text())
    require(manifest['freeze_sha256']==digest({k:v for k,v in manifest.items() if k!='freeze_sha256'})
            and manifest['registry_sha256']==expected_registry_sha256,'Frozen manifest changed','BF_FREEZE_CHANGED')
    for name,pin in manifest['files'].items():
        require(not Path(name).is_absolute() and '..' not in Path(name).parts
                and file_pin(root/name)==pin,'Frozen bytes changed','BF_FREEZE_CHANGED')
    checkpoint=json.loads((root/'CHECKPOINT.json').read_text())
    require(digest(checkpoint)==manifest['checkpoint_sha256']
            and file_pin(checkpoint['bundle_path'])==checkpoint['bundle_file_sha256']
            and checkpoint['all_http_settled'] and not checkpoint['publication_executed'],
            'Freeze or bound artifact differs','BF_FREEZE_CHANGED')
    return checkpoint,manifest


def accept_artifact(run,checkpoint,decision):
    """Commit source refs and acceptance evidence under one workspace writer lock."""
    old=checkpoint['document'];contract=decision['candidate_contract']
    bundle=verify_bundle(checkpoint['bundle_path'],contract,run.environment_sha256)
    retained=[n['result_id'] for n in old['nodes'] if n['role']=='Executor']
    with run.store._transaction():
        snap=run.store._snapshot()
        require(all(snap['files'][r['file_id']]==r for r in decision['candidate_guard']['source_refs']),
                'Source changed before acceptance','BF_ACCEPTANCE_RACE')
        require(all(snap['files'].get(k)==checkpoint['document']['files'].get(k)
                    for k in (CONFIG_KEY,MODEL_KEY,REPORT_KEY)),
                'Retained outputs changed before acceptance','BF_ACCEPTANCE_RACE')
        body=dict(schema_version='bank-artifact-reuse-v1',receipt_id=run.run_id+'.reuse.0000',
            freeze_sha256=decision['freeze_sha256'],old_planner_result_id=checkpoint['planner_result_id'],
            new_planner_result_id=decision['new_result_id'],contract_sha256=contract_digest(contract),
            bundle_path=checkpoint['bundle_path'],bundle_sha256=bundle['sha256'],
            bundle_file_sha256=file_pin(checkpoint['bundle_path']),
            source_refs=decision['candidate_guard']['source_refs'],cut_edges=decision['cut_edges'],
            retained_output_refs=[snap['files'][k] for k in (CONFIG_KEY,MODEL_KEY,REPORT_KEY)],
            retained_result_ids=retained,fixture_only=run.cpu.fixture_only,
            new_training_requests=0,other_inputs_valid=True)
        body['sha256']=digest(body)
        run.store.db.execute('INSERT INTO bf_reuse VALUES(?,?)',(body['receipt_id'],canonical_json(body)))
        run.store._event('artifact_reaccepted',receipt_id=body['receipt_id'],sha256=body['sha256'])
    run.doc['reuse_receipts'].append(body);run.retained_ids=retained
    run.current_bundle=checkpoint['bundle_path']
    return body


def recover_frozen(frozen_root,directory,unit_id,method,gateway,cpu,*,deadline_epoch,
                   environment_sha256,cpu_permit=None,after_update=None,before_accept=None):
    require(method in ('FULL','CONSERVATIVE','CUTOFF'),'Unknown recovery','BF_REGISTRY')
    checkpoint,manifest=load_frozen(frozen_root,expected_registry_sha256=gateway.config.registry_sha256)
    require(unit_id==checkpoint['scene_id']+'.'+method,'Recovery scene differs','BF_REGISTRY')
    require(Path(frozen_root).resolve()==Path(gateway.config.runs_root).parent/'frozen'/checkpoint['scene_id']
            and checkpoint['ledger_authority_path']==str(gateway.ledger.path.resolve()),
            'Frozen scene belongs to another monetary authority','BF_AUTHORITY')
    require(gateway.fixture_only or (after_update is None and before_accept is None),
            'Offline test hooks cannot enter live recovery','BF_TEST_HOOK')
    source_calls = (gateway.ledger.recovery_source_calls() if hasattr(gateway.ledger,'recovery_source_calls')
                    else gateway.ledger.calls())
    paid={c['call_id']:c for c in source_calls}
    for call in checkpoint['document']['llm_calls']:
        row=paid.get(call['call_id'])
        require(row and row['status']=='settled' and row['evidence']['payload']==call['payload']
                and row['evidence']['wire_audit']==call['wire_audit'],
                'Every frozen response must be settled in the shared authority','BF_AUTHORITY')
    prefix=gateway.ledger.connection.execute('SELECT state,receipt FROM bf_units WHERE unit_id=?',
        (checkpoint['scene_id']+'.PREFIX',)).fetchone()
    require(prefix and prefix['state']=='finished'
            and json.loads(prefix['receipt'])['freeze_sha256']==manifest['freeze_sha256'],
            'Prefix acceptance missing or changed','BF_AUTHORITY')
    shutil.copytree(Path(frozen_root)/'state',directory)
    run=BankFaultRun(directory,unit_id,checkpoint['mode'],gateway,cpu,environment_sha256,
        deadline_epoch=deadline_epoch,document=checkpoint['document'],cpu_permit=cpu_permit)
    try:
        run.id_scope=unit_id
        # The same fixed external event is applied to every copied scene.
        before=reference(run.store.read(DOC_KEY));description=json.loads(run.store.read(DOC_KEY)['content'])
        description['note']+=' External owner clarified the documentation.'
        updated=run.store.write(DOC_KEY,canonical_json(description),before,'external-owner')['after']
        if after_update:after_update(run)
        run.episode_messages=[];run.role_messages={};run.latest={}
        run.role('Analyst');new=run.role('Planner');candidate=new['payload']
        guard=run.business_guard(candidate)
        old=checkpoint['document'];old_id=checkpoint['planner_result_id']
        original=next(n for n in old['nodes'] if n['result_id']==old_id)
        equivalent=contract_digest(original['payload'])==contract_digest(candidate)
        files=run.store.snapshot()['files'];seeds={checkpoint['faulty_result_id']}
        for n in old['nodes']:
            if any(files.get(r['file_id'])!=r for r in n.get('file_reads',[])):seeds.add(n['result_id'])
        cuts=[dict(parent_result_id=old_id,child_result_id=n['result_id'])
              for n in old['nodes'] if old_id in n['parent_result_ids']]
        excluded={(e['parent_result_id'],e['child_result_id']) for e in cuts}
        reduced=[{**n,'parent_result_ids':[p for p in n['parent_result_ids'] if (p,n['result_id']) not in excluded]}
                 for n in old['nodes']]
        invalid=set(closure_ids(seeds,reduced))
        executor=[n for n in old['nodes'] if n['role']=='Executor']
        other_valid=all(n['result_id'] not in invalid for n in executor)
        other_valid=other_valid and all(files.get(k)==old['files'].get(k)
                                       for k in (CONFIG_KEY,MODEL_KEY,REPORT_KEY))
        retain=method=='CUTOFF' and equivalent and other_valid and guard['passed']
        decision=dict(method=method,round=1,node_id='Planner',old_result_id=old_id,new_result_id=new['result_id'],
            equivalent=equivalent,other_inputs_valid=other_valid,candidate_guard=guard,
            candidate_contract=candidate,freeze_sha256=manifest['freeze_sha256'],
            cut_edges=cuts if retain else [],action='retain' if retain else 'invalidate',
            invalidated_result_ids=sorted(invalid if retain else set(closure_ids(seeds,old['nodes']))),
            source_update={'before':before,'after':updated},rechecks=1)
        run.doc['decisions'].append(decision)
        if not guard['passed']:
            result=run.finish(candidate,safe_stop=True)
        else:
            if retain:
                if before_accept:before_accept(run)
                accept_artifact(run,checkpoint,decision)
                run.role_messages['Executor']=deepcopy(checkpoint['role_messages']['Executor'])
                run.unit_tools=['write_config','train','write_report']
                pending=checkpoint['pending_publication_request']
                run._tool('Executor',pending,'publish',{},candidate)
            run.role('Executor')
            result=run.finish(candidate)
        result['recovery']=dict(method=method,freeze_sha256=manifest['freeze_sha256'],
            source_update=decision['source_update'],source_update_preserved=reference(run.store.read(DOC_KEY))==updated,
            new_calls=len(result['llm_calls'])-len(old['llm_calls']),
            retained_result_ids=run.retained_ids,training_requests=cpu.training_requests,
            actual_training=result['actual_training'],actual_prediction=result['actual_prediction'])
        write_new(Path(directory)/'RECOVERY_RESULT.json',result)
        return result
    except BusinessStop as error:
        # Expected business refusal is not a provider/budget uncertainty.
        candidate=locals().get('candidate') or checkpoint['document']['audit_policy']
        result=run.finish(candidate,safe_stop=True)
        result['business_stop']=error.code
        result['recovery']=dict(method=method,freeze_sha256=manifest['freeze_sha256'],
            source_update_preserved=reference(run.store.read(DOC_KEY))==updated,
            new_calls=len(run.doc['llm_calls'])-len(checkpoint['document']['llm_calls']),
            training_requests=cpu.training_requests,retained_result_ids=run.retained_ids)
        write_new(Path(directory)/'RECOVERY_RESULT.json',result)
        return result
    finally:
        run.doc.update(run.store.snapshot())
        write_new(Path(directory)/'RUN_STATE.json',run.doc)
        run.close()
