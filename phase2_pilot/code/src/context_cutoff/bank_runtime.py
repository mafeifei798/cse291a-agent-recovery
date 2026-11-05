"""Bank entry sharing the existing agent workflow and tools, with live permits."""
from copy import deepcopy
from pathlib import Path
from time import monotonic_ns

from agent_recovery.contracts import require
from sr_recovery_v2.common import canonical, digest
from .contracts import identity, message_ref
from .runtime import AgentRun, ScriptedAgent,REPORT_KEY,PUBLICATION_KEY,DOC_KEY
from .bank_gateway import BankPilotGateway


class BankAgentRun(AgentRun):
    def __init__(self,directory,run_id,mode,gateway,*,cpu=None,cpu_permit=None):
        require(isinstance(gateway,BankPilotGateway), 'Bank gateway required', 'BANK_ENTRY')
        gateway.validate()
        config,permit = gateway.config,gateway.permit
        require(dict(config.runs).get(run_id)==mode
                and Path(directory).resolve()==Path(config.runs_root)/run_id,
                'Run path/context differs from registered C01/C02', 'BANK_RUN_NOT_REGISTERED')
        require(not Path(directory).exists(), 'Never overwrite or silently rerun a saved branch', 'BANK_RUN_EXISTS')
        if not gateway.fixture_only:
            require(cpu is not None and cpu.fixture_only is False and permit.training_authorized,
                    'Live Bank task requires explicit CPU execution permission', 'BANK_CPU_PERMISSION')
        # Reuse initialization, prompts, tools, provenance and result checks.
        # The legacy constructor stays fixture-only. This separately permitted
        # entry owns all model calls through BankPilotGateway below.
        super().__init__(directory,run_id,mode,gateway.ledger,model=ScriptedAgent(),cpu=cpu,cpu_permit=cpu_permit)
        self.gateway=gateway
        self.initial_real_request_count=gateway.model.real_request_count
        self.doc['bank_launch_config_sha256']=config.config_sha256
        self.doc['llm_fixture_only']=gateway.fixture_only
        self.doc['bank_pilot']=True

    def _call(self,role):
        require(monotonic_ns()-self.started < 120*10**9, 'Run deadline expired', 'BANK_DEADLINE')
        prompt=self.prompt(role)
        require(len(canonical(prompt).encode())<=16000, 'Context bytes exceed policy', 'BANK_CONTEXT_LIMIT')
        index=len(self.doc['llm_calls'])
        if hasattr(self.gateway,'identity_index'):
            index=self.gateway.identity_index(self.run_id,index)
        call_id=identity(self.id_scope,'llm',index)
        provisional=identity(self.id_scope,'node',len(self.store.snapshot()['nodes']))
        record=dict(call_id=call_id,attempt_id=call_id+'.attempt',trial_key=self.id_scope+'.'+role,
            logical_run_key=self.id_scope,branch_id=self.id_scope,run_id=self.run_id,
            result_id=provisional,step_id=role,phase=getattr(self,'call_phase','initial'))
        result=self.gateway.call(role,prompt,record,deadline_monotonic=self.started/10**9+120)
        call=dict(call_id=call_id,node_id=provisional,role=role,episode=self.id_scope,
            prompt_messages=deepcopy(prompt),prompt_refs=[message_ref(m) for m in prompt],
            prompt_sha256=digest(prompt),payload=deepcopy(result['payload']),
            fixture_only=self.gateway.fixture_only,token_usage_kind=result['sidecar']['token_usage_kind'],
            token_statistics=result['sidecar']['local_token_statistics'],wire_audit=result['audit'],
            token_count_comparison=result['token_count_comparison'],
            gateway_call_id=result['gateway_call_id'],replayed=result['replayed'])
        self.doc['llm_calls'].append(call)
        self.doc['real_api_calls']=self.gateway.model.real_request_count-self.initial_real_request_count
        return call,result['payload']

    def _tool(self,role,request_node,name,arguments,contract):
        if role=='Executor':
            tools=[t['name'] for t in self.doc['tool_calls'] if t['name'] in ('write_config','train','write_report','publish')]
            expected=('write_config','train','write_report','publish')
            if len(tools)>=len(expected) or name!=expected[len(tools)]:
                self.ledger.stop('BANK_EXECUTOR_TOOL_ORDER')
                require(False,'Executor must follow the registered tool order exactly once','BANK_EXECUTOR_TOOL_ORDER')
        return super()._tool(role,request_node,name,arguments,contract)

    def role(self,role,**kwargs):
        result=super().role(role,**kwargs)
        if role=='Analyst' and not any(t['name']=='read_file' and
                any(r['file_id']==DOC_KEY for r in t['reads']) for t in self.doc['tool_calls']):
            self.ledger.stop('BANK_ANALYST_DID_NOT_READ_SOURCE')
            require(False,'Analyst must actually read the versioned description','BANK_ANALYST_DID_NOT_READ_SOURCE')
        return result

    def finish(self,contract,**kwargs):
        import json
        tools=[t['name'] for t in self.doc['tool_calls'] if t['name'] in ('write_config','train','write_report','publish')]
        complete=tools==['write_config','train','write_report','publish']
        if complete:
            try:
                report=json.loads(self.store.read(REPORT_KEY)['content'])
                publication=json.loads(self.store.read(PUBLICATION_KEY)['content'])
                complete=(publication['status']=='published' and publication['report_sha256']==digest(report))
            except (KeyError,ValueError,RuntimeError):
                complete=False
        if not complete:
            self.ledger.stop('BANK_EXECUTOR_INCOMPLETE')
            require(False,'Executor final cannot replace successful tool receipts','BANK_EXECUTOR_INCOMPLETE')
        value=super().finish(contract,**kwargs)
        value['llm_fixture_only']=self.gateway.fixture_only
        value['real_api_calls']=self.gateway.model.real_request_count-self.initial_real_request_count
        self.doc=value
        if value['final']['outcome']!='correct_complete':
            self.ledger.stop('BANK_BUSINESS_CHECK_FAILED')
            value['ledger']=self.ledger.snapshot()
        # Correctly label future live model calls; the inherited tools keep
        # their own CPU/simulated-publication provenance.
        (self.directory/'trace.json').write_text(json.dumps(value,indent=2)+'\n')
        return value
