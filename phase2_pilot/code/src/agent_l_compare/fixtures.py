from copy import deepcopy
from decimal import Decimal
import json

from agent_l_approval_confirm.fixtures import SavedService as PriorService
from agent_l_feedback_replay.fixtures import SavedCPU
from agent_recovery.p3_transport import fake_http_response,HTTPResponse
from agent_recovery.contracts import require,digest


class Spend:
    def __init__(self,h):self.value=Decimal(h['expected_key_spend_nano'])
    def get(self,request):
        return HTTPResponse(200,{},json.dumps({'spend_nano':str(self.value),'max_budget_nano':'50000000000'}).encode())


class Service(PriorService):
    def __init__(self,local,frozen,source,mode,unit,spend):
        super().__init__(local,frozen,source,mode)
        self.unit,self.shared=unit,spend
        d=json.loads((source/'outputs/l_confirm_real_20261031_r1/evidence/real/run/RESULT.json').read_text())
        self.success=[c for c in d['llm_calls'] if c['call_id'].startswith('FR04.CUTOFF.')]
        self.saved_confirm=next(c for c in self.success if c['role']=='Reviewer' and c['raw']['final'].get('operation'))
        self.saved_adjusted=next(c for c in self.success if c['role']=='Planner'
            and any(m.get('input_kind')=='confirmed_approval' for m in c['messages']))

    def post(self,request):
        self.spend=self.shared.value
        response=super().post(request)
        body=json.loads(response.body);payload=json.loads(body['choices'][0]['message']['content'])
        wire=json.loads(request.body);system=json.loads(wire['messages'][0]['content'].split('\n',1)[0])
        values=[]
        for m in wire['messages'][1:]:
            if m['role']=='user':
                v=json.loads(m['content'])
                if v.get('source_role')!='tool':values.append(v.get('payload',{}))
        source=None;kind=None
        if system['role']=='Planner' and any(v.get('context_kind')=='confirmed_adjustment_handoff' for v in values):
            source=self.saved_adjusted;payload=deepcopy(source['raw']);kind='saved_successful_adjusted_planner'
            if self.mode=='changed_contract':
                payload={'final':{'bundle':'D8','recipe':'LR'}};source=None;kind='synthetic_legal_changed_contract'
        elif system.get('review_operation')=='confirm_existing_approval' and self.mode not in (
                'typed_stop','saved_real_stop','legacy_adjust','wrong_approval'):
            source=self.saved_confirm;payload=deepcopy(source['raw'])
            payload['final']['evidence_id']=system['confirmation_binding']['evidence_id']
            payload['final']['approval_id']=system['confirmation_binding']['approval_id']
            kind='saved_successful_confirmation_explicit_ID_remap'
        elif system['role']=='Reviewer' and system.get('review_operation')=='normal_review' and self.mode in ('changed_contract','initial_changed'):
            payload['final']['reason']='Synthetic changed-contract fixture: simulated AP meets the fixed goal.'
            source=None;kind='synthetic_review_of_changed_contract'
        if kind:
            self.audit[-1].update(response_kind=kind,response_payload=deepcopy(payload),
                source_call_id=source['call_id'] if source else None,
                source_payload_sha256=digest(source['raw']) if source else None,
                payload_unchanged=bool(source and payload==source['raw']))
        self.shared.value=self.spend
        identity='fixture-'+self.unit+'-'+str(self.sent)
        return fake_http_response(payload,model='api-glm-5.3-flash',
            prompt_tokens=self.local.estimate_request(wire).prompt_tokens,completion_tokens=200,
            request_id=identity,headers={'x-litellm-call-id':identity})


class CPU(SavedCPU):
    def fit(self,*args,**kwargs):
        require(self.fit_count<3,'Same three-task fit cap for every method','CMP_FIT_CAP')
        return super().fit(*args,**kwargs)
