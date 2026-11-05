"""Captured payloads plus explicitly synthetic new confirmation envelopes."""
from copy import deepcopy
from decimal import Decimal
import json

from agent_l_api.fixtures import Service as MetadataService
from agent_recovery.p3_transport import fake_http_response
from agent_recovery.contracts import digest
from .model import CONFIRM

REAL_REL = 'outputs/l_replay_cutoff_real_20261031_r2/evidence/real/run/RESULT.json'


class SavedService(MetadataService):
    def __init__(self, local, frozen, source, mode='equivalent'):
        super().__init__(local)
        self.mode,self.audit = mode,[]
        real = json.loads((source/REAL_REL).read_text())
        self.real = [c for c in real['llm_calls'] if c['call_id'].startswith('FR02.CUTOFF.')]
        self.analyst = [c for c in self.real if c['role'] == 'Analyst']
        self.initial = next(c for c in self.real if c['role'] == 'Planner' and 'final' in c['raw'])
        self.adjusted = next(c for c in frozen['llm_calls'] if c['role'] == 'Planner' and 'final' in c['raw']
                             and any(m.get('input_kind') == 'feedback' for m in c['messages']))
        self.old_adjust = next(c for c in frozen['llm_calls'] if c['role'] == 'Reviewer'
                               and c['raw']['final']['action'] == 'adjust')
        self.final_review = next(c for c in reversed(frozen['llm_calls']) if c['role'] == 'Reviewer')
        self.real_stop = self.real[-1]

    def post(self, request):
        wire = json.loads(request.body)
        system = json.loads(wire['messages'][0]['content'].split('\n',1)[0])
        role = system['role']
        tools,values = [],[]
        for message in wire['messages'][1:]:
            if message['role'] != 'user':continue
            body = json.loads(message['content'])
            if body.get('source_role') == 'tool':tools.append(json.loads(body['content']))
            else:values.append(body.get('payload',{}))
        source,kind = None,'synthetic'
        if role == 'Analyst':
            source = self.analyst[min(len(tools),2)]
            payload = deepcopy(source['raw']);kind = 'saved_payload_unchanged'
        elif role == 'Planner':
            if not tools:
                payload = {'tool':'list_recipes','arguments':{}}
            else:
                handoff = any(v.get('context_kind') == 'confirmed_adjustment_handoff' for v in values)
                source = self.adjusted if handoff else self.initial
                payload = deepcopy(source['raw']);kind = 'saved_payload_unchanged'
                if handoff and self.mode == 'changed_contract':
                    payload = {'final':{'bundle':'D8','recipe':'LR'}};kind = 'synthetic_legal_alternative'
                if not handoff and self.mode == 'initial_changed':
                    payload = {'final':{'bundle':'D0','recipe':'RF'}};kind = 'synthetic_initial_change'
        elif system['review_operation'] == CONFIRM:
            binding = system['confirmation_binding']
            payload = {'final':{'operation':CONFIRM,'action':'confirm',
                'approval_id':binding['approval_id'],'evidence_id':binding['evidence_id'],
                'reason':'Synthetic confirmation of the old approval; no new adjustment is granted.'}}
            kind = 'synthetic_new_confirmation_not_a_real_model_result'
            if self.mode == 'typed_stop':
                source = self.real_stop
                payload['final'].update(action='stop',reason=source['raw']['final']['reason'])
                kind = 'synthetic_typed_stop_with_saved_reason'
            elif self.mode == 'saved_real_stop':
                source = self.real_stop;payload = deepcopy(source['raw'])
                kind = 'saved_payload_unchanged'
            elif self.mode == 'legacy_adjust':
                source = self.old_adjust;payload = deepcopy(source['raw'])
                payload['final']['evidence_id'] = binding['evidence_id']
                kind = 'saved_legacy_adjust_with_explicit_ID_remap'
            elif self.mode == 'wrong_approval':
                payload['final']['approval_id'] += '.other';kind = 'synthetic_wrong_identity'
        else:
            context = next(v for v in values if v.get('context_kind') == 'review_options')
            source = self.final_review;payload = deepcopy(source['raw'])
            payload['final']['evidence_id'] = context['evidence_id']
            kind = 'saved_quality_review_with_explicit_ID_remap'
            if self.mode == 'second_adjustment':
                payload['final'].update(action='adjust',requested_selection={'bundle':'D8','recipe':'LR'})
                kind = 'synthetic_forbidden_second_adjustment'
        self.sent += 1
        prompt = self.local.estimate_request(wire).prompt_tokens
        self.spend += prompt*150+200*500
        self.audit.append({'role':role,'review_operation':system.get('review_operation'),
            'source_call_id':source['call_id'] if source else None,'response_kind':kind,
            'response_payload':deepcopy(payload),'source_payload_sha256':digest(source['raw']) if source else None,
            'payload_unchanged':bool(source and payload == source['raw']),
            'new_real_model_inference':False})
        identity = 'fixture-confirm-'+str(self.sent)
        return fake_http_response(payload,model='api-glm-5.3-flash',prompt_tokens=prompt,
            completion_tokens=200,request_id=identity,headers={'x-litellm-call-id':identity})

    def get(self, request):
        from agent_recovery.p3_transport import HTTPResponse
        return HTTPResponse(200,{},json.dumps({'spend_nano':str(self.spend),
            'max_budget_nano':'50000000000'}).encode())
