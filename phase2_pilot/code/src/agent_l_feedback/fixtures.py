"""Explicit synthetic decisions and metrics; no native work or credentials."""
from copy import deepcopy
import json

from agent_l_api.fixtures import Service as PriorService
from agent_l_v1.cpu import FakeCPU
from agent_recovery.contracts import canonical_json
from agent_recovery.p3_transport import HTTPResponse


class ScenarioCPU(FakeCPU):
    def __init__(self, mode):
        super().__init__()
        self.mode = mode

    def fit(self, contract, kind, data, deadline):
        value = super().fit(contract, kind, data, deadline)
        low = self.mode == 'adjust_stop' or (self.mode != 'accept' and contract['recipe']['model_family'] == 'random_forest')
        value['metrics']['validation']['average_precision'] = 0.07128771828891939 if low else .23
        return value


class Service(PriorService):
    def __init__(self, local, mode, initial=None, saved_review=None):
        super().__init__(local)
        self.mode, self.initial = mode, initial or {'bundle': 'D1', 'recipe': 'RF'}
        self.saved_review = saved_review

    def post(self, request):
        response = super().post(request)
        wire = json.loads(response.body)
        req = json.loads(request.body)
        role = json.loads(req['messages'][0]['content'].split('\n', 1)[0])['role']
        values = [json.loads(m['content']).get('payload', {}) for m in req['messages'][1:] if m['role'] == 'user']
        payload = json.loads(wire['choices'][0]['message']['content'])
        if role == 'Planner' and 'final' in payload:
            handoff = next((v for v in values if v.get('context_kind') == 'adjustment_handoff'), None)
            if handoff is None:
                payload = {'final': deepcopy(self.initial)}
            elif self.mode == 'planner_repeat':
                payload = {'final': deepcopy(handoff['current_selection'])}
            elif self.mode == 'planner_alternative':
                payload = {'final': {'bundle': 'D8', 'recipe': 'LR'}}
        elif role == 'Reviewer':
            context = next(v for v in values if v.get('context_kind') == 'review_options')
            if self.saved_review is not None:
                payload = deepcopy(self.saved_review)
            else:
                final = {'evidence_id': context['evidence_id'], 'reason': 'Synthetic protocol fixture, not a model-quality result.'}
                if self.mode == 'reviewer_repeat':
                    final.update(action='adjust', requested_selection=deepcopy(context['current_selection']))
                elif self.mode == 'bad_accept':
                    final['action'] = 'accept'
                elif self.mode == 'second_adjust' and not context['normal_adjustments_remaining']:
                    final.update(action='adjust', requested_selection=deepcopy(context['untried_candidates'][0]))
                elif context['average_precision'] >= context['required_AP']:
                    final['action'] = 'accept'
                elif 'adjust' in context['allowed_actions']:
                    # A fixture selection, never an implementation fallback.
                    same_bundle = [s for s in context['untried_candidates'] if s['bundle'] == context['current_selection']['bundle']]
                    final.update(action='adjust', requested_selection=deepcopy((same_bundle or context['untried_candidates'])[0]))
                else:
                    final['action'] = 'stop'
                payload = {'final': final}
        wire['choices'][0]['message']['content'] = canonical_json(payload)
        return HTTPResponse(response.status, response.headers, canonical_json(wire).encode())
