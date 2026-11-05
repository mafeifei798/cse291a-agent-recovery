"""Add source-bound candidate context; preserve the original execution policy."""
from copy import deepcopy
import math

from agent_l_api.runtime import APILoop
from agent_l_v1.core import BUNDLES, RECIPES, REGISTRY, TASK
from agent_recovery.contracts import require


class FeedbackLoop(APILoop):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.doc['feedback_protocol_revision'] = 'l-feedback-v1'
        self.doc.setdefault('feedback_contexts', [])

    def candidate_context(self, role, inputs):
        registry_ref, registry = self.read(REGISTRY)
        task_ref, task = self.read(TASK)
        require(registry == {'bundles': BUNDLES, 'recipes': RECIPES},
                'Candidate registry changed', 'L_FEEDBACK_REGISTRY')
        bound = self.doc['active']['contract']
        analyst = self.doc['active']['analyst']
        eligible = set(analyst['payload']['final']['eligible_features'])
        candidates = [
            {'selection': {'bundle': b, 'recipe': r}, 'feature_columns': deepcopy(columns),
             'recipe_definition': deepcopy(recipe)}
            for b, columns in registry['bundles'].items()
            if len(columns) <= task['feature_cap'] and set(columns) <= eligible
            for r, recipe in registry['recipes'].items()
        ]
        # These are actual earlier contracts in this logical run, not guesses
        # about which candidates the model might have considered.
        tried = []
        for node in self.store.snapshot()['nodes']:
            if node['kind'] == 'contract':
                selection = node['payload']['selection']
                if selection not in tried:
                    tried.append(deepcopy(selection))
        current = deepcopy(bound['payload']['selection'])
        require(current in tried, 'Current contract not recorded', 'L_FEEDBACK_CONTEXT')
        untried = [deepcopy(c['selection']) for c in candidates if c['selection'] not in tried]
        payload = {'current_selection': current, 'tried_selections': tried,
                   'legal_candidates': candidates, 'untried_candidates': untried,
                   'feature_cap': task['feature_cap'], 'source_ref': registry_ref}
        parents = [bound['result_id'], analyst['result_id']]
        if role == 'Reviewer':
            screen = next((node, value) for kind, node, value in inputs if kind == 'screen')
            value = screen[1]
            ap, base = value['metrics']['average_precision'], value['constant_AP']
            require(math.isfinite(ap) and math.isfinite(base) and base > 0,
                    'Bad metrics', 'LAPI_REVIEW')
            required = task['quality_AP_ratio_goal'] * base
            remaining = 1 - self.doc['optimization_spent']
            actions = ['accept'] if ap >= required else ['adjust', 'stop'] if remaining and untried else ['stop']
            payload.update(context_kind='review_options', evidence_id=value['receipt_id'],
                           average_precision=ap, constant_AP=base, required_AP=required,
                           quality_AP_ratio_goal=task['quality_AP_ratio_goal'],
                           normal_adjustments_remaining=remaining, allowed_actions=actions)
            parents.append(screen[0]['result_id'])
        else:
            feedback = next(node for kind, node, value in inputs if kind == 'feedback')
            require(self.doc['optimization_spent'] == 1 and feedback['payload']['final']['action'] == 'adjust',
                    'No approved adjustment', 'L_FEEDBACK_HANDOFF')
            payload.update(context_kind='adjustment_handoff', approved_adjustment_in_progress=True,
                           additional_adjustments_remaining=0,
                           reviewer_suggestion=deepcopy(feedback['payload']['final']['requested_selection']))
            parents.append(feedback['result_id'])
        context = self.node('feedback_options', 'controller', payload, parents, [registry_ref, task_ref])
        self.doc['feedback_contexts'].append({'role': role, 'node_id': context['result_id'],
                                             'payload': deepcopy(payload)})
        return context, payload

    def role(self, role, inputs=(), *, fault=False):
        feedback = role == 'Planner' and any(kind == 'feedback' for kind, _, _ in inputs)
        context = None
        if role == 'Reviewer' or feedback:
            context, payload = self.candidate_context(role, inputs)
            inputs = [('review_options' if role == 'Reviewer' else 'adjustment_handoff', context, payload), *inputs]
        result = super().role(role, inputs, fault=fault)
        if context is not None:
            self.doc['feedback_contexts'][-1]['decision_node_id'] = result['result_id']
        return result

    def bind(self, planner):
        # The original runtime already rejects repeating the current contract
        # before a second fit. Check the explicit supplied menu before binding.
        context = next((c for c in reversed(self.doc['feedback_contexts'])
                        if c.get('decision_node_id') == planner['result_id'] and c['role'] == 'Planner'), None)
        if context:
            require(planner['payload']['final'] in context['payload']['untried_candidates'],
                    'Adjustment must choose an untried legal candidate', 'LAPI_REVIEW')
        return super().bind(planner)

    def review(self, bound, screen):
        reviewed = super().review(bound, screen)
        context = self.doc['feedback_contexts'][-1]['payload']
        choice = reviewed['payload']['final']
        if choice['action'] == 'adjust':
            require(choice['requested_selection'] in context['untried_candidates'],
                    'Reviewer requested a tried or unavailable candidate', 'LAPI_REVIEW')
        return reviewed
