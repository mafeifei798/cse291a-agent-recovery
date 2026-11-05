"""Replay a consumed logical adjustment without granting a new adjustment."""
from copy import deepcopy
import math

from agent_l_feedback.runtime import FeedbackLoop
from agent_l_feedback.model import Model as PriorModel
from agent_l_v1.runtime import AgentLoop
from agent_l_v1.core import BUNDLES, RECIPES, DATA, CODE, TASK, SCHEMA, PROFILE, REGISTRY
from agent_l_api.model import validate
from agent_recovery.contracts import require
from sr_recovery_v2.common import digest

SOURCE_KEYS = (DATA, CODE, TASK, SCHEMA, PROFILE, REGISTRY)


def approved_stage(frozen):
    """Resolve the adjustment from recorded edges, not the first Planner call."""
    require(frozen['optimization_spent'] == 1, 'Expected one consumed adjustment', 'FR_STAGE')
    nodes = {n['result_id']: n for n in frozen['store_snapshot']['nodes']}
    final_contract = frozen['active']['contract']
    planner = nodes[final_contract['parent_result_ids'][0]]
    call = next(c for c in frozen['llm_calls'] if c['node_id'] == planner['result_id'])
    feedback_ids = [m['producer_result_id'] for m in call['messages'] if m.get('input_kind') == 'feedback']
    require(len(feedback_ids) == 1, 'Adjusted contract lacks a feedback edge', 'FR_STAGE')
    feedback = nodes[feedback_ids[0]]
    require(feedback['role'] == 'Reviewer' and feedback['payload']['final']['action'] == 'adjust',
            'Adjustment was not approved', 'FR_APPROVAL')
    initial = [nodes[n] for n in feedback['parent_result_ids'] if nodes[n]['kind'] == 'contract']
    screens = [nodes[n] for n in feedback['parent_result_ids'] if nodes[n]['role'] == 'executor']
    require(len(initial) == len(screens) == 1, 'Ambiguous approval inputs', 'FR_STAGE')
    initial, screen = initial[0], screens[0]
    require(screen['payload']['contract'] == initial['payload']['contracts']['screen']
            and feedback['payload']['final']['evidence_id'] == screen['result_id'],
            'Approval evidence does not match contract', 'FR_APPROVAL')
    tried = []
    for node in frozen['store_snapshot']['nodes']:
        if node['result_id'] == feedback['result_id']:
            break
        if node['kind'] == 'contract' and node['payload']['selection'] not in tried:
            tried.append(deepcopy(node['payload']['selection']))
    result = {'logical_adjustment_id': digest({'origin': frozen['run_id'], 'approval': feedback['result_id']}),
              'origin_approval_id': feedback['result_id'], 'adjusted_planner_id': planner['result_id'],
              'initial_contract': deepcopy(initial), 'initial_screen': deepcopy(screen),
              'original_feedback': deepcopy(feedback), 'adjusted_contract': deepcopy(final_contract),
              'tried_before_approval': tried, 'consumed': 1,
              'source_bindings': {k: deepcopy(frozen['store_snapshot']['files'][k]) for k in SOURCE_KEYS}}
    return result


class Model(PriorModel):
    def protocol_text(self, role):
        text = super().protocol_text(role)
        if role in ('Planner', 'Reviewer'):
            text += (' If replay_of_consumed_adjustment is explicitly present, this is revalidation of '
                     'the supplied logical_adjustment_id, not a new round. normal_adjustments_remaining '
                     'stays zero. Reviewer may re-approve only the original requested_selection when '
                     'it is listed as allowed, or stop. Planner may choose an eligible candidate from '
                     'the supplied stage-local untried_candidates. Never request a second adjustment.')
        return text


class ReplayLoop(FeedbackLoop):
    def __init__(self, *args, approval, **kwargs):
        super().__init__(*args, **kwargs)
        self.approval = approval
        self.replay_stage = None
        self.doc['feedback_protocol_revision'] = 'l-feedback-replay-v2'
        self.doc['stage_replays'] = []
        self.doc.update(cpu_fixture_only=True, llm_fixture_only=True, offline_replay_only=True,
                        inherited_native_prefix_is_historical=True)

    def check_approval_sources(self):
        require(self.doc['optimization_spent'] == 1, 'Consumed adjustment changed', 'FR_QUOTA')
        require(all(self.read(k)[0] == ref for k, ref in self.approval['source_bindings'].items()),
                'Approval source version changed', 'FR_APPROVAL_SOURCE_STALE')

    def candidate_context(self, role, inputs):
        if self.replay_stage is None:
            return super().candidate_context(role, inputs)
        self.check_approval_sources()
        registry_ref, registry = self.read(REGISTRY)
        task_ref, task = self.read(TASK)
        require(registry == {'bundles': BUNDLES, 'recipes': RECIPES}, 'Registry changed', 'FR_MENU')
        analyst, bound = self.doc['active']['analyst'], self.doc['active']['contract']
        eligible = set(analyst['payload']['final']['eligible_features'])
        candidates = [{'selection': {'bundle': b, 'recipe': r}, 'feature_columns': deepcopy(cols),
                       'recipe_definition': deepcopy(recipe)} for b, cols in registry['bundles'].items()
                      if len(cols) <= task['feature_cap'] and set(cols) <= eligible
                      for r, recipe in registry['recipes'].items()]
        tried = deepcopy(self.approval['tried_before_approval'])
        payload = {'current_selection': deepcopy(bound['payload']['selection']),
                   'tried_selections': tried, 'untried_candidates': [c['selection'] for c in candidates
                       if c['selection'] not in tried], 'legal_candidates': candidates,
                   'feature_cap': task['feature_cap'], 'source_ref': registry_ref,
                   'logical_adjustment_id': self.approval['logical_adjustment_id'],
                   'replay_of_consumed_adjustment': True, 'normal_adjustments_remaining': 0}
        parents = [analyst['result_id'], bound['result_id']]
        if role == 'Reviewer':
            screen, view = next((n, v) for kind, n, v in inputs if kind == 'screen')
            ap, base = view['metrics']['average_precision'], view['constant_AP']
            require(math.isfinite(ap) and base > 0 and ap < task['quality_AP_ratio_goal']*base,
                    'Original adjustment condition no longer holds', 'FR_APPROVAL_CONDITION')
            requested = self.approval['original_feedback']['payload']['final']['requested_selection']
            require(requested in payload['untried_candidates'], 'Original approval is no longer legal', 'FR_MENU')
            payload.update(context_kind='approved_adjustment_revalidation', evidence_id=view['receipt_id'],
                           average_precision=ap, constant_AP=base, required_AP=task['quality_AP_ratio_goal']*base,
                           allowed_actions=['adjust', 'stop'], original_requested_selection=deepcopy(requested))
            parents.append(screen['result_id'])
        else:
            feedback = next(n for kind, n, _ in inputs if kind == 'feedback')
            payload.update(context_kind='adjustment_handoff', approved_adjustment_in_progress=True,
                           additional_adjustments_remaining=0,
                           reviewer_suggestion=deepcopy(feedback['payload']['final']['requested_selection']))
            parents.append(feedback['result_id'])
        context = self.node('feedback_options', 'controller', payload, parents, [registry_ref, task_ref])
        self.doc['feedback_contexts'].append({'role': role, 'node_id': context['result_id'], 'payload': deepcopy(payload)})
        return context, payload

    def replay_approved(self, analyst, initial_bound, screen):
        self.check_approval_sources()
        require(initial_bound['payload']['contracts'] == self.approval['initial_contract']['payload']['contracts'],
                'Initial-stage contract changed', 'FR_INITIAL_CONTRACT_CHANGED')
        binding = digest({'facts': analyst['payload'], 'contract': initial_bound['payload'],
                          'analyst_id': analyst['result_id'], 'initial_contract_id': initial_bound['result_id'],
                          'screen_result_id': screen['result_id'],
                          'screen_producer_id': screen['payload']['producer_id'],
                          'screen_contract': screen['payload']['contract'],
                          'metrics': screen['payload']['metrics'], 'sources': self.approval['source_bindings']})
        cached = self.ledger.replay(self.unit, self.approval)
        if cached:
            require(cached['input_digest'] == binding, 'Replay inputs changed', 'FR_REPLAY_BINDING')
            return deepcopy(cached['bound'])
        self.replay_stage = 'approval_review'
        try:
            reviewed = AgentLoop.review(self, initial_bound, screen)
            choice = validate('Reviewer', reviewed['payload'])['final']
            require(choice['action'] == 'adjust' and choice['requested_selection'] ==
                    self.approval['original_feedback']['payload']['final']['requested_selection'],
                    'Existing approval not revalidated; no new allowance', 'FR_APPROVAL_REJECTED')
            self.replay_stage = 'adjustment_replay'
            planner = self.role('Planner', [('facts', analyst, analyst['payload']['final']),
                                           ('feedback', reviewed, reviewed['payload']['final'])])
            bound = self.bind(planner)
            record = {'logical_adjustment_id': self.approval['logical_adjustment_id'],
                      'unit': self.unit, 'input_digest': binding, 'bound': deepcopy(bound),
                      'origin_approval_id': self.approval['origin_approval_id'],
                      'revalidated_review_id': reviewed['result_id'],
                      'stage': 'adjustment-1', 'new_normal_adjustments_consumed': 0,
                      'optimization_spent_before': 1, 'optimization_spent_after': self.doc['optimization_spent']}
            require(record['optimization_spent_after'] == 1, 'Allowance reset', 'FR_QUOTA')
            self.ledger.replay(self.unit, self.approval, record)
            self.doc['stage_replays'].append(deepcopy(record))
            return bound
        finally:
            self.replay_stage = None
