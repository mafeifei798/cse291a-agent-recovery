"""Finite scripted decisions and evidence-checked review policy."""
from copy import deepcopy
import json
import math

from agent_l_v1.core import BUNDLES
from context_cutoff.contracts import require


def review_decision(evidence, task):
    ap, base = evidence['metrics']['average_precision'], evidence['constant_AP']
    goal = task['quality_AP_ratio_goal']
    require(all(type(x) in (int, float) and math.isfinite(x) for x in (ap, base, goal))
            and 0 <= ap <= 1 and 0 < base <= 1 and goal > 0, 'L3_REVIEW_METRICS')
    result = {'evidence_id': evidence['receipt_id']}
    if ap >= goal * base:
        return {**result, 'action': 'accept', 'reason': 'AP meets development goal'}
    bundle = evidence['selection']['bundle']
    if task['optimization_remaining'] and bundle != 'D1' and task['feature_cap'] >= 11:
        return {**result, 'action': 'adjust', 'requested_bundle': 'D1',
                'reason': 'Below goal; one legal alternative remains'}
    return {**result, 'action': 'stop', 'reason': 'Below goal; no remaining eligible adjustment'}


class PolicyFixture:
    fixture_only = True

    def __init__(self, fixed_rule=False):
        self.fixed_rule = fixed_rule

    def respond(self, role, messages):
        task = json.loads(messages[0]['content'])['task']
        tools = [json.loads(m['content']) for m in messages if m['role'] == 'tool']
        if role == 'Analyst':
            if not tools: return {'tool': 'read_schema', 'arguments': {}}
            if len(tools) == 1: return {'tool': 'read_profile', 'arguments': {}}
            schema = tools[0]['value']
            return {'final': {'row_count': schema['row_count'], 'eligible_features': schema['columns'],
                'prediction_time': schema['prediction_time'], 'profile': tools[1]['value']}}
        if role == 'Planner':
            if not tools: return {'tool': 'list_recipes', 'arguments': {}}
            facts = next(json.loads(m['content'])['payload'] for m in messages if m.get('input_kind') == 'facts')
            feedback = next((json.loads(m['content'])['payload'] for m in messages if m.get('input_kind') == 'feedback'), None)
            desired = feedback['requested_bundle'] if feedback else task['initial_bundle']
            if self.fixed_rule: desired = 'D1'
            allowed = [k for k, v in BUNDLES.items() if set(v) <= set(facts['eligible_features']) and len(v) <= task['feature_cap']]
            require(bool(allowed), 'L3_NO_CANDIDATE')
            choice = desired if desired in allowed else max(allowed, key=lambda k: len(BUNDLES[k]))
            return {'final': {'bundle': choice, 'recipe': 'LR'}}
        if role == 'Reviewer':
            evidence = next(json.loads(m['content'])['payload'] for m in messages if m.get('input_kind') == 'screen')
            return {'final': review_decision(evidence, task)}
        raise ValueError(role)
