"""One runtime for tracked agents, safety-only agents, and fixed rules."""
from copy import deepcopy
from datetime import datetime, timezone

from agent_l_v1.core import DATA, TASK, D0, save
from agent_l_v1.runtime import AgentLoop
from context_cutoff.contracts import require
from sr_recovery_v2.common import canonical, digest
from .policy import PolicyFixture, review_decision


class TimedStore:
    CATEGORIES = {'read': 'source_reads', 'initialize': 'versioned_writes',
        'write': 'versioned_writes', 'write_checked': 'safe_commit',
        'record_node': 'fine_provenance', 'snapshot': 'trace_snapshot', 'close': 'store_close'}

    def __init__(self, store, timing): self.store, self.timing = store, timing

    def __getattr__(self, name):
        value = getattr(self.store, name)
        if name not in self.CATEGORIES: return value
        def call(*args, **kwargs):
            with self.timing.span(self.CATEGORIES[name]): return value(*args, **kwargs)
        return call


class UnifiedLoop(AgentLoop):
    def __init__(self, *args, timing, fine_tracking=True, fixed_rule=False, **kwargs):
        self.timing = timing
        with timing.span('store_setup'):
            super().__init__(*args, **kwargs)
            self.store = TimedStore(self.store, timing)
            self.node_counter = len(self.store.snapshot()['nodes'])
        self.fine_tracking, self.fixed_rule = fine_tracking, fixed_rule
        require(not fixed_rule or not fine_tracking, 'L3_RULE_MODE')
        self.model = PolicyFixture(fixed_rule)
        self.doc.update(revision='agent-l-unified-v3', fine_tracking=fine_tracking,
                        decision_backend='fixed-rule' if fixed_rule else 'scripted-LLM')
        self.doc.setdefault('delivery_events', [])
        self.doc.setdefault('rule_calls', [])

    def initialize(self, inputs, feature_cap=11, *, goal=1.25, initial_bundle='D1'):
        super().initialize(inputs, feature_cap)
        before, task = self.read(TASK)
        task.update(quality_AP_ratio_goal=goal, quality_goal_hard_gate=True,
                    fixture_exercises_adjustment=False, initial_bundle=initial_bundle,
                    review_policy='accept-if-goal-else-one-adjustment-or-stop')
        self.store.write(TASK, canonical(task), before, 'bootstrap-policy')

    def node(self, kind, role, payload, parents=(), reads=(), **extra):
        with self.timing.span('node_construction'):
            name = self.scope + '.node.' + str(self.node_counter).zfill(4)
            self.node_counter += 1
            value = {'result_id': name, 'kind': kind, 'role': role, 'payload': deepcopy(payload),
                'parent_result_ids': sorted(set(parents)), 'file_reads': deepcopy(list(reads)), **extra}
        if self.fine_tracking: self.store.record_node(value)
        return value

    def _call(self, role, messages, *, fault=False):
        require(type(self.model) is PolicyFixture and self.model.fixture_only, 'L3_REAL_MODEL_DISABLED')
        require(datetime.now(timezone.utc) < self.deadline, 'L_FIXED_DEADLINE')
        calls = self.doc['rule_calls'] if self.fixed_rule else self.doc['llm_calls']
        inherited = self.doc.get('inherited_rule_count', 0) if self.fixed_rule else self.doc['inherited_call_count']
        require(len(calls) - inherited < 10, 'L_CALL_CAP')
        call_id = self.scope + ('.rule.' if self.fixed_rule else '.llm.') + str(len(calls)).zfill(4)
        predicted = self.scope + '.node.' + str(self.node_counter).zfill(4)
        request = {'call_id': call_id, 'attempt_id': call_id + '.attempt', 'trial_key': self.scope + '.' + role,
            'logical_run_key': self.scope, 'branch_id': self.scope, 'run_id': self.scope,
            'result_id': predicted, 'step_id': role,
            'phase': 'initial' if self.doc['phase'] == 'initial' else 'replay', 'input_token_upper_bound': 4000,
            'request': {'messages': deepcopy(messages)}, 'sidecar': {'fixture_only': True,
            'usage_kind': 'synthetic_not_measured_tokens', 'semantic_phase': self.doc['phase']}}
        if not self.fixed_rule:
            with self.timing.span('fixture_ledger'):
                self.ledger.reserve(request); self.ledger.mark_dispatched(call_id)
        with self.timing.span('rule_decision' if self.fixed_rule else 'scripted_model'):
            raw = self.model.respond(role, deepcopy(messages))
        usage = {'prompt_tokens': 100, 'completion_tokens': 100, 'total_tokens': 200}
        if not self.fixed_rule:
            with self.timing.span('fixture_ledger'):
                self.ledger.settle(call_id, provider_request_id='fixture:' + call_id, raw_usage=usage,
                    normalized_usage={**usage, 'cached_input_tokens': 0, 'reasoning_tokens': 0},
                    evidence={'fixture_only': True, 'usage_kind': 'synthetic_not_measured_tokens', 'real_API': False})
        parents = [m['producer_result_id'] for m in messages if m.get('producer_result_id')]
        raw_node = self.node('rule' if self.fixed_rule else 'llm', role, raw, parents,
                             [m['source_ref'] for m in messages if m.get('source_ref')])
        require(raw_node['result_id'] == predicted, 'L3_NODE_ID')
        # Both agent modes retain identical mandatory call/tool/usage audit logs.
        # Only fine mode adds prompt hashes and persistent observed dependency nodes.
        audit = {'call_id': call_id, 'role': role, 'node_id': predicted,
                 'messages': deepcopy(messages), 'raw': deepcopy(raw), 'delivered': deepcopy(raw),
                 'fixture_only': True, 'synthetic_usage': None if self.fixed_rule else usage}
        if self.fine_tracking:
            with self.timing.span('prompt_hash'): audit['prompt_sha256'] = digest(messages)
        calls.append(audit)
        if not fault or role != 'Analyst' or 'final' not in raw: return raw_node, raw
        require(self.fine_tracking and fault in ('DECISION_ELIGIBILITY', 'INCIDENTAL_ROW_COUNT'), 'L3_FAULT')
        delivered = deepcopy(raw)
        if fault == 'DECISION_ELIGIBILITY': delivered['final']['eligible_features'] = deepcopy(D0)
        else: delivered['final']['row_count'] += 1
        node = self.node('fault_delivery', 'Analyst', delivered, [raw_node['result_id']],
                         fault_kind=fault, original_result_id=raw_node['result_id'])
        event = {'type': fault, 'faulty_result_id': node['result_id'],
                 'original_result_id': raw_node['result_id'], 'raw': raw, 'delivered': delivered}
        self.doc['faults'].append(deepcopy(event)); self.doc['delivery_events'].append(deepcopy(event))
        return node, delivered

    def role(self, *args, **kwargs):
        with self.timing.span('role_orchestration'): return super().role(*args, **kwargs)

    def bind(self, planner):
        with self.timing.span('contract_binding'): return super().bind(planner)

    def train(self, bound, kind):
        require(datetime.now(timezone.utc) < self.deadline, 'L_FIXED_DEADLINE')
        with self.timing.span('training_orchestration'): return super().train(bound, kind)

    def review(self, bound, screen):
        with self.timing.span('review_orchestration'):
            reviewed = super().review(bound, screen)
            _, task = self.read(TASK)
            task['optimization_remaining'] = 1 - self.doc['optimization_spent']
            expected = review_decision(self.screen_view(bound, screen), task)
            require(reviewed['payload']['final'] == expected, 'L3_REVIEW_EVIDENCE_OR_POLICY')
            return reviewed

    def finish(self, analyst, bound, *, retained_screen=None, retained_final=None):
        screen = retained_screen if retained_screen else self.train(bound, 'screen')
        self.doc['active']['screen'] = screen
        reviewed = self.review(bound, screen)
        if reviewed['payload']['final']['action'] == 'adjust':
            require(self.doc['optimization_spent'] == 0, 'L_NORMAL_ADJUSTMENT_EXHAUSTED')
            self.doc['optimization_spent'] = 1
            self.event('normal_adjustment_consumed', total=1, remaining=0, reviewer=reviewed['result_id'])
            planner = self.role('Planner', [('facts', analyst, analyst['payload']['final']),
                ('feedback', reviewed, reviewed['payload']['final'])])
            bound = self.bind(planner)
            screen = self.train(bound, 'screen'); reviewed = self.review(bound, screen)
            retained_final = None
        if reviewed['payload']['final']['action'] == 'stop':
            self.doc['stop_reason'] = 'REVIEW_QUALITY_NOT_MET'
            return False
        require(reviewed['payload']['final']['action'] == 'accept', 'L3_REVIEW_FINAL')
        if callable(retained_final): retained_final = retained_final(bound, reviewed)
        if retained_final is None: self.train(bound, 'final')
        else:
            require(retained_final['payload']['contract'] == bound['payload']['contracts']['final'], 'L3_RETAINED_FINAL_CONTRACT')
            self.doc['active']['final'] = retained_final
        self.capture_guard_refs()
        return True

    def run(self, *, fault=False):
        analyst = self.role('Analyst', fault=fault); self.doc['active']['analyst'] = analyst
        planner = self.role('Planner', [('facts', analyst, analyst['payload']['final'])])
        return self.finish(analyst, self.bind(planner))

    def capture_guard_refs(self):
        with self.timing.span('admission_refs'):
            super().capture_guard_refs()
            self.doc['admission_guard_refs'] = deepcopy(self.guard_refs)

    def publish(self, **kwargs):
        with self.timing.span('publication'): return super().publish(**kwargs)

    def export(self, outcome, **extra):
        with self.timing.span('trace_export'):
            self.doc.update(outcome=outcome, **extra)
            _, task = self.read(TASK); _, profile = self.read('inputs/profile.json')
            if 'screen' in self.doc['active']:
                ap = self.doc['active']['screen']['payload']['metrics']['validation']['average_precision']
                self.doc['quality_goal_met'] = ap >= task['quality_AP_ratio_goal'] * profile['feedback_constant_AP']
                self.doc['quality_AP_ratio'] = ap / profile['feedback_constant_AP']
            self.doc['new_fit_count'] = self.cpu.fit_count - self.fit_start
            self.doc['new_scripted_calls'] = len(self.doc['llm_calls']) - self.doc['inherited_call_count']
            self.doc['remaining_seconds'] = max(0., (self.deadline - datetime.now(timezone.utc)).total_seconds())
            self.doc['store_snapshot'] = self.store.snapshot()
            self.doc['new_rule_evaluations'] = len(self.doc['rule_calls']) - self.doc.get('inherited_rule_count', 0)
            save(self.directory / 'RESULT.json', self.doc)
            return deepcopy(self.doc)
