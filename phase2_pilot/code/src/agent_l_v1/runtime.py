"""Three scoped scripted roles, one feedback round, deterministic L-tier tools."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import time

from context_cutoff.contracts import require
from context_cutoff.store import FileProvenanceStore
from sr_recovery_v2.common import canonical, digest
from .core import (REVISION, BUNDLES, DATA, SCHEMA, PROFILE, REGISTRY, CODE,
    PERMISSION, TASK, CHOICE, REVIEW, MODEL, PUBLICATION,
    ScriptedLLM, contract_pair, ref, save)


class AgentLoop:
    def __init__(self, directory, run_id, cpu, ledger, *, model=None, document=None, remaining_seconds=900):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=document is not None)
        self.store = FileProvenanceStore(self.directory / 'store.sqlite', self.directory / 'artifacts')
        self.cpu, self.ledger, self.model = cpu, ledger, model or ScriptedLLM()
        require(type(self.model) is ScriptedLLM and self.model.fixture_only, 'L_REAL_LLM_DISABLED')
        self.scope = run_id
        self.doc = deepcopy(document) if document else {'revision': REVISION, 'messages': [],
            'llm_calls': [], 'tools': [], 'decisions': [], 'faults': [], 'optimization_spent': 0,
            'active': {}, 'llm_fixture_only': True, 'cpu_fixture_only': cpu.fixture_only}
        self.doc.update(run_id=run_id, phase='recovery' if document else 'initial',
                        inherited_call_count=len(self.doc['llm_calls']))
        self.started = time.monotonic()
        self.deadline = datetime.now(timezone.utc) + timedelta(seconds=remaining_seconds)
        self.expected_publication = ref(self.store.read(PUBLICATION)) if document else None
        self.guard_refs = None
        self.fit_start = cpu.fit_count

    def close(self): self.store.close()

    def initialize(self, inputs, feature_cap=11):
        values = {DATA: inputs['data'], SCHEMA: inputs['schema'], PROFILE: inputs['profile'],
            REGISTRY: inputs['registry'], CODE: inputs['code'], PERMISSION: {'publish_allowed': True},
            TASK: {'feature_cap': feature_cap, 'normal_adjustment_limit': 1, 'quality_AP_ratio_goal': 1.25,
                'quality_goal_hard_gate': False, 'fixture_exercises_adjustment': True},
            PUBLICATION: {'status': 'empty'}}
        for key, value in values.items(): self.store.initialize(key, canonical(value))
        self.expected_publication = ref(self.store.read(PUBLICATION))

    def read(self, key):
        value = self.store.read(key)
        return ref(value), json.loads(value['content'])

    def event(self, kind, **value):
        with self.store._transaction(): self.store._event(kind, **value)

    def node(self, kind, role, payload, parents=(), reads=(), **extra):
        name = self.scope + '.node.' + str(len(self.store.snapshot()['nodes'])).zfill(4)
        value = {'result_id': name, 'kind': kind, 'role': role, 'payload': deepcopy(payload),
            'parent_result_ids': sorted(set(parents)), 'file_reads': deepcopy(list(reads)), **extra}
        self.store.record_node(value)
        return value

    def _call(self, role, messages, *, fault=False):
        require(datetime.now(timezone.utc) < self.deadline, 'L_FIXED_DEADLINE')
        require(len(self.doc['llm_calls']) - self.doc['inherited_call_count'] < 10, 'L_CALL_CAP')
        index = len(self.doc['llm_calls'])
        call_id = self.scope + '.llm.' + str(index).zfill(4)
        predicted = self.scope + '.node.' + str(len(self.store.snapshot()['nodes'])).zfill(4)
        request = {'call_id': call_id, 'attempt_id': call_id + '.attempt', 'trial_key': self.scope + '.' + role,
            'logical_run_key': self.scope, 'branch_id': self.scope, 'run_id': self.scope,
            'result_id': predicted, 'step_id': role,
            'phase': 'initial' if self.doc['phase'] == 'initial' else 'replay', 'input_token_upper_bound': 4000,
            'request': {'messages': deepcopy(messages)},
            'sidecar': {'fixture_only': True, 'semantic_phase': self.doc['phase'],
                        'usage_kind': 'synthetic_not_measured_tokens'}}
        self.ledger.reserve(request); self.ledger.mark_dispatched(call_id)
        raw = self.model.respond(role, deepcopy(messages))
        usage = {'prompt_tokens': 100, 'completion_tokens': 100, 'total_tokens': 200}
        self.ledger.settle(call_id, provider_request_id='fixture:' + call_id, raw_usage=usage,
            normalized_usage={**usage, 'cached_input_tokens': 0, 'reasoning_tokens': 0},
            evidence={'fixture_only': True, 'usage_kind': 'synthetic_not_measured_tokens', 'real_API': False})
        delivered = deepcopy(raw)
        if fault and role == 'Analyst' and 'final' in delivered:
            delivered['final']['row_count'] += 1
            self.doc['faults'].append({'type': 'INCIDENTAL_ROW_COUNT', 'call_id': call_id,
                'faulty_result_id': predicted, 'raw': raw, 'delivered': deepcopy(delivered)})
        parents = [m['producer_result_id'] for m in messages if m.get('producer_result_id')]
        node = self.node('llm', role, delivered, parents,
                         [m['source_ref'] for m in messages if m.get('source_ref')])
        require(node['result_id'] == predicted, 'L_CALL_NODE_ID')
        self.doc['llm_calls'].append({'call_id': call_id, 'role': role, 'node_id': predicted,
            'messages': deepcopy(messages), 'prompt_sha256': digest(messages), 'raw': raw,
            'delivered': deepcopy(delivered), 'fixture_only': True, 'synthetic_usage': usage})
        return node, delivered

    def role(self, role, inputs=(), *, fault=False):
        taskref, task = self.read(TASK)
        task = {**task, 'phase': self.doc['phase'], 'optimization_remaining': 1 - self.doc['optimization_spent']}
        messages = [{'role': 'system', 'content': canonical({'role': role, 'task': task}), 'source_ref': taskref}]
        for kind, node, payload in inputs:
            message = {'role': 'user', 'input_kind': kind, 'producer_result_id': node['result_id'],
                       'content': canonical({'payload': payload})}
            if isinstance(payload, dict) and payload.get('source_ref'): message['source_ref'] = payload['source_ref']
            messages.append(message)
        for _ in range(3):
            callnode, delivered = self._call(role, messages, fault=fault)
            messages.append({'role': 'assistant', 'producer_result_id': callnode['result_id'], 'content': canonical(delivered)})
            if 'final' in delivered: return callnode
            name = delivered.get('tool')
            require(delivered.get('arguments') == {}, 'L_TOOL_ARGUMENTS')
            allowed = {'Analyst': {'read_schema': SCHEMA, 'read_profile': PROFILE},
                       'Planner': {'list_recipes': REGISTRY}, 'Reviewer': {}}
            require(name in allowed[role], 'L_TOOL_PERMISSION')
            source_ref, value = self.read(allowed[role][name])
            if name == 'read_profile':
                value = {k: v for k, v in value.items() if k.startswith('training_')}
            toolnode = self.node('tool', role, {'tool': name, 'value': value}, [callnode['result_id']], [source_ref])
            self.doc['tools'].append({'request_result_id': callnode['result_id'], 'result_id': toolnode['result_id'],
                'role': role, 'tool': name, 'source_ref': source_ref, 'returned': value})
            messages.append({'role': 'tool', 'producer_result_id': toolnode['result_id'],
                             'content': canonical({'tool': name, 'value': value})})
        raise RuntimeError('L_ROLE_CALL_CAP')

    def bind(self, planner):
        dataref, data = self.read(DATA); coderef, code = self.read(CODE); taskref, task = self.read(TASK)
        registryref, registry = self.read(REGISTRY)
        require(registry['bundles'] == BUNDLES, 'L_REGISTRY_CHANGED')
        selection = planner['payload']['final']
        pair = contract_pair(selection, data, code, task)
        bound = self.node('contract', 'controller', {'selection': selection, 'contracts': pair},
            [planner['result_id']], [dataref, coderef, taskref, registryref])
        self.doc['active']['contract'] = bound
        current = self.store.snapshot()['files'].get(CHOICE)
        self.store.write(CHOICE, canonical(bound['payload']), current, bound['result_id'])
        return bound

    def train(self, bound, kind):
        dataref, data = self.read(DATA); coderef, _ = self.read(CODE)
        model = self.cpu.fit(bound['payload']['contracts'][kind], kind, data, self.deadline)
        parents = [bound['result_id']]
        if kind == 'final': parents.append(self.doc['active']['review']['result_id'])
        node = self.node('cpu', 'executor', model, parents, [dataref, coderef])
        self.doc['active'][kind] = node
        return node

    def screen_view(self, bound, screening):
        profile_ref, profile = self.read(PROFILE)
        return {'receipt_id': screening['result_id'], 'assessment_kind': 'screen',
            'source_ref': profile_ref,
            'selection': bound['payload']['selection'], 'metrics': screening['payload']['metrics']['validation'],
            'constant_AP': profile['feedback_constant_AP']}

    def review(self, bound, screening):
        view = self.screen_view(bound, screening)
        reviewed = self.role('Reviewer', [('contract', bound, {'selection': bound['payload']['selection']}),
                                         ('screen', screening, view)])
        payload = reviewed['payload']['final']
        require(payload.get('action') in ('accept', 'adjust', 'stop') and payload.get('evidence_id') == screening['result_id'], 'L_REVIEW_PROTOCOL')
        self.doc['active']['review'] = reviewed
        current = self.store.snapshot()['files'].get(REVIEW)
        self.store.write(REVIEW, canonical(payload), current, reviewed['result_id'])
        return reviewed

    def run(self, *, fault=False):
        analyst = self.role('Analyst', fault=fault)
        self.doc['active']['analyst'] = analyst
        planner = self.role('Planner', [('facts', analyst, analyst['payload']['final'])])
        bound = self.bind(planner); screening = self.train(bound, 'screen'); reviewed = self.review(bound, screening)
        if reviewed['payload']['final']['action'] == 'adjust':
            require(self.doc['optimization_spent'] == 0, 'L_NORMAL_ADJUSTMENT_EXHAUSTED')
            self.doc['optimization_spent'] = 1
            self.event('normal_adjustment_consumed', total=1, remaining=0, reviewer=reviewed['result_id'])
            planner = self.role('Planner', [('facts', analyst, analyst['payload']['final']),
                ('feedback', reviewed, reviewed['payload']['final'])])
            bound = self.bind(planner); screening = self.train(bound, 'screen'); reviewed = self.review(bound, screening)
        require(reviewed['payload']['final']['action'] == 'accept', 'L_REVIEW_NOT_ACCEPTED')
        self.train(bound, 'final')
        self.capture_guard_refs()
        return bound

    def capture_guard_refs(self):
        self.guard_refs = [ref(self.store.read(k)) for k in
            (DATA, CODE, TASK, SCHEMA, PROFILE, REGISTRY, CHOICE, REVIEW, PERMISSION)]

    def publish(self, *, expected=None):
        permission_ref, permission = self.read(PERMISSION)
        require(permission['publish_allowed'], 'L_PUBLISH_PERMISSION')
        current = ref(self.store.read(PUBLICATION))
        require(not current['writer_id'].startswith('external'), 'L_EXTERNAL_OWNER')
        bound, model = self.doc['active']['contract'], self.doc['active']['final']
        require(model['payload']['contract'] == bound['payload']['contracts']['final'], 'L_PUBLISH_CONTRACT')
        _, data = self.read(DATA)
        self.cpu.validate(model['payload'], bound['payload']['contracts']['final'], 'final', data)
        report = {'selection': bound['payload']['selection'], 'contract_sha256': digest(model['payload']['contract']),
            'producer_id': model['payload']['producer_id'], 'outer_metrics': model['payload']['metrics']['validation'],
            'llm_fixture_only': True, 'cpu_fixture_only': self.cpu.fixture_only}
        require(self.guard_refs is not None, 'L_ADMISSION_REFS_MISSING')
        refs = deepcopy(self.guard_refs)
        # Keep earlier admission reads; do not refresh them to bless a race.
        require(permission_ref in refs, 'L_PERMISSION_CHANGED_AFTER_CHECK')
        self.store.write_checked(PUBLICATION, canonical(report), self.expected_publication if expected is None else expected,
            self.scope, refs)
        node = self.node('publish', 'executor', report,
            [bound['result_id'], model['result_id'], self.doc['active']['review']['result_id']], refs)
        self.doc['active']['publication'] = node
        return node

    def export(self, outcome, **extra):
        self.doc.update(outcome=outcome, **extra)
        if 'screen' in self.doc['active']:
            _, profile = self.read(PROFILE)
            ap = self.doc['active']['screen']['payload']['metrics']['validation']['average_precision']
            self.doc['quality_goal_met'] = ap >= 1.25 * profile['feedback_constant_AP']
            self.doc['quality_AP_ratio'] = ap / profile['feedback_constant_AP']
        self.doc['new_fit_count'] = self.cpu.fit_count - self.fit_start
        self.doc['new_scripted_calls'] = len(self.doc['llm_calls']) - self.doc['inherited_call_count']
        self.doc['remaining_seconds'] = max(0., (self.deadline - datetime.now(timezone.utc)).total_seconds())
        self.doc['store_snapshot'] = self.store.snapshot()
        save(self.directory / 'trace.json', self.doc)
        return deepcopy(self.doc)

    def freeze(self):
        document = self.export('frozen_before_publish')
        document['checkpoint_sha256'] = digest(document)
        save(self.directory / 'FREEZE.json', document)
        return document
