"""Bounded agent/tool development loop with injected model and CPU clients.

This first adapter only accepts fixtures. It records the exact context sent to
the client, not an assumed static result DAG. No credential or network access.
"""
from copy import deepcopy
import json
from pathlib import Path
from time import monotonic_ns

from agent_recovery.p3_budget import DurableP3Budget
from sr_recovery_v2.common import closure_ids, digest, canonical
from .contracts import (REVISION, MODES, byte_hash, contract_digest, identity,
                        message_ref, normalize_contract, require)
from .store import FileProvenanceStore

ROOT = Path(__file__).resolve().parents[2]
DOC_KEY = 'inputs/bank-description.json'
DATA_KEY = 'inputs/data-binding.json'
CODE_KEY = 'tools/training-entry.txt'
CONFIG_KEY = 'work/features.json'
MODEL_KEY = 'work/fixture-model.json'
REPORT_KEY = 'work/report.json'
PUBLICATION_KEY = 'external/publication.json'
CONSUMPTION_KEY = 'external/consumption.json'
BASE_FEATURES = ['age', 'job', 'education', 'housing', 'loan']


def reference(value):
    return {key: value[key] for key in FileProvenanceStore.REF_FIELDS}


def new_fixture_ledger(path, campaign_id):
    # Reuse durable reservation/dispatch/settlement, including fencing on lost
    # receipts. Fixture token usage and zero prices are never real cost data.
    return DurableP3Budget(path, campaign_id=campaign_id, binding={
        'input_nano_usd_per_token': 0, 'output_nano_usd_per_token': 0,
        'cached_input_nano_usd_per_token': None, 'price_evidence': 'fixture:zero-price-no-inference',
        'simulated': True, 'max_input_tokens': 4000, 'max_output_tokens': 768,
    })


def initial_inputs():
    raw = ROOT / 'sr_v2/v0/data/raw/bank/bank-additional-full.csv'
    rows = ROOT / 'sr_v2/v0/data/splits/bank'
    # Only read existing bytes to bind the future executor. No array/model load.
    binding = {'file_sha256': byte_hash(raw.read_bytes()),
               'train_rows_sha256': byte_hash((rows / 'train_v1.json').read_bytes()),
               'validation_rows_sha256': byte_hash((rows / 'validation.json').read_bytes())}
    code = 'future explicit contract CPU adapter; no execution in development fixture'
    description = {'prediction_time': 'before_call', 'dataset_id': 'bank', 'label_column': 'y',
        'feature_columns': BASE_FEATURES + ['duration'], 'unavailable_before_call': ['duration'],
        'row_count': 41188, 'note': 'Duration is only known after the call.'}
    return description, binding, code


class ScriptedAgent:
    """Tool choices and contract choices for mechanism testing, not model proof."""
    fixture_only = True

    def respond(self, role, prompt_messages):
        own = [m for m in prompt_messages if m.get('agent_role') == role]
        tool_messages = [m for m in own if m['role'] == 'tool']
        if role == 'Analyst':
            if not tool_messages:
                return {'tool': 'list_directory', 'arguments': {'directory': 'inputs'}}
            if not any(json.loads(m['content']).get('tool') == 'read_file' for m in tool_messages):
                return {'tool': 'read_file', 'arguments': {'file_id': DOC_KEY}}
            doc = next(json.loads(m['content'])['content'] for m in reversed(tool_messages)
                       if json.loads(m['content']).get('tool') == 'read_file')
            return {'final': json.loads(doc)}
        if role == 'Planner':
            fact = next(json.loads(m['content'])['final'] for m in reversed(prompt_messages)
                        if m.get('agent_role') == 'Analyst' and m['role'] == 'assistant'
                        and 'final' in json.loads(m['content']))
            task = json.loads(prompt_messages[0]['content'])['task']
            features = [f for f in fact['feature_columns'] if f not in fact['unavailable_before_call']]
            return {'final': {'dataset_id': 'bank', 'data_binding': task['data_binding'],
                'feature_columns': features, 'label_column': fact['label_column'],
                'preprocessing': {'numeric': 'median_standardize', 'categorical': 'onehot_ignore_unknown'},
                'recipe': {'model_family': 'logistic_regression', 'parameters': {'C': 1.0, 'max_iter': 200}},
                'seed': 17, 'code_sha256': task['code_sha256'], 'output_schema': 'binary-probability-v1'}}
        if role == 'Executor':
            tools = [json.loads(m['content'])['tool'] for m in tool_messages]
            order = ['write_config', 'train', 'write_report', 'publish']
            next_tool = next((t for t in order if t not in tools), None)
            return {'tool': next_tool, 'arguments': {}} if next_tool else {'final': {'status': 'published'}}
        raise ValueError(role)


class FakeCPU:
    fixture_only = True

    def execute(self, contract):
        # Deliberately execute the exact proposed feature list; never silently
        # remove duration or repair a bad contract inside the tool adapter.
        return {'fixture_only': True, 'actual_training': 0, 'actual_prediction': 0,
                'contract_sha256': contract_digest(contract),
                'executed_feature_columns': deepcopy(contract['feature_columns']),
                'artifact': 'mechanism fixture; not a fitted model or metric'}


class AgentRun:
    def __init__(self, directory, run_id, mode, ledger, *, document=None, model=None, cpu=None, cpu_permit=None):
        require(mode in MODES, 'CONTEXT_MODE')
        self.model, self.cpu = model or ScriptedAgent(), cpu or FakeCPU()
        require(self.model.fixture_only is True, 'REAL_CLIENT_NOT_ADMITTED')
        if self.cpu.fixture_only is not True:
            from .cpu_client import ContractCPUClient, ServerCPUPermit
            require(isinstance(self.cpu, ContractCPUClient)
                    and isinstance(cpu_permit, ServerCPUPermit) and cpu_permit.authorized,
                    'REAL_CPU_CLIENT_NOT_ADMITTED')
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.store = FileProvenanceStore(self.directory / 'store.sqlite', self.directory / 'artifacts')
        self.run_id, self.mode, self.ledger = run_id, mode, ledger
        self.doc = deepcopy(document) if document else {
            'revision': REVISION, 'fixture_only': self.cpu.fixture_only, 'llm_fixture_only': True,
            'run_id': run_id, 'mode': mode,
            'messages': [], 'llm_calls': [], 'tool_calls': [], 'nodes': [], 'decisions': [],
            'faults': [], 'episodes': [], 'final': {}, 'real_api_calls': 0, 'actual_training': 0,
        }
        self.episode_messages = []
        self.role_messages = {}
        self.latest = {}
        self.id_scope = run_id
        self.started = monotonic_ns() - (document.get('elapsed_ns', 0) if document else 0)

    def close(self):
        self.store.close()

    def initialize(self):
        description, binding, code = initial_inputs()
        if self.cpu.fixture_only is not True:
            code = self.cpu.code_text()
        for key, value in [(DOC_KEY, description), (DATA_KEY, binding), (CODE_KEY, code)]:
            self.store.initialize(key, value if isinstance(value, str) else canonical(value))
        self.doc['audit_policy'] = {'allowed_features': BASE_FEATURES,
            'data_binding': binding, 'code_sha256': byte_hash(code), 'prediction_time': 'pre_call'}

    def _node(self, kind, role, payload, parents, reads=(), **extra):
        node_id = identity(self.id_scope, 'node', len(self.store.snapshot()['nodes']))
        node = {'result_id': node_id, 'parent_result_ids': sorted(set(parents)), 'kind': kind,
                'role': role, 'payload': deepcopy(payload), 'file_reads': deepcopy(list(reads)), **extra}
        self.store.record_node(node)
        return node

    def _message(self, role, agent, content, producer=None):
        msg = {'message_id': identity(self.id_scope, 'msg', len(self.doc['messages'])),
               'role': role, 'agent_role': agent, 'content': canonical(content)}
        if producer:
            msg['producer_result_id'] = producer
        self.doc['messages'].append(msg)
        self.episode_messages.append(msg)
        self.role_messages.setdefault(agent, []).append(msg)
        return msg

    def prompt(self, role):
        task = {'goal': 'Predict bank subscription before the call, using approved recipes.',
                'data_binding': self.doc['audit_policy']['data_binding'],
                'code_sha256': self.doc['audit_policy']['code_sha256']}
        system = {'message_id': self.id_scope + '.system.' + role, 'role': 'system',
                  'content': canonical({'role': role, 'task': task,
                     'instruction': 'Use only your allowed tools; produce a structured final response.'})}
        if not any(m['message_id'] == system['message_id'] for m in self.doc['messages']):
            self.doc['messages'].append(deepcopy(system))
        if self.mode == 'FULL_HISTORY':
            selected = self.episode_messages
        elif role == 'Analyst':
            selected = self.role_messages.get(role, [])
        else:
            upstream = 'Analyst' if role == 'Planner' else 'Planner'
            selected = [self.latest[upstream]] + self.role_messages.get(role, [])
        return [system] + deepcopy(selected)

    def _call(self, role):
        require(monotonic_ns() - self.started < 120 * 10**9, 'FIXED_DEADLINE')
        count = sum(c['role'] == role and c['episode'] == self.id_scope for c in self.doc['llm_calls'])
        require(count < 6, 'ROLE_CALL_CAP')
        prompt = self.prompt(role)
        # Byte-based fixture ceiling only; a real tokenizer is required before
        # this becomes a real entry. Do not report these as measured tokens.
        require(len(canonical(prompt).encode()) <= 16000, 'FIXTURE_CONTEXT_LIMIT')
        call_id = identity(self.id_scope, 'llm', len(self.doc['llm_calls']))
        provisional = identity(self.id_scope, 'node', len(self.store.snapshot()['nodes']))
        prepared = self.model.prepare(role, deepcopy(prompt)) if hasattr(self.model, 'prepare') else None
        record = {'call_id': call_id, 'attempt_id': call_id + '.attempt',
            'trial_key': self.id_scope + '.' + role, 'logical_run_key': self.id_scope,
            'branch_id': self.id_scope, 'run_id': self.run_id, 'result_id': provisional,
            'step_id': role, 'phase': 'initial',
            'input_token_upper_bound': prepared.input_token_upper_bound if prepared else 4000,
            'request': prepared.request if prepared else {'messages': deepcopy(prompt)},
            'sidecar': prepared.sidecar if prepared else {'fixture_only': True}}
        self.ledger.reserve(record)
        exchange = None
        if prepared:
            try:
                exchange = self.model.exchange(prepared,
                    before_send=lambda: self.ledger.mark_dispatched(call_id),
                    deadline_monotonic=self.started / 10**9 + 120)
            except Exception as exc:
                row = next(c for c in self.ledger.calls() if c['call_id'] == call_id)
                if row['status'] == 'dispatched':
                    usage = getattr(exc, 'usage', None)
                    request_id = getattr(exc, 'request_id', None)
                    if usage and request_id:
                        self.ledger.settle(call_id, provider_request_id=request_id,
                            raw_usage=usage['raw'], normalized_usage=usage,
                            evidence={'fixture_only': True, 'error': getattr(exc, 'code', type(exc).__name__)})
                    else:
                        self.ledger.quarantine(call_id, getattr(exc, 'code', 'UNKNOWN_HTTP_SETTLEMENT'))
                # A shared authority must remain stopped even if a rejected
                # response included usable usage and was settled above.
                if hasattr(self.ledger, 'stop'):
                    self.ledger.stop(getattr(exc, 'code', 'UNKNOWN_HTTP_SETTLEMENT'))
                raise
            payload, usage = exchange.payload, exchange.usage
            self.ledger.settle(call_id, provider_request_id=exchange.provider_request_id,
                raw_usage=usage['raw'], normalized_usage=usage,
                evidence={'fixture_only': True, 'wire_audit': exchange.audit})
        else:
            self.ledger.mark_dispatched(call_id)
            payload = self.model.respond(role, deepcopy(prompt))
            usage = {'prompt_tokens': 100, 'completion_tokens': 100, 'total_tokens': 200}
            self.ledger.settle(call_id, provider_request_id='fixture:' + call_id, raw_usage=usage,
                normalized_usage={**usage, 'cached_input_tokens': 0, 'reasoning_tokens': 0},
                evidence={'fixture_only': True, 'token_usage_kind': 'synthetic-not-tokenizer-count'})
        call = {'call_id': call_id, 'node_id': provisional, 'role': role, 'episode': self.id_scope,
            'prompt_messages': prompt, 'prompt_refs': [message_ref(m) for m in prompt],
            'prompt_sha256': digest(prompt), 'payload': deepcopy(payload), 'fixture_only': True,
            'token_usage_kind': prepared.sidecar['token_usage_kind'] if prepared else 'synthetic-not-tokenizer-count'}
        if exchange:
            call['wire_audit'] = exchange.audit
            call['gateway_call_id'] = exchange.gateway_call_id
        self.doc['llm_calls'].append(call)
        return call, payload

    def _read(self, key):
        value = self.store.read(key)
        return reference(value), value['content']

    def _tool(self, role, request_node, name, arguments, contract):
        require(role in ('Analyst', 'Executor'), 'ROLE_TOOL_FORBIDDEN')
        reads, writes, payload = [], [], {}
        def read(key):
            ref, content = self._read(key)
            reads.append(ref)
            return content
        def write(key, content):
            current = self.store.snapshot()['files'].get(key)
            writes.append(self.store.write(key, canonical(content), expected=current, writer_id=request_node['result_id']))
        if name == 'list_directory' and role == 'Analyst':
            require(arguments == {'directory': 'inputs'}, 'TOOL_ARGUMENTS')
            # Directory queries are versioned inputs too; bind the listing in a
            # read-only logical manifest rather than omit this dependency.
            payload = {'entries': json.loads(read('inputs/directory.json'))}
        elif name == 'read_file' and role == 'Analyst':
            require(arguments == {'file_id': DOC_KEY}, 'TOOL_ARGUMENTS')
            payload = {'content': read(DOC_KEY)}
        elif name == 'write_config' and role == 'Executor':
            normalize_contract(contract)
            write(CONFIG_KEY, contract)
            payload = {'config_sha256': contract_digest(contract)}
        elif name == 'train' and role == 'Executor':
            saved = json.loads(read(CONFIG_KEY))
            require(normalize_contract(saved) == normalize_contract(contract), 'ACTUAL_CONFIG_CONTRACT')
            binding, code = json.loads(read(DATA_KEY)), read(CODE_KEY)
            require(binding == saved['data_binding'] and byte_hash(code) == saved['code_sha256'], 'ACTUAL_INPUT_BINDING')
            payload = self.cpu.execute(saved)
            write(MODEL_KEY, payload)
        elif name == 'write_report' and role == 'Executor':
            artifact = json.loads(read(MODEL_KEY))
            payload = {'contract_sha256': contract_digest(contract), 'artifact': artifact}
            write(REPORT_KEY, payload)
        elif name == 'publish' and role == 'Executor':
            report = json.loads(read(REPORT_KEY))
            permission = json.loads(read('inputs/permission.json'))
            require(permission['publish_allowed'] is True, 'PUBLISH_NOT_AUTHORIZED')
            payload = {'status': 'published', 'report_sha256': digest(report), 'fixture_only': True,
                       'compensatable': True}
            write(PUBLICATION_KEY, payload)
        else:
            raise ValueError('tool not allowed: ' + str(name))
        tool_id = identity(self.id_scope, 'tool', len(self.doc['tool_calls']))
        # Writes subsequently read by tools contribute observed producer edges.
        parents = {request_node['result_id']}
        known = {n['result_id'] for n in self.store.snapshot()['nodes']}
        parents.update(r['writer_id'] for r in reads if r['writer_id'] in known)
        node = self._node('tool', role, {'tool': name, **payload}, parents, reads,
                          tool_call_id=tool_id)
        self.doc['tool_calls'].append({'tool_call_id': tool_id, 'node_id': node['result_id'],
            'name': name, 'reads': reads, 'writes': writes,
            'fixture_only': self.cpu.fixture_only if name == 'train' else True})
        self._message('tool', role, {'tool': name, **payload}, node['result_id'])
        return node

    def role(self, role, *, fault=None):
        contract = json.loads(self.latest['Planner']['content'])['final'] if role == 'Executor' else None
        for _ in range(6):
            call, raw = self._call(role)
            delivered = deepcopy(raw)
            if fault and role == 'Analyst' and 'final' in raw:
                if fault == 'F_DECISION':
                    delivered['final']['unavailable_before_call'] = []
                elif fault == 'F_INCIDENTAL':
                    delivered['final']['row_count'] += 1
                else:
                    raise ValueError(fault)
                self.doc['faults'].append({'type': fault, 'call_id': call['call_id'],
                    'raw_payload': raw, 'delivered_payload': deepcopy(delivered), 'fixture_only': True})
            call['delivered_payload'] = deepcopy(delivered)
            parents = [m['producer_result_id'] for m in call['prompt_messages'] if m.get('producer_result_id')]
            payload = delivered.get('final', delivered)
            node = self._node('llm', role, payload, parents, llm_call_id=call['call_id'])
            require(node['result_id'] == call['node_id'], 'CALL_NODE_IDENTITY')
            message = self._message('assistant', role, delivered, node['result_id'])
            if 'final' in delivered:
                self.latest[role] = message
                if role == 'Planner':
                    normalize_contract(delivered['final'])
                return node
            require('tool' in delivered and 'arguments' in delivered, 'MODEL_RESPONSE_SCHEMA')
            self._tool(role, node, delivered['tool'], delivered['arguments'], contract)
        raise ValueError('role did not finish within cap')

    def episode(self, scope, *, fault=None, roles=('Analyst', 'Planner', 'Executor')):
        self.id_scope = scope
        self.episode_messages, self.role_messages, self.latest = [], {}, {}
        selected = {}
        for role in roles:
            selected[role] = self.role(role, fault=fault)
        self.doc['episodes'].append({'scope': scope, 'selected': {k: v['result_id'] for k, v in selected.items()}})
        return selected

    def finish(self, contract, *, retained=(), consumed=False, safe_stop=False):
        from .checker import check_contract
        policy = self.doc['audit_policy']
        verdict = check_contract(contract, policy['allowed_features'], policy['data_binding'], policy['code_sha256'])
        jobs = getattr(self.cpu, 'records', [])
        training = sum(int(j.get('response', {}).get('actual_training', 0)) for j in jobs if j.get('response'))
        prediction = sum(int(j.get('response', {}).get('actual_prediction', 0)) for j in jobs if j.get('response'))
        self.doc['actual_training'], self.doc['actual_prediction'] = training, prediction
        self.doc['final'] = {'outcome': 'correct_complete' if verdict['passed'] else 'wrong_complete',
            'contract': deepcopy(contract), 'retained_result_ids': list(retained),
            'fixture_only': self.cpu.fixture_only, 'actual_training': training, 'actual_prediction': prediction}
        if jobs:
            self.doc['cpu_records'] = [{'spec_sha256': j['spec']['spec_sha256'],
                'job_id': j['spec']['job_id'], 'execution': j['execution'],
                'response_sha256': digest(j['response'])} for j in jobs]
        if safe_stop:
            self.doc['final']['outcome'] = 'safe_stop'
        if consumed:
            self.doc['final']['outcome'] = 'external_unresolved'
            self.doc['final']['external_receipts'] = [reference(self.store.read(CONSUMPTION_KEY))]
        self.doc.update(self.store.snapshot())
        self.doc['ledger'] = self.ledger.snapshot()
        self.doc['elapsed_ns'] = monotonic_ns() - self.started
        (self.directory / 'trace.json').write_text(json.dumps(self.doc, indent=2) + '\n')
        return deepcopy(self.doc)


def make_prefix(directory, run_id, mode, fault, ledger):
    run = AgentRun(directory, run_id, mode, ledger)
    try:
        run.initialize()
        run.store.initialize('inputs/directory.json', canonical([DOC_KEY, DATA_KEY, 'inputs/permission.json']))
        run.store.initialize('inputs/permission.json', canonical({'publish_allowed': True}))
        selected = run.episode(run_id + '.initial', fault=fault)
        contract = selected['Planner']['payload']
        result = run.finish(contract)
        result['checkpoint'] = {'faulty_result_id': selected['Analyst']['result_id'],
            'planner_result_id': selected['Planner']['result_id'],
            'prefix_sha256': digest({k: result[k] for k in ('nodes', 'messages', 'tool_calls', 'files')})}
        (Path(directory) / 'trace.json').write_text(json.dumps(result, indent=2) + '\n')
        return result
    finally:
        run.close()


def recover(prefix_directory, document, destination, method, ledger, *, external_update=True, consumed=False):
    require(method in ('FULL', 'CONSERVATIVE', 'CUTOFF'), 'RECOVERY_METHOD')
    with FileProvenanceStore(Path(prefix_directory) / 'store.sqlite', Path(prefix_directory) / 'artifacts') as saved:
        saved.save_to(destination)
    run = AgentRun(destination, document['run_id'], document['mode'], ledger, document=document)
    try:
        if consumed:
            # Establish the external consumption before any correction. Its
            # receipt continues to name the old publication after local repair.
            run.store.initialize(CONSUMPTION_KEY, canonical({'status': 'consumed',
                'publication_ref': document['files'][PUBLICATION_KEY], 'retractable': False}), writer='external-consumer')
        original_docs = run.store.snapshot()['files'][DOC_KEY]
        if external_update:
            desc = json.loads(run.store.read(DOC_KEY)['content'])
            desc['note'] += ' External owner clarified the documentation.'
            updated = run.store.write(DOC_KEY, canonical(desc), expected=original_docs, writer_id='external-owner')['after']
        else:
            updated = original_docs
        # All arms see the same legitimate source update. No method restores it.
        run.id_scope = document['run_id'] + '.' + method + ('.consumed' if consumed else '')
        run.episode_messages, run.role_messages, run.latest = [], {}, {}
        run.role('Analyst')
        new_planner = run.role('Planner')
        nodes = run.store.snapshot()['nodes']
        old_id = document['checkpoint']['planner_result_id']
        old = next(n for n in nodes if n['result_id'] == old_id)
        equivalent = contract_digest(old['payload']) == contract_digest(new_planner['payload'])
        current_doc = json.loads(run.store.read(DOC_KEY)['content'])
        candidate = new_planner['payload']
        checks = {
            'current_feature_eligibility': set(candidate['feature_columns']).issubset(set(current_doc['feature_columns']))
                and not set(candidate['feature_columns']).intersection(current_doc['unavailable_before_call'])
                and candidate['label_column'] not in candidate['feature_columns'],
            'current_data_binding': candidate['data_binding'] == json.loads(run.store.read(DATA_KEY)['content']),
            'current_code_binding': candidate['code_sha256'] == byte_hash(run.store.read(CODE_KEY)['content']),
            'current_publish_permission': json.loads(run.store.read('inputs/permission.json')['content'])['publish_allowed'] is True,
        }
        candidate_valid = all(checks.values())
        invalid_seeds = {document['checkpoint']['faulty_result_id']}
        # Stale environmental reads are separate roots; an equivalent Planner
        # cannot hide a direct read or prompt exposure that bypasses it.
        files = run.store.snapshot()['files']
        for n in document['nodes']:
            if any(files[r['file_id']] != r for r in n.get('file_reads', [])):
                invalid_seeds.add(n['result_id'])
        proposed_edges = {(old_id, n['result_id']) for n in document['nodes'] if old_id in n['parent_result_ids']}
        reduced = [{**n, 'parent_result_ids': [p for p in n['parent_result_ids']
                    if (p, n['result_id']) not in proposed_edges]} for n in document['nodes']]
        invalid_after_cut = set(closure_ids(invalid_seeds, reduced))
        executor_nodes = [n for n in document['nodes'] if n['role'] == 'Executor']
        other_valid = all(n['result_id'] not in invalid_after_cut for n in executor_nodes)
        can_retain = method == 'CUTOFF' and equivalent and other_valid and candidate_valid
        cut_edges = [{'parent_result_id': p, 'child_result_id': c} for p, c in sorted(proposed_edges)] if can_retain else []
        run.doc['decisions'].append({'method': method, 'round': 1, 'node_id': 'Planner',
            'old_result_id': old_id, 'new_result_id': new_planner['result_id'], 'equivalent': equivalent,
            'cut_edges': cut_edges, 'other_inputs_valid': other_valid,
            'action': 'retain' if can_retain else 'invalidate',
            'invalidated_result_ids': sorted(invalid_after_cut if can_retain else set(closure_ids(invalid_seeds, document['nodes']))),
            'reason': 'equivalent_contract_and_all_other_inputs_current' if can_retain else 'conservative_fallback',
            'equivalence_sha256': contract_digest(new_planner['payload']),
            'candidate_guard': {'passed': candidate_valid, 'checks': checks,
                'source_refs': [files[k] for k in (DOC_KEY, DATA_KEY, CODE_KEY, 'inputs/permission.json')]},
            'source_update': {'before': original_docs, 'after': updated}})
        if can_retain:
            retained = [n['result_id'] for n in executor_nodes]
        elif candidate_valid:
            run.role('Executor')
            retained = []
        else:
            retained = []
        # A real external consumption cannot be undone by replacing a local
        # report/publication. Keep the receipt even when local correction works.
        result = run.finish(new_planner['payload'], retained=retained, consumed=consumed, safe_stop=not candidate_valid)
        result['recovery'] = {'method': method, 'checkpoint_sha256': document['checkpoint']['prefix_sha256'],
            'new_calls': len(result['llm_calls']) - len(document['llm_calls']),
            'retained_nodes': len(retained), 'retained_fixture_train_jobs': int(can_retain),
            'new_fixture_train_jobs': int(not can_retain and candidate_valid), 'source_update_preserved': result['files'][DOC_KEY] == updated,
            'real_api_calls': 0, 'actual_training': 0, 'actual_prediction': 0}
        (Path(destination) / 'trace.json').write_text(json.dumps(result, indent=2) + '\n')
        return result
    finally:
        run.close()
