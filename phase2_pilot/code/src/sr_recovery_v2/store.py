"""SQLite acceptance boundary for V1 synthetic workflows.

The current document and append-only command receipts are committed together.
Artifacts are immutable files staged before acceptance, not an assertion of a
filesystem/SQLite distributed transaction. This module has no network client.
"""
import copy
import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path

from .common import (REV, ProtocolError, canonical, digest, source_fingerprint,
                     selected_graph_digest, closure_ids, node_map, utc_parse, utc_format)
from .guard import diagnose
from .policy import advance


class V1Store:
    def __init__(self, db_path, artifact_root):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.artifact_root = Path(artifact_root).resolve()
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(self.db_path), timeout=10, isolation_level=None)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS document (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS commands (seq INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL, command_digest TEXT NOT NULL,
                event TEXT NOT NULL, response TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS dispatches (attempt_id TEXT PRIMARY KEY,
                node_id TEXT NOT NULL, stage TEXT NOT NULL, UNIQUE(node_id,stage));
        ''')

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @contextmanager
    def _transaction(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            raise

    def _load(self):
        row = self.db.execute('SELECT payload FROM document WHERE id=1').fetchone()
        if not row:
            raise ProtocolError('STORE_NOT_CREATED')
        return json.loads(row[0])

    def _save(self, doc):
        self.db.execute('UPDATE document SET payload=? WHERE id=1', (canonical(doc),))

    def _validate(self, record):
        # Strict unchanged V0 record definitions; implementation envelopes have
        # their own separate fields rather than expanding frozen record shapes.
        import jsonschema
        if not hasattr(self, '_schema'):
            path = Path(__file__).resolve().parents[2] / 'sr_v2/v0/contracts/records.schema.json'
            self._schema = json.loads(path.read_text())
        schema = {**self._schema, 'oneOf': [{'$ref': '#/$defs/' + record['record_type']}]}
        try:
            jsonschema.Draft202012Validator(schema).validate(record)
        except jsonschema.ValidationError as exc:
            raise ProtocolError('RECORD_SCHEMA_INVALID', str(exc.message)) from exc

    def create(self, scene, dag, branch_id, policy):
        if policy not in ('FULL', 'LAZY', 'EAGER'):
            raise ProtocolError('UNKNOWN_POLICY')
        initial = copy.deepcopy(scene)
        request_digest = digest({'scene': initial, 'dag': dag, 'branch_id': branch_id, 'policy': policy})
        with self._transaction():
            old = self.db.execute('SELECT payload FROM document WHERE id=1').fetchone()
            if old:
                if json.loads(old[0])['metadata']['creation_digest'] != request_digest:
                    raise ProtocolError('STORE_ALREADY_BOUND')
            else:
                run = initial['run_state']
                state = {'record_type': 'BranchState', 'revision': REV, 'fixture_only': True,
                    'branch_id': branch_id, 'scene_id': run['scene_id'], 'run_id': run['run_id'],
                    'policy': policy, 'state_version': 0, 'notice_id': initial['notice']['notice_id'],
                    'stage': 'first', 'status': 'ready', 'selected_by_node': copy.deepcopy(run['selected_by_node']),
                    'pending_node_ids': [], 'invalidated_result_ids': [],
                    'counters': {'stale_used': 0, 'semantic_used': 0, 'physical_calls': 0, 'cpu_jobs': 0},
                    'stage_completed_node_ids': [], 'active_attempt_ids': [], 'unsettled_call_ids': [],
                    'source_fingerprint': source_fingerprint(initial['current_sources']),
                    'active_plan_id': None, 'terminal_status': None, 'started_at_utc': None, 'deadline_utc': None}
                self._validate(state)
                task = copy.deepcopy(initial['task'])
                if initial.get('source_aliases'):
                    task.setdefault('resolved_source_aliases', copy.deepcopy(initial['source_aliases']))
                doc = {'state': state, 'dag': copy.deepcopy(dag), 'task': task,
                    'notice': copy.deepcopy(initial['notice']), 'results': copy.deepcopy(initial['results']),
                    'sources': copy.deepcopy(initial['current_sources']),
                    'source_history': copy.deepcopy(initial.get('source_history', [])),
                    'artifacts': copy.deepcopy(initial['artifact_manifest']),
                    'calls': copy.deepcopy(initial.get('call_evidence', [])),
                    'tool_receipts': copy.deepcopy(initial.get('tool_receipts', [])),
                    'input_producers': copy.deepcopy(initial.get('input_producers', [])),
                    'attempts': [], 'plans': [], 'guards': [], 'effects': [], 'objects': {},
                    'last_guard': None, 'pending_decision': None, 'last_observed_utc': None,
                    'initial_snapshot': initial, 'prefix_digest': digest(initial),
                    'source_aliases': initial.get('source_aliases', task.get('resolved_source_aliases', {})),
                    'domain': initial.get('domain', 'micro' if 'read_metadata' in dag['topological_order'] else 'macro'),
                    'metadata': {'creation_digest': request_digest,
                        'initial_result_ids': [r['result_id'] for r in initial['results']],
                        'prefix_mode': initial.get('prefix_mode', 'frozen_V0_synthetic_fixture'),
                        'implementation': 'V1-offline-r1', 'real_api_requests': 0,
                        'real_cost_nano_usd': 0, 'actual_training': 0},
                    'late_outputs': [], 'dispatch_payloads': []}
                refusal = initial.get('prefix_refusal')
                if refusal:
                    doc['guards'].append(copy.deepcopy(refusal))
                self.db.execute('INSERT INTO document VALUES(1,?)', (canonical(doc),))
        return self.snapshot()

    def snapshot(self):
        return self._load()

    def export(self):
        doc = self._load()
        doc['events'] = [json.loads(row[0]) for row in self.db.execute('SELECT event FROM commands ORDER BY seq')]
        return doc

    def _clock(self, doc, now, allow_expired=False):
        value = utc_parse(now)
        old = doc.get('last_observed_utc')
        if old and value < utc_parse(old):
            raise ProtocolError('BACKWARDS_CLOCK')
        deadline = doc['state']['deadline_utc']
        if deadline and not allow_expired and value >= utc_parse(deadline):
            raise ProtocolError('FIXED_DEADLINE_EXPIRED')
        doc['last_observed_utc'] = now

    def _apply(self, event_id, kind, command, now, mutation, allow_expired=False):
        command_hash = digest({'kind': kind, 'command': command})
        with self._transaction():
            old = self.db.execute('SELECT command_digest,response FROM commands WHERE event_id=?', (event_id,)).fetchone()
            if old:
                if old[0] != command_hash:
                    raise ProtocolError('IDEMPOTENCY_PAYLOAD_MISMATCH')
                return json.loads(old[1])
            doc = self._load()
            before = copy.deepcopy(doc['state'])
            self._clock(doc, now, allow_expired=allow_expired)
            details, response = mutation(doc)
            doc['state']['state_version'] += 1
            self._validate(doc['state'])
            event = {'event_id': event_id, 'kind': kind, 'accepted_at_utc': now,
                'command_digest': command_hash, 'decision': command.get('decision'),
                'before': before, 'after': copy.deepcopy(doc['state']), 'details': details}
            if response is None:
                response = {'state': copy.deepcopy(doc['state'])}
            elif isinstance(response, dict) and 'state' in response:
                response['state'] = copy.deepcopy(doc['state'])
            self._save(doc)
            self.db.execute('INSERT INTO commands(event_id,command_digest,event,response) VALUES(?,?,?,?)',
                (event_id, command_hash, canonical(event), canonical(response)))
            return copy.deepcopy(response)

    def begin_branch(self, event_id, now_utc):
        def mutate(doc):
            state = doc['state']
            if not state['started_at_utc']:
                state['started_at_utc'] = now_utc
                state['deadline_utc'] = utc_format(utc_parse(now_utc) + timedelta(seconds=1800))
                state['status'] = 'running'
            return {'deadline_reused': state['started_at_utc'] != now_utc}, None
        return self._apply(event_id, 'begin_branch', {}, now_utc, mutate, allow_expired=True)

    def _check_guard(self, doc, guard):
        self._validate(guard)
        if guard['selected_graph_digest'] != selected_graph_digest(doc['state']['selected_by_node'], doc['results']):
            raise ProtocolError('GUARD_GRAPH_BINDING_MISMATCH')
        if guard['source_fingerprint'] != source_fingerprint(doc['sources']):
            raise ProtocolError('GUARD_SOURCE_BINDING_MISMATCH')
        candidate = next((r for r in doc['results'] if r['result_id'] == guard['candidate_result_id']), None)
        actual = diagnose(doc, guard['node_id'], checkpoint=guard['checkpoint'], candidate=candidate,
                          full=guard['full_version_diagnosis'], artifact_root=self.artifact_root)
        if actual != guard:
            raise ProtocolError('GUARD_EVIDENCE_MISMATCH')

    @staticmethod
    def _append_guard(doc, guard):
        old = next((g for g in doc['guards'] if g['guard_id'] == guard['guard_id']), None)
        if old is not None and old != guard:
            raise ProtocolError('GUARD_ID_REBOUND')
        if old is None:
            doc['guards'].append(copy.deepcopy(guard))
        doc['last_guard'] = copy.deepcopy(guard)

    def record_guard(self, guard, event_id, now_utc):
        def mutate(doc):
            self._check_guard(doc, guard)
            self._append_guard(doc, guard)
            return {'guard_id': guard['guard_id'], 'classification': guard['classification']}, None
        return self._apply(event_id, 'guard', {'guard': guard}, now_utc, mutate)

    def record_scan(self, decision, guard, event_id, now_utc):
        def mutate(doc):
            if decision['expected_state_version'] != doc['state']['state_version']:
                raise ProtocolError('STALE_STATE_VERSION')
            if decision['kind'] != 'need_version_scan' or not guard['full_version_diagnosis']:
                raise ProtocolError('FULL_SCAN_REQUIRED')
            if doc['state']['active_attempt_ids']:
                raise ProtocolError('ACTIVE_OR_UNSETTLED_WORK')
            self._check_guard(doc, guard)
            self._append_guard(doc, guard)
            return {'guard_id': guard['guard_id'], 'full_version_scan': True,
                    'read_object_keys': [s['object_key'] for s in doc['sources']]}, None
        return self._apply(event_id, 'version_scan', {'decision': decision, 'guard': guard}, now_utc, mutate)

    def _expected_decision(self, doc, output, now, guard):
        self._validate(output)
        if output['expected_state_version'] != doc['state']['state_version']:
            raise ProtocolError('STALE_STATE_VERSION')
        if guard is not None:
            if not any(g == guard for g in doc['guards']):
                raise ProtocolError('UNPERSISTED_GUARD')
            if guard['selected_graph_digest'] != selected_graph_digest(doc['state']['selected_by_node'], doc['results']):
                raise ProtocolError('GUARD_GRAPH_BINDING_MISMATCH')
        from .runner import advance_input
        expected = advance(advance_input(doc, now, guard, event_id=output['event_id']), doc['dag'])
        if output != expected:
            raise ProtocolError('POLICY_DECISION_MISMATCH')

    def _invalidate(self, doc, ids):
        state = doc['state']
        invalid = set(state['invalidated_result_ids']) | set(ids)
        if not self._compensate(doc, invalid):
            state.update(status='terminal', terminal_status='conflict_safe')
            return False
        state['invalidated_result_ids'] = sorted(invalid)
        state['selected_by_node'] = {n: None if rid in invalid else rid
                                     for n, rid in state['selected_by_node'].items()}
        return True

    def admit_decision(self, output, now_utc, guard_evidence=None):
        def mutate(doc):
            state = doc['state']
            self._expected_decision(doc, output, now_utc, guard_evidence)
            if state['active_attempt_ids'] or state['unsettled_call_ids']:
                raise ProtocolError('ACTIVE_OR_UNSETTLED_WORK')
            kind = output['kind']
            if state['status'] == 'terminal' and kind != 'return_existing':
                raise ProtocolError('TERMINAL_BRANCH')
            details = {'kind': kind}
            if kind == 'compensate':
                if state['active_plan_id'] is not None:
                    raise ProtocolError('INITIAL_PLAN_ALREADY_ACCEPTED')
                seeds = [doc['notice']['faulty_result_id']]
                if state['policy'] == 'FULL':
                    invalid = [r['result_id'] for r in doc['results']]
                else:
                    if state['policy'] == 'EAGER' and guard_evidence:
                        seeds += [rid for issue in guard_evidence['issues']
                                  if issue['code'] in ('STALE_EFFECTIVE_READ', 'PROVABLE_MIXED_READ_VERSIONS')
                                  for rid in issue['related_result_ids']]
                    invalid = closure_ids(seeds, doc['results'])
                if self._invalidate(doc, invalid):
                    state['pending_node_ids'] = output['ordered_node_ids'][:]
                    state['active_plan_id'] = 'v1.initial.' + output['decision_id']
                    state['stage_completed_node_ids'] = []
                details['invalidated_result_ids'] = invalid
            elif kind == 'admit_correction':
                cls = output['correction_kind']
                if cls not in ('stale', 'semantic') or not guard_evidence or guard_evidence['classification'] != cls:
                    raise ProtocolError('INVALID_CORRECTION_DIAGNOSIS')
                if cls == 'stale' and not guard_evidence['full_version_diagnosis']:
                    raise ProtocolError('FULL_SCAN_REQUIRED')
                if state['counters'][cls + '_used']:
                    raise ProtocolError('CORRECTION_ALREADY_USED')
                relevant = [i for i in guard_evidence['issues'] if cls != 'stale' or i['code'] in
                            ('STALE_EFFECTIVE_READ', 'PROVABLE_MIXED_READ_VERSIONS')]
                seeds = sorted({rid for issue in relevant for rid in issue['related_result_ids']})
                if not seeds and guard_evidence['candidate_result_id']:
                    seeds = [guard_evidence['candidate_result_id']]
                invalid = closure_ids(seeds, doc['results'])
                before = copy.deepcopy(state['counters'])
                after = {**before, cls + '_used': 1}
                plan = {'record_type': 'CorrectionPlan', 'revision': REV, 'fixture_only': True,
                    'plan_id': 'v1.plan.' + output['decision_id'], 'branch_id': state['branch_id'],
                    'kind': cls, 'guard_id': guard_evidence['guard_id'], 'source_fingerprint': state['source_fingerprint'],
                    'seed_result_ids': seeds, 'invalidated_result_ids': invalid,
                    'pending_before': state['pending_node_ids'][:],
                    'carried_pending_node_ids': output['carried_pending_node_ids'][:],
                    'ordered_node_ids': output['ordered_node_ids'][:],
                    'selected_before': copy.deepcopy(state['selected_by_node']),
                    'counters_before': before, 'counters_after': after, 'admission_event_id': output['event_id']}
                self._validate(plan)
                if self._invalidate(doc, invalid):
                    doc['plans'].append(plan)
                    state.update(stage=cls, counters=after, active_plan_id=plan['plan_id'],
                                 pending_node_ids=plan['ordered_node_ids'][:], stage_completed_node_ids=[])
                    details['plan_id'] = plan['plan_id']
            elif kind == 'execute_node':
                if doc['pending_decision'] is not None:
                    raise ProtocolError('ACCEPTED_DISPATCH_PENDING')
                doc['pending_decision'] = copy.deepcopy(output)
            elif kind in ('terminal', 'return_existing'):
                state.update(status='terminal', terminal_status=output['terminal_status'])
            elif kind == 'commit':
                final = doc['dag']['topological_order'][-1]
                candidate = next((r for r in doc['results'] if r['result_id'] == state['selected_by_node'][final]), None)
                guard = diagnose(doc, final, 'precommit', candidate=candidate, full=True, artifact_root=self.artifact_root)
                self._append_guard(doc, guard)
                if guard['classification'] != 'passed':
                    raise ProtocolError('COMMIT_GUARD_REFUSED')
                state.update(status='terminal', terminal_status='completed_correct')
            else:
                raise ProtocolError('ACTION_NOT_ADMISSIBLE')
            if kind not in ('commit',):
                doc['last_guard'] = None
            return details, None
        return self._apply(output['event_id'], 'admit', {'decision': output, 'guard': guard_evidence},
                           now_utc, mutate, allow_expired=output['kind'] in ('terminal', 'return_existing'))

    def start_node(self, decision, event_id, now_utc):
        def mutate(doc):
            state = doc['state']
            if state['status'] != 'running' or doc['pending_decision'] != decision:
                raise ProtocolError('DISPATCH_NOT_ACCEPTED')
            if state['active_attempt_ids'] or state['unsettled_call_ids']:
                raise ProtocolError('ACTIVE_OR_UNSETTLED_WORK')
            node_id = decision['node_id']
            if node_id in state['stage_completed_node_ids']:
                raise ProtocolError('NODE_ALREADY_EXECUTED_IN_STAGE')
            node = node_map(doc['dag'])[node_id]
            guard = diagnose(doc, node_id, artifact_root=self.artifact_root)
            if guard['classification'] != 'passed':
                raise ProtocolError('DISPATCH_GUARD_REFUSED', guard['classification'])
            if state['source_fingerprint'] != source_fingerprint(doc['sources']):
                raise ProtocolError('SOURCE_DRIFT_AFTER_FREEZE')
            used = sum(a['counter_llm'] for a in doc['attempts'] if a['stage'] == state['stage'])
            if used + node['llm_calls_per_execution'] > 5 or state['counters']['physical_calls'] + node['llm_calls_per_execution'] > 15 or state['counters']['cpu_jobs'] + node['cpu_jobs_per_execution'] > 30:
                raise ProtocolError('BRANCH_CALL_OR_JOB_CAP')
            aid = 'v1.attempt.' + digest({'branch_id': state['branch_id'], 'decision': decision['decision_id']})[:32]
            attempt = {'attempt_id': aid, 'node_id': node_id, 'stage': state['stage'],
                'plan_id': state['active_plan_id'], 'decision_id': decision['decision_id'], 'status': 'running',
                'started_at_utc': now_utc, 'finished_at_utc': None, 'result_id': None, 'input_digest': None,
                'dispatch_id': event_id, 'counter_llm': node['llm_calls_per_execution'],
                'counter_cpu': node['cpu_jobs_per_execution'], 'worker_reaped': True,
                'deadline_utc': utc_format(min(utc_parse(state['deadline_utc']), utc_parse(now_utc) + timedelta(seconds=120))),
                'late': False}
            if node_id == doc['dag']['topological_order'][-1]:
                keys = ('config', 'draft') if node_id == 'execute' else ('manifest', 'report_index')
                attempt['target_before'] = {key: copy.deepcopy(doc['objects'].get(key)) for key in keys}
            try:
                self.db.execute('INSERT INTO dispatches VALUES(?,?,?)', (aid, node_id, state['stage']))
            except sqlite3.IntegrityError as exc:
                raise ProtocolError('NODE_ALREADY_EXECUTED_IN_STAGE') from exc
            state['counters']['physical_calls'] += attempt['counter_llm']
            state['counters']['cpu_jobs'] += attempt['counter_cpu']
            state['active_attempt_ids'].append(aid)
            if attempt['counter_llm']:
                state['unsettled_call_ids'].append(aid + '.call')
            doc['attempts'].append(attempt)
            doc['pending_decision'] = None
            return {'attempt_id': aid, 'node_id': node_id}, copy.deepcopy(attempt)
        return self._apply(event_id, 'dispatch', {'decision': decision}, now_utc, mutate)

    def _stage_artifacts(self, package):
        for art in package.get('artifacts', []):
            self._validate(art)
            path = (self.artifact_root / art['uri']).resolve()
            if not path.is_relative_to(self.artifact_root):
                raise ProtocolError('ARTIFACT_PATH_ESCAPE')
            body = package.get('artifact_contents', {}).get(art['artifact_id'])
            if body is None:
                body = path.read_bytes()
            if len(body) != art['size_bytes'] or hashlib.sha256(body).hexdigest() != art['sha256']:
                raise ProtocolError('ARTIFACT_HASH_MISMATCH')
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                with path.open('xb') as out:
                    out.write(body)
            except FileExistsError:
                if path.read_bytes() != body:
                    raise ProtocolError('IMMUTABLE_ARTIFACT_REWRITE')

    def finish_node(self, attempt_id, package, now_utc):
        # Byte staging cannot mutate any business object. Refused candidates and
        # their artifacts remain available for failure analysis.
        self._stage_artifacts(package)
        persisted_package = {k: v for k, v in package.items() if k != 'artifact_contents'}
        def mutate(doc):
            state = doc['state']
            attempt = next((a for a in doc['attempts'] if a['attempt_id'] == attempt_id), None)
            if not attempt:
                raise ProtocolError('UNKNOWN_ATTEMPT')
            if attempt['status'] != 'running':
                raise ProtocolError('ATTEMPT_ALREADY_SETTLED')
            result = copy.deepcopy(package['result'])
            self._validate(result)
            if result['attempt_id'] != attempt_id or result['node_id'] != attempt['node_id'] or result['run_id'] != state['run_id']:
                raise ProtocolError('RESULT_IDENTITY_MISMATCH')
            expected_parents = [state['selected_by_node'][p] for p in node_map(doc['dag'])[result['node_id']]['parents']]
            if result['parent_result_ids'] != expected_parents:
                raise ProtocolError('RESULT_PARENT_BINDING_MISMATCH')
            if any(r['result_id'] == result['result_id'] for r in doc['results']):
                raise ProtocolError('DUPLICATE_RESULT_ID')
            if any(bool(c.get('request_sent')) or c.get('cost_nano_usd', 0) or not c.get('fixture_only')
                   or c.get('mode') not in ('fixture', 'fake_http') for c in package.get('calls', [])):
                raise ProtocolError('REAL_CLIENT_FORBIDDEN')
            for name, identity in [('calls', 'call_id'), ('tool_receipts', 'receipt_id'), ('artifacts', 'artifact_id')]:
                values = package.get(name, [])
                old_ids = {v[identity] for v in doc[name]}
                if len({v[identity] for v in values}) != len(values) or any(v[identity] in old_ids for v in values):
                    raise ProtocolError('EVIDENCE_ID_REBOUND')
                for value in values:
                    self._validate(value)
                doc[name].extend(copy.deepcopy(values))
            if len(package.get('calls', [])) != attempt['counter_llm'] or len(package.get('tool_receipts', [])) != attempt['counter_cpu']:
                raise ProtocolError('DISPATCH_EVIDENCE_COUNT_MISMATCH')
            if any(c['status'] != 'completed' for c in package.get('calls', [])) or any(
                    r['exit_code'] != 0 for r in package.get('tool_receipts', [])):
                result['execution_status'] = 'uncertain'
            late = utc_parse(now_utc) >= utc_parse(attempt['deadline_utc']) or state['status'] == 'terminal'
            attempt.update(status='late_ignored' if late else 'completed', finished_at_utc=now_utc,
                           result_id=result['result_id'], input_digest=result['input_digest'], late=late)
            state['active_attempt_ids'].remove(attempt_id)
            if attempt['counter_llm']:
                state['unsettled_call_ids'].remove(attempt_id + '.call')
            if late:
                doc['late_outputs'].append({'attempt_id': attempt_id, 'raw_result': result, 'observed_at_utc': now_utc})
                result['execution_status'] = 'cancelled'
                doc['results'].append(result)
                state.update(status='terminal', terminal_status='budget_or_time_stopped')
                return {'late_ignored': True, 'raw_candidate': package['result']}, {'result': result, 'guard': None, 'state': state, 'late': True}
            final = result['node_id'] == doc['dag']['topological_order'][-1]
            guard = diagnose(doc, result['node_id'], 'precommit' if final else 'post_tool',
                             candidate=result, full=False, artifact_root=self.artifact_root)
            doc['results'].append(result)
            # Guard digest refers to exactly the persisted candidate-inclusive
            # result list. Store accepts refusal status as a separate disposition.
            if guard['classification'] != 'passed':
                if result['execution_status'] == 'success':
                    result['execution_status'] = 'validation_rejected'
                guard = diagnose(doc, result['node_id'], 'precommit' if final else 'post_tool',
                                 candidate=result, full=False, artifact_root=self.artifact_root)
                self._append_guard(doc, guard)
            else:
                state['selected_by_node'][result['node_id']] = result['result_id']
                state['pending_node_ids'] = [n for n in state['pending_node_ids'] if n != result['node_id']]
                state['stage_completed_node_ids'].append(result['node_id'])
                doc['last_guard'] = None
                if final:
                    self._publish(doc, result)
                    state.update(status='terminal', terminal_status='completed_correct')
                doc['guards'].append(guard)
            return ({'attempt_id': attempt_id, 'raw_candidate': package['result'],
                    'guard_id': guard['guard_id'], 'classification': guard['classification']},
                    {'result': result, 'guard': guard, 'state': state, 'late': False})
        return self._apply('v1.finish.' + attempt_id, 'settle', {'attempt_id': attempt_id, 'package': persisted_package},
                           now_utc, mutate, allow_expired=True)

    @staticmethod
    def _publish(doc, result):
        # Exactly two objects per operation, one atomic SQL document mutation.
        node = result['node_id']
        if node == 'execute':
            payloads = {'config': result['payload']['config'], 'draft': result['payload']['command']}
        else:
            payloads = {'manifest': result['payload'], 'report_index': {
                'report_result_id': doc['state']['selected_by_node']['report'],
                'candidate_artifact_id': result['payload']['candidate_artifact_id']}}
        before, after = {}, {}
        for key, payload in payloads.items():
            old = doc['objects'].get(key, {'version': 0, 'payload': None, 'owner_result_id': None})
            before[key] = copy.deepcopy(old)
            after[key] = {'version': old['version'] + 1, 'payload': copy.deepcopy(payload),
                          'owner_result_id': result['result_id']}
        doc['objects'].update(after)
        doc['effects'].append({'effect_id': 'v1.effect.' + result['result_id'], 'producer_result_id': result['result_id'],
            'operation_id': 'v1.operation.' + result['attempt_id'], 'before': before, 'after': after,
            'status': 'committed', 'atomic_group': sorted(payloads)})

    @staticmethod
    def _compensate(doc, invalid):
        targets = [e for e in doc['effects'] if e['status'] == 'committed' and e['producer_result_id'] in invalid]
        # Check all owned members first; no partial tombstone if any member was
        # changed by another writer. Versions only increase, including removal.
        if any(doc['objects'].get(k) != v for e in targets for k, v in e['after'].items()):
            return False
        for effect in targets:
            for key, old in effect['after'].items():
                doc['objects'][key] = {'version': old['version'] + 1, 'payload': None, 'owner_result_id': None}
            effect['status'] = 'compensated'
        return True

    def harness_update_source(self, source, event_id, now_utc):
        """Offline anomaly harness only; drift never silently repairs the freeze."""
        def mutate(doc):
            self._validate(source)
            old = next((s for s in doc['sources'] if s['object_key'] == source['object_key']), None)
            if old is None or source['version'] <= old['version']:
                raise ProtocolError('NON_MONOTONIC_SOURCE_WRITE')
            if not any(s['object_key'] == old['object_key'] and s['version'] == old['version']
                       for s in doc['source_history']):
                doc['source_history'].append(copy.deepcopy(old))
            doc['source_history'].append(copy.deepcopy(source))
            doc['sources'] = [copy.deepcopy(source) if s['object_key'] == source['object_key'] else s for s in doc['sources']]
            return {'source_update': source['object_key'], 'offline_harness_only': True}, None
        return self._apply(event_id, 'harness_source_update', {'source': source}, now_utc, mutate)
