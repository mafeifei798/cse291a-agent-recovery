"""SQLite acceptance boundary for V2 CPU workflows.

The current document and append-only command receipts are committed together.
Artifacts are immutable files staged before acceptance, not an assertion of a
filesystem/SQLite distributed transaction. This module has no network client.
"""
import copy
import hashlib
import json
import math
import sqlite3
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path

from sr_recovery_v2.common import (REV, ProtocolError, canonical, digest, source_fingerprint,
                     selected_graph_digest, closure_ids, node_map, utc_parse, utc_format)
from .guard import diagnose
from sr_recovery_v2.policy import advance


class V2Store:
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
                state = {'record_type': 'BranchState', 'revision': REV, 'fixture_only': False,
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
                    'attempts': [], 'plans': [], 'guards': [],
                    'effects': copy.deepcopy(initial.get('effects', [])),
                    'objects': copy.deepcopy(initial.get('objects', {})),
                    'last_guard': None, 'pending_decision': None, 'last_observed_utc': None,
                    'initial_snapshot': initial, 'prefix_digest': digest(initial),
                    'source_aliases': initial.get('source_aliases', task.get('resolved_source_aliases', {})),
                    'domain': initial.get('domain', 'micro' if 'read_metadata' in dag['topological_order'] else 'macro'),
                    'metadata': {'creation_digest': request_digest,
                        'initial_result_ids': [r['result_id'] for r in initial['results']],
                        'prefix_mode': initial.get('prefix_mode', 'transactional_CPU_initial_execution'),
                        'implementation': 'V2-CPU-r1', 'real_api_requests': 0,
                        'real_cost_nano_usd': 0, 'actual_training': 0,
                        'initial_mode': False},
                    'late_outputs': [], 'dispatch_payloads': []}
                refusal = initial.get('prefix_refusal')
                if refusal:
                    doc['guards'].append(copy.deepcopy(refusal))
                self.db.execute('INSERT INTO document VALUES(1,?)', (canonical(doc),))
        return self.snapshot()

    def create_initial(self, task, dag, sources, artifacts, input_producers, run_id,
                       source_history=None):
        """Bind a normal run before any node has executed, without a Notice.

        BranchState's frozen V0 shape requires a nonempty notice_id.  The
        reserved marker below is explicitly not a Notice and never reaches the
        recovery policy.  The envelope's notice is None.
        """
        request = {'task': task, 'dag': dag, 'sources': sources, 'artifacts': artifacts,
                   'input_producers': input_producers, 'run_id': run_id,
                   'source_history': source_history or []}
        creation_digest = digest(request)
        for row in sources + list(artifacts):
            self._validate(row)
        if len({s['object_key'] for s in sources}) != len(sources):
            raise ProtocolError('DUPLICATE_AUTHORITY_KEY')
        if any(digest(s['payload']) != s['payload_digest'] for s in sources):
            raise ProtocolError('SOURCE_PAYLOAD_DIGEST_MISMATCH')
        state = {'record_type': 'BranchState', 'revision': REV, 'fixture_only': False,
            'branch_id': run_id + '.initial', 'scene_id': run_id + '.prefix', 'run_id': run_id,
            'policy': 'FULL', 'state_version': 0, 'notice_id': 'initial-execution:no-notice',
            'stage': 'first', 'status': 'ready',
            'selected_by_node': {n: None for n in dag['topological_order']},
            'pending_node_ids': list(dag['topological_order']), 'invalidated_result_ids': [],
            'counters': {'stale_used': 0, 'semantic_used': 0, 'physical_calls': 0, 'cpu_jobs': 0},
            'stage_completed_node_ids': [], 'active_attempt_ids': [], 'unsettled_call_ids': [],
            'source_fingerprint': source_fingerprint(sources),
            'active_plan_id': 'initial-execution', 'terminal_status': None,
            'started_at_utc': None, 'deadline_utc': None}
        self._validate(state)
        doc = {'state': state, 'dag': copy.deepcopy(dag), 'task': copy.deepcopy(task),
            'notice': None, 'results': [], 'sources': copy.deepcopy(sources),
            'source_history': copy.deepcopy(source_history or sources),
            'artifacts': copy.deepcopy(artifacts), 'calls': [], 'tool_receipts': [],
            'input_producers': copy.deepcopy(input_producers), 'attempts': [], 'plans': [],
            'guards': [], 'effects': [], 'objects': {}, 'last_guard': None,
            'pending_decision': None, 'last_observed_utc': None,
            'initial_snapshot': copy.deepcopy(request), 'prefix_digest': digest(request),
            'source_aliases': copy.deepcopy(task.get('resolved_source_aliases', {})),
            'domain': 'macro', 'late_outputs': [], 'dispatch_payloads': [],
            'metadata': {'creation_digest': creation_digest, 'initial_result_ids': [],
                'prefix_mode': 'transactional_CPU_initial_execution',
                'implementation': 'V2-CPU-r1', 'initial_mode': True,
                'real_api_requests': 0, 'real_cost_nano_usd': 0, 'actual_training': 0}}
        with self._transaction():
            old = self.db.execute('SELECT payload FROM document WHERE id=1').fetchone()
            if old:
                if json.loads(old[0])['metadata']['creation_digest'] != creation_digest:
                    raise ProtocolError('STORE_ALREADY_BOUND')
            else:
                self.db.execute('INSERT INTO document VALUES(1,?)', (canonical(doc),))
        return self.snapshot()

    def initial_decision(self, event_id, now_utc):
        """Deterministic next-node request for the normal initial execution."""
        doc = self._load()
        if not doc['metadata'].get('initial_mode') or doc['notice'] is not None:
            raise ProtocolError('INITIAL_MODE_REQUIRED')
        state = doc['state']
        if state['status'] != 'running' or state['active_attempt_ids']:
            raise ProtocolError('INITIAL_RUN_NOT_READY')
        if doc['pending_decision'] is not None:
            return copy.deepcopy(doc['pending_decision'])
        if doc['last_guard'] and doc['last_guard']['classification'] != 'passed':
            raise ProtocolError('INITIAL_REFUSAL_REQUIRES_FREEZE')
        if not state['pending_node_ids']:
            raise ProtocolError('INITIAL_RUN_ALREADY_COMPLETE')
        node_id = state['pending_node_ids'][0]
        parents = [state['selected_by_node'][n] for n in node_map(doc['dag'])[node_id]['parents']]
        if any(r is None for r in parents):
            raise ProtocolError('INITIAL_PARENT_NOT_SELECTED')
        output = {'record_type': 'AdvanceOutput', 'revision': REV, 'fixture_only': False,
            'decision_id': 'v2.initial.decision.' + digest({'branch': state['branch_id'],
                'event': event_id, 'version': state['state_version'], 'node': node_id})[:24],
            'event_id': event_id, 'branch_id': state['branch_id'],
            'expected_state_version': state['state_version'], 'kind': 'execute_node',
            'node_id': node_id, 'parent_result_ids': parents,
            'ordered_node_ids': [], 'carried_pending_node_ids': [], 'guard_id': None,
            'correction_kind': None, 'source_fingerprint': state['source_fingerprint'],
            'reason_codes': ['NORMAL_INITIAL_EXECUTION'], 'terminal_status': None}
        self._validate(output)
        return output

    def freeze_prefix(self, notice, updated_sources, event_id, now_utc):
        """Freeze a refused initial run and its admitted source changes once.

        The returned scene contains every actual prefix attempt and event.  A
        recovery create() resets only recovery counters, never prefix evidence.
        """
        self._validate(notice)
        def mutate(doc):
            state = doc['state']
            if not doc['metadata'].get('initial_mode'):
                raise ProtocolError('INITIAL_MODE_REQUIRED')
            if state['active_attempt_ids'] or state['unsettled_call_ids'] or doc['pending_decision']:
                raise ProtocolError('ACTIVE_OR_UNSETTLED_WORK')
            refusal = doc['last_guard']
            if not refusal or refusal['checkpoint'] != 'precommit' or refusal['classification'] != 'semantic':
                raise ProtocolError('PREFIX_BUSINESS_REFUSAL_REQUIRED')
            if notice['run_id'] != state['run_id'] or notice['faulty_result_id'] not in {r['result_id'] for r in doc['results']}:
                raise ProtocolError('NOTICE_PREFIX_BINDING_MISMATCH')
            current = {s['object_key']: copy.deepcopy(s) for s in doc['sources']}
            for source in updated_sources:
                self._validate(source)
                old = current.get(source['object_key'])
                if old is None or digest(source['payload']) != source['payload_digest']:
                    raise ProtocolError('INVALID_FREEZE_SOURCE')
                if source != old and source['version'] <= old['version']:
                    raise ProtocolError('NON_MONOTONIC_SOURCE_WRITE')
                if source != old:
                    doc['source_history'].append(copy.deepcopy(source))
                current[source['object_key']] = copy.deepcopy(source)
            doc['sources'] = [current[s['object_key']] for s in doc['sources']]
            doc['notice'] = copy.deepcopy(notice)
            state['notice_id'] = notice['notice_id']
            state['source_fingerprint'] = source_fingerprint(doc['sources'])
            state['status'] = 'paused'
            doc['metadata']['initial_mode'] = False
            doc['metadata']['prefix_frozen'] = True
            return {'notice_id': notice['notice_id'], 'initial_results_preserved': len(doc['results']),
                    'frozen_source_fingerprint': state['source_fingerprint']}, None
        self._apply(event_id, 'freeze_prefix', {'notice': notice, 'updated_sources': updated_sources},
                    now_utc, mutate)
        doc = self.export()
        return {'task': doc['task'], 'results': doc['results'],
            'tool_receipts': doc['tool_receipts'], 'call_evidence': doc['calls'],
            'source_history': doc['source_history'], 'current_sources': doc['sources'],
            'artifact_manifest': doc['artifacts'], 'input_producers': doc['input_producers'],
            'notice': doc['notice'], 'prefix_refusal': next(g for g in reversed(doc['guards'])
                if g['checkpoint'] == 'precommit' and g['classification'] == 'semantic'),
            'attempts': doc['attempts'], 'initial_events': doc['events'],
            'initial_guards': doc['guards'], 'source_aliases': doc['source_aliases'],
            'effects': doc['effects'], 'objects': doc['objects'], 'domain': 'macro',
            'prefix_mode': 'transactional_CPU_initial_execution',
            'run_state': {'run_id': doc['state']['run_id'], 'scene_id': doc['state']['scene_id'],
                'task_id': doc['task']['task_id'], 'lifecycle': 'frozen_recoverable',
                'selected_by_node': doc['state']['selected_by_node'],
                'active_attempt_ids': [], 'unsettled_call_ids': [],
                'business_effects': doc['effects'], 'failed_candidate_result_ids': [
                    r['result_id'] for r in doc['results'] if r['execution_status'] != 'success']}}

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
        if doc['metadata'].get('initial_mode'):
            if guard is not None:
                if (guard not in doc['guards'] or guard['classification'] != 'passed' or
                        guard['node_id'] != output['node_id'] or guard['checkpoint'] != 'pre_dispatch'):
                    raise ProtocolError('INVALID_INITIAL_DISPATCH_GUARD')
                if (guard['selected_graph_digest'] != selected_graph_digest(doc['state']['selected_by_node'], doc['results']) or
                        guard['source_fingerprint'] != source_fingerprint(doc['sources'])):
                    raise ProtocolError('INITIAL_GUARD_BINDING_MISMATCH')
            if output != self.initial_decision(output['event_id'], now):
                raise ProtocolError('INITIAL_DECISION_MISMATCH')
            return
        if guard is not None:
            if not any(g == guard for g in doc['guards']):
                raise ProtocolError('UNPERSISTED_GUARD')
            if guard['selected_graph_digest'] != selected_graph_digest(doc['state']['selected_by_node'], doc['results']):
                raise ProtocolError('GUARD_GRAPH_BINDING_MISMATCH')
        from sr_recovery_v2.runner import advance_input
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
                    state['active_plan_id'] = 'v2.initial.' + output['decision_id']
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
                plan = {'record_type': 'CorrectionPlan', 'revision': REV, 'fixture_only': False,
                    'plan_id': 'v2.plan.' + output['decision_id'], 'branch_id': state['branch_id'],
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
            aid = 'v2.attempt.' + digest({'branch_id': state['branch_id'], 'decision': decision['decision_id']})[:32]
            attempt = {'attempt_id': aid, 'node_id': node_id, 'stage': state['stage'],
                'plan_id': state['active_plan_id'], 'decision_id': decision['decision_id'], 'status': 'running',
                'started_at_utc': now_utc, 'finished_at_utc': None, 'result_id': None, 'input_digest': None,
                'dispatch_id': event_id, 'counter_llm': node['llm_calls_per_execution'],
                'counter_cpu': node['cpu_jobs_per_execution'],
                'worker_reaped': not bool(node['cpu_jobs_per_execution']),
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

    def record_worker_started(self, attempt_id, job_identity, event_id, now_utc):
        """Durably bind a spawned CPU process before the executor monitors it.

        PID alone is insufficient after a restart because the OS may reuse it.
        The kernel start tick and immutable specification path identify the
        admitted worker.  This method neither signals nor waits for a process;
        the executor must reap a spawned worker if this admission fails.
        """
        identity = copy.deepcopy(job_identity)
        required = {'job_id', 'pid', 'pgid', 'process_start_ticks', 'spec_path', 'started_at_utc'}
        if not isinstance(identity, dict) or not required <= identity.keys():
            raise ProtocolError('WORKER_IDENTITY_REQUIRED')
        if (not isinstance(identity['job_id'], str) or not identity['job_id'] or
                any(isinstance(identity[k], bool) or not isinstance(identity[k], int) or identity[k] <= 0
                    for k in ('pid', 'pgid', 'process_start_ticks')) or
                not isinstance(identity['spec_path'], str) or not Path(identity['spec_path']).is_absolute() or
                not isinstance(identity['started_at_utc'], str)):
            raise ProtocolError('WORKER_IDENTITY_INVALID')
        try:
            started = utc_parse(identity['started_at_utc'])
            observed = utc_parse(now_utc)
        except (TypeError, ValueError) as exc:
            raise ProtocolError('WORKER_CLOCK_INVALID') from exc
        if started > observed:
            raise ProtocolError('WORKER_CLOCK_INVALID')

        def mutate(doc):
            state = doc['state']
            attempt = next((a for a in doc['attempts'] if a['attempt_id'] == attempt_id), None)
            if not attempt or attempt['status'] != 'running' or attempt_id not in state['active_attempt_ids']:
                raise ProtocolError('WORKER_ACTIVE_ATTEMPT_REQUIRED')
            if not attempt['counter_cpu']:
                raise ProtocolError('WORKER_CPU_ATTEMPT_REQUIRED')
            if started < utc_parse(attempt['started_at_utc']):
                raise ProtocolError('WORKER_CLOCK_INVALID')
            if utc_parse(now_utc) >= utc_parse(attempt['deadline_utc']):
                raise ProtocolError('WORKER_STARTED_AFTER_DEADLINE')
            old = attempt.get('worker_identity')
            if old is not None and old != identity:
                raise ProtocolError('WORKER_IDENTITY_REBOUND')
            if any(a['attempt_id'] != attempt_id and a.get('worker_identity', {}).get('pid') == identity['pid'] and
                   a.get('worker_identity', {}).get('process_start_ticks') == identity['process_start_ticks']
                   for a in doc['attempts']):
                raise ProtocolError('WORKER_ALREADY_BOUND')
            attempt['worker_identity'] = copy.deepcopy(identity)
            attempt['worker_reaped'] = False
            return {'attempt_id': attempt_id, 'worker_identity': identity, 'identity_already_bound': old is not None}, {
                'attempt_id': attempt_id, 'worker_identity': identity}
        return self._apply(event_id, 'worker_started', {'attempt_id': attempt_id, 'job_identity': identity},
                           now_utc, mutate)

    def _stage_artifacts(self, package):
        for art in package.get('artifacts', []):
            self._validate(art)
            if art['size_bytes'] > 134217728:
                raise ProtocolError('ARTIFACT_SIZE_LIMIT')
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
            execution = package.get('job_execution')
            if attempt['counter_cpu']:
                if result.get('fixture_only') is not False:
                    raise ProtocolError('REAL_CPU_RESULT_REQUIRED')
                required = {'job_id', 'tool', 'pid', 'pgid', 'started_at_utc', 'finished_at_utc',
                    'deadline_utc', 'effective_timeout_seconds', 'status', 'returncode',
                    'worker_reaped', 'timed_out', 'peak_rss_bytes', 'cpu_seconds', 'wall_seconds',
                    'output_bytes', 'signal', 'termination', 'limits', 'source_sha256'}
                if not isinstance(execution, dict) or not required <= execution.keys():
                    raise ProtocolError('RESOURCE_EXECUTION_RECEIPT_REQUIRED')
                if execution['deadline_utc'] != attempt['deadline_utc']:
                    raise ProtocolError('EXECUTION_DEADLINE_BINDING_MISMATCH')
                if (utc_parse(execution['started_at_utc']) < utc_parse(attempt['started_at_utc']) or
                        utc_parse(execution['finished_at_utc']) < utc_parse(execution['started_at_utc']) or
                        utc_parse(execution['finished_at_utc']) > utc_parse(now_utc)):
                    raise ProtocolError('EXECUTION_CLOCK_BINDING_MISMATCH')
                if execution['effective_timeout_seconds'] > 120 or execution['effective_timeout_seconds'] < 0:
                    raise ProtocolError('EXECUTION_TIMEOUT_LIMIT_INVALID')
                limits = execution['limits']
                expected_limits = {'address_space_bytes': 8589934592,
                    'rss_monitor_bytes': 8589934592, 'max_artifact_bytes': 134217728,
                    'total_disk_bytes': 4294967296}
                if limits != expected_limits:
                    raise ProtocolError('EXECUTION_LIMITS_MISMATCH')
                worker_identity = attempt.get('worker_identity')
                if worker_identity is None and execution['status'] == 'success':
                    raise ProtocolError('EXECUTION_WORKER_BINDING_REQUIRED')
                if worker_identity is not None and any(execution.get(k) != worker_identity[k]
                        for k in ('job_id', 'pid', 'pgid', 'started_at_utc')):
                    raise ProtocolError('EXECUTION_WORKER_BINDING_MISMATCH')
                measurements = ('effective_timeout_seconds', 'peak_rss_bytes', 'cpu_seconds',
                                'wall_seconds', 'output_bytes')
                if any(isinstance(execution[k], bool) or not isinstance(execution[k], (int, float)) or
                       not math.isfinite(execution[k]) or execution[k] < 0 for k in measurements):
                    raise ProtocolError('EXECUTION_MEASUREMENTS_INVALID')
                if (execution['status'] not in ('success', 'failed', 'timeout', 'memory_exceeded', 'disk_exceeded', 'uncertain') or
                        not isinstance(execution['worker_reaped'], bool) or not isinstance(execution['timed_out'], bool) or
                        any(isinstance(execution[k], bool) or not isinstance(execution[k], int) or execution[k] <= 0 for k in ('pid', 'pgid')) or
                        not isinstance(execution['source_sha256'], str) or len(execution['source_sha256']) != 64 or
                        any(c not in '0123456789abcdef' for c in execution['source_sha256'])):
                    raise ProtocolError('EXECUTION_IDENTITY_INVALID')
                if any(r.get('fixture_only') is not False or r.get('parameters', {}).get('execution') != execution
                       for r in package.get('tool_receipts', [])):
                    raise ProtocolError('REAL_TOOL_EXECUTION_BINDING_REQUIRED')
                attempt['worker_reaped'] = bool(execution['worker_reaped'])
                attempt['job_execution'] = copy.deepcopy(execution)
                resource_failed = (execution['status'] != 'success' or execution['returncode'] != 0 or
                    not execution['worker_reaped'] or execution['timed_out'] or
                    execution['peak_rss_bytes'] > 8589934592 or
                    execution['output_bytes'] > 4294967296 or
                    execution['wall_seconds'] > execution['effective_timeout_seconds'])
                if resource_failed:
                    result['execution_status'] = 'uncertain'
            else:
                if execution is not None:
                    raise ProtocolError('UNEXPECTED_CPU_EXECUTION')
                resource_failed = False
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
                if resource_failed:
                    state.update(status='terminal', terminal_status='uncertain')
            else:
                state['selected_by_node'][result['node_id']] = result['result_id']
                state['pending_node_ids'] = [n for n in state['pending_node_ids'] if n != result['node_id']]
                state['stage_completed_node_ids'].append(result['node_id'])
                doc['last_guard'] = None
                if final:
                    self._publish(doc, result)
                    state.update(status='terminal', terminal_status='completed_correct')
                doc['guards'].append(guard)
                if result['node_id'] in ('fit_lr', 'fit_rf'):
                    doc['metadata']['actual_training'] += 1
            return ({'attempt_id': attempt_id, 'raw_candidate': package['result'],
                    'guard_id': guard['guard_id'], 'classification': guard['classification']},
                    {'result': result, 'guard': guard, 'state': state, 'late': False})
        return self._apply('v2.finish.' + attempt_id, 'settle', {'attempt_id': attempt_id, 'package': persisted_package},
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
        doc['effects'].append({'effect_id': 'v2.effect.' + result['result_id'], 'producer_result_id': result['result_id'],
            'operation_id': 'v2.operation.' + result['attempt_id'], 'before': before, 'after': after,
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
