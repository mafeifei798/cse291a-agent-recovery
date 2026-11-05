"""One authoritative durable acceptance kernel for every offline policy.

The SQLite document, dispatch outbox, raw settlement, guard, selected result,
publication effects and hash-chained command receipt change in one transaction.
Artifact bytes are staged immutably before that transaction; they are not business
state and a rejected/rolled-back attempt may leave inspectable orphan bytes.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import sqlite3

from sr_recovery_v2.common import (REV, ProtocolError, canonical, digest,
    source_fingerprint, closure_ids, node_map, utc_parse, utc_format)
from sr_recovery_v2.fake import input_projection
from sr_recovery_v2.guard import diagnose
from sr_recovery_v2.store import V1Store
from .guards import GuardDispatcher

PROTOCOL = 'phase2-unified-durable-kernel-v1'
GENESIS = '0' * 64


class DurableKernel:
    """Single writer, FULL-synchronous SQLite; no network or estimator imports."""
    def __init__(self, db_path, artifact_root, *, failpoint=None, artifact_mode='fixture'):
        dispatcher=GuardDispatcher(artifact_mode)
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.artifact_root = Path(artifact_root).resolve()
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        if self.db_path.is_symlink() or Path(artifact_root).is_symlink():
            raise ProtocolError('KERNEL_SYMLINK_FORBIDDEN')
        self.db = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        self.db.execute('PRAGMA journal_mode=DELETE')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS document(id INTEGER PRIMARY KEY CHECK(id=1),payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS commands(seq INTEGER PRIMARY KEY AUTOINCREMENT,
              event_id TEXT UNIQUE NOT NULL,kind TEXT NOT NULL,command_digest TEXT NOT NULL,
              payload TEXT NOT NULL,before_digest TEXT NOT NULL,after_digest TEXT NOT NULL,
              previous_hash TEXT NOT NULL,command_hash TEXT NOT NULL,response TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS dispatches(attempt_id TEXT PRIMARY KEY,node_id TEXT NOT NULL,
              phase TEXT NOT NULL,input_digest TEXT NOT NULL,status TEXT NOT NULL,intent TEXT NOT NULL,
              settlement TEXT,selected INTEGER NOT NULL DEFAULT 0);
        ''')
        self.failpoint = failpoint
        self.artifact_mode=artifact_mode
        self._diagnose=dispatcher
        old=self.db.execute('SELECT payload FROM document WHERE id=1').fetchone()
        if old and json.loads(old[0]).get('metadata',{}).get('guard_artifact_mode')!=artifact_mode:
            self.db.close()
            raise ProtocolError('KERNEL_ARTIFACT_MODE_IMMUTABLE')

    def __enter__(self): return self
    def __exit__(self, *args): self.close()
    def close(self): self.db.close()

    @contextmanager
    def transaction(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            raise

    def snapshot(self):
        row = self.db.execute('SELECT payload FROM document WHERE id=1').fetchone()
        if row is None: raise ProtocolError('KERNEL_NOT_CREATED')
        return json.loads(row[0])

    def _validate(self, value):
        return V1Store._validate(self, value)

    def _save(self, doc):
        self.db.execute('UPDATE document SET payload=? WHERE id=1', (canonical(doc),))

    def _apply(self, event_id, kind, payload, mutation):
        envelope = {'kind': kind, 'payload': payload}
        command_digest = digest(envelope)
        with self.transaction():
            old = self.db.execute('SELECT command_digest,response FROM commands WHERE event_id=?', (event_id,)).fetchone()
            if old:
                if old[0] != command_digest: raise ProtocolError('IDEMPOTENCY_PAYLOAD_MISMATCH')
                return json.loads(old[1])
            doc = self.snapshot(); before = digest(doc)
            response = mutation(doc)
            doc['state']['state_version'] += 1
            self._save(doc)
            after = digest(doc)
            last = self.db.execute('SELECT command_hash FROM commands ORDER BY seq DESC LIMIT 1').fetchone()
            previous = last[0] if last else GENESIS
            chain = {'event_id': event_id, 'kind': kind, 'command_digest': command_digest,
                'payload': payload, 'before_digest': before, 'after_digest': after,
                'previous_hash': previous, 'response': response}
            command_hash = digest(chain)
            self.db.execute('INSERT INTO commands(event_id,kind,command_digest,payload,before_digest,after_digest,previous_hash,command_hash,response) VALUES(?,?,?,?,?,?,?,?,?)',
                (event_id, kind, command_digest, canonical(payload), before, after,
                 previous, command_hash, canonical(response)))
            if self.failpoint: self.failpoint(kind, deepcopy(doc))
            return deepcopy(response)

    def create(self, scene, dag, row, now_utc):
        binding = digest({'scene': scene, 'dag': dag, 'row': row,'artifact_mode':self.artifact_mode})
        with self.transaction():
            old = self.db.execute('SELECT payload FROM document WHERE id=1').fetchone()
            if old:
                if json.loads(old[0])['metadata']['creation_digest'] != binding:
                    raise ProtocolError('KERNEL_ALREADY_BOUND')
                return self.snapshot()
            run = scene['run_state']; inherited = [r['result_id'] for r in scene['results']]
            state = {'record_type': 'BranchState', 'revision': REV, 'fixture_only': True,
                'branch_id': row['row_id'], 'run_id': run['run_id'], 'scene_id': run['scene_id'],
                'policy': row['strategy'], 'state_version': 0, 'stage': 'initial', 'status': 'running',
                'terminal_status': None, 'selected_by_node': deepcopy(run['selected_by_node']),
                'invalidated_result_ids': [], 'active_attempt_ids': [], 'unsettled_call_ids': [],
                'source_fingerprint': source_fingerprint(scene['current_sources']),
                'started_at_utc': now_utc, 'deadline_utc': utc_format(utc_parse(now_utc) + timedelta(seconds=row.get('fixed_deadline_seconds', 1800))),
                'counters': {'physical_calls': 0, 'cpu_jobs': 0, 'semantic_used': 0, 'stale_used': 0}}
            published = scene.get('published_state', {})
            doc = {'state': state, 'dag': deepcopy(dag), 'task': deepcopy(scene['task']),
                'results': deepcopy(scene['results']), 'sources': deepcopy(scene['current_sources']),
                'source_history': deepcopy(scene['source_history']), 'artifacts': deepcopy(scene['artifact_manifest']),
                'calls': deepcopy(scene['call_evidence']), 'tool_receipts': deepcopy(scene['tool_receipts']),
                'source_aliases': deepcopy(scene.get('source_aliases', {})), 'domain': scene.get('domain', 'macro'),
                'input_producers': deepcopy(scene.get('input_producers', [])), 'attempts': [], 'guards': [],
                'effects': deepcopy(published.get('effects', [])), 'objects': deepcopy(published.get('objects', {})),
                'plans': [], 'late_outputs': [], 'error': None, 'notice': deepcopy(scene.get('notice')),
                'supplement_evidence': deepcopy(scene.get('supplement_evidence', {})),
                'metadata': {'implementation': PROTOCOL, 'creation_digest': binding,
                    'fixture_only': True, 'initial_result_ids': inherited,
                    'evaluation_binding': deepcopy(scene['evaluation_binding']),
                    'actual_training': 0, 'actual_model_prediction': 0, 'real_api_requests': 0,
                    'same_durability_for_all_methods': True, 'synchronous': 'FULL', 'journal_mode': 'DELETE',
                    'guard_artifact_mode':self.artifact_mode,'scientific_execution_evaluated':False},
                'phase2_row': deepcopy(row), 'phase2_pack_sha256': scene['evaluation_binding']['pack_sha256'],
                'fixture_only': True, 'prefix_digest': digest(scene) if inherited else None,
                'initial_snapshot': deepcopy(scene)}
            if scene.get('prefix_refusal'): doc['guards'].append(deepcopy(scene['prefix_refusal']))
            self.db.execute('INSERT INTO document VALUES(1,?)', (canonical(doc),))
        self._apply(row['row_id'] + '.create', 'create', {'creation_digest': binding}, lambda d: {'creation_digest': binding})
        return self.snapshot()

    def check(self, node_id, *, checkpoint='pre_dispatch', full=False, candidate=None):
        """Guard observation itself is durably recorded; never a selection write."""
        view = self.snapshot()
        guard = self._diagnose(view, node_id, checkpoint=checkpoint, candidate=candidate,
                         full=full, artifact_root=self.artifact_root)
        event_id = self._event_id('guard', guard['guard_id'])
        self._apply(event_id, 'guard', {'guard': guard},
            lambda doc: self._guard_mutation(doc, guard))
        return guard

    @staticmethod
    def _guard_mutation(doc, guard):
        if not any(g['guard_id'] == guard['guard_id'] for g in doc['guards']):
            doc['guards'].append(deepcopy(guard))
        return {'guard_id': guard['guard_id'], 'classification': guard['classification']}

    @staticmethod
    def _event_id(kind, identity): return 'unified.' + kind + '.' + identity

    def start_node(self, node_id, phase, event_id, now_utc):
        def mutate(doc):
            state = doc['state']
            if state['status'] != 'running': raise ProtocolError('KERNEL_NOT_RUNNING')
            if state['active_attempt_ids'] or state['unsettled_call_ids']:
                raise ProtocolError('ACTIVE_OR_UNKNOWN_DISPATCH_FORBIDS_RETRY')
            if utc_parse(now_utc) >= utc_parse(state['deadline_utc']):
                raise ProtocolError('FIXED_DEADLINE_EXPIRED')
            node = node_map(doc['dag'])[node_id]
            if state['selected_by_node'].get(node_id): raise ProtocolError('NODE_ALREADY_SELECTED')
            guard = self._diagnose(doc, node_id, artifact_root=self.artifact_root)
            if guard['classification'] != 'passed': raise ProtocolError('DISPATCH_GUARD_REFUSED')
            snap,trusted_artifacts = self._diagnose.project(doc,node_id,self.artifact_root)
            aid = 'unified.attempt.' + digest({'row': state['branch_id'], 'event': event_id})[:32]
            intent = {'attempt_id': aid, 'node_id': node_id, 'phase': phase, 'input_digest': digest(snap),
                'input_snapshot': snap,'trusted_artifact_bindings':deepcopy(trusted_artifacts), 'expected_parent_result_ids': [state['selected_by_node'][p] for p in node['parents']],
                'expected_llm': node['llm_calls_per_execution'], 'expected_cpu': node['cpu_jobs_per_execution'],
                'status': 'intent_persisted', 'dispatch_id': event_id,
                'started_at_utc': now_utc, 'deadline_utc': utc_format(min(utc_parse(state['deadline_utc']), utc_parse(now_utc)+timedelta(seconds=120)))}
            if node_id == 'publish': intent['target_before'] = {key: deepcopy(doc['objects'].get(key)) for key in ('manifest', 'report_index')}
            attempt = {**deepcopy(intent), 'counter_llm': 0, 'counter_cpu': 0, 'worker_reaped': True,
                'result_id': None, 'finished_at_utc': None, 'late': False, 'stage': phase}
            doc['attempts'].append(attempt); state['active_attempt_ids'].append(aid)
            self.db.execute('INSERT INTO dispatches VALUES(?,?,?,?,?,?,NULL,0)',
                (aid, node_id, phase, intent['input_digest'], 'intent_persisted', canonical(intent)))
            return deepcopy(attempt)
        return self._apply(event_id, 'dispatch_intent', {'node_id': node_id, 'phase': phase, 'now_utc': now_utc}, mutate)

    @staticmethod
    def _budget_binding(event, attempt, row_id, stage):
        expected={'stage':stage,'call_id':attempt['attempt_id']+'.call',
            'row_id':row_id,'node_id':attempt['node_id'],'attempt_id':attempt['attempt_id'],
            'input_digest':attempt['input_digest'],'fixture_only':True,
            'request_sent':False,'real_api_requests':0}
        if not isinstance(event,dict) or any(event.get(k)!=v for k,v in expected.items()):
            raise ProtocolError('BUDGET_EVENT_BINDING_MISMATCH')
        usage=event.get('usage')
        if stage=='after' and event.get('status')=='completed':
            if not isinstance(usage,dict) or any(type(usage.get(k)) is not int or usage[k]<0
                    for k in ('prompt_tokens','completion_tokens','total_tokens')) or \
                    usage['total_tokens'] != usage['prompt_tokens']+usage['completion_tokens']:
                raise ProtocolError('BUDGET_USAGE_INVALID')

    def mark_dispatched(self, attempt_id, reservation, now_utc):
        def mutate(doc):
            attempt = next(a for a in doc['attempts'] if a['attempt_id'] == attempt_id)
            if attempt['status'] != 'intent_persisted': raise ProtocolError('DISPATCH_INTENT_NOT_READY')
            if utc_parse(now_utc) >= utc_parse(attempt['deadline_utc']): raise ProtocolError('FIXED_DEADLINE_EXPIRED')
            if attempt['expected_llm'] and (not isinstance(reservation, dict) or reservation.get('stage') != 'before'
                  or reservation.get('call_id') != attempt_id + '.call'):
                raise ProtocolError('BUDGET_RESERVATION_REQUIRED')
            if attempt['expected_llm']:
                self._budget_binding(reservation,attempt,doc['state']['branch_id'],'before')
            if reservation and (reservation.get('request_sent') or reservation.get('real_api_requests', 0)):
                raise ProtocolError('REAL_CLIENT_FORBIDDEN')
            attempt.update(status='dispatched', counter_llm=attempt['expected_llm'], counter_cpu=attempt['expected_cpu'])
            state = doc['state']; state['counters']['physical_calls'] += attempt['counter_llm']; state['counters']['cpu_jobs'] += attempt['counter_cpu']
            if attempt['counter_llm']: state['unsettled_call_ids'].append(attempt_id + '.call')
            self.db.execute('UPDATE dispatches SET status=? WHERE attempt_id=?', ('dispatched', attempt_id))
            return {'attempt_id': attempt_id, 'dispatched': True}
        return self._apply(self._event_id('sent', attempt_id), 'dispatch_started',
            {'attempt_id': attempt_id, 'reservation': reservation, 'now_utc': now_utc}, mutate)

    def _stage_artifacts(self, package):
        for art in package.get('artifacts', []):
            self._validate(art)
            target = self.artifact_root / art['uri']
            if target.is_symlink() or any(p.is_symlink() for p in target.parents if p != self.artifact_root.parent):
                raise ProtocolError('ARTIFACT_SYMLINK_FORBIDDEN')
            if not target.resolve().is_relative_to(self.artifact_root): raise ProtocolError('ARTIFACT_PATH_ESCAPE')
            data = package.get('artifact_contents', {}).get(art['artifact_id'])
            if data is None: data = target.read_bytes()
            if len(data) != art['size_bytes'] or hashlib.sha256(data).hexdigest() != art['sha256']:
                raise ProtocolError('ARTIFACT_HASH_MISMATCH')
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                with target.open('xb') as handle:
                    handle.write(data); handle.flush(); os.fsync(handle.fileno())
            except FileExistsError:
                if target.read_bytes() != data: raise ProtocolError('IMMUTABLE_ARTIFACT_REWRITE')
            target.chmod(0o444)

    def finish_node(self, attempt_id, package, now_utc, *, budget_settlement=None,
                    verify=False, forced_unknown=False, forced_late=False, evidence=None, cpu_evidence=None):
        self._stage_artifacts(package)
        persisted = {k: deepcopy(v) for k, v in package.items() if k != 'artifact_contents'}
        command = {'attempt_id': attempt_id, 'package': persisted, 'now_utc': now_utc,
            'budget_settlement': budget_settlement, 'verify': verify,
            'forced_unknown': forced_unknown, 'forced_late': forced_late, 'evidence': evidence, 'cpu_evidence': cpu_evidence}
        def mutate(doc):
            state = doc['state']; attempt = next((a for a in doc['attempts'] if a['attempt_id']==attempt_id), None)
            if attempt is None or attempt['status'] != 'dispatched': raise ProtocolError('ATTEMPT_NOT_DISPATCHED')
            result = deepcopy(package['result']); self._validate(result)
            if attempt['counter_cpu'] and cpu_evidence is not None:
                spec=cpu_evidence.get('spec',{}); receipt=cpu_evidence.get('receipt',{})
                if spec.get('attempt_id')!=attempt_id or spec.get('node_id')!=attempt['node_id'] or spec.get('input_digest')!=attempt['input_digest'] or \
                        receipt.get('spec_sha256')!=spec.get('spec_sha256') or receipt.get('payload')!=result['payload'] or \
                        receipt.get('artifacts')!=package['artifacts'] or receipt.get('settled') is not True or receipt.get('status')!='success':
                    raise ProtocolError('CPU_GATEWAY_SETTLEMENT_BINDING_MISMATCH')
                doc.setdefault('cpu_gateway_receipts',[]).append(deepcopy(cpu_evidence))
            if any(result.get(k) != v for k,v in (('attempt_id', attempt_id), ('node_id', attempt['node_id']), ('run_id', state['run_id']), ('input_digest', attempt['input_digest']))):
                raise ProtocolError('RESULT_IDENTITY_OR_INPUT_MISMATCH')
            if result['input_snapshot'] != attempt['input_snapshot'] or result['parent_result_ids'] != attempt['expected_parent_result_ids']:
                raise ProtocolError('RESULT_PARENT_OR_SNAPSHOT_MISMATCH')
            if any(r['result_id']==result['result_id'] for r in doc['results']): raise ProtocolError('DUPLICATE_RESULT_ID')
            if any(c.get('request_sent') or c.get('cost_nano_usd', 0) or c.get('mode') not in ('fixture','fake_http') or not c.get('fixture_only') for c in package.get('calls', [])):
                raise ProtocolError('REAL_CLIENT_FORBIDDEN')
            if len(package.get('calls', [])) != attempt['counter_llm'] or len(package.get('tool_receipts', [])) != attempt['counter_cpu']:
                raise ProtocolError('DISPATCH_EVIDENCE_COUNT_MISMATCH')
            if result['call_ids'] != [c['call_id'] for c in package.get('calls', [])] or result['tool_receipt_ids'] != [r['receipt_id'] for r in package.get('tool_receipts', [])]:
                raise ProtocolError('RESULT_EVIDENCE_IDS_MISMATCH')
            unknown = forced_unknown or any(c['status'] != 'completed' for c in package.get('calls', []))
            if attempt['counter_llm']:
                if not isinstance(budget_settlement, dict) or budget_settlement.get('stage') != 'after' or budget_settlement.get('call_id') != attempt_id + '.call':
                    raise ProtocolError('BUDGET_SETTLEMENT_BEFORE_ACCEPTANCE_REQUIRED')
                self._budget_binding(budget_settlement,attempt,state['branch_id'],'after')
                if budget_settlement.get('status') != 'completed' or budget_settlement.get('usage') is None: unknown = True
            late = forced_late or utc_parse(now_utc) >= utc_parse(attempt['deadline_utc']) or state['status'] == 'terminal'
            for name, key in (('calls','call_id'), ('tool_receipts','receipt_id'), ('artifacts','artifact_id')):
                values = deepcopy(package.get(name, [])); old_ids = {v[key] for v in doc[name]}
                if len({v[key] for v in values}) != len(values) or any(v[key] in old_ids for v in values): raise ProtocolError('EVIDENCE_ID_REBOUND')
                for value in values: self._validate(value)
                if name=='calls' and unknown:
                    for value in values: value.update(status='uncertain', usage=None)
                doc[name].extend(values)
            if any(r.get('exit_code') != 0 for r in package.get('tool_receipts',[])):
                result['execution_status']='uncertain'
            guard = None
            if unknown or late:
                result['execution_status'] = 'uncertain' if unknown else 'cancelled'
                doc['late_outputs'].append({'attempt_id': attempt_id, 'raw_result': deepcopy(package['result']),
                    'observed_at_utc': now_utc, 'accepted': False, 'unknown_usage': unknown})
            else:
                checkpoint = 'precommit' if verify or result['node_id']=='publish' else 'post_tool'
                guard = self._diagnose(doc, result['node_id'], checkpoint, candidate=result,
                    full=result['node_id']=='publish', artifact_root=self.artifact_root)
                if guard['classification'] != 'passed': result['execution_status'] = 'validation_rejected'
            doc['results'].append(result)
            if guard and guard['classification'] != 'passed':
                guard = self._diagnose(doc, result['node_id'], guard['checkpoint'], candidate=result,
                    full=result['node_id']=='publish', artifact_root=self.artifact_root)
            accepted = bool(guard and guard['classification']=='passed' and result['execution_status']=='success')
            if guard: doc['guards'].append(guard)
            if accepted:
                state['selected_by_node'][result['node_id']] = result['result_id']
                if result['node_id']=='publish': V1Store._publish(doc, result)
            attempt.update(status='uncertain' if unknown else 'late_ignored' if late else 'completed' if accepted else 'validation_rejected',
                result_id=result['result_id'], finished_at_utc=now_utc, late=late)
            state['active_attempt_ids'].remove(attempt_id)
            if attempt['counter_llm'] and not unknown: state['unsettled_call_ids'].remove(attempt_id+'.call')
            if evidence is not None: doc['supplement_evidence'] = deepcopy(evidence)
            settlement = {'raw_package': persisted, 'budget_settlement': deepcopy(budget_settlement),
                'guard': guard, 'result_id': result['result_id'], 'accepted': accepted, 'unknown_usage': unknown,
                'late': late, 'observed_at_utc': now_utc}
            self.db.execute('UPDATE dispatches SET status=?,settlement=?,selected=? WHERE attempt_id=?',
                (attempt['status'], canonical(settlement), int(accepted), attempt_id))
            return {'attempt_id': attempt_id, 'result': deepcopy(result), 'guard': guard,
                    'accepted': accepted, 'unknown_usage': unknown, 'late': late}
        return self._apply(self._event_id('settle', attempt_id), 'settle', command, mutate)

    def abandon(self, attempt_id, code, *, unknown=False, raw_package=None, cpu_evidence=None):
        def mutate(doc):
            attempt = next(a for a in doc['attempts'] if a['attempt_id']==attempt_id)
            if attempt['status'] not in ('intent_persisted','dispatched'): raise ProtocolError('ATTEMPT_ALREADY_SETTLED')
            is_unknown = unknown or (attempt['status']=='dispatched' and bool(attempt['counter_llm']))
            was_dispatched=attempt['status']=='dispatched'
            attempt['status'] = 'uncertain' if is_unknown else 'integrity_rejected' if was_dispatched else 'not_dispatched'
            if raw_package is not None:
                doc.setdefault('rejected_raw_candidates',[]).append({'attempt_id':attempt_id,'code':code,
                    'raw_package':deepcopy(raw_package),'cpu_evidence':deepcopy(cpu_evidence),'accepted':False})
            doc['state']['active_attempt_ids'].remove(attempt_id)
            self.db.execute('UPDATE dispatches SET status=? WHERE attempt_id=?', (attempt['status'], attempt_id))
            return {'attempt_id': attempt_id, 'code': code, 'unknown_usage': is_unknown}
        return self._apply(self._event_id('abandon', attempt_id), 'abandon', {'attempt_id':attempt_id,'code':code,'unknown':unknown,'raw_package':raw_package,'cpu_evidence':cpu_evidence}, mutate)

    def invalidate(self, ids, *, phase, reason, correction_class=None, full=False):
        requested = sorted(set(ids))
        def mutate(doc):
            state = doc['state']
            if state['active_attempt_ids'] or state['unsettled_call_ids']: raise ProtocolError('ACTIVE_OR_UNKNOWN_DISPATCH_FORBIDS_RETRY')
            if correction_class is not None:
                key = correction_class + '_used'
                if correction_class not in ('semantic','stale') or state['counters'][key] >= 1: raise ProtocolError('CORRECTION_ALLOWANCE_EXHAUSTED')
                state['counters'][key] += 1
            invalid = [r['result_id'] for r in doc['results']] if full else closure_ids(requested, doc['results'])
            if not V1Store._compensate(doc, set(invalid)): raise ProtocolError('CONDITIONAL_COMPENSATION_CONFLICT')
            state['invalidated_result_ids'] = sorted(set(state['invalidated_result_ids']) | set(invalid))
            for node,rid in list(state['selected_by_node'].items()):
                if rid in invalid: state['selected_by_node'][node] = None
            state['stage'] = phase
            plan = {'kind': reason, 'phase': phase, 'invalidated_result_ids': invalid,
                'correction_class': correction_class, 'full_restart': full}
            doc['plans'].append(plan)
            return plan
        identity = digest({'phase':phase,'reason':reason,'ids':requested,'class':correction_class,'full':full})
        return self._apply(self._event_id('invalidate', identity), 'invalidation_and_compensation',
            {'ids':requested,'phase':phase,'reason':reason,'correction_class':correction_class,'full':full}, mutate)

    def update_sources(self, sources, history, evidence, event_id):
        def mutate(doc):
            old = {s['object_key']:s for s in doc['sources']}
            if len(sources)!=len(old) or {s['object_key'] for s in sources}!=set(old):
                raise ProtocolError('SOURCE_KEYSET_CHANGED')
            for source in sources:
                self._validate(source)
                if source['object_key'] not in old or source['version'] < old[source['object_key']]['version']:
                    raise ProtocolError('NON_MONOTONIC_SOURCE_WRITE')
                if source['version']==old[source['object_key']]['version'] and source!=old[source['object_key']]:
                    raise ProtocolError('SAME_VERSION_SOURCE_REBOUND')
                if digest(source['payload'])!=source['payload_digest']:
                    raise ProtocolError('SOURCE_PAYLOAD_DIGEST_MISMATCH')
                if not any(h==source for h in history): raise ProtocolError('SOURCE_HISTORY_BINDING_MISSING')
            doc['sources'] = deepcopy(sources); doc['source_history'] = deepcopy(history)
            doc['state']['source_fingerprint'] = source_fingerprint(sources)
            doc['supplement_evidence'] = deepcopy(evidence)
            return {'sources': [{'object_key':s['object_key'],'version':s['version']} for s in sources]}
        return self._apply(event_id, 'source_update', {'sources':sources,'history':history,'evidence':evidence}, mutate)

    def annotate(self, values, event_id):
        def mutate(doc):
            allowed={'supplement_evidence','prefix_refusal','prefix_candidate_result','notice',
                'initial_execution','initial_snapshot','metadata','transport_receipts','cpu_gateway_receipts',
                'phase2_unified_pack_sha256','supplement_only','unified_only','consumption_outcome',
                'independent_numeric_check','unaccepted_cpu_gateway_receipts'}
            for key,value in values.items():
                if key not in allowed: raise ProtocolError('ANNOTATION_CANNOT_MUTATE_BUSINESS_STATE')
                if key=='metadata' and ({k:v for k,v in value.items() if k!='initial_result_ids'} !=
                        {k:v for k,v in doc['metadata'].items() if k!='initial_result_ids'}):
                    raise ProtocolError('ANNOTATION_METADATA_BINDING_IMMUTABLE')
                if key=='metadata' and (len(value.get('initial_result_ids',[]))!=len(set(value.get('initial_result_ids',[]))) or
                        not set(value.get('initial_result_ids',[]))<={r['result_id'] for r in doc['results']}):
                    raise ProtocolError('RETENTION_ANCHOR_UNKNOWN_RESULT')
                if key=='notice':
                    self._validate(value)
                    if value['run_id']!=doc['state']['run_id'] or value['faulty_result_id'] not in {r['result_id'] for r in doc['results']}:
                        raise ProtocolError('NOTICE_RESULT_IDENTITY_MISMATCH')
                if key=='initial_snapshot' and (value.get('results')!=doc['results'] or
                        value.get('run_state',{}).get('selected_by_node')!=doc['state']['selected_by_node']):
                    raise ProtocolError('HANDOFF_SNAPSHOT_MUST_BE_CURRENT_AUTHORITY')
                if key=='cpu_gateway_receipts' and value!=doc.get('cpu_gateway_receipts',[]):
                    raise ProtocolError('ANNOTATION_CANNOT_REWRITE_CPU_SETTLEMENTS')
                if key=='prefix_refusal' and value not in doc['guards']:
                    raise ProtocolError('REFUSAL_MUST_BE_DURABLE_GUARD')
                if key=='prefix_candidate_result' and not any(all(r.get(k)==v for k,v in value.items() if k!='execution_status') for r in doc['results']):
                    raise ProtocolError('REFUSAL_CANDIDATE_MUST_BE_DURABLE_RESULT')
                doc[key] = deepcopy(value)
            return {'annotated': sorted(values)}
        return self._apply(event_id, 'annotation', values, mutate)

    def stop(self, status, error=None):
        def mutate(doc):
            if doc['state']['active_attempt_ids']: raise ProtocolError('ACTIVE_ATTEMPTS_MUST_BE_SETTLED')
            if status=='completed_correct' and (doc['state']['unsettled_call_ids'] or not doc['state']['selected_by_node'].get('publish')):
                raise ProtocolError('COMPLETION_WITHOUT_SETTLED_PUBLICATION')
            doc['state'].update(status='terminal', terminal_status=status); doc['error'] = deepcopy(error)
            return {'terminal_status': status, 'error': deepcopy(error)}
        return self._apply(self._event_id('terminal', digest({'status':status,'error':error})), 'terminal', {'status':status,'error':error}, mutate)

    def export(self):
        doc = self.snapshot()
        commands = []
        for row in self.db.execute('SELECT seq,event_id,kind,command_digest,payload,before_digest,after_digest,previous_hash,command_hash,response FROM commands ORDER BY seq'):
            names = ('seq','event_id','kind','command_digest','payload','before_digest','after_digest','previous_hash','command_hash','response')
            item = dict(zip(names,row)); item['payload'] = json.loads(item['payload']); item['response'] = json.loads(item['response']); commands.append(item)
        dispatches = []
        for row in self.db.execute('SELECT attempt_id,node_id,phase,input_digest,status,intent,settlement,selected FROM dispatches ORDER BY rowid'):
            item = dict(zip(('attempt_id','node_id','phase','input_digest','status','intent','settlement','selected'),row))
            item['intent']=json.loads(item['intent']); item['settlement']=json.loads(item['settlement']) if item['settlement'] else None; dispatches.append(item)
        doc['events'] = commands
        doc['kernel_evidence'] = {'protocol': PROTOCOL, 'database_path':'workflow.sqlite',
            'synchronous':'FULL','journal_mode':'DELETE','single_authoritative_document':True,
            'commands':commands, 'dispatches':dispatches, 'transaction_count':len(commands),
            'state_digest':digest(doc['state']), 'document_digest':digest(self.snapshot())}
        return doc
