"""Serial execution of the unchanged 168-row P0 registration.

This is the explicit formal entry. P3's development allowlist is not widened.
The original Store, five-step workflow, verifier and once-only restart remain
the baseline; development business guards and replanning are deliberately absent.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
from time import monotonic

from .contracts import digest, new_id, require, utc_now
from .p1_runner import P0, legacy_task, load_fault
from .p2_runner import CORE_TASK_IDS, load_shadow_slots, _task
from .p3_delivery import P3DeliveryHooks
from .p3_gateway import P3ModelGateway, P3Store
from .p3_runner import (begin_p3_restart, evaluate_p3_trial, fixture_client,
                        freeze_p3, run_five)


def write(path, value):
    """Atomic publication of a checkpoint; never discard an uncertain attempt."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name('.' + path.name + '.tmp')
    with temporary.open('w', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


class _FreezeView:
    """Only the current terminal run is needed inside the one-second freeze gap.

    Monetary admission still delegates to the complete external ledger. This
    view avoids serializing hundreds of historical HTTP responses while the
    deliberately late controlled tool response is becoming ready.
    """
    def __init__(self, campaign, source_run_id):
        self._campaign, self.source_run_id = campaign, source_run_id
        self.ref = campaign.ref

    def snapshot(self):
        row = self._campaign.connection.execute('SELECT state FROM p3_campaign').fetchone()
        return {'status': row[0]}

    def calls(self):
        rows = self._campaign.connection.execute(
            "SELECT body FROM p3_calls WHERE json_extract(body,'$.run_id')=? ORDER BY rowid",
            (self.source_run_id,))
        return [json.loads(row[0]) for row in rows]


def _evidence(store, gateway, hooks, campaign, report, *, condition, policy, trial_key):
    snapshot = store.snapshot_run()
    accounting = store.model_accounting_snapshot()
    hooks.close_evidence(snapshot, accounting)
    # Keep copied ancestral calls as provenance in a restart branch; physical
    # accounting is always partitioned by the external ledger's trial_key.
    local_ids = {c['call_id'] for c in accounting['calls']}
    external = ([json.loads(row[0]) for row in campaign.connection.execute(
        'SELECT body FROM p3_calls WHERE call_id IN (' + ','.join('?' for _ in local_ids) + ') ORDER BY rowid',
        tuple(local_ids))] if local_ids else [])
    sidecars = [c['sidecar'] for c in external]
    accounting['requests_by_call'] = {c['call_id']: c['request'] for c in external}
    campaign_row = campaign.connection.execute('SELECT state,reason FROM p3_campaign').fetchone()
    return {'snapshot': snapshot, 'selected': deepcopy(report['selected']),
            'accounting': accounting, 'p1_sidecars': sidecars,
            'campaign_snapshot': {'status': campaign_row[0], 'pause_reason': campaign_row[1],
                                  'calls': external,
                                  'uncertain_call_ids': [c['call_id'] for c in external if c['status'] == 'uncertain'],
                                  'reserved_call_ids': [c['call_id'] for c in external if c['status'] == 'reserved']},
            'delivery_audit': deepcopy(hooks.audit),
            'verifier_receipts': deepcopy(hooks.verifier_receipts),
            'condition': condition, 'policy': policy, 'trial_key': trial_key,
            'terminal_state_known': report['log_complete'],
            'unknown_operation_ids': report.get('unknown_operation_ids', []),
            'uncertain_call_ids': [c['call_id'] for c in external if c['status'] == 'uncertain']}


def run_formal_trial(output_dir, campaign, binding, *, slot, client_factory,
                     token_counter=None, p0_root=P0):
    require(slot['policy'] in ('BASE', 'VERIFY_STOP'), 'Expected initial formal slot', 'P4_SCOPE')
    task = _task(slot['task_id'], p0_root)
    require(task['task_digest'] == slot['task_digest'], 'Formal task digest changed', 'P4_SCOPE')
    fault = load_fault(task, slot['condition'], p0_root=p0_root)
    dest = Path(output_dir).resolve()
    require(not dest.exists(), 'Refusing to overwrite a formal trial', 'P4_ALREADY_STARTED')
    dest.mkdir(parents=True)
    write(dest / 'task.json', task)
    # This alias is the frozen standard-record reader's task artifact name.
    write(dest / 'task_manifest.json', task)
    logical = slot['trial_key']
    recovery_key = logical.rsplit('__', 1)[0] + '__FULL_RESTART'
    branch_id = new_id()
    gateway = P3ModelGateway(client_factory(), campaign, trial_key=logical,
        logical_run_key=logical, branch_id=branch_id, token_counter=token_counter)
    hooks = P3DeliveryHooks(task, gateway, condition=slot['condition'], policy=slot['policy'], fault_spec=fault)
    adapter = legacy_task(task)
    adapter['split'] = 'eval'
    adapter['execution_settings'].update(model_config_ref=binding.binding_ref, call_timeout_s=binding.timeout_s)
    adapter['tags'] = ['P4', 'formal_eval_core', 'legacy_schema_adapter',
                       'simulated' if binding.simulated else 'real_api']
    freeze = drain = admission = replay_report = replay_check = before_drain = duplicate = None
    replay_elapsed_ms = None
    control_elapsed_ms = 0.0
    started = monotonic()
    with P3Store(dest / 'initial.sqlite') as store:
        store.initialize_run(adapter)
        store.bind_p3(binding, campaign.ref)
        source_run_id = store.runtime_view()['run_id']
        report = run_five(store, gateway, hooks)
        initial_elapsed_ms = (monotonic() - started) * 1000
        snapshot = store.snapshot_run()
        hooks.close_evidence(snapshot, store.model_accounting_snapshot())
        identity = hooks.fault_identity()
        decision = evaluate_p3_trial(task, snapshot, report['selected'], hooks.audit, identity,
            policy=slot['policy'], terminal_known=report['log_complete'])
        ctx = {'logical_run_key': logical, 'source_run_id': source_run_id,
               'recovery_trial_key': recovery_key, 'restart_request_id': new_id(),
               'freeze_monotonic_s': hooks.clock.seconds}
        should_restart = slot['policy'] == 'BASE' and decision['restart_eligible']
        should_freeze = should_restart or hooks.pending_delivery is not None
        # Freeze comes before serializing HTTP evidence and campaign records.
        state = campaign.connection.execute('SELECT state FROM p3_campaign').fetchone()[0]
        if should_freeze and report['log_complete'] and state == 'active':
            control_started = monotonic()
            try:
                freeze = freeze_p3(store, dest / 'frozen', ctx, identity,
                    _FreezeView(campaign, source_run_id), clock=hooks.clock,
                    reply_ready_s=hooks.pending_delivery['reply_ready_s'] if hooks.pending_delivery else None)
            except BaseException:
                campaign.quarantine(None, 'P4_FREEZE_OR_PERSISTENCE_FAILED')
                raise
            control_elapsed_ms += (monotonic() - control_started) * 1000
        # A pending controlled response is outside the frozen DB. Drain promptly
        # before post-hoc reports or any replay model dispatch.
        if freeze:
            control_started = monotonic()
            if slot['condition'] == 'TMO' and should_restart:
                before_drain = begin_p3_restart(dest / 'frozen', dest / 'restart', ctx, decision, None, campaign)
            try:
                drain = hooks.drain_after_freeze(freeze, frozen_database=dest / 'frozen/scene.sqlite')
                write(dest / 'drain_receipt.json', drain)
                write(dest / 'delivery_audit.json', hooks.audit)
            except BaseException:
                campaign.quarantine(None, 'P4_TOOL_DRAIN_OR_PERSISTENCE_FAILED')
                raise
            control_elapsed_ms += (monotonic() - control_started) * 1000
        evidence = _evidence(store, gateway, hooks, campaign, report, condition=slot['condition'],
                             policy=slot['policy'], trial_key=logical)
        write(dest / 'initial_snapshot.json', snapshot)
        write(dest / 'initial_report.json', report)
        write(dest / 'initial_check.json', decision)
        write(dest / 'initial_evidence.json', evidence)
    if freeze and should_restart:
        control_started = monotonic()
        admission = begin_p3_restart(dest / 'frozen', dest / 'restart', ctx, decision, drain, campaign)
        duplicate = begin_p3_restart(dest / 'frozen', dest / 'restart', ctx, decision, drain, campaign)
        control_elapsed_ms += (monotonic() - control_started) * 1000
        if admission['status'] == 'ready':
            replay_gateway = P3ModelGateway(client_factory(), campaign, trial_key=recovery_key,
                logical_run_key=logical, branch_id=admission['branch_id'], phase='replay', token_counter=token_counter)
            replay_hooks = P3DeliveryHooks(task, replay_gateway, condition=slot['condition'],
                                          policy='FULL_RESTART', recovery_round=1)
            started = monotonic()
            with P3Store(admission['branch_db_path']) as branch:
                branch.bind_p3(binding, campaign.ref)
                replay_report = run_five(branch, replay_gateway, replay_hooks, admission['recovery_id'])
                replay_elapsed_ms = (monotonic() - started) * 1000
                replay_snapshot = branch.snapshot_run()
                replay_check = evaluate_p3_trial(task, replay_snapshot, replay_report['selected'], [], None,
                    policy='FULL_RESTART', terminal_known=replay_report['log_complete'])
                replay_evidence = _evidence(branch, replay_gateway, replay_hooks, campaign, replay_report,
                    condition=slot['condition'], policy='FULL_RESTART', trial_key=recovery_key)
            for name, value in (('snapshot', replay_snapshot), ('report', replay_report), ('check', replay_check)):
                write(dest / ('replay_' + name + '.json'), value)
            write(dest / 'restart/evidence.json', replay_evidence)
            write(dest / 'restart/report.json', replay_report)
            write(dest / 'restart/check.json', replay_check)
    summary = {'schema_version': 'p4-trial-v1', 'task_id': task['task_id'],
        'condition': slot['condition'], 'policy': slot['policy'], 'repeat': slot['repeat'],
        'simulated': binding.simulated, 'execution_kind': 'formal_fake_http' if binding.simulated else 'authorized_real_formal',
        'trial_key': logical, 'source_trial_key': slot['source_trial_key'],
        'recovery_trial_key': recovery_key, 'run_id': source_run_id, 'branch_id': branch_id,
        'initial': report, 'initial_check': decision, 'freeze': freeze, 'drain': drain,
        'before_drain': before_drain, 'admission': admission, 'duplicate_restart': duplicate,
        'replay': replay_report, 'replay_check': replay_check, 'waits': hooks.clock.waits,
        'initial_elapsed_ms': initial_elapsed_ms, 'replay_elapsed_ms': replay_elapsed_ms,
        'recovery_control_elapsed_ms': control_elapsed_ms if freeze else None,
        'restart_total_elapsed_ms': control_elapsed_ms + replay_elapsed_ms if replay_elapsed_ms is not None else None,
        'campaign_budget_ref': campaign.ref}
    write(dest / 'delivery_audit.json', hooks.audit)
    write(dest / 'verifier_receipts.json', hooks.verifier_receipts)
    write(dest / 'summary.json', summary)
    return summary


def _projection(row, campaign_id, source_sha):
    parent = row['parent_trial_key']
    initial_key = parent or row['trial_key']
    return {'schema_version': 'p4-slot-v1', 'campaign_id': campaign_id,
        'trial_key': campaign_id + '::' + row['trial_key'], 'source_trial_key': row['trial_key'],
        'parent_trial_key': campaign_id + '::' + parent if parent else None,
        'source_parent_trial_key': parent, 'formal_manifest_sha256': source_sha,
        **{k: row[k] for k in ('task_id', 'task_digest', 'condition', 'repeat', 'policy', 'sequence_index')},
        'source_sequence_index': row['sequence_index'], 'phase': 'replay' if parent else 'initial',
        'trial_dir': 'trials/' + initial_key, 'processed': False, 'executed': False,
        'status': 'not_started', 'skipped_reason': 'pending_formal_execution',
        'run_id': None, 'branch_id': None, 'call_ids': [], 'new_call_ids': [], 'result_ids': []}


def _publish(root, common, slots, campaign, *, checkpoint):
    snapshot = campaign.snapshot()
    write(root / 'execution_manifest.json', {**common, 'slots': slots})
    write(root / 'campaign_snapshot.json', snapshot)
    report = {**common, 'status': 'completed' if all(s['processed'] for s in slots) else
              'checkpoint' if snapshot['status'] == 'active' else 'stopped',
        'checkpoint': checkpoint, 'slot_count': len(slots),
        'processed_slots': sum(s['processed'] for s in slots),
        'executed_slots': sum(s['executed'] for s in slots),
        'skipped_slots': sum(s['processed'] and not s['executed'] for s in slots),
        'not_started_slots': sum(not s['processed'] for s in slots),
        'campaign_status': snapshot['status'], 'budget': snapshot['budget'],
        'cumulative': snapshot.get('cumulative_budget'), 'formal_manifest_unchanged': True,
        'real_api_requests': snapshot['real_api_requests'], 'updated_at': utc_now()}
    write(root / 'campaign_report.json', report)
    return report


def run_batch(output_root, binding, *, campaign_id='p4-formal-v1', stop_after=14,
              client_factory=None, token_counter=None, p0_root=P0, authorization=None):
    """Execute a prefix, then stop for independent audit before the next batch.

    Existing terminal rows are never reexecuted. A durable in_progress marker,
    unreported trial directory, pending HTTP call or stopped ledger fences resume.
    """
    from .p4_budget import DurableP4Budget
    require(stop_after in (14, 56, 112, 168), 'P4 checkpoint must end at a complete 14-row cell', 'P4_SCOPE')
    root, p0_root = Path(output_root).resolve(), Path(p0_root).resolve()
    if not binding.simulated:
        require(isinstance(authorization, dict) and authorization.get('authorized') is True
            and authorization.get('simulated') is False
            and authorization.get('output_root') == str(root)
            and authorization.get('campaign_id') == campaign_id
            and authorization.get('binding_digest') == binding.binding_digest
            and authorization.get('max_new_calls') == 840
            and authorization.get('max_total_calls') == 1843
            and authorization.get('max_cost_nano_usd') == 1_000_000_000
            and isinstance(authorization.get('authorization_reference'), str)
            and bool(authorization['authorization_reference'].strip()),
            'Formal execution needs its matching explicit cumulative grant', 'P4_REAL_DISABLED')
    source = p0_root / 'manifests/trials.jsonl'
    source_sha = sha(source)
    rows = load_shadow_slots(p0_root=p0_root)
    require(len(rows) == 168 and {r['task_id'] for r in rows} == set(CORE_TASK_IDS), 'Formal coverage differs', 'P4_SCOPE')
    require(isinstance(campaign_id, str) and campaign_id.startswith('p4-') and '::' not in campaign_id,
            'Explicit P4 campaign namespace required', 'P4_SCOPE')
    initial_slots = [_projection(r, campaign_id, source_sha) for r in rows]
    common = {'schema_version': 'p4-execution-v1', 'campaign_id': campaign_id,
        'scope': 'formal_eval_core', 'simulated': binding.simulated,
        'formal_manifest_sha256': source_sha, 'source_manifest_ref': 'phase1/p0/manifests/trials.jsonl',
        'binding': binding.to_dict(), 'binding_digest': binding.binding_digest,
        'protocol': 'frozen_P0_BASE_VERIFY_STOP_one_FULL_RESTART',
        'business_guard': False, 'bounded_replanning': False, 'concurrency': 1,
        'call_cap': 840, 'slot_call_cap': 5, 'logical_call_cap': 10,
        'formal_registration_mutated': False}
    if authorization is not None:
        common.update(authorization_reference=authorization['authorization_reference'],
                      grant_digest=digest(authorization), grant_ref='authorization.json')
    if root.exists():
        require((root / 'campaign_manifest.json').is_file(), 'Consumed root has no valid manifest', 'P4_ALREADY_STARTED')
        require(read(root / 'campaign_manifest.json') == {**common, 'slots': initial_slots},
                'P4 frozen runtime manifest changed', 'P4_MANIFEST_CHANGED')
        require(sha(root / 'registry_copy.jsonl') == source_sha, 'Registry copy changed', 'P4_MANIFEST_CHANGED')
        if authorization is not None:
            require(read(root / 'authorization.json') == authorization,
                    'Persisted formal authorization changed', 'P4_MANIFEST_CHANGED')
        execution = read(root / 'execution_manifest.json')
        require({k: execution[k] for k in common} == common, 'P4 execution identity changed', 'P4_MANIFEST_CHANGED')
        slots = execution['slots']
        require(len(slots) == 168 and all(s['source_trial_key'] == r['trial_key'] for s, r in zip(slots, rows)),
                'P4 slot order changed', 'P4_MANIFEST_CHANGED')
        require(not any(s['status'] == 'in_progress' for s in slots), 'Interrupted trial needs reconciliation', 'P4_UNCERTAIN_RESUME')
        processed = [s['processed'] for s in slots]
        require(processed == sorted(processed, reverse=True), 'P4 processed rows are not a prefix', 'P4_UNCERTAIN_RESUME')
    else:
        require(stop_after == 14, 'The first formal batch must stop after 14 rows', 'P4_FIRST_CHECKPOINT_REQUIRED')
        root.mkdir(parents=True)
        (root / 'registry_copy.jsonl').write_bytes(source.read_bytes())
        slots = initial_slots
        write(root / 'campaign_manifest.json', {**common, 'slots': initial_slots})
        write(root / 'execution_manifest.json', {**common, 'slots': slots})
        from .p4_config import formal_binding_record
        write(root / 'resolved_model_binding.json', formal_binding_record(binding))
        if authorization is not None:
            write(root / 'authorization.json', authorization)
    factory = client_factory or (lambda: fixture_client(binding))
    require(binding.simulated or client_factory is not None, 'Real P4 requires an explicit authorized transport factory', 'P4_REAL_DISABLED')
    resume_checkpoint = read(root / 'budget_resume_checkpoint.json') if (root / 'budget_resume_checkpoint.json').is_file() else None
    with DurableP4Budget(root / 'campaign.sqlite', campaign_id=campaign_id, binding=binding.to_dict(),
                         resume_checkpoint=resume_checkpoint) as campaign:
        require(campaign.snapshot()['status'] == 'active', 'P4 ledger is stopped or uncertain', 'P4_UNCERTAIN_RESUME')
        for slot in slots[:stop_after]:
            if slot['processed']:
                continue
            if campaign.snapshot()['status'] != 'active':
                break
            directory = root / slot['trial_dir']
            if slot['phase'] == 'replay':
                require((directory / 'summary.json').is_file(), 'Replay lacks completed parent evidence', 'P4_UNCERTAIN_RESUME')
                parent = read(directory / 'summary.json')
                replay = parent['replay']
                if replay is None:
                    reason = 'not_needed' if parent['initial_check']['correctness'] == 'correct' else 'not_eligible'
                    slot.update(processed=True, status=reason, skipped_reason=reason)
                else:
                    evidence = read(directory / 'restart/evidence.json')
                    old_ids = {r['result_id'] for r in read(directory / 'initial_snapshot.json')['results']}
                    calls = [c for c in campaign.calls() if c['trial_key'] == slot['trial_key']]
                    slot.update(processed=True, executed=True, status=replay['status'], skipped_reason=None,
                        run_id=parent['run_id'], branch_id=parent['admission']['branch_id'],
                        call_ids=[c['call_id'] for c in calls], new_call_ids=[c['call_id'] for c in calls],
                        result_ids=[r['result_id'] for r in evidence['snapshot']['results'] if r['result_id'] not in old_ids])
            else:
                require(not directory.exists(), 'Previously touched formal trial cannot be relaunched', 'P4_ALREADY_STARTED')
                slot.update(status='in_progress', skipped_reason=None)
                write(root / 'execution_manifest.json', {**common, 'slots': slots})
                try:
                    summary = run_formal_trial(directory, campaign, binding, slot=slot,
                        client_factory=factory, token_counter=token_counter, p0_root=p0_root)
                except BaseException:
                    campaign.quarantine(None, 'P4_TRIAL_OR_ARTIFACT_OUTCOME_UNCERTAIN')
                    _publish(root, common, slots, campaign, checkpoint=stop_after)
                    raise
                evidence = read(directory / 'initial_evidence.json')
                calls = [c for c in campaign.calls() if c['trial_key'] == slot['trial_key']]
                slot.update(processed=True, executed=True, status=summary['initial']['status'], skipped_reason=None,
                    run_id=summary['run_id'], branch_id=summary['branch_id'],
                    call_ids=[c['call_id'] for c in calls], new_call_ids=[c['call_id'] for c in calls],
                    result_ids=[r['result_id'] for r in evidence['snapshot']['results']])
            _publish(root, common, slots, campaign, checkpoint=stop_after)
        require(sha(source) == source_sha, 'P4 altered original registration', 'P4_MANIFEST_CHANGED')
        result = _publish(root, common, slots, campaign, checkpoint=stop_after)
        if (campaign.snapshot()['status'] == 'active'
                and sum(s['processed'] for s in slots) == stop_after
                and not any(s['status'] == 'in_progress' for s in slots)):
            write(root / 'budget_resume_checkpoint.json',
                  campaign.make_resume_checkpoint([s['trial_key'] for s in slots if s['processed']]))
    from .p4_records import write_campaign_records
    write_campaign_records(root, p0_root=p0_root, checkpoint=stop_after)
    return result
