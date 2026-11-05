"""Real CPU node packages and offline orchestration around the durable Store."""
import copy
import hashlib
import json
import os
from pathlib import Path
import time
from datetime import timedelta

from sr_recovery_v2.common import REV, ProtocolError, canonical, digest, merge_reads, node_map, utc_parse, utc_format
from sr_recovery_v2.policy import advance
from sr_recovery_v2.runner import advance_input
from .store import V2Store
from .guard import diagnose
from .executor import run_job, now


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + '\n')


def _initial_bindings(v0, files, dataset):
    assets = json.loads((v0 / 'tasks/input_artifacts.json').read_text())
    made = []
    for asset in assets['artifacts']:
        if not asset['artifact_id'].startswith('input.' + dataset + '.') or asset['access'] == 'checker_only':
            continue
        raw = (v0.parents[1] / asset['path']).read_bytes()
        if hashlib.sha256(raw).hexdigest() != asset['sha256'] or len(raw) != asset['size_bytes']:
            raise ProtocolError('FROZEN_INPUT_DIGEST_MISMATCH')
        uri = 'inputs/' + asset['artifact_id'] + Path(asset['path']).suffix
        target = files / uri
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if target.read_bytes() != raw:
                raise ProtocolError('IMMUTABLE_INPUT_REWRITE')
        else:
            with target.open('xb') as out:
                out.write(raw)
            target.chmod(0o444)
        made.append({'record_type': 'Artifact', 'revision': REV, 'fixture_only': False,
            'artifact_id': asset['artifact_id'], 'producer_result_id': asset['producer_id'],
            'uri': uri, 'sha256': asset['sha256'], 'size_bytes': asset['size_bytes'],
            'media_type': 'application/json' if target.suffix == '.json' else 'text/csv'})
    producers = [{'producer_result_id': p, 'kind': 'locked_external_input'}
                 for p in assets['input_producers'] if '.' + dataset + '.' in p]
    history = json.loads((v0 / ('tasks/authority/macro-' + dataset + '-01.sources.json')).read_text())['sources']
    sources = [copy.deepcopy(s) for s in history if s['version'] == 1]
    task = next(t for t in json.loads((v0 / 'tasks/macro_tasks.json').read_text())['tasks'] if t['public_request']['dataset_id'] == dataset)
    task = copy.deepcopy(task)
    task['request'] = {**task['public_request'], 'tie_break': {'epsilon': 1e-6, 'winner': 'LR'}}
    return task, sources, made, producers


def _projection(view, node_id):
    node = node_map(view['dag'])[node_id]
    by_id = {r['result_id']: r for r in view['results']}
    sources = {s['object_key']: s for s in view['sources']}
    parents = [by_id[view['state']['selected_by_node'][p]] for p in node['parents']]
    direct = [copy.deepcopy(sources[key]) for key in node['direct_source_keys']]
    visible_artifacts = {aid for parent in parents for aid in parent['artifact_refs']}
    visible_artifacts.update(aid for source in direct for aid in source['artifact_refs'])
    registry = {a['artifact_id']: a for a in view['artifacts']}
    body = {'run_id': view['state']['run_id'], 'node_id': node_id,
        'request': copy.deepcopy(view['task']['request']),
        'parent_inputs': [{'result_id': p['result_id'], 'node_id': p['node_id'],
            'payload': copy.deepcopy(p['payload']), 'payload_digest': digest(p['payload']),
            'artifact_refs': p['artifact_refs'][:], 'effective_reads': p['effective_reads'][:]} for p in parents],
        'direct_source_inputs': direct,
        'artifact_bindings': [copy.deepcopy(registry[aid]) for aid in sorted(visible_artifacts)]}
    body['rendered_messages'] = [
        {'role': 'system', 'content': 'Offline scripted agent. Follow the fixed JSON node contract from the cited inputs; no arbitrary code or tools.'},
        {'role': 'user', 'content': canonical(body)}]
    # Worker access is a separate trusted-tool projection of actual ancestry.
    allowed, visited = set(visible_artifacts), set()
    def walk(result):
        if result['result_id'] in visited:
            return
        visited.add(result['result_id'])
        allowed.update(result['artifact_refs'])
        for source in result.get('input_snapshot', {}).get('direct_source_inputs', []):
            allowed.update(source['artifact_refs'])
        for rid in result['parent_result_ids']:
            walk(by_id[rid])
    for parent in parents:
        walk(parent)
    return body, parents, [copy.deepcopy(registry[aid]) for aid in sorted(allowed)]


def _parent_payloads(snapshot):
    return {p['node_id']: p['payload'] for p in snapshot['parent_inputs']}


def _script(snapshot):
    # Every scripted decision is derived from its serialized message, rather
    # than global scenario/authority state or a private checker answer.
    snapshot = json.loads(snapshot['rendered_messages'][1]['content'])
    node = snapshot['node_id']
    parents = _parent_payloads(snapshot)
    if node == 'inspect':
        return {'status': 'ready', 'fit_preprocessing_on': 'training_rows_only',
                'dataset_id': snapshot['request']['dataset_id']}
    if node in ('plan_lr', 'plan_rf'):
        family = node[-2:]
        recipe = next(s['payload'] for s in snapshot['direct_source_inputs'] if s['object_key'] == 'recipe:' + family)
        return {'family': family, 'parameters': recipe['parameters'],
                'matrix_artifact_id': parents['prepare']['families'][family]['matrix_artifact_id']}
    if node == 'report':
        summaries = {f: parents['summary_' + f.lower()] for f in ('LR', 'RF')}
        scores = {f: p['metrics']['average_precision'] for f, p in summaries.items()}
        choice = 'LR' if scores['LR'] + 1e-6 >= scores['RF'] else 'RF'
        chosen = summaries[choice]
        return {'chosen_family': choice, 'selected_family': choice,
            'validation_average_precision': scores, 'metrics': chosen['metrics'],
            'model_artifact_id': chosen['model_artifact_id'],
            'prediction_artifact_id': chosen['prediction_artifact_id'],
            'validation_row_ids_digest': chosen['validation_row_ids_digest'],
            'report_text': 'The selected candidate has the higher validation average precision under the fixed selection rule.'}
    if node == 'publish':
        return {'action': 'publish_manifest', 'report': parents['report']}
    raise ProtocolError('UNKNOWN_SCRIPTED_NODE')


def _json_artifact(files, result_id, label, value):
    uri = 'scripted/' + result_id + '.' + label + '.json'
    raw = (canonical(value) + '\n').encode()
    path = files / uri
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as out:
        out.write(raw)
    path.chmod(0o444)
    return {'record_type': 'Artifact', 'revision': REV, 'fixture_only': False,
        'artifact_id': result_id + '.' + label, 'producer_result_id': result_id,
        'uri': uri, 'sha256': hashlib.sha256(raw).hexdigest(), 'size_bytes': len(raw), 'media_type': 'application/json'}


def execute_node(store, decision, v0, campaign, fault=False):
    attempt = store.start_node(decision, 'v2.start.' + decision['decision_id'], now())
    view = store.snapshot()
    node_id = decision['node_id']
    node = node_map(view['dag'])[node_id]
    snapshot, parents, allowed = _projection(view, node_id)
    aid, rid = attempt['attempt_id'], attempt['attempt_id'] + '.result'
    input_digest = digest(snapshot)
    payload, made, calls, receipts, execution = None, [], [], [], None
    if node['llm_calls_per_execution']:
        payload = _script(snapshot)
        if node_id == 'report':
            doc = _json_artifact(store.artifact_root, rid, 'report', payload)
            made.append(doc)
            payload['report_artifact_id'] = doc['artifact_id']
        calls.append({'record_type': 'CallEvidence', 'revision': REV, 'fixture_only': True,
            'call_id': aid + '.call', 'run_id': view['state']['run_id'], 'node_id': node_id,
            'attempt_id': aid, 'mode': 'fixture', 'status': 'completed', 'provider_request_id': None,
            'usage': None, 'cost_nano_usd': 0, 'input_digest': input_digest, 'request_sent': False,
            'http_status': None, 'endpoint': None, 'model': 'deterministic_scripted_client_v2',
            'worker_started': False, 'evidence_kind': 'executed_offline_scripted_client',
            'raw_response_payload': copy.deepcopy(payload), 'note': 'No model API or network request.'})
    failed = False
    if node['cpu_jobs_per_execution']:
        bodies = {p['node_id']: p['payload'] for p in parents}
        source = next(s for s in view['sources'] if s['object_key'] == 'data:train')
        inputs = {'dataset_id': view['task']['request']['dataset_id'], 'train_version': source['version']}
        if node_id.startswith(('fit_', 'predict_', 'summary_')):
            family = node_id[-2:]
            inputs.update(family=family, prepare=bodies['prepare'])
            if node_id.startswith('fit_'):
                inputs['parameters'] = bodies['plan_' + family]['parameters']
            elif node_id.startswith('predict_'):
                inputs['fit'] = bodies['fit_' + family]
            else:
                inputs['predict'] = bodies['predict_' + family]
        elif node_id == 'publish':
            inputs.update(report=payload['report'], action=payload['action'])
        stage = store.artifact_root / 'jobs' / aid
        spec = {'tool': node_id, 'job_id': aid, 'result_id': rid,
            'output_dir': str(stage), 'v0_root': str(v0), 'artifact_root': str(store.artifact_root),
            'inputs': inputs, 'artifacts': allowed, 'deadline_utc': attempt['deadline_utc'],
            'output_reservation_bytes': 128 * 1024 ** 2 if node_id in ('prepare', 'fit_rf') else 64 * 1024 ** 2}
        run = run_job(spec, campaign, on_started=lambda identity: store.record_worker_started(
            aid, identity, 'v2.worker.started.' + aid, now()))
        execution = run['execution']
        response = run['response'] or {}
        failed = execution['status'] != 'success'
        payload = copy.deepcopy(response.get('payload')) if not failed else None
        if not failed:
            made.extend(response.get('artifacts', []))
            if node_id == 'publish':
                manifest_art = next(a for a in made if a['artifact_id'] == payload['candidate_artifact_id'])
                payload['publish_manifest'] = json.loads((store.artifact_root / manifest_art['uri']).read_text())
        params = {**response.get('parameters', {}), 'execution': execution}
        receipts.append({'record_type': 'ToolReceipt', 'revision': REV, 'fixture_only': False,
            'receipt_id': aid + '.receipt', 'run_id': view['state']['run_id'], 'node_id': node_id,
            'attempt_id': aid, 'producer_result_id': rid, 'tool': 'v2.cpu.' + node_id,
            'input_digest': input_digest, 'parameters': params,
            'artifact_refs': [a['artifact_id'] for a in made], 'cpu_seconds': execution['cpu_seconds'],
            'wall_seconds': execution['wall_seconds'], 'exit_code': execution['returncode'] if execution['returncode'] is not None else 255,
            'warnings': response.get('warnings', [])})
        if fault and node_id == 'summary_lr' and not failed:
            payload['metrics']['average_precision'] = 0.0 if payload['metrics']['average_precision'] >= .5 else 1.0
    direct = sorted([{'object_key': s['object_key'], 'version': s['version']} for s in snapshot['direct_source_inputs']], key=lambda r: r['object_key'])
    result = {'record_type': 'NodeResult', 'revision': REV, 'fixture_only': False,
        'run_id': view['state']['run_id'], 'node_id': node_id, 'attempt_id': aid, 'result_id': rid,
        'producer': node['role'], 'execution_status': 'tool_failed' if failed else 'success',
        'parent_result_ids': [p['result_id'] for p in parents], 'direct_reads': direct,
        'effective_reads': merge_reads([direct] + [p['effective_reads'] for p in parents]),
        'input_digest': input_digest, 'input_snapshot': snapshot, 'payload': payload,
        'artifact_refs': [a['artifact_id'] for a in made], 'call_ids': [c['call_id'] for c in calls],
        'tool_receipt_ids': [r['receipt_id'] for r in receipts]}
    return store.finish_node(aid, {'result': result, 'artifacts': made,
        'calls': calls, 'tool_receipts': receipts, 'job_execution': execution}, now())


def initial_run(v0_root, files_root, campaign_root, run_id, dataset_id, fault=False):
    v0, files, campaign = Path(v0_root).resolve(), Path(files_root).resolve(), Path(campaign_root).resolve()
    files.mkdir(parents=True, exist_ok=True)
    db = campaign / 'db' / (run_id + '.sqlite')
    if db.exists():
        raise ProtocolError('INITIAL_DB_ALREADY_EXISTS')
    task, sources, artifacts, producers = _initial_bindings(v0, files, dataset_id)
    dag = json.loads((v0 / 'dags/macro.json').read_text())
    with V2Store(db, files) as store:
        store.create_initial(task, dag, sources, artifacts, producers, run_id, source_history=sources)
        store.begin_branch('v2.begin.' + run_id, now())
        for _ in range(20):
            view = store.snapshot()
            if view['state']['status'] == 'terminal' or (view['last_guard'] and view['last_guard']['classification'] != 'passed'):
                break
            decision = store.initial_decision('v2.initial.' + str(view['state']['state_version']), now())
            guard = diagnose(view, decision['node_id'], artifact_root=files)
            store.record_guard(guard, 'v2.guard.' + guard['guard_id'], now())
            if guard['classification'] != 'passed':
                break
            decision = store.initial_decision('v2.initial.' + str(store.snapshot()['state']['state_version']), now())
            store.admit_decision(decision, now(), guard_evidence=guard)
            execute_node(store, decision, v0, campaign, fault=fault)
        return {'view': store.export(), 'db_path': str(db)}


def recovery_run(scene, policy, files_root, campaign_root, branch_id):
    files, campaign = Path(files_root).resolve(), Path(campaign_root).resolve()
    v0 = Path(__file__).resolve().parents[2] / 'sr_v2/v0'
    dag = json.loads((v0 / 'dags/macro.json').read_text())
    db = campaign / 'db' / (branch_id + '.sqlite')
    if db.exists():
        raise ProtocolError('RECOVERY_DB_ALREADY_EXISTS')
    with V2Store(db, files) as store:
        store.create(scene, dag, branch_id, policy)
        store.begin_branch('v2.begin.' + branch_id, now())
        for _ in range(150):
            view = store.snapshot()
            if view['state']['status'] == 'terminal':
                return store.export()
            if view['state']['active_attempt_ids']:
                raise ProtocolError('ACTIVE_OR_UNSETTLED_WORK')
            guard = view.get('last_guard')
            if guard and guard['classification'] == 'passed':
                guard = None
            decision = advance(advance_input(view, now(), guard), dag)
            if decision['kind'] == 'need_version_scan':
                guard = diagnose(view, 'publish', full=True, artifact_root=files)
                store.record_scan(decision, guard, 'v2.scan.' + guard['guard_id'], now())
                view = store.snapshot()
                decision = advance(advance_input(view, now(), guard), dag)
            elif decision['kind'] == 'execute_node':
                guard = diagnose(view, decision['node_id'], artifact_root=files)
                store.record_guard(guard, 'v2.guard.' + guard['guard_id'], now())
                view = store.snapshot()
                decision = advance(advance_input(view, now(), guard), dag)
                if decision['kind'] == 'need_version_scan':
                    guard = diagnose(view, 'publish', full=True, artifact_root=files)
                    store.record_scan(decision, guard, 'v2.scan.' + guard['guard_id'], now())
                    view = store.snapshot()
                    decision = advance(advance_input(view, now(), guard), dag)
            if decision['kind'] in ('need_version_scan', 'commit'):
                raise ProtocolError('UNEXPECTED_RECOVERY_ACTION_' + decision['kind'])
            store.admit_decision(decision, now(), guard_evidence=guard)
            if decision['kind'] == 'execute_node':
                execute_node(store, decision, v0, campaign)
        raise ProtocolError('CPU_DRIVER_STEP_CAP')


def freeze_scene(db_path, v0_root, files_root, condition, scene_id):
    with V2Store(db_path, files_root) as store:
        view = store.export()
        bad = next(r for r in view['results'] if r['node_id'] == 'summary_lr')
        notice = {'record_type': 'Notice', 'revision': REV, 'fixture_only': False,
            'notice_id': 'notice.' + scene_id, 'run_id': view['state']['run_id'], 'faulty_result_id': bad['result_id']}
        dataset = view['task']['request']['dataset_id']
        history = json.loads((Path(v0_root) / ('tasks/authority/macro-' + dataset + '-01.sources.json')).read_text())['sources']
        key = 'recipe:rf' if condition == 'N2' else 'data:train' if condition == 'N3' else None
        changed = [s for s in history if s['object_key'] == key and s['version'] == 2]
        scene = store.freeze_prefix(notice, changed, 'v2.freeze.' + scene_id, now())
        # Scene identity is persisted in the initial run id; the registry also
        # records its public condition identity, never passed into node context.
        return scene


def numerical_check(view, v0_root, files_root, campaign_root, label, prefix=False):
    by_id = {r['result_id']: r for r in view['results']}
    selected = dict(view['state']['selected_by_node'])
    if prefix:
        failed_publish = next(r for r in reversed(view['results']) if r['node_id'] == 'publish')
        selected['publish'] = failed_publish['result_id']
    payloads = {n: by_id[rid]['payload'] for n, rid in selected.items() if rid}
    version = 1 if prefix else next(s['version'] for s in view['sources'] if s['object_key'] == 'data:train')
    expected = {family: next(s['payload']['parameters'] for s in view['sources'] if s['object_key'] == 'recipe:' + family)
                for family in ('lr', 'rf')}
    inputs = {'dataset_id': view['task']['request']['dataset_id'], 'train_version': version,
        'selected_payloads': payloads, 'selected_result_ids': selected,
        'expected_parameters': expected, 'evaluate_test': not prefix,
        'allow_delivered_summary_fault': prefix}
    if prefix:
        inputs.update(prefix_refusal=view['last_guard'], prefix_publish_status=by_id[selected['publish']]['execution_status'])
    job_id = 'check.' + label
    spec = {'tool': 'independent_check', 'job_id': job_id, 'result_id': job_id,
        'output_dir': str(Path(files_root).resolve() / 'checker_jobs' / job_id),
        'artifact_root': str(Path(files_root).resolve()), 'v0_root': str(Path(v0_root).resolve()),
        'inputs': inputs, 'artifacts': view['artifacts'],
        'deadline_utc': utc_format(utc_parse(now()) + timedelta(seconds=120)),
        'output_reservation_bytes': 4 * 1024 ** 2}
    return run_job(spec, campaign_root)
