#!/usr/bin/env python3
"""Explain retained Phase 1 results without running an agent, model or tool."""
from collections import Counter, defaultdict
from pathlib import Path
import argparse
import csv
import hashlib
import json
import math
import statistics
import sys

RAW_SHA = '731f77997898af2c985a5b8f17a35b675cbb35a3279bd469740648c8f2b43da6'
LABELS = ('schema_valid', 'stage_semantic_valid', 'fresh_at_consume', 'authority_consistent_at_decision')


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path):
    return json.loads(path.read_text())


def bodies(rows):
    return [json.loads(row['body']) for row in rows]


def classify(step):
    labels = step['labels']
    require(set(labels) == set(LABELS), 'Unexpected validity dimensions')
    if any(labels[k] is False for k in LABELS) or step['execution_status'] == 'schema_error':
        return 'invalid_on_at_least_one_check'
    if step['execution_status'] == 'success' and all(labels[k] is True for k in LABELS):
        return 'all_four_checks_passed'
    return 'no_fully_judged_result'


def check_natural_defect(results, request):
    byid = {r['result_id']: r for r in results}
    for result in sorted(results, key=lambda r: ('read_metadata', 'read_permission', 'read_resources', 'plan', 'execute').index(r['step_id'])):
        if result['payload'] is None:
            continue
        step = result['step_id']
        actual = result['payload']
        snap = result['input_snapshot']
        if step.startswith('read_'):
            expected = snap['tool_snapshots'][0]['payload']
            if actual != expected:
                return dict(step=step, kind='source_copy_error', result_id=result['result_id'], actual=actual, expected=expected)
        elif step == 'plan':
            parents = {byid[p['result_id']]['step_id']: p['payload'] for p in snap['parents']}
            metadata = parents['read_metadata']
            n, b, e = metadata['num_examples'], request['batch_size'], request['epochs']
            expected = dict(dataset_id=request['dataset_id'], purpose=request['purpose'],
                            batch_size=b, epochs=e, num_examples=n,
                            steps=((n + b - 1) // b) * e,
                            workers=min(request['requested_workers'], parents['read_resources']['max_workers']),
                            permission_allowed=parents['read_permission']['allowed'])
            if actual != expected:
                kind = 'planner_copy_error' if any(actual.get(k) != v for k, v in expected.items() if k != 'steps') else 'planner_step_count_mismatch'
                return dict(step=step, kind=kind, result_id=result['result_id'], actual=actual, expected=expected)
    return None


def analyze(bundle, output):
    bundle, output = Path(bundle).resolve(), Path(output).resolve()
    require(not output.exists(), 'Output must be a new directory')
    rawpath = bundle / 'evidence/p4/records.json'
    require(sha(rawpath) == RAW_SHA, 'Raw P4 export changed')
    raw = load(rawpath)
    recpath = bundle / 'analysis/submission_review/recomputed'
    saved = load(recpath / 'p4_recomputed.json')
    audit = load(recpath / 'p4_independent_audit.json')
    require(audit['passed'] and not audit['findings'], 'Saved independent audit failed')
    ledger = {c['call_id']: c for c in bodies(raw['databases']['campaign.sqlite']['p3_calls'])}
    require(len(ledger) == 602, 'Physical-call coverage differs')
    slots = raw['artifacts']['execution_manifest.json']['slots']
    slotmap = {s['trial_key']: s for s in slots}
    trials = {t['trial_key']: t for t in saved['trials']}
    stepmap = defaultdict(list)
    for step in audit['steps']:
        stepmap[step['trial_key']].append(step)
    discarded, categories = [], Counter()
    for pair in saved['recovery_pairs']:
        if not pair['restart_executed']:
            continue
        key = pair['base_trial_key']
        slot, trial = slotmap[key], trials[key]
        db = raw['databases'][slot['trial_dir'] + '/initial.sqlite']
        results = {r['result_id']: r for r in bodies(db['results'])}
        objects = {o['object_key']: o for o in bodies(db['objects'])}
        for step in stepmap[key]:
            for cid in step['call_ids']:
                call, result = ledger[cid], results[step['result_id']]
                require(call['result_id'] == result['result_id'] and call['step_id'] == step['step_id'], 'Call/result binding differs')
                require(cid in trial['new_call_ids'], 'Call belongs to a different trial')
                category = classify(step)
                if category == 'all_four_checks_passed':
                    # Independently verify these particular candidate outputs against raw
                    # public snapshots and the source version present in the frozen branch.
                    require(result['step_id'].startswith('read_'), 'Unexpected candidate node; extend independent rule before reporting')
                    source = result['input_snapshot']['tool_snapshots'][0]
                    require(result['payload'] == source['payload'], 'Candidate copied a source incorrectly')
                    require(objects[source['object_key']] == source, 'Candidate no longer current at freeze')
                if category == 'no_fully_judged_result':
                    require(result['execution_status'] == 'stale_input' and result['payload'] is None,
                            'Undetermined output has an unexpected cause')
                row = dict(base_trial_key=key, restart_trial_key=pair['restart_trial_key'],
                           condition=slot['condition'], task_id=slot['task_id'], repeat=slot['repeat'],
                           result_id=result['result_id'], step_id=result['step_id'], call_id=cid,
                           category=category, known_cost_nano_usd=call['known_cost_nano_usd'],
                           labels=step['labels'])
                discarded.append(row)
                categories[category] += 1
    require(len(discarded) == len({r['call_id'] for r in discarded}) == 135, 'Discarded-call identity partition differs')
    require(dict(categories) == {'all_four_checks_passed': 63, 'invalid_on_at_least_one_check': 60,
                                 'no_fully_judged_result': 12}, 'Discarded-call classification changed')
    require(sum(r['known_cost_nano_usd'] for r in discarded) == 7330250, 'Discarded cost differs')

    commits, focus = [], []
    seen_commits = set()
    for slot in slots:
        if not slot['executed']:
            continue
        replay = slot['phase'] == 'replay'
        dbref = slot['trial_dir'] + ('/restart/branch.sqlite' if replay else '/initial.sqlite')
        db = raw['databases'][dbref]
        own = set(slot['result_ids'])
        results = [r for r in bodies(db['results']) if r['result_id'] in own]
        objects = {o['object_key']: o for o in bodies(db['objects'])}
        for effect in bodies(db['effects']):
            if effect['owner_result_id'] not in own:
                continue
            require(effect['effect_id'] not in seen_commits, 'Inherited write counted twice')
            seen_commits.add(effect['effect_id'])
            for read in effect['source_read_set']:
                require(objects[read['object_key']]['version'] == read['version'], 'Need historical source reconstruction before classifying this commit')
            config = next(t['after']['payload'] for t in effect['targets'] if t['object_key'].startswith('job_config:'))
            permission = objects['permission:' + config['dataset_id'] + ':' + config['purpose']]['payload']
            resource = objects['resource_policy:default']['payload']
            commits.append(dict(trial_key=slot['trial_key'], effect_id=effect['effect_id'],
                                policy=slot['policy'], condition=slot['condition'],
                                workers=config['workers'], max_workers=resource['max_workers'],
                                permission_allowed=permission['allowed'],
                                resource_violation=config['workers'] > resource['max_workers'],
                                denied_permission_write=permission['allowed'] is not True,
                                business_wrong=effect['effect_id'] in trials[slot['trial_key']]['new_wrong_committed_effect_ids']))
        t = trials[slot['trial_key']]
        if (slot['condition'] == 'CLEAN' or replay) and t['correctness'] != 'correct':
            request = raw['artifacts'][slot['trial_dir'] + '/task.json']['request']
            defect = check_natural_defect(results, request)
            require(defect is not None, 'Unexplained clean or restart failure')
            focus.append(dict(trial_key=slot['trial_key'], task_id=slot['task_id'],
                              condition=slot['condition'], policy=slot['policy'], repeat=slot['repeat'],
                              first_new_defect=defect, business_outcome=t['business_outcome']))
    require(len(commits) == 91 and sum(c['business_wrong'] for c in commits) == 24, 'Commit partition differs')
    require(not any(c['resource_violation'] or c['denied_permission_write'] for c in commits), 'Unauthorized commit found')
    require(len(focus) == 15 and Counter(r['first_new_defect']['kind'] for r in focus)
            == Counter(source_copy_error=10, planner_copy_error=1, planner_step_count_mismatch=4), 'Failure taxonomy differs')

    verifier, timings = [], []
    for condition in ['CLEAN', 'ERR', 'ADV', 'TMO', 'STL']:
        chosen = [t for t in saved['trials'] if t['policy'] == 'VERIFY_STOP' and t['condition'] == condition]
        ms = [t['timing']['verifier_elapsed_ms'] for t in chosen]
        verifier.append(dict(condition=condition, trials=len(chosen),
                             recorded_check_ms_median=statistics.median(ms),
                             recorded_check_ms_min=min(ms), recorded_check_ms_max=max(ms),
                             logical_reads=sum(t['extra_verifier_logical_reads'] for t in chosen),
                             model_calls=sum(len(t['new_call_ids']) for t in chosen),
                             correct=sum(t['correctness']=='correct' for t in chosen),
                             verifier_rejections=sum(t['verifier_rejected'] for t in chosen),
                             safe_unfinished_total=sum(t['safe_stop'] is True for t in chosen),
                             clean_false_rejects=sum(t['clean_false_reject'] is True for t in chosen)))
    for condition in ['ERR', 'TMO', 'STL']:
        chosen = [t for t in saved['trials'] if t['policy'] == 'FULL_RESTART' and t['condition'] == condition and t['executed']]
        for t in chosen:
            timing = t['timing']
            require(math.isclose(timing['wall_recovery_total_ms'], timing['wall_execution_ms'] + timing['wall_recovery_control_ms'], abs_tol=1e-6), 'Restart timing accounting changed')
        timings.append(dict(condition=condition, trials=len(chosen),
                            replay_seconds_median=statistics.median(t['timing']['wall_execution_ms']/1000 for t in chosen),
                            control_seconds_median=statistics.median(t['timing']['wall_recovery_control_ms']/1000 for t in chosen),
                            recorded_control_plus_replay_seconds_median=statistics.median(t['timing']['wall_recovery_total_ms']/1000 for t in chosen)))
    check = dict(schema_version='phase1-depth-analysis-v1', passed=True, raw_records_sha256=RAW_SHA,
                 registered_slots=168, executed_workflows=156, historical_calls=602,
                 discarded_calls=dict(categories),
                 discarded_cost_by_category_nano_usd={c:sum(r['known_cost_nano_usd'] for r in discarded if r['category']==c) for c in categories},
                 strict_valid_fraction_of_discarded_calls=63/135,
                 strict_valid_discarded_by_step=dict(Counter(r['step_id'] for r in discarded if r['category']=='all_four_checks_passed')),
                 writes=dict(unique_commit_operations=len(commits), business_wrong=24,
                             resource_limit_violations=0, denied_permission_commits=0,
                             caveat='All authoritative permissions in these tasks allow training. Zero observed violations is not a permission-revocation experiment.'),
                 failure_cases=len(focus), first_defect_kinds=dict(Counter(r['first_new_defect']['kind'] for r in focus)),
                 verifier=verifier, restart_timing=timings,
                 limits=['63 checked outputs are candidates for later reuse, not a measured selective-recovery gain.',
                         '12 null-label cases are stale-input Executor calls, not financially unknown calls.',
                         'Per-trial recorded verifier intervals are not isolated full-runtime overhead.',
                         'Recorded control+replay intervals exclude the original failed prefix and later audit/export; not a new complete monotonic timer.',
                         'Four tasks, three repeated model draws each. No generalization or significance claim.',
                         'Existing raw/checker results were cross-checked; the full historical audit suite was not rerun.'],
                 new_api_calls=0, new_training=0, new_prediction=0)
    # Guard the important non-equivalences without changing any retained input.
    refusal = dict(execution_status='stale_input', labels={k:None for k in LABELS})
    require(classify(refusal) == 'no_fully_judged_result', 'Null labels were treated as valid')
    require(classify(dict(execution_status='success', labels={k:True for k in LABELS})) == 'all_four_checks_passed', 'Valid result rejected')
    mixed = {k:True for k in LABELS};mixed['fresh_at_consume']=False
    require(classify(dict(execution_status='success', labels=mixed)) == 'invalid_on_at_least_one_check', 'Stale result counted valid')
    output.mkdir(parents=True)
    for name, value in [('SUMMARY.json',check), ('DISCARDED_CALLS.json',discarded),
                        ('COMMIT_OPERATIONS.json',commits), ('FAILURE_CASES.json',focus)]:
        (output/name).write_text(json.dumps(value,indent=2,ensure_ascii=False,allow_nan=False)+'\n')
    with (output/'DISCARDED_CALLS.csv').open('w',newline='') as f:
        fields=[k for k in discarded[0] if k!='labels']; writer=csv.DictWriter(f,fieldnames=fields)
        writer.writeheader();writer.writerows({k:r[k] for k in fields} for r in discarded)
    pins={str(p.relative_to(bundle)):sha(p) for p in [rawpath,recpath/'p4_recomputed.json',recpath/'p4_independent_audit.json']}
    (output/'INPUTS.json').write_text(json.dumps(pins,indent=2)+'\n')
    print(json.dumps({k:check[k] for k in ['passed','discarded_calls','writes','failure_cases','new_api_calls']}))


def offline(event, args):
    if event.startswith('socket.') or event in ('subprocess.Popen','os.system','os.fork','os.posix_spawn','pickle.find_class'):
        raise RuntimeError('OFFLINE_ONLY:'+event)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--output', required=True)
    args=parser.parse_args();sys.addaudithook(offline)
    analyze(args.bundle,args.output)
