#!/usr/bin/env python3
"""Read-only 314-history, 64-total feedback workflow and recovery audit."""
import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3

from check_l_api_batch import check as base_check, check_stopped as base_stop

UNITS = {'LC04': 10, 'LI01.PREFIX': 10, 'LI01.FULL': 10, 'LI01.CONSERVATIVE': 10,
         'LI01.CUTOFF': 10, 'LI01.CAL_RAW': 1, 'LI01.CAL_CORRECTED': 1}


def read(path):
    return json.loads(Path(path).read_text())


def audit_feedback(directory, document):
    nodes = {n['result_id']: n for n in document['store_snapshot']['nodes']}
    with closing(sqlite3.connect(Path(directory, 'store.sqlite').resolve().as_uri()+'?mode=ro', uri=True)) as db:
        persisted = {v['result_id']: v for (body,) in db.execute('SELECT payload FROM ctx_nodes') for v in [json.loads(body)]}
    assert persisted == nodes
    spent = 0
    contexts = document['feedback_contexts']
    assert contexts and document['feedback_protocol_revision'] == 'l-feedback-v1'
    for row in contexts:
        n = nodes[row['node_id']]
        c = row['payload']
        assert n['kind'] == 'feedback_options' and n['payload'] == c
        refs = {r['file_id']: r for r in n['file_reads']}
        assert set(refs) == {'inputs/registry.json', 'inputs/task.json'}
        registry, task = [read(Path(directory, 'artifacts/sha256', refs[k]['sha256']))
                          for k in ('inputs/registry.json', 'inputs/task.json')]
        analyst = next(nodes[p] for p in n['parent_result_ids'] if nodes[p]['role'] == 'Analyst')
        eligible = set(analyst['payload']['final']['eligible_features'])
        legal = [{'selection': {'bundle': b, 'recipe': r}, 'feature_columns': columns, 'recipe_definition': recipe}
                 for b, columns in registry['bundles'].items()
                 if len(columns) <= task['feature_cap'] and set(columns) <= eligible
                 for r, recipe in registry['recipes'].items()]
        assert c['legal_candidates'] == legal and c['source_ref'] == refs['inputs/registry.json']
        ordinal = int(row['node_id'].rsplit('.node.', 1)[1])
        previous = sorted((node for node in nodes.values() if node['kind'] == 'contract'
                           and int(node['result_id'].rsplit('.node.', 1)[1]) < ordinal),
                          key=lambda node: int(node['result_id'].rsplit('.node.', 1)[1]))
        tried = []
        for node in previous:
            if node['payload']['selection'] not in tried:
                tried.append(node['payload']['selection'])
        assert c['tried_selections'] == tried and c['current_selection'] in tried
        assert c['untried_candidates'] == [v['selection'] for v in legal if v['selection'] not in tried]
        decision = nodes[row['decision_node_id']]
        assert row['node_id'] in decision['parent_result_ids']
        value = decision['payload']['final']
        if row['role'] == 'Reviewer':
            assert c['normal_adjustments_remaining'] == 1-spent
            assert c['required_AP'] == task['quality_AP_ratio_goal']*c['constant_AP']
            meets = c['average_precision'] >= c['required_AP']
            expected = ['accept'] if meets else ['adjust', 'stop'] if not spent and c['untried_candidates'] else ['stop']
            assert c['allowed_actions'] == expected and value['action'] in expected
            assert value['evidence_id'] == c['evidence_id']
            if value['action'] == 'adjust':
                assert value['requested_selection'] in c['untried_candidates'] and spent == 0
                spent = 1
        else:
            assert row['role'] == 'Planner' and spent == 1 and c['approved_adjustment_in_progress']
            assert c['additional_adjustments_remaining'] == 0 and value in c['untried_candidates']
    assert document['optimization_spent'] == spent
    return {'contexts_checked': len(contexts), 'normal_adjustments_spent': spent}


def budget_checks(root):
    ledger = read(Path(root, 'LEDGER.json'))
    b = ledger['L_budget']
    assert b['Bank_historical_calls'] == 314 and b['project_historical_dispatches'] == 2792
    assert b['first_total_generation_cap'] == 64 and b['new_generation_cap'] == 52
    assert b['first_generations_used'] == len(ledger['calls'])+12 <= 64
    assert len(ledger['calls']) <= 52
    assert all(c['run_id'] in UNITS for c in ledger['calls'])
    assert all(sum(c['run_id'] == uid for c in ledger['calls']) <= cap for uid, cap in UNITS.items())
    assert not {'LC01', 'LC02', 'LC03'} & {u['unit'] for u in ledger['units']}
    return ledger


def check(root, source, require_native=False):
    result = base_check(root, source, require_native, feedback_mode=True)
    ledger = budget_checks(root)
    assert {u['unit'] for u in ledger['units']} == set(UNITS)
    campaign = Path(root, 'campaign')
    summary = read(campaign/'SUMMARY.json')
    audited = {}
    recovery_rows = {}
    for uid, row in summary['units'].items():
        if 'active' not in row['result']:
            continue
        audited[uid] = audit_feedback(campaign/'runs'/uid, row['result'])
        if uid in ('LI01.FULL', 'LI01.CONSERVATIVE', 'LI01.CUTOFF'):
            r = row['result']['recovery']
            recovery_rows[uid] = {'new_fit_tasks': row['new_fits'], 'readmissions': row['new_admissions'],
                                  'retained_producer_ids': r['retained_producer_ids'],
                                  'normal_remaining_before': r['normal_remaining_before'],
                                  'normal_remaining_after': r['normal_remaining_after']}
    assert len(audited) == 5
    result.update(feedback_protocol='l-feedback-v1', all_recoveries_use_feedback_loop=True,
                  first_total_generation_cap=64, new_generation_cap=52, feedback_audits=audited,
                  recovery_rows=recovery_rows, old_LC02_restarted=False, old_LC03_restarted=False)
    return result


def check_stopped(root, source):
    result = base_stop(root, source, feedback_mode=True)
    budget_checks(root)
    result.update(first_total_generation_cap=64, new_generation_cap=52,
                  inherited_Bank_attempts=314, old_LC02_restarted=False, old_LC03_restarted=False)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', type=Path, required=True)
    p.add_argument('--source-root', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--require-native', action='store_true')
    p.add_argument('--stopped', action='store_true')
    a = p.parse_args()
    result = check_stopped(a.run, a.source_root) if a.stopped else check(a.run, a.source_root, a.require_native)
    with a.output.open('x') as f:
        json.dump(result, f, indent=2); f.write('\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
