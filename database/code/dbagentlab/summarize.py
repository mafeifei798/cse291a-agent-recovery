"""Offline CSV aggregation. Never calls the API or opens a database."""
import argparse
import csv
import json
from pathlib import Path
from collections import defaultdict


def collect(root):
    rows = []
    for path in sorted(Path(root).rglob('RECEIPT.json')):
        receipt = json.loads(path.read_text())
        if receipt.get('command') != 'run':
            continue
        branches = receipt.get('branches', [])
        if not branches:
            # Retain failures before fixture/API initialization; never silently filter them out.
            branches = [{'branch':'initial','status':'pre_branch_failure','task_success':False,
                         'fault_delivery_status':'not_reached','model_calls':receipt.get('model_calls',0)}]
        for branch in branches:
            analysis_path = path.parent/branch['branch']/'analysis.json'
            analysis = json.loads(analysis_path.read_text()) if analysis_path.exists() else {}
            evaluation = branch.get('evaluation', {})
            rows.append({'run_id':path.parent.name, 'branch':branch['branch'],
                'code_version':receipt.get('code_version','unversioned'),
                'diagnostic_experts':receipt.get('diagnostic_experts',2),
                'role_policy':receipt.get('role_policy','shared'),
                'case':receipt['case'], 'condition':receipt['fault'],
                'branch_fault':branch.get('fault',receipt['fault']),
                'verification':receipt['verification'], 'restart':receipt['restart'],
                'status':branch['status'], 'task_success':bool(branch.get('task_success')),
                'fixture_valid':evaluation.get('fixture_valid',False),
                'operational_success':evaluation.get('operational_success',False),
                'inventory_integrity':evaluation.get('inventory_integrity'),
                'execution_outcome_resolved':evaluation.get('execution_outcome_resolved',False),
                'fault_delivery_status':branch.get('fault_delivery_status','not_reached'),
                'direct_exposure_calls':len(analysis.get('direct_model_exposure_calls',[])),
                'potentially_affected_calls':len(analysis.get('potentially_affected_calls',[])),
                'downstream_structured_errors':analysis.get('downstream_structured_error_count',0),
                'unauthorized_attempts':evaluation.get('unauthorized_action_attempts',0),
                'unauthorized_applied':evaluation.get('unauthorized_actions_applied',0),
                'model_calls':branch.get('model_calls',0),
                'branch_seconds':branch.get('end_to_end_seconds_including_cleanup'),
                'total_run_seconds':receipt.get('end_to_end_seconds'),
                'total_run_calls':receipt.get('model_calls'),
                'unknown_usage_calls_total':receipt.get('calls_with_unknown_usage',0),
                'total_known_tokens':receipt.get('known_token_usage',{}).get('total_tokens'),
                'cleanup_verified':branch.get('cleanup',{}).get('verified',False)})
    return rows


def aggregate(rows):
    grouped = defaultdict(list)
    for row in rows:
        defaults={'diagnostic_experts':2,'role_policy':'shared'}
        key = tuple(row.get(k,defaults.get(k,'unversioned')) for k in
                    ('code_version','diagnostic_experts','role_policy','case','condition','verification','restart','branch'))
        grouped[key].append(row)
    results = []
    for key, group in sorted(grouped.items()):
        successful = sum(r['task_success'] for r in group)
        results.append(dict(zip(('code_version','diagnostic_experts','role_policy','case','condition','verification','restart','branch'), key),
            runs=len(group), successful=successful, success_rate=successful/len(group),
            fixture_invalid_or_unavailable=sum(not r['fixture_valid'] for r in group),
            faults_delivered=sum(r['fault_delivery_status']=='delivered' for r in group),
            direct_exposure_calls=sum(r['direct_exposure_calls'] for r in group),
            downstream_structured_errors=sum(r['downstream_structured_errors'] for r in group),
            unauthorized_attempts=sum(r['unauthorized_attempts'] for r in group),
            unauthorized_applied=sum(r['unauthorized_applied'] for r in group),
            model_calls=sum(r['model_calls'] for r in group)))
    return results


def write_csv(path, rows):
    with Path(path).open('x', newline='') as stream:
        if rows:
            writer = csv.DictWriter(stream,fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runs', type=Path, default=Path('runs'))
    parser.add_argument('--output', type=Path, required=True, help='New directory, never overwritten')
    args = parser.parse_args()
    rows = collect(args.runs)
    args.output.mkdir(parents=True,exist_ok=False)
    write_csv(args.output/'branches.csv', rows)
    write_csv(args.output/'groups.csv', aggregate(rows))
    (args.output/'NOTES.txt').write_text(
        'All started run receipts retained, including pre-branch failures. This is not a preregistered '
        'campaign denominator: scheduled-but-never-started slots need a separate manifest.\n'
        'Accidental (pid_swap, timeout) and adversarial (instruction) conditions remain separate.\n'
        'Total-run cost/time columns repeat across initial/restart rows: do not sum them by branch.\n'
        'Exposure is not causal influence. Automated structured errors do not cover all prose errors.\n'
        'No fake zero costs for unknown API usage; no USD pricing is assumed.\n')
    print('Offline summary:', args.output, '; branch rows:', len(rows))


if __name__ == '__main__':
    main()
