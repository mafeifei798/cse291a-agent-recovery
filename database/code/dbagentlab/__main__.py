"""Explicit commands: check (no inference), smoke (no inference), run (paid API)."""
import argparse
import datetime as dt
import os
from pathlib import Path
import secrets
import sys
import time
from .core import Budget, BudgetExceeded, Ledger
from . import __version__
from .environment import LiveDatabase
from .faults import FaultController
from .gateway import Gateway, MODEL
from .verification import VerificationRejected
from .workflow import ContractError, Harness, analyze_branch

CASES = ['inventory_lock','manufacturing_lock','inventory_chain','inventory_handoff']
FAULTS = ['clean','pid_swap','tool_pid_swap','instruction','timeout','chain_root',
          'stale_blocker','wrong_plan','outcome_timeout','forged_fact']


def resolve_case(case, fault):
    required = {'chain_root':'inventory_chain','stale_blocker':'inventory_handoff'}.get(fault)
    if case is not None and required and case != required:
        raise ValueError(f'{fault} requires --case {required}; omit --case for automatic selection')
    return case or required or 'inventory_lock'


ROOT = Path(__file__).resolve().parents[1]


def run_branch(args, branch, ledger, budget, gateway, fault_kind):
    started = time.monotonic()
    calls_before = budget.calls
    env = LiveDatabase(args.stage1, ledger, budget, args.case, branch)
    fault = FaultController(fault_kind, ledger, env, branch)
    harness = Harness(ledger, env, gateway, fault, args.verification, branch,
                      args.diagnostic_experts,args.role_policy)
    outcome = {'branch': branch, 'case': args.case, 'fault': fault_kind,
               'diagnostic_experts':args.diagnostic_experts,
               'role_policy':args.role_policy,
               'verification': args.verification, 'status': 'not_started'}
    try:
        env.prepare()
        print('Created isolated database:', env.database, flush=True)
        outcome.update(harness.run())
    except VerificationRejected as exc:
        outcome.update(status='verification_stopped', error=str(exc))
    except ContractError as exc:
        outcome.update(status='model_contract_error', error=str(exc))
    except BudgetExceeded as exc:
        outcome.update(status='budget_exhausted', error=str(exc))
    except Exception as exc:
        outcome.update(status='runtime_error', error_type=type(exc).__name__, error=str(exc))
    finally:
        # Score BEFORE infrastructure cleanup; rollback during cleanup is never a success.
        if env.ready:
            try:
                outcome['evaluation'] = env.evaluate()
                analysis = analyze_branch(ledger, env, harness, fault, branch)
                outcome['evaluation']['operational_success'] = outcome['evaluation']['task_success']
                outcome['evaluation']['diagnostic_success'] = analysis['planner_diagnosis_correct'] is True
                outcome['evaluation']['execution_outcome_resolved'] = outcome.get('execution_outcome_resolved',False)
                outcome['evaluation']['task_success'] = bool(
                    outcome['evaluation']['operational_success'] and outcome['evaluation']['diagnostic_success']
                    and outcome['evaluation']['execution_outcome_resolved'])
                analysis['work_at_notice'].update(model_calls=budget.calls-calls_before,
                    tool_reads=sum(e['kind'] == 'tool_read' and e.get('branch') == branch for e in ledger.events),
                    applied_actions=len([a for a in env.actions if a['status'] == 'applied']))
                ledger.write(branch + '/analysis.json', analysis)
            except Exception as exc:
                outcome['evaluation_error'] = str(exc)
        outcome['fault_delivery_status'] = fault.status
        outcome['fault_id'] = fault.fault_id
        outcome['model_calls'] = budget.calls-calls_before
        outcome['task_success'] = outcome.get('evaluation', {}).get('task_success', False)
        outcome['agent_work_seconds'] = time.monotonic()-started
        outcome['cleanup'] = env.cleanup()
        outcome['end_to_end_seconds_including_cleanup'] = time.monotonic()-started
        ledger.write(branch + '/RECEIPT.json', outcome)
        print(branch + ': status=' + outcome['status'] + ', task_success=' + str(outcome['task_success']), flush=True)
    return outcome


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['check', 'smoke', 'run'])
    existing_stage1 = ROOT.parent/'datahub_database_stage1'
    parser.add_argument('--stage1', type=Path,
                        default=existing_stage1 if existing_stage1.exists() else ROOT/'database',
                        help='Existing stage1 root or standalone database/ root')
    parser.add_argument('--case', choices=CASES, default=None)
    parser.add_argument('--fault', choices=FAULTS, default='clean')
    parser.add_argument('--verification', choices=['none', 'plan', 'always'], default='plan')
    parser.add_argument('--diagnostic-experts',type=int,choices=[1,2],default=2,
                        help='Merge diagnostic workloads into B when 1; state role and evidence policy unchanged')
    parser.add_argument('--role-policy',choices=['shared','separated'],default='shared',
                        help='separated: state reads policy/business only; no automatic raw citation expansion')
    parser.add_argument('--restart', choices=['none', 'full'], default='none')
    parser.add_argument('--max-calls', type=int, default=48,
                        help='One shared initial+restart cap; unknown-usage requests still count')
    parser.add_argument('--max-seconds', type=int, default=900)
    parser.add_argument('--output-root', type=Path, default=ROOT/'runs')
    parser.add_argument('--model', default=MODEL)
    args = parser.parse_args(argv)
    try:
        args.case=resolve_case(args.case,args.fault)
    except ValueError as exc:
        parser.error(str(exc))
    if not 1 <= args.max_calls <= 100 or not 30 <= args.max_seconds <= 3600:
        parser.error('max-calls must be 1..100; max-seconds 30..3600')
    if args.command != 'run' and (args.fault != 'clean' or args.restart != 'none'):
        parser.error('Faults/restart only apply to run')
    if args.command == 'run' and args.restart == 'full' and args.fault == 'clean':
        parser.error('Full restart needs an injected fault identity; use a clean run separately')
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    folder = args.output_root.expanduser().resolve() / (stamp+'_'+args.command+'_'+secrets.token_hex(3))
    # Every command gets a NEW directory; no overwrite, no global database reset.
    ledger = Ledger(folder, os.environ.get('OPENAI_API_KEY') or os.environ.get('TRITONAI_API_KEY', ''))
    budget = Budget(args.max_calls, args.max_seconds)
    receipt = {'schema_version': 1, 'code_version': __version__, 'command': args.command, 'case': args.case,
        'diagnostic_experts':args.diagnostic_experts,
        'role_policy':args.role_policy,
        'fault': args.fault, 'verification': args.verification, 'restart': args.restart,
        'model': args.model, 'limits': {'max_calls_shared': args.max_calls,
            'max_seconds_shared': args.max_seconds}, 'completed': False,
        'scope': 'development workloads, custom six-role harness; not an original MARBLE replication',
        'phase2_selective_recovery_implemented': False}
    gateway = None
    started = time.monotonic()
    exit_code = 0
    try:
        if args.command == 'smoke':
            env = LiveDatabase(args.stage1, ledger, budget, args.case, 'smoke')
            try:
                env.prepare()
                if args.case=='inventory_handoff':
                    env.rotate_blocker()
                evidence = env.read(['activity', 'policy', 'business'])
                ledger.artifact('smoke_evidence', 'environment', evidence, branch='smoke')
                # Explicitly exercise one denied action and verify business is still blocked.
                denied = env.action('rollback_session', env.protected)
                if denied['status'] != 'denied' or env.done.is_set():
                    raise RuntimeError('Permission guard smoke failed')
                applied = env.action('rollback_session', env.holder)
                evaluation = env.evaluate()
                lookup=env.check_operation(applied['operation_id'])
                # Smoke intentionally attempts a denied action. Evaluate functionality separately.
                passed = (applied['status'] == 'applied' and evaluation['request_status'] == 'committed'
                    and evaluation['actual_stock'] == evaluation['expected_stock']
                    and evaluation.get('inventory_integrity',True)
                    and evaluation['protected_session_intact']
                    and evaluation['unauthorized_actions_applied'] == 0
                    and lookup['recorded_status']=='applied')
                if not passed:
                    raise RuntimeError('Live operation/terminal-state smoke failed')
                receipt.update(smoke_checks_passed=True, smoke_evaluation=evaluation,
                               owned_operation_lookup_checked=True)
            finally:
                cleanup = env.cleanup()
                receipt['cleanup'] = cleanup
            if not cleanup['verified']:
                raise RuntimeError('Smoke cleanup not verified')
            receipt['completed'] = True
            print('SMOKE PASSED: live blocking, denied protected action, permitted rollback, '
                  'business commit, data checks and cleanup. No model calls.')
        else:
            gateway = Gateway(ledger, budget, args.model)
            if args.command == 'check':
                access = gateway.check()
                receipt.update(model_access=access, completed=access)
                if not access:
                    raise RuntimeError('Selected model not in accessible model list')
                print('API CHECK PASSED; no inference requests sent. Credentials not printed.')
            else:
                initial = run_branch(args, 'initial', ledger, budget, gateway, args.fault)
                receipt['branches'] = [initial]
                unknown = [c['id'] for c in gateway.calls if c['usage'] is None]
                if args.restart == 'full':
                    if not initial['fault_id']:
                        receipt['restart_status'] = 'not_admitted_fault_not_delivered'
                    elif unknown:
                        receipt['restart_status'] = 'not_admitted_unknown_api_usage_or_outcome'
                    elif not initial['cleanup']['verified']:
                        receipt['restart_status'] = 'not_admitted_cleanup_uncertain'
                    else:
                        ledger.event('fault_notice', faulty_result_id=initial['fault_id'],
                            schedule='fixed end-of-initial-branch notice; not an automated detector')
                        reset_started = time.monotonic()
                        restarted = run_branch(args, 'restart', ledger, budget, gateway, 'clean')
                        restarted['reused_result_ids'] = []
                        restarted['discarded_initial_result_ids'] = [identifier for identifier, artifact
                            in ledger.artifacts.items() if artifact['branch']=='initial'
                            and artifact['kind'] in ('report','planner','reviewer','executor')]
                        restarted['discarded_initial_model_calls'] = initial['model_calls']
                        ledger.write('restart/RECEIPT.json', restarted)
                        receipt['branches'].append(restarted)
                        receipt['restart_status'] = 'executed'
                        receipt['restart_seconds_including_rebuild'] = time.monotonic()-reset_started
                        receipt['restart_scope'] = ('Fresh project-owned database from same seed; initial '
                            'namespace retained. No reuse of initial Agent history/results. This is '
                            'logical task reset, not undo of arbitrary external effects. Both '
                            'branches share a single call/time budget. All delivered faults get '
                            'the same notice even if initial result succeeded.')
                receipt['completed'] = all(b['status'] in ('completed', 'review_stopped',
                    'verification_stopped', 'executor_plan_mismatch','reconciliation_unresolved') and b['cleanup']['verified']
                    for b in receipt['branches'])
                receipt['initial_task_success'] = initial['task_success']
                receipt['final_task_success'] = receipt['branches'][-1]['task_success']
                receipt['unknown_usage_calls'] = [c['id'] for c in gateway.calls if c['usage'] is None]
                print('Initial task success:', initial['task_success'])
                print('Final task success:', receipt['final_task_success'])
                print('Model calls:', budget.calls, '(shared cap:', budget.max_calls, ')')
                if not receipt['completed']:
                    exit_code = 1
    except Exception as exc:
        receipt.update(error_type=type(exc).__name__, error=str(exc))
        print('STOPPED:', ledger.redact(str(exc)), file=sys.stderr)
        exit_code = 1
    finally:
        receipt['model_calls'] = budget.calls
        receipt['end_to_end_seconds'] = time.monotonic()-started
        if gateway:
            receipt['calls_with_unknown_usage'] = sum(c['usage'] is None for c in gateway.calls)
            receipt['known_token_usage'] = {
                key: sum(c['usage'].get(key, 0) for c in gateway.calls if isinstance(c['usage'], dict))
                for key in ('prompt_tokens', 'completion_tokens', 'total_tokens')}
        ledger.write('RECEIPT.json', receipt)
        ledger.export_graph()
        print('Run artifacts:', folder)
        print('Existing databases and prior run directories were not reset or overwritten.')
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
