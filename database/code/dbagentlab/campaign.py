"""Freeze a small campaign before execution. No automatic retries/resubmission.

Planning is offline. Execution is explicit and invokes the real run command.
The runner stops on unsettled calls, uncertain cleanup, or interrupted slots.
"""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import random
import subprocess
import sys
import time
from .core import save, utc
from .__main__ import CASES, FAULTS, resolve_case


def make_plan(cases, faults, modes, repeats, seed, restart, expert_counts=(2,), role_policies=('shared',)):
    slots = []
    for case,fault,verification,repeat,experts,role_policy in itertools.product(
            cases,faults,modes,range(1,repeats+1),expert_counts,role_policies):
        resolve_case(case,fault)  # Reject invalid fixed matrices before dispatching any slot.
        slots.append({'case':case,'fault':fault,'verification':verification,'repeat':repeat,
                      'diagnostic_experts':experts,
                      'role_policy':role_policy,
                      'restart':'full' if restart and fault!='clean' else 'none'})
    random.Random(seed).shuffle(slots)
    for index,slot in enumerate(slots,1):
        slot['slot_id']='slot_%03d' % index
    return {'schema_version':1,'created':utc(),'seed':seed,'slots':slots,
        'max_calls_per_slot':48,'max_seconds_per_slot':900,
        'semantics':'repeat identities are bookkeeping, not deterministic LLM seeds; '
                    'fixed order, no selective reruns, one notification per injected branch'}


def load_state(folder):
    path=folder/'STATE.json'
    return json.loads(path.read_text()) if path.exists() else {'slots':{},'model_calls':0}


def make_extended_plan(modes, repeats, seed, restart, expert_counts=(2,), role_policies=('shared',)):
    pairs=[('inventory_chain','clean'),('inventory_chain','chain_root'),
           ('inventory_handoff','clean'),('inventory_handoff','stale_blocker'),
           ('inventory_lock','clean'),('inventory_lock','wrong_plan'),
           ('inventory_lock','outcome_timeout'),('inventory_lock','forged_fact'),
           ('inventory_lock','timeout')]
    plan=make_plan(['inventory_lock'],['clean'],modes,repeats,seed,restart,expert_counts,role_policies)
    slots=[]
    for case,fault in pairs:
        slots.extend(make_plan([case],[fault],modes,repeats,seed,restart,expert_counts,role_policies)['slots'])
    random.Random(seed).shuffle(slots)
    for index,slot in enumerate(slots,1):
        slot['slot_id']='slot_%03d' % index
    plan.update(slots=slots,suite='cdfhk_with_matched_clean_controls_and_timeout')
    return plan


def execute(folder, max_total_calls, max_total_seconds, stage1=None):
    plan=json.loads((folder/'PLAN.json').read_text())
    expected=(folder/'PLAN.sha256').read_text().strip()
    if hashlib.sha256((folder/'PLAN.json').read_bytes()).hexdigest()!=expected:
        raise RuntimeError('Frozen plan hash mismatch; no execution started')
    state=load_state(folder)
    started=time.monotonic()
    elapsed_before=state.get('elapsed_seconds',0)
    for slot in plan['slots']:
        prior=state['slots'].get(slot['slot_id'])
        if prior:
            if prior['status']!='finished':
                raise RuntimeError('Unsettled prior slot; inspect records before any new dispatch: '+slot['slot_id'])
            if prior.get('halt_reason'):
                raise RuntimeError('Prior terminal safety halt requires manual reconciliation: '+prior['halt_reason'])
            continue
        # Reserve the full per-slot allowance, keeping resource caps identical across conditions.
        if state['model_calls']+plan['max_calls_per_slot']>max_total_calls:
            state['stop_reason']='campaign_call_budget_insufficient_for_next_slot'
            save(folder/'STATE.json',state)
            print(state['stop_reason'])
            return 2
        if max_total_seconds-(elapsed_before+time.monotonic()-started)<plan['max_seconds_per_slot']:
            state['stop_reason']='campaign_wall_budget_insufficient_for_next_slot'
            save(folder/'STATE.json',state)
            print(state['stop_reason'])
            return 2
        output=folder/'slots'/slot['slot_id']
        command=[sys.executable,'-m','dbagentlab','run','--case',slot['case'],'--fault',slot['fault'],
            '--diagnostic-experts',str(slot.get('diagnostic_experts',2)),
            '--role-policy',slot.get('role_policy','shared'),
            '--verification',slot['verification'],'--restart',slot['restart'],
            '--max-calls',str(plan['max_calls_per_slot']),'--max-seconds',str(plan['max_seconds_per_slot']),
            '--output-root',str(output)]
        if stage1:
            command.extend(['--stage1',str(stage1)])
        state['slots'][slot['slot_id']]={'status':'dispatching','slot':slot,'command':command,'started':utc()}
        save(folder/'STATE.json',state)
        print('Running',slot['slot_id'],slot,flush=True)
        result=subprocess.run(command,check=False)
        receipts=list(output.glob('*/RECEIPT.json'))
        if len(receipts)!=1:
            raise RuntimeError('Slot has no unique terminal receipt; stop without retry')
        receipt=json.loads(receipts[0].read_text())
        state['model_calls']+=receipt.get('model_calls',0)
        entry=state['slots'][slot['slot_id']]
        entry.update(status='finished',exit_code=result.returncode,receipt=str(receipts[0]),finished=utc())
        branches=receipt.get('branches',[])
        halt=None
        if receipt.get('calls_with_unknown_usage',0):
            halt='API outcome or usage unknown'
        elif any(not b.get('cleanup',{}).get('verified',False) for b in branches):
            halt='database cleanup uncertain'
        elif receipt.get('error') or any(b['status']=='runtime_error' for b in branches):
            halt='runtime/infrastructure error'
        entry['halt_reason']=halt
        state['elapsed_seconds']=elapsed_before+time.monotonic()-started
        save(folder/'STATE.json',state)
        if halt:
            raise RuntimeError(halt+'; stop without retry')
    state['stop_reason']='all_scheduled_slots_processed'
    save(folder/'STATE.json',state)
    print('Campaign processed:',len(state['slots']),'slots; calls:',state['model_calls'])
    return 0


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    plan_parser=sub.add_parser('plan',help='Offline only; writes a new plan, sends no API requests')
    plan_parser.add_argument('--output',type=Path,required=True)
    plan_parser.add_argument('--suite',choices=['basic','cdfhk'],default='basic',
                             help='cdfhk fixes nine case/fault pairs including clean controls and timeout')
    plan_parser.add_argument('--diagnostic-experts',type=int,nargs='+',choices=[1,2],default=[2],
                             help='Use 1 for merged diagnostician; 1 2 creates paired count conditions')
    plan_parser.add_argument('--role-policy',nargs='+',choices=['shared','separated'],default=['shared'])
    plan_parser.add_argument('--cases',nargs='+',choices=CASES,default=['inventory_lock'])
    plan_parser.add_argument('--faults',nargs='+',choices=FAULTS,
                             default=['clean','pid_swap','instruction'])
    plan_parser.add_argument('--modes',nargs='+',choices=['none','plan','always'],default=None)
    plan_parser.add_argument('--repeats',type=int,default=1)
    plan_parser.add_argument('--seed',type=int,default=17)
    plan_parser.add_argument('--full-restart',action='store_true')
    execute_parser=sub.add_parser('execute',help='Real API calls; explicit aggregate caps required')
    execute_parser.add_argument('folder',type=Path)
    execute_parser.add_argument('--max-total-calls',type=int,required=True)
    execute_parser.add_argument('--max-total-seconds',type=int,required=True)
    execute_parser.add_argument('--stage1',type=Path)
    args=parser.parse_args()
    if args.command=='plan':
        if not 1<=args.repeats<=20:
            parser.error('repeats must be 1..20')
        modes=args.modes or (['plan'] if args.suite=='cdfhk' else ['none','plan','always'])
        try:
            plan=(make_extended_plan(modes,args.repeats,args.seed,args.full_restart,args.diagnostic_experts,args.role_policy) if args.suite=='cdfhk'
                  else make_plan(args.cases,args.faults,modes,args.repeats,args.seed,args.full_restart,args.diagnostic_experts,args.role_policy))
        except ValueError as exc:
            parser.error(str(exc))
        args.output.mkdir(parents=True,exist_ok=False)
        save(args.output/'PLAN.json',plan)
        (args.output/'PLAN.sha256').write_text(hashlib.sha256((args.output/'PLAN.json').read_bytes()).hexdigest()+'\n')
        print('Offline plan saved:',args.output/'PLAN.json')
        print('Scheduled slots:',len(plan['slots']),'; worst-case call cap:',len(plan['slots'])*plan['max_calls_per_slot'])
        print('No model calls, database creation, or training performed.')
        return 0
    if args.max_total_calls<48 or args.max_total_seconds<900:
        parser.error('execution caps must allow at least one full slot (48 calls, 900 seconds)')
    return execute(args.folder.expanduser().resolve(),args.max_total_calls,args.max_total_seconds,args.stage1)


if __name__=='__main__':
    raise SystemExit(main())
