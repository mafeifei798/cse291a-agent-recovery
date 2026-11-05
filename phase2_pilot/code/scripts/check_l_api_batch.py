#!/usr/bin/env python3
"""Independent read-only batch ledger, raw usage, lineage and saved-array audit."""
import argparse,hashlib,json,sys
from decimal import Decimal
from pathlib import Path
sys.dont_write_bytecode=True
from check_l_api_pilot import check as workflow_check,digest,sha

def profile(resume_mode=False,feedback_mode=False):
    assert not (resume_mode and feedback_mode)
    if feedback_mode:
        return dict(folder='l_feedback_api_20261031_v1',known=250726250,first=500843400,
            bank=314,project=2792,used=12,cap=64,old_GETs=18,clean='LC04',retired=('LC01','LC02','LC03'))
    if resume_mode:
        return dict(folder='l_api_resume_20261031_v1',known=250247350,first=500364500,
            bank=308,project=2786,used=6,cap=62,old_GETs=12,clean='LC02',retired=('LC01','LC03'))
    return dict(folder='l_api_batch_20261031_v1',known=249882850,first=500000000,
        bank=303,project=2781,used=1,cap=62,old_GETs=7,clean='LC03',retired=('LC01',))

def check_stopped(root,source,*,resume_mode=False,feedback_mode=False):
    """Validate a stopped dispatch/accounting trace; never call it recovery success."""
    root=Path(root);source=Path(source)
    s=json.loads((root/'ENTRY_RESULT.json').read_text());v=json.loads((root/'LEDGER.json').read_text())
    assert s['business_status']!='complete' or s['accounting_status'] not in ('aggregate_reconciled','pending')
    p=profile(resume_mode,feedback_mode)
    h=json.loads((source/'phase2'/p['folder']/'HISTORY.json').read_text())
    assert digest({k:x for k,x in h.items() if k!='sha256'})==v['L_budget']['history_sha256']==h['sha256']
    assert all(sha(source/n)==x for n,x in h['source_files'].items())
    old={r['call_id'] for r in h['receipts']};calls=v['calls'];known=held=0
    expected_known=p['known'];prior_first=p['first']
    for c in calls:
        assert c['call_id'] not in old and c['run_id'] not in p['retired']
        if c['status']=='settled':
            u=c['usage'];raw=u['raw']
            assert u['prompt_tokens']==raw['prompt_tokens'] and u['completion_tokens']==raw['completion_tokens']
            assert raw['total_tokens']==raw['prompt_tokens']+raw['completion_tokens']
            assert 0<=raw['prompt_tokens']<=4000 and 0<=raw['completion_tokens']<=768
            assert c['held_cost_nano_usd']==0 and c['known_cost_nano_usd']==raw['prompt_tokens']*150+raw['completion_tokens']*500
        else:assert c['held_cost_nano_usd']==c['reserved_cost_nano_usd'] and c['known_cost_nano_usd']==0
        known+=c['known_cost_nano_usd'];held+=c['held_cost_nano_usd']
    b=v['L_budget'];assert b['project_known_nano']==expected_known+known
    assert b['project_held_nano']==1003252000+held and b['L_held_nano']==500000000+held
    assert b['first_occupied_nano']==prior_first+known+held<=b['first_cap_nano']
    assert len(calls)+p['used']<=p['cap'] and b['Bank_historical_calls']==p['bank']
    assert s['accounting_status'] not in ('initial','running') and not s['old_LC01_restarted'] and not s['old_holds_released']
    assert sum(x['kind']=='GET' for x in v['http'])<=4
    return {'passed':True,'audit_scope':'stopped request and budget evidence only','recovery_success_claimed':False,
        'business_status':s['business_status'],'accounting_status':s['accounting_status'],
        'calls_recorded':len(calls),'locally_priced_nano':known,'new_held_nano':held,
        'historical_held_nano':1003252000,'old_LC01_restarted':False,'model_loads':0,'fits':0,'predict_calls':0}

def check(root,source,require_native=False,*,resume_mode=False,feedback_mode=False):
    root=Path(root);source=Path(source)
    result=workflow_check(root/'campaign',source,require_native,batch_mode=True,resume_mode=resume_mode,feedback_mode=feedback_mode)
    final=json.loads((root/'LEDGER.json').read_text())
    campaign=json.loads((root/'campaign/LEDGER.json').read_text())
    assert final['calls']==campaign['calls']
    p=profile(resume_mode,feedback_mode)
    h=json.loads((source/'phase2'/p['folder']/'HISTORY.json').read_text())
    assert digest({k:v for k,v in h.items() if k!='sha256'})==h['sha256']==final['L_budget']['history_sha256']
    assert all(sha(source/n)==v for n,v in h['source_files'].items())
    ids={r['call_id'] for r in h['receipts']};provider_ids={r['provider_request_id'] for r in h['receipts']}
    assert len(ids)==p['bank'] and h['project_dispatches']==p['project']
    assert not ids&{c['call_id'] for c in final['calls']}
    assert not provider_ids&{c['provider_request_id'] for c in final['calls']}
    assert not set(p['retired']) & {v['unit'] for v in final['units']}
    assert next(v for v in final['units'] if v['unit']==p['clean'])['state']=='complete'
    assert len(final['calls'])+p['used']<=p['cap']
    known=sum(c['known_cost_nano_usd'] for c in final['calls'])
    b=final['L_budget'];assert b['first_occupied_nano']==p['first']+known<=b['first_cap_nano']
    assert b['L_held_nano']==500000000 and b['project_held_nano']==1003252000
    assert b['project_known_nano']==p['known']+known and final['real_cost_usd'] is None
    accounting=json.loads((root/'BATCH_ACCOUNTING.json').read_text())['result']
    assert accounting['state']==final['batch_accounting']['state']
    assert accounting['local_priced_nano']==known and not accounting['old_holds_released']
    assert not accounting['provider_invoice_verified'] and not accounting['automatic_expansion_allowed']
    observations=accounting['observations']
    assert observations[0]['phase']=='baseline'
    assert Decimal(observations[0]['snapshot']['spend_nano'])==Decimal(h['expected_key_spend_nano'])
    target=Decimal(h['expected_key_spend_nano'])+known
    assert Decimal(accounting['expected_spend_nano'])==target
    if accounting['state']=='aggregate_reconciled':
        assert abs(Decimal(observations[-1]['snapshot']['spend_nano'])-target)<=1
    elif accounting['state']=='pending':
        assert all(Decimal(h['expected_key_spend_nano'])<=Decimal(o['snapshot']['spend_nano'])<target for o in observations[1:])
    else:raise AssertionError('Completed independent audit expects reconciled or pending, not silently ignored errors')
    gets=[r for r in final['http'] if r['kind']=='GET'];gens=[r for r in final['http'] if r['kind']=='GEN']
    assert len(gets)<=4 and all(r['unit']=='BATCH' for r in gets)
    assert gets[0]['phase']=='baseline' and all(r['phase']=='close' for r in gets[1:])
    assert gets[0]['seq']<gens[0]['seq'] and all(r['seq']>gens[-1]['seq'] for r in gets[1:])
    assert len(gets)+2<=6 and len(gets)+2+p['old_GETs']<=95
    assert accounting['elapsed_seconds']<=30 and accounting['close_GETs']==len(gets)-1
    result.update(batch_mode=True,GETs=len(gets),external_preflight_GET_reserve=2,
        accounting_status=accounting['state'],locally_priced_nano=known,
        inherited_Bank_attempts=p['bank'],first_total_generations=len(gens)+p['used'],
        old_LC01_restarted=False,old_holds_released=False,provider_invoice_verified=False)
    fixture_count=all(c['sidecar']['local_token_statistics'].get('fixture_only') for c in final['calls'])
    result.update(counter_fixture_only=fixture_count,full_wire_message_count_checked=True,
        local_full_message_counter_checked=not fixture_count)
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run',type=Path,required=True);p.add_argument('--source-root',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--require-native',action='store_true')
    p.add_argument('--stopped',action='store_true',help='Audit a stopped trace without claiming recovery completion')
    a=p.parse_args();r=check_stopped(a.run,a.source_root) if a.stopped else check(a.run,a.source_root,a.require_native)
    with a.output.open('x') as f:json.dump(r,f,indent=2,sort_keys=True);f.write('\n')
    print(json.dumps(r))

if __name__=='__main__':main()
