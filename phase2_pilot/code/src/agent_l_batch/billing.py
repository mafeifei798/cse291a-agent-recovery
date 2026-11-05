"""No per-call GET: local usage estimates and a bounded batch-end observation."""
from decimal import Decimal
from copy import deepcopy
import json
from time import monotonic
from agent_recovery.contracts import canonical_json,require
from agent_recovery.p3_transport import FakeHTTPSender,HTTPRequest
from context_cutoff.bank_billing import _read_isolated

class Billing:
    def __init__(self,ledger,*,fake_sender=None,credential_provider=None):
        self.ledger=ledger;self.sender=fake_sender;self.provider=credential_provider
        self.expected=Decimal(ledger.historical['expected_key_spend_nano'])
        self.receipts=[];self.waits=[];self.baseline=None;self.result=None

    def read(self,phase,number=0,*,end_mono=None,end_wall=None):
        seq,end=self.ledger.begin_metadata(phase,'BATCH.'+phase+'.'+str(number),end_mono=end_mono,end_wall=end_wall)
        try:
            if self.sender is not None:
                require(type(self.sender) is FakeHTTPSender,'Explicit fake sender required','LB_METADATA')
                r=self.sender.send(HTTPRequest('GET','https://tritonai-api.ucsd.edu/key/info',b'',end-self.ledger.clock.mono()))
                require(r.status==200,'Metadata HTTP failure including 429','LB_METADATA_HTTP')
                s=json.loads(r.body)
            else:
                p=_read_isolated(self.provider,monotonic()+min(12,end-self.ledger.clock.mono()))
                require(p.get('ok') and p['cleanup']['worker_reaped'],'Metadata failed or unreaped','LB_METADATA_HTTP')
                s=p['snapshot']
            self.ledger.end_http(seq)
            a,b=Decimal(str(s['spend_nano'])),Decimal(str(s['max_budget_nano']))
            require(a.is_finite() and b.is_finite() and 0<=a<b,'Invalid/exhausted provider budget','LB_KEY_BUDGET')
            s={'spend_nano':str(a),'max_budget_nano':str(b)}
            self.receipts.append({'phase':phase,'number':number,'snapshot':s});return s
        except Exception:
            row=self.ledger.connection.execute('SELECT state FROM lapi_http WHERE seq=?',(seq,)).fetchone()
            if row['state']=='started':
                try:self.ledger.end_http(seq,failed=True)
                except Exception:pass
            raise

    def begin(self):
        require(self.ledger.batch_state()=='initial','No repeated preflight','LB_BATCH_CLOSED')
        s=self.read('baseline')
        require(abs(Decimal(s['spend_nano'])-self.expected)<=1,'Unexplained baseline/reset','LB_BILLING_MISMATCH')
        require(Decimal(s['max_budget_nano'])-Decimal(s['spend_nano'])>=min(500000000,self.ledger.config['limits']['max_cost_nano_usd']),
            'Insufficient provider headroom at batch start','LB_KEY_BUDGET')
        self.baseline=s
        self.ledger.batch_transition('running',{'baseline':s});return s

    def start(self,unit):
        require(self.baseline is not None and self.ledger.batch_state()=='running','No preflight','LB_BASELINE')

    def confirm(self,unit,call_id,cost):
        # Gateway subsequently validates and durably settles the full raw usage.
        # No provider posting assertion, metadata read, wait, or old-hold release.
        self.ledger.require_time(unit)
        self.expected+=cost
        return {'local_usage_priced':True,'local_estimate_nano':cost,'reconciled':False,
            'provider_invoice_verified':False,'posting_state':'deferred_to_batch_end','GETs':0}

    def price_failed_response(self,unit,call_id,evidence):
        # A bad agent JSON answer can still have a valid, billable receipt.
        # Only this post-usage-validation error is priced. Timeouts, missing
        # usage, wrong model/identity and bounds failures retain the full risk.
        a=evidence['wire_audit']
        if evidence['error']!='CTX_MODEL_SCHEMA' or a.get('status')!=200 or not a.get('usage') or not a.get('request_id'):
            return False
        u=a['usage'];cost=u['prompt_tokens']*150+u['completion_tokens']*500
        e=deepcopy(evidence);e.update(billing=self.confirm(unit,call_id,cost),
            task_output_valid=False,usage_is_synthetic=bool(a['fixture_only']))
        self.ledger.settle(call_id,provider_request_id=a['request_id'],raw_usage=u['raw'],normalized_usage=u,evidence=e)
        return True

    def finish(self):
        require(self.result is None and self.ledger.batch_state()=='running','No repeated batch close','LB_BATCH_CLOSED')
        begin_m=self.ledger.clock.mono();begin_w=self.ledger.clock.wall()
        end_m=begin_m+30;end_w=begin_w+30
        calls=self.ledger.calls();known=sum(c['known_cost_nano_usd'] for c in calls if c['status']=='settled')
        target=Decimal(self.baseline['spend_nano'])+known
        result={'state':'pending','local_priced_nano':known,'expected_spend_nano':str(target),
            'provider_invoice_verified':False,'old_holds_released':False,'automatic_expansion_allowed':False,
            'completed_workflow_outcomes_unchanged':True,'close_GETs':0}
        try:
            if any(c['status']!='settled' for c in calls):result['state']='unknown_usage';return result
            for i,offset in enumerate((0,8,20),1):
                delay=max(0.,begin_m+offset-self.ledger.clock.mono())
                if min(end_m-self.ledger.clock.mono(),end_w-self.ledger.clock.wall())<=delay+2:
                    result['state']='timeout';break
                self.ledger.clock.sleep(delay)
                result['close_GETs']+=1
                s=self.read('close',i,end_mono=end_m,end_wall=end_w)
                value=Decimal(s['spend_nano']);base=Decimal(self.baseline['spend_nano'])
                if s['max_budget_nano']!=self.baseline['max_budget_nano'] or value<base-1 or value>target+1:
                    result['state']='mismatch';break
                if abs(value-target)<=1:result['state']='aggregate_reconciled';break
        except Exception as exc:
            result.update(state='metadata_failure',error=getattr(exc,'code',type(exc).__name__))
        finally:
            result['elapsed_seconds']=self.ledger.clock.mono()-begin_m
            result['observations']=self.receipts
            self.result=result;self.expected=target
            self.ledger.batch_transition(result['state'],result)
        return result

    def snapshot(self):
        return {'mode':'usage-priced-then-batch-reconciled','receipts':self.receipts,
            'expected_nano':str(self.expected),'result':self.result,'provider_invoice_verified':False}
