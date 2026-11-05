"""One reserve/POST/usage/billing settlement; no automatic request retry."""
from copy import deepcopy
from decimal import Decimal
import json
from time import monotonic

from agent_recovery.contracts import canonical_json, digest, require
from agent_recovery.p3_transport import HTTPRequest, FakeHTTPSender
from context_cutoff.bank_billing import _read_isolated
from .protocol import MODEL,UNITS


# Relative to the first unposted receipt, not a new unit deadline. These are
# polling offsets, not an assertion about the provider's posting latency.
POSTING_WAIT_SECONDS = (8., 24., 60.)


class Billing:
    def __init__(self,ledger,*,fake_sender=None,credential_provider=None):
        self.ledger=ledger;self.sender=fake_sender;self.provider=credential_provider
        self.expected=Decimal(ledger.historical['expected_key_spend_nano']);self.receipts=[];self.baselines={};self.waits=[]

    def read(self,unit,phase,identity):
        seq,end=self.ledger.begin_http(unit,'GET',phase,identity)
        try:
            if self.sender is not None:
                require(type(self.sender) is FakeHTTPSender,'Only explicit fake metadata sender','LAPI_BILLING')
                r=self.sender.send(HTTPRequest('GET','https://tritonai-api.ucsd.edu/key/info',b'',min(12,end-self.ledger.clock.mono())))
                require(r.status==200,'Billing HTTP error including 429','LAPI_BILLING_HTTP')
                v=json.loads(r.body);s={'spend_nano':str(v['spend_nano']),'max_budget_nano':str(v['max_budget_nano'])}
            else:
                packet=_read_isolated(self.provider,monotonic()+min(12,end-self.ledger.clock.mono()))
                require(packet.get('ok') and packet['cleanup']['worker_reaped'],'Billing worker/HTTP failed','LAPI_BILLING_HTTP')
                s=packet['snapshot']
            self.ledger.end_http(seq)
            require(Decimal(s['max_budget_nano'])>Decimal(s['spend_nano']),'Provider key budget exhausted','LAPI_KEY_BUDGET')
            self.receipts.append({'unit':unit,'phase':phase,'snapshot':s,'identity':identity})
            return s
        except Exception:
            row=self.ledger.connection.execute('SELECT state FROM lapi_http WHERE seq=?',(seq,)).fetchone()
            if row['state']=='started':self.ledger.end_http(seq,failed=True)
            self.ledger.quarantine(None,'LAPI_BILLING_FAILED');raise

    def start(self,unit):
        s=self.read(unit,'baseline',unit+'.BASELINE')
        require(abs(Decimal(s['spend_nano'])-self.expected)<=1,'Unexplained inherited spend/reset','LAPI_BILLING_MISMATCH')
        self.baselines[unit]=s

    def confirm(self,unit,call_id,cost):
        target=self.expected+cost
        s=self.read(unit,'receipt',call_id+'.GET')
        own=self.baselines[unit]
        def matched(v):
            amount=Decimal(v['spend_nano'])
            require(Decimal(v['max_budget_nano'])==Decimal(own['max_budget_nano'])
                and self.expected-1<=amount<=target+1,'Mismatched spend or key budget changed','LAPI_BILLING_MISMATCH')
            return abs(amount-target)<=1
        okay=matched(s)
        wait_started=self.ledger.clock.mono()
        local_waits=0
        # No next POST while this receipt is unposted. At most three close GETs
        # across the whole unit, all inside its original 240-second deadline.
        while not okay:
            used=sum(r['unit']==unit and r['phase']=='close' for r in self.ledger.http_rows())
            require(used<3,'Posting still pending after bounded wait','LAPI_BILLING_PENDING')
            # Spread the existing queries over the remaining original window.
            # Never spend all three immediately, extend a deadline, or reopen
            # an old/quarantined authority. Leave room for the bounded GET and
            # cleanup. If the window is short, the last query moves earlier.
            self.ledger.require_time(unit,13)
            before=self.ledger.clock.mono()
            planned=max(0.,wait_started+POSTING_WAIT_SECONDS[local_waits]-before)
            delay=min(planned,max(0.,self.ledger.remaining(unit)-13))
            event={'unit':unit,'call_id':call_id,'close_number':used+1,
                'offset_seconds':POSTING_WAIT_SECONDS[local_waits],
                'remaining_before':self.ledger.remaining(unit),'wait_seconds':delay,
                'mono_started':before,'original_deadline_extended':False}
            self.waits.append(event)
            self.ledger.clock.sleep(delay)
            event['mono_finished']=self.ledger.clock.mono()
            event['remaining_after']=self.ledger.remaining(unit)
            self.ledger.require_time(unit,12)
            local_waits+=1
            s=self.read(unit,'close',unit+'.CLOSE.'+str(used+1));okay=matched(s)
        self.expected=target
        return {'reconciled':True,'expected_nano':str(target),'observed_nano':s['spend_nano'],
                'provider_invoice_verified':False,'original_deadline_extended':False}


class Gateway:
    def __init__(self,model,ledger,billing):self.model=model;self.ledger=ledger;self.billing=billing

    def call(self,role,messages,*,unit,call_id,exact_wire=None,result_id=None):
        self.ledger.require_time(unit,15)
        prepared=self.model.prepare(role,deepcopy(messages))
        if exact_wire is not None:require(prepared.request==exact_wire,'Calibration request changed','LAPI_CAL_WIRE')
        record={'call_id':call_id,'attempt_id':call_id+'.attempt','trial_key':unit+'.'+role,
            'logical_run_key':unit,'branch_id':unit,'run_id':unit,'result_id':result_id or call_id+'.result','step_id':role,
            'phase':'probe' if '.CAL_' in unit else ('replay' if unit.startswith('LI01.') and not unit.endswith('PREFIX') else 'initial'),
            'input_token_upper_bound':4000,'request':prepared.request,'sidecar':prepared.sidecar}
        admitted=self.ledger.reserve(record)
        if not admitted['dispatch_allowed']:
            require(admitted['status']=='settled' and admitted['evidence'] and 'payload' in admitted['evidence'],
                'Only successful duplicate may return saved result','LAPI_DUPLICATE')
            return {**admitted['evidence'],'replayed':True}
        seq=None
        try:
            seq,end=self.ledger.begin_http(unit,'GEN','generation',call_id)
            duration=end-self.ledger.clock.mono()
            exchange=self.model.exchange(prepared,before_send=lambda:self.ledger.mark_dispatched(call_id),
                deadline_monotonic=monotonic()+min(120,duration))
            self.ledger.end_http(seq)
            usage=exchange.usage
            cost=usage['prompt_tokens']*150+usage['completion_tokens']*500
            billing=self.billing.confirm(unit,call_id,cost)
            evidence={'kind':'l-api-exchange-v1','payload':exchange.payload,'wire_audit':exchange.audit,
                'billing':billing,'fixture_only':self.model.fixture_only,'usage_is_synthetic':self.model.fixture_only}
            self.ledger.settle(call_id,provider_request_id=exchange.provider_request_id,
                raw_usage=usage['raw'],normalized_usage=usage,evidence=evidence)
            return {**deepcopy(evidence),'usage':usage,'call_id':call_id,'replayed':False}
        except Exception as exc:
            if seq is not None:
                row=self.ledger.connection.execute('SELECT state FROM lapi_http WHERE seq=?',(seq,)).fetchone()
                if row and row['state']=='started':
                    try:self.ledger.end_http(seq,failed=True)
                    except Exception:pass
            # Even priced but unposted usage cannot silently release the risk.
            try:
                audit=getattr(exc,'audit',None) or (self.model.traces[-1] if self.model.traces else {})
                evidence={'kind':'l-api-failed-exchange-v1','error':getattr(exc,'code',type(exc).__name__),
                    'wire_audit':deepcopy(audit),'fixture_only':self.model.fixture_only}
                price_failure=getattr(self.billing,'price_failed_response',None)
                priced=price_failure(unit,call_id,evidence) if price_failure else False
                if not priced:self.ledger.attach_evidence(call_id,evidence)
            finally:self.ledger.quarantine(call_id,getattr(exc,'code',type(exc).__name__))
            raise
