"""Bounded fake-HTTP cap exercise; no fit, model, key or sockets."""
from pathlib import Path
import json
from agent_recovery.contracts import canonical_json
from agent_recovery.p3_transport import FakeHTTPSender,HTTPRequest
from agent_l_v1.core import BUNDLES,save
from .budget import Budget,FakeClock
from .protocol import Config,UNITS,history
from .model import Model,bound_counter
from .gateway import Gateway,Billing
from .fixtures import Service


class SyntheticCounter:
    """Dependency-free test double, never a tokenizer/native acceptance."""
    def estimate_request(self,req):
        class Value:prompt_tokens=100
        return Value()
    def request_statistics(self,req):
        return {'fixture_only':True,'count_scope':'all-wire-messages-test-double','prompt_tokens':100,
                'message_count':len(req['messages']),'input_messages_dropped':0,'server_wrapping_verified':False}


def messages(role):
    system={'role':role,'task':{'feature_cap':11,'optimization_remaining':1,'quality_AP_ratio_goal':1.25,'phase':'initial'}}
    m=[{'role':'system','content':canonical_json(system)}]
    if role=='Analyst':
        m += [{'role':'tool','content':canonical_json({'tool':'read_schema','value':{'row_count':41188,'columns':BUNDLES['D1'],'prediction_time':'pre_call'}})},
              {'role':'tool','content':canonical_json({'tool':'read_profile','value':{'training_rows':24712}})}]
    else:
        m += [{'role':'user','content':canonical_json({'payload':{'eligible_features':BUNDLES['D1']}})},
              {'role':'tool','content':canonical_json({'tool':'list_recipes','value':{}})}]
    return m


def cap_exercise(output,history_path,local=None):
    root=Path(output);root.mkdir(parents=True,exist_ok=False)
    h=history(history_path);clock=FakeClock();ledger=Budget(root/'authority.sqlite',config=Config(),historical=h,clock=clock)
    local=local or SyntheticCounter();counter,stats=bound_counter(local,simulated=True)
    service=Service(local);post=FakeHTTPSender([service.post]*62);get=FakeHTTPSender([service.get]*96)
    model=Model(post,token_counter=counter,token_statistics=stats);billing=Billing(ledger,fake_sender=get);g=Gateway(model,ledger,billing)
    try:
        seq,_=ledger.begin_http('CATALOG','GET','catalog','CAP.CATALOG')
        get.send(HTTPRequest('GET','https://tritonai-api.ucsd.edu/public/model_hub',b'',12));ledger.end_http(seq)
        for uid,cap in UNITS.items():
            ledger.start_unit(uid);billing.start(uid);service.unit=uid
            for n in range(cap):
                role='Analyst' if cap>1 and n<5 else 'Planner'
                g.call(role,messages(role),unit=uid,call_id=uid+'.llm.'+str(n).zfill(4))
            for n in range(3):billing.read(uid,'close',uid+'.EXTRA_CLOSE.'+str(n))
            if uid!=list(UNITS)[-1]:ledger.finish_unit(uid)
        assert post.request_count==62 and get.request_count==95
        before=post.request_count
        try:g.call('Planner',messages('Planner'),unit=uid,call_id=uid+'.llm.0001')
        except Exception as exc:gen_code=getattr(exc,'code',str(exc))
        else:raise AssertionError('63rd generation was admitted')
        assert post.request_count==before
        before=get.request_count
        try:billing.read(uid,'receipt',uid+'.GET96')
        except Exception as exc:get_code=getattr(exc,'code',str(exc))
        else:raise AssertionError('96th GET was admitted')
        assert get.request_count==before
        result={'passed':True,'synthetic_load_not_task_success':True,'generation_attempts':62,'GET_attempts':95,
            'generation_63_rejected':gen_code,'GET_96_rejected':get_code,'real_API_calls':0,'real_key_reads':0,
            'model_fits':0,'risk_policy':'serial 0.50 USD until usage and posting reconcile'}
        save(root/'RESULT.json',result);save(root/'LEDGER.json',ledger.snapshot());return result
    finally:ledger.close()
