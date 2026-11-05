"""Same L-tier tools and provenance, with injected accounted HTTP decisions."""
from copy import deepcopy
import math

from agent_l_v1.core import BUNDLES, RECIPES, DATA, TASK, PUBLICATION, PERMISSION, ref
from agent_l_v1.runtime import AgentLoop
from agent_l_v3.runtime import UnifiedLoop
from agent_recovery.contracts import require
from sr_recovery_v2.common import canonical,digest
from .model import validate


class APILoop(UnifiedLoop):
    def __init__(self,*args,gateway,unit,**kwargs):
        self.gateway,self.unit=gateway,unit
        kwargs['remaining_seconds']=gateway.ledger.remaining(unit)
        super().__init__(*args,**kwargs)
        self.model=gateway.model
        self.doc.update(revision='l-api-first-v1',decision_backend='fake-HTTP' if self.model.fixture_only else 'TritonAI',
            llm_fixture_only=self.model.fixture_only,http_unit=unit,new_API_request_cap=10)

    def initialize(self,inputs,feature_cap=11,**kwargs):
        super().initialize(inputs,feature_cap,**kwargs)
        before,task=self.read(TASK);task.pop('initial_bundle',None)
        task['review_policy']='bounded-accept-adjust-stop-with-evidence-and-free-reason'
        self.store.write(TASK,canonical(task),before,'bootstrap-live-protocol')

    def _call(self,role,messages,*,fault=False):
        self.gateway.ledger.require_time(self.unit,15)
        cid=self.unit+'.llm.'+str(len(self.doc['llm_calls'])-self.doc['inherited_call_count']).zfill(4)
        predicted=self.scope+'.node.'+str(self.node_counter).zfill(4)
        with self.timing.span('accounted_HTTP_and_billing'):
            exchange=self.gateway.call(role,messages,unit=self.unit,call_id=cid,result_id=predicted)
        raw=exchange['payload'];parents=[m['producer_result_id'] for m in messages if m.get('producer_result_id')]
        node=self.node('llm',role,raw,parents,[m['source_ref'] for m in messages if m.get('source_ref')])
        require(node['result_id']==predicted,'Call result identity differs','LAPI_NODE')
        self.doc['llm_calls'].append({'call_id':cid,'role':role,'node_id':node['result_id'],'messages':deepcopy(messages),
            'prompt_sha256':digest(messages),'raw':deepcopy(raw),'delivered':deepcopy(raw),
            'fixture_only':self.model.fixture_only,'usage':exchange['usage'],'wire_audit':exchange['wire_audit']})
        if not fault or role!='Analyst' or 'final' not in raw:return node,raw
        require(fault=='INCIDENTAL_ROW_COUNT','Only first-batch fault is registered','LAPI_SCOPE')
        delivered=deepcopy(raw);delivered['final']['row_count']+=1
        n=self.node('fault_delivery','Analyst',delivered,[node['result_id']],original_result_id=node['result_id'])
        event={'type':fault,'faulty_result_id':n['result_id'],'original_result_id':node['result_id'],
            'raw':deepcopy(raw),'delivered':delivered}
        self.doc['faults'].append(event);self.doc['delivery_events'].append(deepcopy(event))
        return n,delivered

    def review(self,bound,screen):
        reviewed=AgentLoop.review(self,bound,screen)
        v=validate('Reviewer',reviewed['payload'])['final']
        _,task=self.read(TASK);view=self.screen_view(bound,screen)
        ap,base=view['metrics']['average_precision'],view['constant_AP']
        require(math.isfinite(ap) and math.isfinite(base) and base>0,'Bad metrics','LAPI_REVIEW')
        meets=ap>=task['quality_AP_ratio_goal']*base
        if v['action']=='accept':require(meets,'Cannot accept below goal','LAPI_REVIEW')
        elif v['action']=='adjust':
            s=v['requested_selection']
            require(not meets and self.doc['optimization_spent']==0 and s!=bound['payload']['selection']
                and len(BUNDLES[s['bundle']])<=task['feature_cap'],'Invalid or exhausted adjustment','LAPI_REVIEW')
        else:require(not meets,'Unnecessary quality stop above fixed goal','LAPI_REVIEW')
        return reviewed

    def finish(self,analyst,bound,*,retained_screen=None,retained_final=None):
        screen=retained_screen if retained_screen else self.train(bound,'screen')
        self.doc['active']['screen']=screen
        reviewed=self.review(bound,screen)
        if reviewed['payload']['final']['action']=='adjust':
            require(self.doc['optimization_spent']==0,'Normal quota exhausted','LAPI_REVIEW')
            self.doc['optimization_spent']=1
            self.event('normal_adjustment_consumed',total=1,remaining=0)
            previous=bound['payload']['selection']
            planner=self.role('Planner',[('facts',analyst,analyst['payload']['final']),('feedback',reviewed,reviewed['payload']['final'])])
            bound=self.bind(planner)
            require(bound['payload']['selection']!=previous,'Adjustment repeated same candidate','LAPI_REVIEW')
            screen=self.train(bound,'screen');reviewed=self.review(bound,screen);retained_final=None
        if reviewed['payload']['final']['action']=='stop':
            self.doc['stop_reason']='REVIEW_QUALITY_NOT_MET';return False
        require(reviewed['payload']['final']['action']=='accept','Second adjustment forbidden','LAPI_REVIEW')
        if callable(retained_final):retained_final=retained_final(bound,reviewed)
        if retained_final is None:self.train(bound,'final')
        else:self.doc['active']['final']=retained_final
        self.capture_guard_refs();return True

    def publish(self,**kwargs):
        self.gateway.ledger.require_time(self.unit,1)
        with self.timing.span('publication'):
            permission_ref,permission=self.read(PERMISSION)
            require(permission['publish_allowed'],'Publication denied','L_PUBLISH_PERMISSION')
            require(not ref(self.store.read(PUBLICATION))['writer_id'].startswith('external'),'External owner','L_EXTERNAL_OWNER')
            bound,model=self.doc['active']['contract'],self.doc['active']['final']
            _,data=self.read(DATA);self.cpu.validate(model['payload'],bound['payload']['contracts']['final'],'final',data)
            require(permission_ref in self.guard_refs,'Permission changed','L_PERMISSION_CHANGED_AFTER_CHECK')
            report={'selection':bound['payload']['selection'],'contract_sha256':digest(model['payload']['contract']),
                'producer_id':model['payload']['producer_id'],'outer_metrics':model['payload']['metrics']['validation'],
                'llm_fixture_only':self.model.fixture_only,'cpu_fixture_only':self.cpu.fixture_only}
            self.store.write_checked(PUBLICATION,canonical(report),self.expected_publication,self.scope,self.guard_refs)
            self.doc['active']['publication']=self.node('publish','executor',report,
                [bound['result_id'],model['result_id'],self.doc['active']['review']['result_id']],self.guard_refs)

    def export(self,outcome,**extra):
        # The inherited file stores the conservative intersection of both clocks.
        from datetime import datetime,timedelta,timezone
        remaining=max(0.,self.gateway.ledger.remaining(self.unit))
        self.deadline=min(self.deadline,datetime.now(timezone.utc)+timedelta(seconds=remaining))
        return super().export(outcome,**extra)
