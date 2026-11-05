"""Explicit fake HTTP service: scripted decisions and synthetic usage only."""
from decimal import Decimal
import json

from agent_recovery.p3_transport import HTTPResponse, fake_http_response
from agent_recovery.contracts import canonical_json
from agent_l_v1.core import BUNDLES
from .protocol import MODEL


class Service:
    def __init__(self,local):
        self.local=local;self.unit='';self.sent=0;self.spend=Decimal('250062750.00000000')

    def post(self,request):
        req=json.loads(request.body);messages=[]
        for i,m in enumerate(req['messages']):
            value={'role':m['role'],'content':m['content']}
            if i==0:value['content']=m['content'].split('\n',1)[0]
            elif m['role']=='user':
                content=json.loads(m['content'])
                if content.get('source_role')=='tool':value={'role':'tool','content':content['content']}
            messages.append(value)
        task=json.loads(messages[0]['content'])['task'];role=json.loads(messages[0]['content'])['role']
        tools=[json.loads(m['content']) for m in messages if m['role']=='tool']
        values=[json.loads(m['content']).get('payload',{}) for m in messages if m['role']=='user']
        if role=='Analyst':
            if not tools:payload={'tool':'read_schema','arguments':{}}
            elif len(tools)==1:payload={'tool':'read_profile','arguments':{}}
            else:
                schema=tools[0]['value'];payload={'final':{'row_count':schema['row_count'],'eligible_features':schema['columns'],
                    'prediction_time':schema['prediction_time'],'profile':tools[1]['value']}}
        elif role=='Planner':
            if not tools:payload={'tool':'list_recipes','arguments':{}}
            else:
                facts=next(v for v in values if 'eligible_features' in v)
                feedback=next((v for v in values if v.get('action')=='adjust'),None)
                allowed=[k for k,v in BUNDLES.items() if set(v)<=set(facts['eligible_features']) and len(v)<=task['feature_cap']]
                selection=feedback['requested_selection'] if feedback else {'bundle':max(allowed,key=lambda k:len(BUNDLES[k])),
                    'recipe':'RF' if self.unit=='LC02' else 'LR'}
                payload={'final':selection}
        else:
            view=next(v for v in values if v.get('assessment_kind')=='screen')
            if view['metrics']['average_precision']>=task['quality_AP_ratio_goal']*view['constant_AP']:
                final={'action':'accept'}
            elif task['optimization_remaining']:
                final={'action':'adjust','requested_selection':{'bundle':'D1','recipe':'LR' if view['selection']['recipe']=='RF' else 'RF'}}
            else:final={'action':'stop'}
            payload={'final':{**final,'evidence_id':view['receipt_id'],'reason':'Evidence checked by the HTTP fixture; wording is deliberately free.'}}
        self.sent+=1
        prompt=self.local.estimate_request(req).prompt_tokens
        self.spend+=prompt*150+200*500
        return fake_http_response(payload,model=MODEL,prompt_tokens=prompt,completion_tokens=200,
            request_id='fixture-l-api-'+str(self.sent),headers={'content-type':'application/json','x-litellm-call-id':'fixture-l-api-'+str(self.sent)})

    def get(self,request):
        if request.url.endswith('/public/model_hub'):
            return HTTPResponse(200,{},canonical_json({'model':MODEL,'input_nano':150,'output_nano':500,'fixture_only':True}).encode())
        return HTTPResponse(200,{},canonical_json({'spend_nano':str(self.spend),'max_budget_nano':'25000000000'}).encode())
