"""Reuse P3 durable accounting; inherited holds remain separate and immutable."""
from copy import deepcopy
from pathlib import Path
import json,sqlite3
from contextlib import contextmanager
from agent_recovery.contracts import canonical_json,digest,require
from agent_recovery.p3_budget import DurableP3Budget
from agent_l_api.budget import Budget as PriorBudget,Clock
from .protocol import Config,HISTORY_SHA,REGISTRATION_SHA,UNITS

class Budget(DurableP3Budget):
    config_type=Config
    history_pin=HISTORY_SHA
    registration_pin=REGISTRATION_SHA
    unit_caps=UNITS
    new_call_cap=61
    campaign_name='l-api-batch-v1'
    bounds=PriorBudget.bounds
    remaining=PriorBudget.remaining
    require_time=PriorBudget.require_time
    http_rows=PriorBudget.http_rows
    end_http=PriorBudget.end_http
    finish_unit=PriorBudget.finish_unit

    @contextmanager
    def _transaction(self):
        if self.connection.in_transaction:yield
        else:
            with super()._transaction():yield

    def __init__(self,path,*,config,historical,clock=None):
        require(isinstance(config,self.config_type) and historical['sha256']==self.history_pin
            and digest({k:v for k,v in historical.items() if k!='sha256'})==self.history_pin,'Latest history required','LB_HISTORY')
        path=Path(path).resolve()
        # Continuation always owns a new authority. Even a stopped new batch
        # cannot be reopened through this entry, nor can it adopt the old DB.
        require(not path.exists(),'Never reopen a prior authority','LB_AUTHORITY_EXISTS')
        self.launch_config=config;self.historical=deepcopy(historical);self.clock=clock or Clock()
        self.meta={'config':config.__dict__,'history':historical,'registration_sha256':self.registration_pin}
        self.meta_text=canonical_json(self.meta)
        available=min(config.first_cap_nano-historical['first_held_nano']-historical.get('first_known_nano',0),
            config.L_cap_nano-historical['L_held_nano']-historical.get('L_known_nano',0),
            config.project_cap_nano-historical['known_project_nano']-historical['project_held_nano'])
        require(available>0,'Inherited holds exhaust the budget','LB_MONEY_CAP')
        binding={'model':config.model,'input_nano_usd_per_token':150,'output_nano_usd_per_token':500,
            'cached_input_nano_usd_per_token':None,'price_evidence':('fixture:' if config.simulated else '')+'l-batch:'+config.catalog_sha256,
            'max_input_tokens':4000,'max_output_tokens':768,'simulated':config.simulated}
        super().__init__(path,campaign_id=self.campaign_name,binding=binding,
            limits={'call_cap':self.new_call_cap,'input_token_cap':self.new_call_cap*4000,'output_token_cap':self.new_call_cap*768,
                'max_cost_nano_usd':available,'slot_call_cap':5,'logical_call_cap':10})
        self.connection.executescript('''
          CREATE TABLE lapi_meta(body TEXT NOT NULL);
          CREATE TABLE lapi_units(unit TEXT PRIMARY KEY,body TEXT NOT NULL,state TEXT NOT NULL);
          CREATE TABLE lapi_http(seq INTEGER PRIMARY KEY,unit TEXT NOT NULL,kind TEXT NOT NULL,
            phase TEXT NOT NULL,identity TEXT UNIQUE NOT NULL,body TEXT NOT NULL,state TEXT NOT NULL);
          CREATE TABLE lb_batch(singleton INTEGER PRIMARY KEY,state TEXT NOT NULL,body TEXT NOT NULL);
          CREATE TRIGGER fixed_unit BEFORE UPDATE OF body ON lapi_units BEGIN SELECT RAISE(ABORT,'fixed deadline'); END;
          CREATE TRIGGER fixed_meta BEFORE UPDATE ON lapi_meta BEGIN SELECT RAISE(ABORT,'immutable'); END;
        ''')
        self._write('INSERT INTO lapi_meta VALUES(?)',(self.meta_text,))
        self._write("INSERT INTO lb_batch VALUES(1,'initial','{}')")

    def check_binding(self):
        current={'config':self.launch_config.__dict__,'history':self.historical,'registration_sha256':self.registration_pin}
        require(canonical_json(current)==self.meta_text and self.connection.execute('SELECT body FROM lapi_meta').fetchone()[0]==self.meta_text
            and digest(self.binding)==self.config['binding_digest'],'Budget binding changed','LB_BINDING')

    def batch_state(self):return self.connection.execute('SELECT state FROM lb_batch').fetchone()[0]
    def batch_transition(self,state,body):
        require(self.batch_state() in ('initial','running'),'Batch already closed','LB_BATCH_CLOSED')
        self._write('UPDATE lb_batch SET state=?,body=? WHERE singleton=1',(state,canonical_json(body)))

    def start_unit(self,unit,remaining=240.):
        self._assert_active();self.check_binding()
        require(self.batch_state()=='running' and unit in self.unit_caps and 0<remaining<=240,'Unregistered or inactive unit','LB_UNIT')
        require(not self.connection.execute('SELECT 1 FROM lapi_units WHERE unit=?',(unit,)).fetchone(),'Unit already started','LB_UNIT_STARTED')
        body={'wall_started':self.clock.wall(),'mono_started':self.clock.mono(),
            'wall_deadline':self.clock.wall()+remaining,'mono_deadline':self.clock.mono()+remaining,'duration':remaining}
        self._write('INSERT INTO lapi_units VALUES(?,?,?)',(unit,canonical_json(body),'active'));return body

    def _http(self,unit,kind,phase,identity,duration,end_mono=None,end_wall=None):
        rows=self.http_rows()
        if rows:self.clock.sleep(max(0.,rows[-1]['body']['mono_started']+2-self.clock.mono()))
        if kind=='GEN':self.require_time(unit,15);duration=min(duration,self.remaining(unit)-15)
        if end_mono is not None:
            duration=min(duration,end_mono-self.clock.mono()-1,end_wall-self.clock.wall()-1)
        require(duration>0,'Metadata total deadline expired','LB_METADATA_DEADLINE')
        body={'mono_started':self.clock.mono(),'wall_started':self.clock.wall(),'duration':duration,
            'deadline_mono':self.clock.mono()+duration,'deadline_wall':self.clock.wall()+duration}
        self._write('INSERT INTO lapi_http VALUES(?,?,?,?,?,?,?)',(len(rows)+1,unit,kind,phase,identity,canonical_json(body),'started'))
        return len(rows)+1,body['deadline_mono']

    def begin_http(self,unit,kind,phase,identity):
        self._assert_active();self.check_binding()
        require(kind=='GEN' and phase=='generation' and self.batch_state()=='running','No per-call metadata requests','LB_HTTP')
        self.require_time(unit,15)
        require(sum(r['kind']=='GEN' for r in self.http_rows())<self.new_call_cap,'New call cap exhausted','LB_CALL_CAP')
        return self._http(unit,kind,phase,identity,120)

    def begin_metadata(self,phase,identity,*,end_mono=None,end_wall=None):
        rows=self.http_rows();gets=[r for r in rows if r['kind']=='GET']
        # Two additional GETs are reserved outside this ledger for the bound
        # fresh catalog and model-permission receipts. Four here => six total.
        require(phase in ('baseline','close') and len(gets)<4,'Batch metadata cap','LB_GET_CAP')
        require(sum(r['phase']==phase for r in gets)<(3 if phase=='close' else 1),'Duplicate metadata query','LB_GET_CAP')
        require(self.batch_state()==('running' if phase=='close' else 'initial'),'Wrong accounting phase','LB_BATCH_CLOSED')
        return self._http('BATCH','GET',phase,identity,12,end_mono,end_wall)

    def reserve(self,record):
        unit=record.get('run_id');self.check_binding();self._assert_active()
        require(self.batch_state()=='running' and unit in self.unit_caps and record.get('step_id') in ('Analyst','Planner','Reviewer'),
            'Unknown continuation unit','LB_UNIT')
        require(record.get('call_id') not in {r['call_id'] for r in self.historical['receipts']},'Historical request is forbidden','LB_OLD_CALL')
        self.require_time(unit,15)
        with self._transaction():
            old=self.connection.execute('SELECT 1 FROM p3_calls WHERE call_id=?',(record['call_id'],)).fetchone()
            calls=self.calls()
            if not old:
                require(sum(c['run_id']==unit for c in calls)<self.unit_caps[unit],'Unit call cap','LB_CALL_CAP')
                used=sum(c['known_cost_nano_usd']+c['held_cost_nano_usd'] for c in calls)
                risk=min(500000000,self.config['limits']['max_cost_nano_usd']-used)
                # Admission floor is a local pricing estimate, not a verified
                # provider token upper bound. All remaining headroom is held.
                require(risk>=4000*150+768*500,'Insufficient remaining headroom','LB_MONEY_CAP')
            body=super().reserve(record)
            if not old:
                body.update(reserved_cost_nano_usd=risk,held_cost_nano_usd=risk)
                self._write('UPDATE p3_calls SET body=? WHERE call_id=?',(canonical_json(body),body['call_id']))
            return {**body,'dispatch_allowed':not old}

    def mark_dispatched(self,call_id):
        self.check_binding();self.require_time(next(c for c in self.calls() if c['call_id']==call_id)['run_id'],15)
        return super().mark_dispatched(call_id)

    def settle(self,call_id,**kwargs):
        self.check_binding();self.require_time(next(c for c in self.calls() if c['call_id']==call_id)['run_id'])
        require(kwargs['provider_request_id'] not in {r['provider_request_id'] for r in self.historical['receipts']},
            'Historical provider receipt reused','LB_OLD_RECEIPT')
        return super().settle(call_id,**kwargs)

    def snapshot(self):
        s=super().snapshot();known=s['budget']['known_cost_nano_usd'];held=s['budget']['held_cost_nano_usd']
        s['real_cost_usd']=None
        s['settled_semantics']='local usage priced; not provider invoice confirmed'
        h=self.historical
        s['L_budget']={'historical_known_nano':h['known_project_nano'],'historical_held_nano':h['project_held_nano'],
            'Bank_historical_calls':h['Bank_calls'],'project_historical_dispatches':h['project_dispatches'],
            'first_historical_generations':h['first_generations_used'],
            'project_known_nano':h['known_project_nano']+known,'project_held_nano':h['project_held_nano']+held,
            'L_known_nano':h.get('L_known_nano',0)+known,'L_held_nano':h['L_held_nano']+held,
            'first_occupied_nano':h.get('first_known_nano',0)+h['first_held_nano']+known+held,
            'project_cap_nano':self.launch_config.project_cap_nano,'L_cap_nano':self.launch_config.L_cap_nano,
            'first_cap_nano':self.launch_config.first_cap_nano,'old_authority_mutated':False,'old_holds_released':False,
            'provider_invoice_verified':False,'history_sha256':self.history_pin}
        s['http']=self.http_rows();s['units']=[dict(r,body=json.loads(r['body'])) for r in self.connection.execute('SELECT * FROM lapi_units')]
        row=self.connection.execute('SELECT state,body FROM lb_batch').fetchone()
        s['batch_accounting']={'state':row['state'],'body':json.loads(row['body'])}
        return s
