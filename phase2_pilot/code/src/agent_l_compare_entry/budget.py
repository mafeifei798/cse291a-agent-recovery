"""Single30-call/$0.50 authority. The old first pilot is read-only metadata."""
from copy import deepcopy
import json
from pathlib import Path

from agent_l_approval_confirm.budget import Budget as SharedBudget
from agent_recovery.p3_budget import DurableP3Budget
from agent_l_api.budget import FakeClock,Clock
from agent_recovery.contracts import canonical_json,digest,require
from .protocol import Config,HISTORY_SHA,REGISTRATION_SHA,UNITS


class Budget(SharedBudget):
    registration_pin=REGISTRATION_SHA
    history_pin=HISTORY_SHA

    def __init__(self,path,*,config,historical,clock=None):
        require(type(config) is Config and historical['sha256']==HISTORY_SHA
            and digest({k:v for k,v in historical.items() if k!='sha256'})==HISTORY_SHA,'Exact history/config','CMP_HISTORY')
        require(not Path(path).exists(),'No old authority may reopen','CMP_AUTHORITY')
        self.launch_config=config;self.historical=deepcopy(historical);self.clock=clock or (FakeClock() if config.simulated else Clock())
        self.new_call_cap=config.generation_cap;self.unit_caps={u:config.unit_call_cap for u in UNITS.values()}
        self.meta={'config':config.__dict__,'history':historical,'registration_sha256':self.registration_pin}
        self.meta_text=canonical_json(self.meta)
        available=min(config.batch_cap_nano,config.project_cap_nano-historical['known_project_nano']-historical['project_held_nano'],
            config.L_cap_nano-historical['L_known_nano']-historical['L_held_nano'])
        require(available>0,'No new comparison headroom','CMP_MONEY_CAP')
        binding={'model':config.model,'input_nano_usd_per_token':150,'output_nano_usd_per_token':500,
            'cached_input_nano_usd_per_token':None,'price_evidence':('fixture:' if config.simulated else '')+'l-compare-entry:'+config.catalog_sha256,
            'max_input_tokens':4000,'max_output_tokens':768,'simulated':config.simulated}
        DurableP3Budget.__init__(self,path,campaign_id='l-compare-entry-v1',binding=binding,
            limits={'call_cap':config.generation_cap,'input_token_cap':config.generation_cap*4000,
                'output_token_cap':config.generation_cap*768,'max_cost_nano_usd':available,
                'slot_call_cap':5,'logical_call_cap':10})
        self.connection.executescript('''
          CREATE TABLE lapi_meta(body TEXT NOT NULL);
          CREATE TABLE lapi_units(unit TEXT PRIMARY KEY,body TEXT NOT NULL,state TEXT NOT NULL);
          CREATE TABLE lapi_http(seq INTEGER PRIMARY KEY,unit TEXT NOT NULL,kind TEXT NOT NULL,
            phase TEXT NOT NULL,identity TEXT UNIQUE NOT NULL,body TEXT NOT NULL,state TEXT NOT NULL);
          CREATE TABLE lb_batch(singleton INTEGER PRIMARY KEY,state TEXT NOT NULL,body TEXT NOT NULL);
          CREATE TRIGGER fixed_unit BEFORE UPDATE OF body ON lapi_units BEGIN SELECT RAISE(ABORT,'fixed deadline'); END;
          CREATE TRIGGER fixed_meta BEFORE UPDATE ON lapi_meta BEGIN SELECT RAISE(ABORT,'immutable'); END;
          CREATE TABLE fr_approvals(id TEXT PRIMARY KEY,body TEXT NOT NULL);
          CREATE TABLE fr_replays(unit TEXT NOT NULL,id TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(unit,id));
          CREATE TABLE ac_confirmations(unit TEXT NOT NULL,id TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(unit,id));
        ''')
        for table in ('fr_approvals','fr_replays','ac_confirmations'):
            for op in ('UPDATE','DELETE'):
                self.connection.execute(f"CREATE TRIGGER {table}_{op} BEFORE {op} ON {table} BEGIN SELECT RAISE(ABORT,'immutable'); END")
        self._write('INSERT INTO lapi_meta VALUES(?)',(self.meta_text,))
        self._write("INSERT INTO lb_batch VALUES(1,'initial','{}')")

    def start_unit(self,unit,remaining=192.470543):
        require(remaining==192.470543,'Every method inherits the same frozen remainder','CMP_DEADLINE')
        return super().start_unit(unit,remaining)

    def snapshot(self):
        s=DurableP3Budget.snapshot(self);h=self.historical
        known=s['budget']['known_cost_nano_usd'];held=s['budget']['held_cost_nano_usd'];c=self.launch_config
        s['comparison_budget']={'historical_calls':364,'project_historical_dispatches':2842,
            'historical_known_nano':h['known_project_nano'],'historical_project_held_nano':h['project_held_nano'],
            'new_known_nano':known,'new_held_nano':held,'batch_cap_nano':c.batch_cap_nano,
            'project_cap_nano':c.project_cap_nano,'L_cap_nano':c.L_cap_nano,
            'project_known_nano':h['known_project_nano']+known,'project_held_nano':h['project_held_nano']+held,
            'L_known_nano':h['L_known_nano']+known,'L_held_nano':h['L_held_nano']+held,
            'sealed_first_used':62,'sealed_first_cap':64,'sealed_first_known_nano':h['first_known_nano'],
            'sealed_first_held_nano':h['first_held_nano'],'old_first_allowance_accessible':False,
            'new_generation_cap':c.generation_cap,'new_generations_used':len(s['calls']),
            'old_holds_released':False,'old_authority_mutated':False,'simulated_increment_only':c.simulated}
        for table,key in (('fr_approvals','feedback_approvals'),('fr_replays','feedback_replays'),('ac_confirmations','approval_confirmations')):
            s[key]=[json.loads(r[0]) for r in self.connection.execute('SELECT body FROM '+table)]
        s['units']=[dict(r,body=json.loads(r['body'])) for r in self.connection.execute('SELECT * FROM lapi_units')]
        s['http']=self.http_rows()
        r=self.connection.execute('SELECT state,body FROM lb_batch').fetchone()
        s['batch_accounting']={'state':r['state'],'body':json.loads(r['body'])}
        s.update(real_cost_usd=None,provider_invoice_verified=False,real_calls_and_spend_unchanged=c.simulated)
        return s
