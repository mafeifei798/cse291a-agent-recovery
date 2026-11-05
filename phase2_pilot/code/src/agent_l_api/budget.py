"""Latest liability inheritance plus serial $0.50 risk in the existing P3 ledger."""
from contextlib import contextmanager, closing
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import time

from agent_recovery.contracts import canonical_json, digest, require
from agent_recovery.p3_budget import DurableP3Budget
from .protocol import Config, HISTORY_SHA, UNITS, REGISTRATION, REGISTRATION_SHA


class Clock:
    wall=staticmethod(time.time); mono=staticmethod(time.monotonic); sleep=staticmethod(time.sleep)


class FakeClock:
    def __init__(self):self.value=1000.
    def wall(self):return 1800000000+self.value
    def mono(self):return self.value
    def sleep(self,seconds):self.value+=seconds


class Budget(DurableP3Budget):
    def __init__(self,path,*,config,historical,clock=None):
        require(isinstance(config,Config) and historical['sha256']==HISTORY_SHA,'Exact history/config required','LAPI_HISTORY')
        require(digest({k:v for k,v in historical.items() if k!='sha256'})==HISTORY_SHA,'History changed','LAPI_HISTORY')
        self.launch_config=config;self.historical=deepcopy(historical);self.clock=clock or Clock()
        self.meta={'config':config.__dict__,'history':historical,'registration_sha256':REGISTRATION_SHA}
        self.meta_text=canonical_json(self.meta)
        path=Path(path).resolve()
        if path.exists():
            with closing(sqlite3.connect(path.as_uri()+'?mode=ro&immutable=1',uri=True)) as db:
                names={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                require('lapi_meta' in names and db.execute('SELECT body FROM lapi_meta').fetchall()==[(self.meta_text,)],
                    'Do not adopt an old/foreign authority','LAPI_AUTHORITY')
        binding={'model':config.model,'input_nano_usd_per_token':150,'output_nano_usd_per_token':500,
            'cached_input_nano_usd_per_token':None,'price_evidence':('fixture:' if config.simulated else '')+'l-api-pinned-catalog:'+config.catalog_sha256,
            'max_input_tokens':4000,'max_output_tokens':768,'simulated':config.simulated}
        super().__init__(path,campaign_id='l-api-first-v1',binding=binding,
            limits={'call_cap':62,'input_token_cap':62*4000,'output_token_cap':62*768,
                    'max_cost_nano_usd':config.first_cap_nano,'slot_call_cap':5,'logical_call_cap':10})
        self.connection.executescript('''
          CREATE TABLE IF NOT EXISTS lapi_meta(body TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS lapi_units(unit TEXT PRIMARY KEY,body TEXT NOT NULL,state TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS lapi_http(seq INTEGER PRIMARY KEY,unit TEXT NOT NULL,kind TEXT NOT NULL,
            phase TEXT NOT NULL,identity TEXT UNIQUE NOT NULL,body TEXT NOT NULL,state TEXT NOT NULL);
          CREATE TRIGGER IF NOT EXISTS lapi_meta_fixed BEFORE UPDATE ON lapi_meta BEGIN SELECT RAISE(ABORT,'immutable'); END;
          CREATE TRIGGER IF NOT EXISTS lapi_meta_nodelete BEFORE DELETE ON lapi_meta BEGIN SELECT RAISE(ABORT,'immutable'); END;
          CREATE TRIGGER IF NOT EXISTS lapi_deadline_fixed BEFORE UPDATE OF body ON lapi_units BEGIN SELECT RAISE(ABORT,'fixed deadline'); END;
          CREATE TRIGGER IF NOT EXISTS lapi_units_nodelete BEFORE DELETE ON lapi_units BEGIN SELECT RAISE(ABORT,'immutable'); END;
        ''')
        if not self.connection.execute('SELECT 1 FROM lapi_meta').fetchone():
            with self._transaction():self._write('INSERT INTO lapi_meta VALUES(?)',(self.meta_text,))

    @contextmanager
    def _transaction(self):
        if self.connection.in_transaction:yield
        else:
            with super()._transaction():yield

    def start_unit(self,unit,remaining=240.):
        require(unit in UNITS and 0<remaining<=240,'Unknown unit/remaining time','LAPI_UNIT')
        with self._transaction():
            self._assert_active()
            require(not self.connection.execute('SELECT 1 FROM lapi_units WHERE unit=?',(unit,)).fetchone(),'Unit may not restart','LAPI_UNIT_STARTED')
            body={'wall_started':self.clock.wall(),'mono_started':self.clock.mono(),
                'wall_deadline':self.clock.wall()+remaining,'mono_deadline':self.clock.mono()+remaining,'duration':remaining}
            self._write('INSERT INTO lapi_units VALUES(?,?,?)',(unit,canonical_json(body),'active'))
        return body

    def check_binding(self):
        body={'config':self.launch_config.__dict__,'history':self.historical,'registration_sha256':REGISTRATION_SHA}
        if canonical_json(body)!=self.meta_text or digest(self.binding)!=self.config['binding_digest'] or self.connection.execute('SELECT body FROM lapi_meta').fetchone()[0]!=self.meta_text:
            self._error('LAPI_BINDING_CHANGED','Pinned budget/source changed')

    def bounds(self,unit):
        row=self.connection.execute('SELECT * FROM lapi_units WHERE unit=?',(unit,)).fetchone()
        require(row is not None,'Unit not started','LAPI_UNIT')
        return json.loads(row['body'])

    def remaining(self,unit):
        b=self.bounds(unit)
        return min(b['wall_deadline']-self.clock.wall(),b['mono_deadline']-self.clock.mono())

    def require_time(self,unit,reserve=0):
        self._assert_active()
        row=self.connection.execute('SELECT state FROM lapi_units WHERE unit=?',(unit,)).fetchone()
        require(row and row['state']=='active','Unit is not active','LAPI_UNIT_FINISHED')
        require(self.remaining(unit)>reserve,'Fixed unit deadline exceeded','LAPI_DEADLINE')

    def http_rows(self):return [dict(r,body=json.loads(r['body'])) for r in self.connection.execute('SELECT * FROM lapi_http ORDER BY seq')]

    def begin_http(self,unit,kind,phase,identity):
        self._assert_active();rows=self.http_rows()
        require(kind in ('GEN','GET'),'Unknown HTTP kind','LAPI_HTTP')
        if phase=='catalog':
            require(unit=='CATALOG' and kind=='GET' and not any(r['phase']=='catalog' for r in rows),'Catalog once only','LAPI_HTTP_CAP')
        else:
            require(unit in UNITS,'Unknown unit','LAPI_HTTP')
            self.require_time(unit,15 if kind=='GEN' else 1)
            own=[r for r in rows if r['unit']==unit]
            if kind=='GET':
                require(phase in ('baseline','receipt','close') and sum(r['kind']=='GET' for r in own)<UNITS[unit]+4
                    and sum(r['phase']==phase for r in own)<{'baseline':1,'receipt':UNITS[unit],'close':3}[phase],
                    'Per-unit GET cap exceeded','LAPI_HTTP_CAP')
        require(sum(r['kind']==kind for r in rows)<(62 if kind=='GEN' else 95),'Batch HTTP cap exceeded','LAPI_HTTP_CAP')
        if rows:
            self.clock.sleep(max(0.,rows[-1]['body']['mono_started']+2-self.clock.mono()))
        if phase!='catalog':self.require_time(unit,15 if kind=='GEN' else 1)
        duration=(12 if kind=='GET' else 120) if phase=='catalog' else min(12 if kind=='GET' else 120,self.remaining(unit)-(1 if kind=='GET' else 15))
        body={'mono_started':self.clock.mono(),'wall_started':self.clock.wall(),'duration':duration,
            'deadline_mono':self.clock.mono()+duration,'deadline_wall':self.clock.wall()+duration}
        with self._transaction():
            self._write('INSERT INTO lapi_http VALUES(?,?,?,?,?,?,?)',
                (len(rows)+1,unit,kind,phase,identity,canonical_json(body),'started'))
        return len(rows)+1,body['deadline_mono']

    def end_http(self,seq,*,failed=False):
        row=self.connection.execute('SELECT body,state FROM lapi_http WHERE seq=?',(seq,)).fetchone()
        require(row and row['state']=='started','HTTP completion repeated','LAPI_HTTP')
        body=json.loads(row['body']);late=self.clock.mono()>=body['deadline_mono'] or self.clock.wall()>=body['deadline_wall']
        with self._transaction():self._write('UPDATE lapi_http SET state=? WHERE seq=?',('failed' if failed or late else 'complete',seq))
        require(not late,'Late HTTP result rejected','LAPI_DEADLINE')

    def reserve(self,record):
        unit=record.get('run_id');require(unit in UNITS and record.get('step_id') in ('Analyst','Planner','Reviewer'),'Unregistered call','LAPI_UNIT')
        require(record.get('call_id') not in {r['call_id'] for r in self.historical['receipts']},'Old request cannot dispatch','LAPI_OLD_CALL')
        self.require_time(unit,15)
        with self._transaction():
            self._assert_active()
            self.check_binding()
            require(self.connection.execute('SELECT body FROM lapi_meta').fetchone()[0]==self.meta_text,'Budget inheritance changed','LAPI_HISTORY')
            old=self.connection.execute('SELECT 1 FROM p3_calls WHERE call_id=?',(record['call_id'],)).fetchone()
            if not old:
                calls=self.calls(); occupied=sum(c['known_cost_nano_usd']+c['held_cost_nano_usd'] for c in calls)
                require(sum(c['run_id']==unit for c in calls)<UNITS[unit],'Unit call cap exceeded','LAPI_UNIT_CAP')
                for used,cap in [(occupied,self.launch_config.first_cap_nano),(occupied,self.launch_config.L_cap_nano),
                                 (occupied+self.historical['project_total_nano'],self.launch_config.project_cap_nano)]:
                    if used+500_000_000>cap:self._error('LAPI_MONEY_CAP','Risk headroom exhausted',budget=True)
            body=super().reserve(record)
            if not old:
                body.update(reserved_cost_nano_usd=500_000_000,held_cost_nano_usd=500_000_000)
                self._write('UPDATE p3_calls SET body=? WHERE call_id=?',(canonical_json(body),body['call_id']))
            return {**body,'dispatch_allowed':not old}

    def mark_dispatched(self,call_id):
        with self._transaction():
            self.check_binding()
            call=next(c for c in self.calls() if c['call_id']==call_id)
            self.require_time(call['run_id'],15)
            return super().mark_dispatched(call_id)

    def settle(self,call_id,**kwargs):
        with self._transaction():
            self.check_binding()
            call=next(c for c in self.calls() if c['call_id']==call_id)
            self.require_time(call['run_id'])
            return super().settle(call_id,**kwargs)

    def finish_unit(self,unit):
        self.require_time(unit)
        require(not any(c['run_id']==unit and c['status']!='settled' for c in self.calls()),'Pending liability','LAPI_PENDING')
        with self._transaction():self._write("UPDATE lapi_units SET state='complete' WHERE unit=?",(unit,))

    def snapshot(self):
        s=super().snapshot();known=s['budget']['known_cost_nano_usd'];held=s['budget']['held_cost_nano_usd']
        s['L_budget']={'history_sha256':HISTORY_SHA,'Bank_historical_calls':302,'project_historical_dispatches':2780,
            'historical_known_nano':249882850,'historical_held_nano':503252000,
            'project_known_nano':249882850+known,'project_held_nano':503252000+held,
            'project_occupied_nano':753134850+known+held,'L_known_nano':known,'L_held_nano':held,
            'project_cap_nano':self.launch_config.project_cap_nano,'L_cap_nano':self.launch_config.L_cap_nano,
            'first_cap_nano':self.launch_config.first_cap_nano,'synthetic_new_costs':self.launch_config.simulated,
            'old_authority_mutated':False,'old_holds_released':False,'provider_invoice_verified':False}
        if self.connection.execute("SELECT 1 FROM sqlite_master WHERE name='lapi_http'").fetchone():
            s['http']=self.http_rows();s['units']=[dict(r,body=json.loads(r['body'])) for r in self.connection.execute('SELECT * FROM lapi_units')]
        return s
