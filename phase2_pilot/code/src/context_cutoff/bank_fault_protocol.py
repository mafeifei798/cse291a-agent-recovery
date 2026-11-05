"""Independent Bank fault pilot registration and shared monetary authority.

The fixed 162-call profile grants no live model, training or cloud permission.
Old C01/C02 authorities remain read-only evidence, never copied as an authority.
"""
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
from pathlib import Path
from time import time
import zipfile

from agent_recovery.contracts import digest, require
from .bank_launch import BankLaunchConfig, BankLaunchPermit
from .bank_pilot_budget import BankPilotBudget

SCENES = (
    ('BF01','SCOPED','F_INCIDENTAL'),
    ('BF02','FULL_HISTORY','F_INCIDENTAL'),
    ('BF03','SCOPED','F_DECISION'),
    ('BF04','FULL_HISTORY','F_DECISION'),
)
METHODS = ('FULL','CONSERVATIVE','CUTOFF')
UNITS = tuple((scene+'.'+kind,mode) for scene,mode,_ in SCENES
              for kind in ('PREFIX',*METHODS)) + (('BF01.CAL','SCOPED'),('BF02.CAL','FULL_HISTORY'))
REGISTRY = dict(schema_version='bank-fault-pilot-registry-v1',scenes=[
    dict(scene_id=s,mode=m,fault=f) for s,m,f in SCENES],
    units=[dict(unit_id=u,mode=m,kind=u.rsplit('.',1)[1],call_cap=1 if u.endswith('.CAL') else 10)
           for u,m in UNITS],
    methods=list(METHODS),new_call_cap=162,role_call_cap=5,
    new_batch_cap_nano=1_000_000_000,pilot_cap_nano=3_000_000_000,
    project_cap_nano=20_000_000_000,unit_deadline_seconds=120,
    per_unit_training_requests=1,cutoff_rechecks_per_point=1,
    calibration_analysis_only=True,protocol_frozen_for_offline_validation=True,
    scientific_evaluation_frozen=False)
REGISTRY_SHA = digest(REGISTRY)
R6_SHA = 'a87d4bc7d02e57ebc7fd948114340cc2f1d7e6392799ec86b035d915ffecfa7f'


def write_new(path, value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x') as handle:
        json.dump(value,handle,indent=2,ensure_ascii=False,allow_nan=False)
        handle.write('\n');handle.flush()
        import os
        os.fsync(handle.fileno())


def checked_archive(path, prefix):
    with zipfile.ZipFile(path) as z:
        require(z.testzip() is None,'Archive CRC differs','BF_SOURCE')
        manifest=json.loads(z.read(prefix+'EVIDENCE_MANIFEST.json'))['files']
        for name,pin in manifest.items():
            require(hashlib.sha256(z.read(name)).hexdigest()==pin,'Evidence file differs','BF_SOURCE')
        return {name:z.read(name) for name in manifest}


def load_inheritance(root):
    """Pin the complete eleven-receipt chain plus the seven settled r6 calls."""
    from .bank_continuation import load_c02_continuation
    root=Path(root)
    a=root/'outputs/bank_pilot_live_20261024'
    b=root/'outputs/bank_pilot_continue_20261024'
    c=root/'outputs/bank_pilot_protocol_20261024'
    prior=load_c02_continuation(a/'bank-c01-c02-20261024-r1-evidence.zip',a/'POSTSTOP_KEY_SPEND.json',
        b/'bank-c01-c02-20261024-r2-evidence.zip',b/'bank-c01-c02-20261024-r2-poststop.zip',
        c/'bank-c01-c02-20261024-r3-evidence.zip',c/'bank-c01-c02-20261024-r3-poststop.zip',
        c/'bank-c01-c02-20261024-r4-evidence.zip',c/'bank-c01-c02-20261024-r4-poststop.zip',
        c/'bank-c01-c02-20261024-r5-evidence.zip',c/'bank-c01-c02-20261024-r5-poststop.zip')
    path=root/'outputs/bank_c02_resume_20261024/bank-c02-20261024-r6-evidence.zip'
    require(hashlib.sha256(path.read_bytes()).hexdigest()==R6_SHA,'r6 source differs','BF_SOURCE')
    prefix='outputs/bank_c02_real_r6/'
    files=checked_archive(path,prefix)
    result=json.loads(files[prefix+'RESULTS.json']);ledger=json.loads(files[prefix+'LEDGER.json'])
    require(result['runs'][0]['run_id']=='C02' and result['runs'][0]['outcome']=='correct_complete'
            and result['final_billing']['reconciled'] is True
            and result['inherited_generation_requests']==11
            and result['total_generation_requests_including_prior']==18,
            'Completed, reconciled C02 source required','BF_SOURCE')
    receipts=deepcopy(prior['inherited_paid_receipts'])
    for row in ledger['calls']:
        usage=row['usage'];audit=row['evidence']['wire_audit']
        require(row['run_id']=='C02' and row['status']=='settled' and audit['status']==200
                and audit['cleanup_receipt']['reaped']
                and usage['total_tokens']==usage['prompt_tokens']+usage['completion_tokens'],
                'Incomplete inherited r6 receipt','BF_SOURCE')
        receipts.append(dict(call_id=row['call_id'],run_id='C02',step_id=row['step_id'],
                             cost_nano=usage['prompt_tokens']*150+usage['completion_tokens']*500))
    require(len(receipts)==18 and len({r['call_id'] for r in receipts})==18
            and sum(r['cost_nano'] for r in receipts)==3789550,
            'All eighteen costs must be inherited once','BF_SOURCE')
    after=Decimal(result['final_billing']['after']['spend_nano'])
    require(abs(after-183475650)<=1,'Inherited balance differs','BF_SOURCE')
    handoff=dict(schema_version='bank-fault-inheritance-v1',r6_archive_sha256=R6_SHA,
        prior_continuation_sha256=prior['continuation_sha256'],receipts=receipts,
        inherited_generation_calls=18,inherited_bank_known_nano=3789550,
        expected_start_key_spend_nano=str(after),historical_unknown_hold_nano=3252000,
        old_authorities_mutated=False,provider_invoice_verified=False)
    handoff['sha256']=digest(handoff)
    return handoff


@dataclass(frozen=True)
class BankFaultConfig(BankLaunchConfig):
    schema_version: str = 'bank-fault-launch-v1'
    batch_id: str = 'bank-fault-B01'
    runs: tuple = UNITS
    total_call_cap: int = 162
    registry_sha256: str = REGISTRY_SHA

    def registry_policy(self):
        return ('bank-fault-launch-v1','bank-fault-B01',UNITS,162)

    def allowed_budget_revisions(self):
        return ('bank-budget-20261024-r2',)

    def expected_registry_sha256(self):
        return REGISTRY_SHA

    def __post_init__(self):
        super().__post_init__()
        require(self.registry_sha256==self.expected_registry_sha256() and self.budget_revision in self.allowed_budget_revisions(),
                'Fault registry or budget revision changed','BF_REGISTRY')


@dataclass(frozen=True)
class BankFaultPermit(BankLaunchPermit):
    recovery_authorized: bool = False
    registry_sha256: str = ''

    def validate(self,config,*,fixture_only,now_utc=None):
        super().validate(config,fixture_only=fixture_only,now_utc=now_utc)
        require(isinstance(config,BankFaultConfig) and self.recovery_authorized is True
                and self.registry_sha256==config.registry_sha256==config.expected_registry_sha256(),
                'Explicit matching recovery grant required','BF_PERMIT')
        if not fixture_only:
            require(self.training_authorized and self.key_read_authorized
                    and self.credential_source=='datahub-existing-env',
                    'Live recovery needs separate DataHub key and CPU permission','BF_PERMIT')


class BankFaultBudget(BankPilotBudget):
    _p3_execution_profile='bank-fault-pilot-162-v1'

    def registry_policy(self):
        return (dict(UNITS),162)

    def allowed_budget_revisions(self):
        return ('bank-budget-20261024-r2',)

    def __init__(self,path,*,inheritance,**kwargs):
        from .budget_policy import budget_policy,CURRENT_BUDGET_REVISION
        revision=kwargs.get('budget_revision',CURRENT_BUDGET_REVISION)
        require(revision in self.allowed_budget_revisions(),'Fault budget revision not admitted','BF_REGISTRY')
        batch_cap=budget_policy(revision)['batch_cap_nano']
        body=deepcopy(inheritance);supplied=body.pop('sha256',None)
        require(supplied==digest(body) and body.get('r6_archive_sha256')==R6_SHA
                and body.get('inherited_generation_calls')==18
                and body.get('inherited_bank_known_nano')==3789550
                and body.get('historical_unknown_hold_nano')==3252000
                and len(body.get('receipts',[]))==18
                and sum(r['cost_nano'] for r in body['receipts'])==3789550,
                'Verified eighteen-call inheritance required','BF_SOURCE')
        self.handoff=deepcopy(inheritance);self._handoff_text=json.dumps(inheritance,sort_keys=True)
        self._fault_ready=False
        limits=dict(call_cap=162,input_token_cap=162*4000,output_token_cap=162*768,
            max_cost_nano_usd=batch_cap,slot_call_cap=5,logical_call_cap=10)
        super().__init__(path,batch_id='bank-fault-B01',batch_call_cap=162,run_call_cap=10,
            limits=limits,campaign_id='bank-fault-pilot-v1',**kwargs)
        self.connection.executescript('''
            CREATE TABLE IF NOT EXISTS bf_handoff (singleton INTEGER PRIMARY KEY,body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS bf_units (unit_id TEXT PRIMARY KEY,state TEXT NOT NULL,
                started REAL NOT NULL,deadline REAL NOT NULL,receipt TEXT);
            CREATE TABLE IF NOT EXISTS bf_final_hold (singleton INTEGER PRIMARY KEY,amount INTEGER NOT NULL,evidence TEXT NOT NULL);
        ''')
        with self._transaction():
            row=self.connection.execute('SELECT body FROM bf_handoff WHERE singleton=1').fetchone()
            if row is None:
                require(not self.calls(),'Cannot adopt used fault authority','BF_SOURCE')
                self._write('INSERT INTO bf_handoff VALUES(1,?)',(self._handoff_text,))
            else:require(row['body']==self._handoff_text,'Inherited balance changed','BF_SOURCE')
        self._fault_ready=True

    def start_unit(self,unit_id):
        require(unit_id in dict(UNITS),'Unknown unit','BF_REGISTRY')
        with self._transaction():
            self._assert_active()
            require(self.connection.execute('SELECT 1 FROM bf_units WHERE unit_id=?',(unit_id,)).fetchone() is None,
                    'A started unit cannot reset its deadline or run again','BF_UNIT_ALREADY_STARTED')
            began=time()
            self._write('INSERT INTO bf_units VALUES(?,?,?,?,NULL)',(unit_id,'running',began,began+120))
        return began+120

    def finish_unit(self,unit_id,receipt):
        with self._transaction():
            row=self.connection.execute('SELECT state FROM bf_units WHERE unit_id=?',(unit_id,)).fetchone()
            require(row and row['state']=='running','Unit is not running','BF_UNIT_STATE')
            self._write('UPDATE bf_units SET state=?,receipt=? WHERE unit_id=?',
                        ('finished',json.dumps(receipt,sort_keys=True),unit_id))

    def reserve(self,record):
        with self._transaction():
            require(self.connection.execute('SELECT body FROM bf_handoff WHERE singleton=1').fetchone()['body']==self._handoff_text,
                    'Inherited source changed','BF_SOURCE')
            unit=record.get('run_id');row=self.connection.execute('SELECT * FROM bf_units WHERE unit_id=?',(unit,)).fetchone()
            require(row and row['state']=='running' and time()<row['deadline'],
                    'Unit absent, finished or expired','BF_UNIT_DEADLINE')
            if unit.endswith('.CAL'):
                require(record.get('step_id')=='Planner','Calibration may only call Planner','BF_CALIBRATION')
                if not any(r['call_id']==record['call_id'] for r in self.calls()):
                    require(not any(r['run_id']==unit for r in self.calls()),
                            'Calibration limited to one call','BF_CALIBRATION')
            if not any(r['call_id']==record['call_id'] for r in self.calls()):
                occupied=self.snapshot()['unified_budget']
                require(occupied['pilot_total_nano']+self.worstcase_per_call_nano<=3_000_000_000
                        and occupied['project_total_nano']+self.worstcase_per_call_nano<=20_000_000_000,
                        'Inherited and new liability exceeds budget','BF_MONEY_CAP')
            return super().reserve(record)

    def retain_billing_hold(self,evidence):
        with self._transaction():
            snap=self.snapshot()['bank_budget']
            held=snap['base_held_nano']+snap['extra_held_nano']
            self._write('INSERT OR IGNORE INTO bf_final_hold VALUES(1,?,?)',
                        (max(0,self.worstcase_per_call_nano-held),json.dumps(evidence,sort_keys=True)))

    def snapshot(self):
        result=super().snapshot()
        if not self._fault_ready:return result
        carried=self.handoff['inherited_bank_known_nano'];u=result['unified_budget']
        for k in ('pilot_known_nano','pilot_total_nano','project_known_nano','project_total_nano'):u[k]+=carried
        for k in ('project_remaining_nano','pilot_remaining_nano'):u[k]-=carried
        for k in ('project_generation_calls','project_accounted_dispatches'):u[k]+=18
        u.update(inherited_bank_known_nano=carried,inherited_bank_generations=18,
                 source_handoff_sha256=self.handoff['sha256'])
        hold=self.connection.execute('SELECT amount FROM bf_final_hold WHERE singleton=1').fetchone()
        held=hold['amount'] if hold else 0
        result['bank_budget']['billing_pending_hold_nano']=held
        for k in ('total_nano',):result['bank_budget'][k]+=held
        result['bank_budget']['remaining_nano']-=held
        result['budget']['held_cost_nano_usd']+=held
        result['budget']['remaining_cost_nano_usd']=max(0,result['budget']['remaining_cost_nano_usd']-held)
        for k in ('pilot_held_nano','pilot_total_nano','project_held_nano','project_total_nano'):u[k]+=held
        for k in ('project_remaining_nano','pilot_remaining_nano','effective_remaining_nano'):u[k]-=held
        u['effective_remaining_nano']=min(result['bank_budget']['remaining_nano'],u['pilot_remaining_nano'],u['project_remaining_nano'])
        result['bank_budget']['over_cap']=(result['bank_budget']['total_nano']>result['bank_budget']['batch_cap_nano']
            or u['pilot_total_nano']>3_000_000_000 or u['project_total_nano']>20_000_000_000)
        result['fault_pilot']=dict(registry_sha256=REGISTRY_SHA,inheritance=deepcopy(self.handoff),
            units=[dict(row) for row in self.connection.execute('SELECT * FROM bf_units ORDER BY rowid')])
        return result
