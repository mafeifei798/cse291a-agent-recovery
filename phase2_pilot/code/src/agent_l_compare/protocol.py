from dataclasses import dataclass,asdict
from pathlib import Path
import hashlib
import json

from agent_recovery.contracts import digest,require

HISTORY_REL='outputs/l_confirm_real_20261031_r1/LEDGER_SUCCESSOR_364.json'
HISTORY_SHA='d664ae973b0e32a700823a9adaa07ac3f2e06cb69a3fcd8a4c2840d772d877a7'
METHODS=('FULL','CONSERVATIVE','CUTOFF')
UNITS={m:'LCMP01.'+m for m in METHODS}
REGISTRATION={'revision':'l-compare-offline-v1','units':{UNITS[m]:10 for m in METHODS},
    'batch_generation_cap':30,'batch_cap_nano':500000000,'historical_calls':364,
    'sealed_first_generations':62,'sealed_first_total_cap':64,'old_first_allowance_accessible':False,
    'unit_seconds':192.470543,'normal_adjustment_consumed':1,'normal_adjustment_remaining':0,
    'simulated_fit_cap_per_unit':3,'batch_GET_cap':4,'future_config_GET_slots':2,
    'real_API_permission':False,'real_training_permission':False,'cloud_permission':False}
REGISTRATION_SHA=digest(REGISTRATION)


def history(root):
    root=Path(root).resolve();h=json.loads((root/HISTORY_REL).read_text())
    require(h['sha256']==HISTORY_SHA==digest({k:v for k,v in h.items() if k!='sha256'}),'Exact364 history required','CMP_HISTORY')
    require(len(h['receipts'])==len({x['call_id'] for x in h['receipts']})==h['Bank_calls']==364
        and h['project_dispatches']==2842 and h['known_project_nano']==256624400
        and h['L_known_nano']==h['first_known_nano']==6741550 and h['first_generations_used']==62
        and [x['amount_nano'] for x in h['holds']]==[503252000,500000000]
        and h['project_held_nano']==1003252000 and h['L_held_nano']==h['first_held_nano']==500000000,
        'History, costs, holds or sealed quota changed','CMP_HISTORY')
    for n,value in h['source_files'].items():
        p=root/n
        require(not Path(n).is_absolute() and '..' not in Path(n).parts and not p.is_symlink()
            and p.resolve().is_relative_to(root) and hashlib.sha256(p.read_bytes()).hexdigest()==value,
            'Historical evidence changed','CMP_HISTORY')
    return h


@dataclass(frozen=True)
class Config:
    revision:str='l-compare-offline-v1'
    model:str='api-glm-5.3-flash'
    simulated:bool=True
    history_sha256:str=HISTORY_SHA
    registration_sha256:str=REGISTRATION_SHA
    project_cap_nano:int=20000000000
    L_cap_nano:int=2000000000
    batch_cap_nano:int=500000000
    generation_cap:int=30
    unit_call_cap:int=10
    order:tuple=METHODS

    def __post_init__(self):
        require(self.revision==REGISTRATION['revision'] and self.model=='api-glm-5.3-flash'
            and self.simulated is True and self.history_sha256==HISTORY_SHA
            and self.registration_sha256==REGISTRATION_SHA,'Offline exact config required','CMP_OFFLINE_ONLY')
        require((self.project_cap_nano,self.L_cap_nano)==(20000000000,2000000000)
            and type(self.batch_cap_nano) is int and 0<self.batch_cap_nano<=500000000,'Caps cannot expand','CMP_MONEY_CAP')
        require(type(self.generation_cap) is int and 1<=self.generation_cap<=30
            and type(self.unit_call_cap) is int and 1<=self.unit_call_cap<=10,'Call caps cannot expand','CMP_CALL_CAP')
        require(type(self.order) is tuple and len(self.order)==3 and set(self.order)==set(METHODS),
            'Three unique methods required','CMP_REGISTRATION')

    @property
    def sha256(self):return digest(asdict(self))


def source_sha(root):
    root=Path(root)
    from agent_l_confirm_entry.protocol import source_sha as prior
    paths=list((root/'src/agent_l_compare').glob('*.py'))+[root/'scripts'/n for n in ('run_l_compare_offline.py','check_l_compare_offline.py')]
    return digest({'prior_core':prior(root),'comparison':{str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}})
