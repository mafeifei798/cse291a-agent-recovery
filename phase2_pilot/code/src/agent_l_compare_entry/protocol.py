"""A new batch capability, never a continuation of the sealed first pilot."""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

from agent_l_compare.protocol import HISTORY_REL, HISTORY_SHA, history, METHODS, UNITS
from agent_l_compare.protocol import source_sha as previous_source_sha
from agent_l_confirm_entry.protocol import require_resources
from agent_recovery.contracts import digest, require

MODEL = 'api-glm-5.3-flash'
SECONDS = 192.470543
REGISTRATION = {'revision':'l-compare-entry-v1','units':{UNITS[m]:10 for m in METHODS},
    'history_calls':364,'generation_cap':30,'batch_cap_nano':500000000,
    'old_first_used':62,'old_first_cap':64,'old_first_allowance_accessible':False,
    'normal_adjustment_spent':1,'normal_adjustment_remaining':0,'unit_seconds':SECONDS,
    'fit_cap_per_unit':3,'batch_GET_cap':4,'configuration_GET_slots':2,
    'GET_cap_including_configuration':6,'registration_is_permission':False}
REGISTRATION_SHA = digest(REGISTRATION)


def source_sha(root):
    root = Path(root)
    paths = list((root/'src/agent_l_compare_entry').glob('*.py'))
    paths += [root/'scripts'/n for n in ('run_l_compare_entry.py','check_l_compare_entry.py','accept_l_compare_linux.py')]
    return digest({'previous_core':previous_source_sha(root),'entry':{
        str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}})


@dataclass(frozen=True)
class Config:
    revision:str = 'l-compare-entry-v1'
    model:str = MODEL
    simulated:bool = True
    history_sha256:str = HISTORY_SHA
    registration_sha256:str = REGISTRATION_SHA
    project_cap_nano:int = 20000000000
    L_cap_nano:int = 2000000000
    batch_cap_nano:int = 500000000
    generation_cap:int = 30
    unit_call_cap:int = 10
    order:tuple = METHODS
    target_root:str = ''
    output_root:str = ''
    source_sha256:str = ''
    acceptance_sha256:str = ''
    catalog_sha256:str = ''
    models_sha256:str = ''

    def __post_init__(self):
        require(self.revision=='l-compare-entry-v1' and self.model==MODEL and type(self.simulated) is bool
            and self.history_sha256==HISTORY_SHA and self.registration_sha256==REGISTRATION_SHA,
            'Exact new comparison configuration required','CMPE_CONFIG')
        require(type(self.project_cap_nano) is int and type(self.L_cap_nano) is int
            and (self.project_cap_nano,self.L_cap_nano)==(20000000000,2000000000)
            and type(self.batch_cap_nano) is int and 0<self.batch_cap_nano<=500000000,
            'Money limits cannot expand','CMPE_CAP')
        require(type(self.generation_cap) is int and 1<=self.generation_cap<=30
            and type(self.unit_call_cap) is int and 1<=self.unit_call_cap<=10,'Call limits cannot expand','CMPE_CAP')
        require(type(self.order) is tuple and len(self.order)==3 and set(self.order)==set(METHODS),
            'Three unique methods required','CMPE_ORDER')

    @classmethod
    def from_json(cls, value):
        return cls(**{**value,'order':tuple(value['order'])})

    @property
    def sha256(self):return digest(asdict(self))


@dataclass(frozen=True)
class Permit:
    config_sha256:str = ''
    real_API_authorized:bool = False
    key_read_authorized:bool = False
    CPU_authorized:bool = False
    training_authorized:bool = False
    prediction_authorized:bool = False
    authorization_reference:str = ''
    expires_utc:str = ''
    generation_cap:int = 30
    methods:tuple = METHODS

    def validate_live(self, c, root, acceptance, catalog, models):
        require(not c.simulated and self.config_sha256==c.sha256
            and all(v is True for v in (self.real_API_authorized,self.key_read_authorized,self.CPU_authorized,
                self.training_authorized,self.prediction_authorized)) and bool(self.authorization_reference.strip())
            and self.generation_cap==c.generation_cap and tuple(self.methods)==c.order,
            'Fresh permission including equal CPU training rights is required','CMPE_PERMISSION')
        now = datetime.now(timezone.utc)
        end = datetime.fromisoformat(self.expires_utc.replace('Z','+00:00'))
        require(now<end and (end-now).total_seconds()<=7200,'Expired permission','CMPE_PERMISSION')
        require_resources()
        root = Path(root).resolve()
        require(c.target_root==str(root) and c.source_sha256==source_sha(root)
            and os.environ.get('JUPYTERHUB_USER')=='hoding','Wrong target/source','CMPE_TARGET')
        for path, pin in ((acceptance,c.acceptance_sha256),(catalog,c.catalog_sha256),(models,c.models_sha256)):
            require(path is not None and pin and hashlib.sha256(Path(path).read_bytes()).hexdigest()==pin,
                'Missing or changed proof','CMPE_PROOF')
        a = json.loads(Path(acceptance).read_text())
        require(a.get('revision')=='l-compare-native-v1' and a.get('passed') is True
            and a.get('source_sha256')==c.source_sha256 and a.get('history_sha256')==HISTORY_SHA
            and a.get('target_root')==str(root) and a.get('target_kind')=='datahub-course-cpu'
            and a.get('tokenizers')=='0.22.1' and a.get('real_tokenizer_used') is True
            and a.get('three_method_fake_HTTP_passed') is True and a.get('array_numeric_passed') is True
            and a.get('cpu_fit_smoke_passed') is True and a.get('native_numeric_passed') is True
            and a.get('source_artifacts_unchanged') is True and a.get('children_reaped') is True
            and datetime.fromisoformat(a['accepted_utc'])<=now<datetime.fromisoformat(a['expires_utc']),
            'Fresh full target proof required; offline-only or research-server proof is insufficient','CMPE_PROOF')
        from br7_a_live.catalog import validate_catalog
        validate_catalog(json.loads(Path(catalog).read_text()))
        m = json.loads(Path(models).read_text())
        require(m.get('ok') is True and m.get('http_status')==200 and m.get('worker_reaped') is True
            and m.get('model_access_confirmed') is True and m.get('model')==MODEL
            and datetime.fromisoformat(m['observed_utc'])<=now<datetime.fromisoformat(m['expires_utc']),
            'Fresh model permission required','CMPE_MODELS')
