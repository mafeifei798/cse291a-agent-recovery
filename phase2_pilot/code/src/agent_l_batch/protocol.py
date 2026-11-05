"""303-attempt inheritance, no revival of LC01, default-denied live capability."""
from dataclasses import dataclass,asdict
from datetime import datetime,timezone
import hashlib,json,os,sys
from pathlib import Path
from agent_recovery.contracts import digest,require
from agent_l_api.protocol import MODEL,source_sha as prior_source_sha

HISTORY_SHA='fbd12f6e0dfaf9e055d245dbc17703682dba6d757d1e3ef5abb5201f7ac4fa6f'
UNITS={'LC03':9,'LC02':10,'LI01.PREFIX':10,'LI01.FULL':10,
       'LI01.CONSERVATIVE':10,'LI01.CUTOFF':10,'LI01.CAL_RAW':1,'LI01.CAL_CORRECTED':1}
REGISTRATION={'revision':'l-api-batch-v1','units':UNITS,'new_generation_cap':61,
    'first_total_generation_cap':62,'new_GET_cap':6,'old_GETs':7,'unit_seconds':240,
    'batch_close_seconds':30,'close_GET_cap':3,'HTTP_interval_seconds':2,
    'billing_mode':'usage-priced-then-batch-reconciled','registration_is_permission':False}
REGISTRATION_SHA=digest(REGISTRATION)

def history(path,source):
    h=json.loads(Path(path).read_text())
    require(h.get('sha256')==HISTORY_SHA==digest({k:v for k,v in h.items() if k!='sha256'}),
        'Exact latest history required','LB_HISTORY')
    require(all(hashlib.sha256((Path(source)/n).read_bytes()).hexdigest()==v for n,v in h['source_files'].items()),
        'Historical source evidence changed','LB_HISTORY')
    require(len(h['receipts'])==len({r['call_id'] for r in h['receipts']})==303
        and h['project_dispatches']==2781 and sum(v['amount_nano'] for v in h['holds'])==1003252000
        and h['known_project_nano']==249882850 and h['first_held_nano']==500000000,
        'Historical liability mismatch','LB_HISTORY')
    return h

def source_sha(root):
    root=Path(root)
    extra=[p for p in (root/'src/agent_l_batch').glob('*.py')]
    extra += [root/'scripts/run_l_api_batch.py',root/'scripts/check_l_api_batch.py',root/'scripts/accept_l_api_batch.py']
    return digest({'prior_core':prior_source_sha(root),
        'batch':{str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(extra)}})

@dataclass(frozen=True)
class Config:
    revision:str='l-api-batch-v1'
    model:str=MODEL
    history_sha256:str=HISTORY_SHA
    registration_sha256:str=REGISTRATION_SHA
    project_cap_nano:int=20_000_000_000
    L_cap_nano:int=2_000_000_000
    first_cap_nano:int=1_000_000_000
    simulated:bool=True
    target_root:str=''
    source_sha256:str=''
    acceptance_sha256:str=''
    catalog_sha256:str=''
    models_sha256:str=''
    output_root:str=''
    def __post_init__(self):
        require(self.revision=='l-api-batch-v1' and self.model==MODEL and self.history_sha256==HISTORY_SHA
            and self.registration_sha256==REGISTRATION_SHA and type(self.simulated) is bool,'Unknown config','LB_CONFIG')
        for k,v in [('project_cap_nano',20_000_000_000),('L_cap_nano',2_000_000_000),('first_cap_nano',1_000_000_000)]:
            require(type(getattr(self,k)) is int and 0<getattr(self,k)<=v,'Caps may only shrink','LB_CONFIG')
    @property
    def sha256(self):return digest(asdict(self))

@dataclass(frozen=True)
class Permit:
    config_sha256:str=''
    real_API_authorized:bool=False
    key_read_authorized:bool=False
    CPU_authorized:bool=False
    authorization_reference:str=''
    expires_utc:str=''
    def proof_source_sha(self,root):return source_sha(root)
    def proof_history_sha(self):return HISTORY_SHA
    def validate_live(self,c,root,acceptance,catalog,models):
        require(not c.simulated and self.config_sha256==c.sha256 and self.real_API_authorized
            and self.key_read_authorized and self.CPU_authorized and self.authorization_reference,
            'Matching explicit live permission required','LB_LIVE_PERMISSION')
        now=datetime.now(timezone.utc);end=datetime.fromisoformat(self.expires_utc.replace('Z','+00:00'))
        require(now<end and (end-now).total_seconds()<=7200,'Expired live permission','LB_LIVE_PERMISSION')
        require(sys.platform=='linux' and str(Path(root).resolve())==c.target_root
            and self.proof_source_sha(root)==c.source_sha256 and os.environ.get('JUPYTERHUB_USER')=='hoding',
            'Wrong target/source','LB_NATIVE_PROOF')
        require(hashlib.sha256(Path(acceptance).read_bytes()).hexdigest()==c.acceptance_sha256
            and hashlib.sha256(Path(catalog).read_bytes()).hexdigest()==c.catalog_sha256
            and hashlib.sha256(Path(models).read_bytes()).hexdigest()==c.models_sha256,'Changed proof','LB_NATIVE_PROOF')
        a=json.loads(Path(acceptance).read_text())
        require(a.get('passed') is True and a.get('fixture_only') is False and a.get('source_sha256')==c.source_sha256
            and a.get('history_sha256')==self.proof_history_sha() and a.get('tokenizers')=='0.22.1'
            and a.get('RF_numeric_passed') is True and a.get('children_reaped') is True
            and a.get('batch_accounting_passed') is True,'Incomplete native proof','LB_NATIVE_PROOF')
        require(datetime.fromisoformat(a['accepted_utc'].replace('Z','+00:00'))<=now<
            datetime.fromisoformat(a['expires_utc'].replace('Z','+00:00')),'Expired native proof','LB_NATIVE_PROOF')
        from br7_a_live.catalog import validate_catalog
        validate_catalog(json.loads(Path(catalog).read_text()))
        m=json.loads(Path(models).read_text())
        require(m.get('ok') is True and m.get('http_status')==200 and m.get('model_access_confirmed') is True
            and m.get('worker_reaped') is True and m.get('model')==MODEL
            and datetime.fromisoformat(m['observed_utc'].replace('Z','+00:00'))<=now<
                datetime.fromisoformat(m['expires_utc'].replace('Z','+00:00')),
            'Fresh model permission evidence required','LB_MODEL_PROOF')
