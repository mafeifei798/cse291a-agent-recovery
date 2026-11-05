"""Independent immutable first-batch registration and explicit live capability."""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import json

from agent_recovery.contracts import digest, require

HISTORY_SHA = 'e5c89f06bc79d1734b966cd3bd6a976de654f8e86a98d7c145785cbb2f113b47'
MODEL = 'api-glm-5.3-flash'
UNITS = {'LC01':10, 'LC02':10, 'LI01.PREFIX':10, 'LI01.FULL':10,
         'LI01.CONSERVATIVE':10, 'LI01.CUTOFF':10, 'LI01.CAL_RAW':1, 'LI01.CAL_CORRECTED':1}
REGISTRATION = {'revision':'l-api-first-v1', 'units':UNITS, 'generation_cap':62, 'GET_cap':95,
    'unit_seconds':240, 'HTTP_seconds':120, 'GET_seconds':12, 'close_guard_seconds':15,
    'close_GETs_per_unit':3, 'minimum_HTTP_interval_seconds':2,
    'project_cap_nano':20_000_000_000, 'L_cap_nano':2_000_000_000, 'first_cap_nano':1_000_000_000,
    'risk_per_call_nano':500_000_000, 'input_policy_tokens':4000, 'output_parameter_tokens':768,
    'normal_adjustment_limit':1, 'cutoff_rechecks':1, 'tier':'L', 'registration_is_permission':False}
REGISTRATION_SHA = digest(REGISTRATION)


def history(path):
    h=json.loads(Path(path).read_text())
    require(h.get('sha256') == HISTORY_SHA == digest({k:v for k,v in h.items() if k!='sha256'}), 'Pinned 302 history differs', 'LAPI_HISTORY')
    rows=h['receipts']
    require(len(rows)==len({r['call_id'] for r in rows})==len({r['provider_request_id'] for r in rows})==302,
            'History identities differ','LAPI_HISTORY')
    require(sum(r['cost_nano'] for r in rows)+179686100==h['known_project_nano']==249882850
        and h['original_hold_nano']==503252000 and h['project_total_nano']==753134850
        and h['project_dispatches']==2780, 'Historical liability differs','LAPI_HISTORY')
    return h


def source_sha(root):
    root=Path(root)
    names=[]
    for folder in ('agent_l_api','agent_l_v1','agent_l_v3','agent_recovery','context_cutoff','phase2_unified','sr_cpu_v2','sr_recovery_v2'):
        names += [str(p.relative_to(root)) for p in (root/'src'/folder).glob('*.py')]
    names += ['scripts/run_l_api_pilot.py','scripts/check_l_api_pilot.py','scripts/accept_l_api_first.py']
    import hashlib
    return digest({n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in sorted(names)})


@dataclass(frozen=True)
class Config:
    revision:str='l-api-first-v1'
    model:str=MODEL
    registration_sha256:str=REGISTRATION_SHA
    history_sha256:str=HISTORY_SHA
    project_cap_nano:int=20_000_000_000
    L_cap_nano:int=2_000_000_000
    first_cap_nano:int=1_000_000_000
    target_root:str=''
    source_sha256:str=''
    acceptance_sha256:str=''
    catalog_sha256:str=''
    simulated:bool=True

    def __post_init__(self):
        require(self.revision=='l-api-first-v1' and self.model==MODEL and self.registration_sha256==REGISTRATION_SHA
            and self.history_sha256==HISTORY_SHA and type(self.simulated) is bool,
            'Unknown model/registration/history','LAPI_CONFIG')
        for key,cap in [('project_cap_nano',20_000_000_000),('L_cap_nano',2_000_000_000),('first_cap_nano',1_000_000_000)]:
            require(type(getattr(self,key)) is int and 0 < getattr(self,key)<=cap,'Cap may only shrink','LAPI_CONFIG')

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

    def validate_live(self, config, root, acceptance, catalog):
        import hashlib,sys,os
        require(not config.simulated and self.config_sha256==config.sha256 and self.real_API_authorized
            and self.key_read_authorized and self.CPU_authorized and self.authorization_reference.strip(),
            'No matching explicit live grant','LAPI_LIVE_PERMISSION')
        now=datetime.now(timezone.utc)
        end=datetime.fromisoformat(self.expires_utc.replace('Z','+00:00'))
        require(now<end and (end-now).total_seconds()<=7200,'Live grant expired','LAPI_LIVE_PERMISSION')
        require(sys.platform=='linux' and str(Path(root).resolve())==config.target_root
            and source_sha(root)==config.source_sha256,'Target/source changed','LAPI_NATIVE_PROOF')
        a=Path(acceptance); c=Path(catalog)
        require(hashlib.sha256(a.read_bytes()).hexdigest()==config.acceptance_sha256
            and hashlib.sha256(c.read_bytes()).hexdigest()==config.catalog_sha256,'Target evidence changed','LAPI_NATIVE_PROOF')
        proof=json.loads(a.read_text())
        require(proof.get('passed') is True and proof.get('fixture_only') is False
            and proof.get('source_sha256')==config.source_sha256
            and proof.get('tokenizers')=='0.22.1' and proof.get('RF_numeric_passed') is True
            and proof.get('children_reaped') is True and proof.get('target_kind')=='datahub-course-cpu'
            and os.environ.get('JUPYTERHUB_USER')=='hoding','Current native proof incomplete','LAPI_NATIVE_PROOF')
        require(datetime.fromisoformat(proof['accepted_utc'].replace('Z','+00:00'))<=now<
            datetime.fromisoformat(proof['expires_utc'].replace('Z','+00:00')),'Native proof expired','LAPI_NATIVE_PROOF')
        from br7_a_live.catalog import validate_catalog
        validate_catalog(json.loads(c.read_text()))
