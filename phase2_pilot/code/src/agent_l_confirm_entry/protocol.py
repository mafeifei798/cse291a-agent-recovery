from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import os
import resource
import sys

from agent_l_batch.protocol import Config as BaseConfig, Permit as BasePermit
from agent_l_approval_confirm.protocol import HISTORY_REL, HISTORY_SHA, history, source_sha as old_source_sha
from agent_recovery.contracts import digest, require

MODEL = 'api-glm-5.3-flash'
UNIT = 'FR04.CUTOFF'
REGISTRATION = {'revision':'confirm-entry-v1','units':{UNIT:10},'method':'CUTOFF',
    'inherited_Bank_calls':356,'inherited_first_generations':54,'first_total_generation_cap':64,
    'new_generation_cap':10,'new_GET_cap':6,'batch_GET_cap':4,'normal_adjustment_spent':1,
    'normal_adjustment_remaining':0,'training_authorized':False,'unit_seconds_max':240,
    'remaining_seconds':192.470543,'registration_is_permission':False}
REGISTRATION_SHA = digest(REGISTRATION)


def source_sha(root):
    root = Path(root)
    files = list((root/'src/agent_l_confirm_entry').glob('*.py'))
    files += [root/'scripts'/n for n in ('run_l_confirm_entry.py','check_l_confirm_entry.py','accept_l_confirm_linux.py')]
    return digest({'prior_core':old_source_sha(root),'entry':{
        str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}})


def require_resources():
    require(sys.platform == 'linux' and sys.version.split()[0] == '3.10.12',
            'Pinned Linux Python required','ACE_ENVIRONMENT')
    require(len(os.sched_getaffinity(0)) == 1 and os.nice(0) >= 10
            and resource.getrlimit(resource.RLIMIT_AS)[0] == 8*1024**3
            and os.environ.get('CUDA_VISIBLE_DEVICES') == ''
            and all(os.environ.get(k) == '1' for k in
                ('OMP_NUM_THREADS','OPENBLAS_NUM_THREADS','MKL_NUM_THREADS','NUMEXPR_NUM_THREADS')),
            'One CPU, 8GiB, single-thread, no-GPU envelope required','ACE_RESOURCES')


@dataclass(frozen=True)
class Config(BaseConfig):
    revision:str = 'confirm-entry-v1'
    history_sha256:str = HISTORY_SHA
    registration_sha256:str = REGISTRATION_SHA
    method:str = 'CUTOFF'
    new_generation_cap:int = 10
    first_total_generation_cap:int = 64
    allow_training:bool = False

    def __post_init__(self):
        require(self.revision == 'confirm-entry-v1' and self.model == MODEL
                and self.history_sha256 == HISTORY_SHA and self.registration_sha256 == REGISTRATION_SHA
                and type(self.simulated) is bool,'Exact new config required','ACE_CONFIG')
        require(self.method == 'CUTOFF' and self.allow_training is False,
                'CUTOFF only; training cannot be enabled','ACE_NO_TRAINING')
        require(type(self.new_generation_cap) is int and 1 <= self.new_generation_cap <= 10
                and self.first_total_generation_cap == 64 and 54+self.new_generation_cap <= 64,
                'Only10 first-batch generations remain','ACE_CALL_CAP')
        require((self.project_cap_nano,self.L_cap_nano,self.first_cap_nano) ==
                (20000000000,2000000000,1000000000),'Money caps unchanged','ACE_CAPS')


@dataclass(frozen=True)
class Permit(BasePermit):
    method:str = 'CUTOFF'
    generation_cap:int = 10
    training_authorized:bool = False

    def validate_live(self, c, root, acceptance, catalog, models):
        require(not c.simulated and self.config_sha256 == c.sha256 and self.real_API_authorized is True
                and self.key_read_authorized is True and self.CPU_authorized is True
                and bool(self.authorization_reference) and self.method == c.method
                and self.generation_cap == c.new_generation_cap and self.training_authorized is False
                and c.allow_training is False,'Fresh explicit CUTOFF permission required','ACE_PERMISSION')
        now = datetime.now(timezone.utc)
        end = datetime.fromisoformat(self.expires_utc.replace('Z','+00:00'))
        require(now < end and (end-now).total_seconds() <= 7200,'Expired permit','ACE_PERMISSION')
        require_resources()
        root = Path(root).resolve()
        require(str(root) == c.target_root and os.environ.get('JUPYTERHUB_USER') == 'hoding'
                and source_sha(root) == c.source_sha256,'Wrong target or source','ACE_TARGET')
        for p,expected in ((acceptance,c.acceptance_sha256),(catalog,c.catalog_sha256),(models,c.models_sha256)):
            require(p is not None and expected and hashlib.sha256(Path(p).read_bytes()).hexdigest() == expected,
                    'Changed or missing proof','ACE_PROOF')
        proof = json.loads(Path(acceptance).read_text())
        require(proof.get('revision') == 'confirm-entry-native-v1' and proof.get('passed') is True
                and proof.get('source_sha256') == c.source_sha256 and proof.get('history_sha256') == HISTORY_SHA
                and proof.get('target_root') == str(root) and proof.get('target_kind') == 'datahub-course-cpu'
                and proof.get('tokenizers') == '0.22.1' and proof.get('real_tokenizer_used') is True
                and proof.get('confirmation_protocol_checked') is True and proof.get('no_fit_numeric_passed') is True
                and proof.get('children_reaped') is True and proof.get('model_fits') == 0
                and proof.get('inherited_first_generations') == 54 and proof.get('remaining_generations') == 10
                and proof.get('source_artifacts_unchanged') is True,
                'Fresh target proof required; research-server proof cannot authorize DataHub','ACE_PROOF')
        require(datetime.fromisoformat(proof['accepted_utc']) <= now < datetime.fromisoformat(proof['expires_utc']),
                'Expired native proof','ACE_PROOF')
        from br7_a_live.catalog import validate_catalog
        validate_catalog(json.loads(Path(catalog).read_text()))
        model = json.loads(Path(models).read_text())
        require(model.get('ok') is True and model.get('http_status') == 200 and model.get('worker_reaped') is True
                and model.get('model_access_confirmed') is True and model.get('model') == MODEL
                and datetime.fromisoformat(model['observed_utc']) <= now < datetime.fromisoformat(model['expires_utc']),
                'Fresh model permission required','ACE_MODELS')
