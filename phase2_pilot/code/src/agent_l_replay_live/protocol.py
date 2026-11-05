from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import os
import sys

from agent_recovery.contracts import digest, require
from agent_l_batch.protocol import Config as PriorConfig, Permit as PriorPermit
from agent_l_feedback_api.protocol import source_sha as old_source_sha
from agent_l_feedback_replay.protocol import history, HISTORY_SHA

MODEL = 'api-glm-5.3-flash'
UNITS = {f'FR02.{m}': 10 for m in ('FULL', 'CONSERVATIVE', 'CUTOFF')}
REGISTRATION = {'revision': 'stage-replay-entry-v1', 'units': UNITS,
                'one_method_per_authority': True, 'max_new_generations': 10,
                'inherited_first_generations': 48, 'first_total_generation_cap': 64,
                'new_GET_cap': 6, 'unit_seconds': 240, 'metadata_seconds': 30,
                'normal_adjustment_limit': 1, 'same_stage_rechecks': 1,
                'registration_is_permission': False}
REGISTRATION_SHA = digest(REGISTRATION)


def source_sha(root):
    root = Path(root)
    files = [p for d in ('agent_l_feedback_replay', 'agent_l_replay_live') for p in (root/'src'/d).glob('*.py')]
    files += [root/'scripts'/n for n in ('run_l_replay_entry.py', 'check_l_replay_entry.py', 'accept_l_replay_linux.py')]
    return digest({'prior_core': old_source_sha(root),
                   'stage_replay': {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                                    for p in sorted(files)}})


@dataclass(frozen=True)
class Config(PriorConfig):
    revision: str = 'stage-replay-entry-v1'
    history_sha256: str = HISTORY_SHA
    registration_sha256: str = REGISTRATION_SHA
    method: str = 'CUTOFF'
    new_generation_cap: int = 10
    first_total_generation_cap: int = 64
    allow_training: bool = False

    def __post_init__(self):
        require(self.revision == 'stage-replay-entry-v1' and self.model == MODEL
                and self.history_sha256 == HISTORY_SHA and self.registration_sha256 == REGISTRATION_SHA
                and type(self.simulated) is bool and type(self.allow_training) is bool,
                'Exact independent config required', 'FRL_CONFIG')
        require(self.method in ('FULL', 'CONSERVATIVE', 'CUTOFF') and type(self.new_generation_cap) is int
                and 1 <= self.new_generation_cap <= 10 and self.first_total_generation_cap == 64
                and 48+self.new_generation_cap <= self.first_total_generation_cap,
                'Do not enlarge original generation scope', 'FRL_CALL_CAP')
        require((self.project_cap_nano, self.L_cap_nano, self.first_cap_nano) ==
                (20000000000, 2000000000, 1000000000), 'Money caps unchanged', 'FRL_CAPS')


@dataclass(frozen=True)
class Permit(PriorPermit):
    method: str = ''
    generation_cap: int = 0
    training_authorized: bool = False

    def validate_live(self, config, root, acceptance, catalog, models):
        require(not config.simulated and self.config_sha256 == config.sha256
                and self.real_API_authorized is True and self.key_read_authorized is True
                and self.CPU_authorized is True and self.authorization_reference
                and self.method == config.method and self.generation_cap == config.new_generation_cap,
                'Fresh method-bound explicit permission required', 'FRL_PERMISSION')
        require((not config.allow_training or self.training_authorized)
                and (config.method == 'CUTOFF' or config.allow_training),
                'Training requires separate explicit capability', 'FRL_TRAINING')
        now = datetime.now(timezone.utc)
        expires = datetime.fromisoformat(self.expires_utc.replace('Z', '+00:00'))
        require(now < expires and (expires-now).total_seconds() <= 7200, 'Expired permit', 'FRL_PERMISSION')
        root = Path(root).resolve()
        require(sys.platform == 'linux' and str(root) == config.target_root
                and os.environ.get('JUPYTERHUB_USER') == 'hoding' and source_sha(root) == config.source_sha256,
                'Wrong target or source', 'FRL_TARGET')
        for p, expected in ((acceptance, config.acceptance_sha256), (catalog, config.catalog_sha256),
                            (models, config.models_sha256)):
            require(hashlib.sha256(Path(p).read_bytes()).hexdigest() == expected, 'Proof changed', 'FRL_PROOF')
        proof = json.loads(Path(acceptance).read_text())
        require(proof.get('passed') is True and proof.get('source_sha256') == config.source_sha256
                and proof.get('history_sha256') == HISTORY_SHA and proof.get('target_root') == str(root)
                and proof.get('target_kind') == 'datahub-course-cpu' and proof.get('tokenizers') == '0.22.1'
                and proof.get('real_tokenizer_used') is True and proof.get('stage_replay_checked') is True
                and proof.get('children_reaped') is True and proof.get('no_fit_numeric_passed') is True,
                'Fresh target acceptance required; server proof cannot authorize DataHub', 'FRL_PROOF')
        require(datetime.fromisoformat(proof['accepted_utc']) <= now < datetime.fromisoformat(proof['expires_utc']),
                'Expired target proof', 'FRL_PROOF')
        from br7_a_live.catalog import validate_catalog
        validate_catalog(json.loads(Path(catalog).read_text()))
        model = json.loads(Path(models).read_text())
        require(model.get('ok') is True and model.get('http_status') == 200
                and model.get('worker_reaped') is True and model.get('model_access_confirmed') is True
                and model.get('model') == MODEL
                and datetime.fromisoformat(model['observed_utc']) <= now < datetime.fromisoformat(model['expires_utc']),
                'Fresh model access proof required', 'FRL_MODEL')
