from dataclasses import dataclass
from pathlib import Path
import hashlib
import json

from agent_recovery.contracts import digest, require
from agent_l_batch.protocol import Config as PriorConfig, MODEL

HISTORY_SHA = 'e7a1587eae8323c287a693ad4e0b26f12bbdf67b7c0019d04fa8b57fb9f7dc3c'
HISTORY_REL = 'phase2/l_approval_confirm_20261031_v1/HISTORY.json'
REGISTRATION = {'revision':'approval-confirm-offline-v1',
    'units':{'FR03.'+m:10 for m in ('FULL','CONSERVATIVE','CUTOFF')},
    'inherited_real_generations':54,'first_total_generation_cap':64,
    'normal_adjustment_limit':1,'normal_adjustment_already_spent':1,
    'confirmation_per_stage':1,'new_GET_cap':6,'unit_seconds_max':240,
    'execution':'Independent per-method fake-HTTP simulation only',
    'real_API_authorized':False,'training_authorized':False,'cloud_authorized':False}
REGISTRATION_SHA = digest(REGISTRATION)


def history(path, source):
    root = Path(source).resolve()
    h = json.loads(Path(path).read_text())
    require(h.get('sha256') == HISTORY_SHA == digest({k:v for k,v in h.items() if k!='sha256'}),
            'Exact 356 history required', 'AC_HISTORY')
    for name, value in h['source_files'].items():
        p = root/name
        require(not Path(name).is_absolute() and '..' not in Path(name).parts
                and p.resolve().is_relative_to(root) and not p.is_symlink()
                and hashlib.sha256(p.read_bytes()).hexdigest() == value,
                'Historical evidence changed', 'AC_HISTORY')
    require(h['Bank_calls'] == len(h['receipts']) == len({r['call_id'] for r in h['receipts']}) == 356
            and h['project_dispatches'] == 2834 and h['known_project_nano'] == 255512150
            and h['L_known_nano'] == h['first_known_nano'] == 5629300
            and h['first_generations_used'] == 54 and h['normal_adjustment_already_spent'] == 1
            and [r['amount_nano'] for r in h['holds']] == [503252000,500000000]
            and h['project_held_nano'] == 1003252000 and h['first_held_nano'] == h['L_held_nano'] == 500000000,
            'Do not reset history, costs, holds or allowance', 'AC_HISTORY')
    return h


@dataclass(frozen=True)
class Config(PriorConfig):
    revision: str = 'approval-confirm-offline-v1'
    history_sha256: str = HISTORY_SHA
    registration_sha256: str = REGISTRATION_SHA
    method: str = 'CUTOFF'
    new_generation_cap: int = 10
    first_total_generation_cap: int = 64

    def __post_init__(self):
        require(self.simulated is True and self.model == MODEL and self.revision == REGISTRATION['revision']
                and self.history_sha256 == HISTORY_SHA and self.registration_sha256 == REGISTRATION_SHA,
                'This revision has offline permission only', 'AC_OFFLINE_ONLY')
        require(self.method in ('FULL','CONSERVATIVE','CUTOFF') and type(self.new_generation_cap) is int
                and 1 <= self.new_generation_cap <= 10 and self.first_total_generation_cap == 64,
                'Generation scope cannot expand', 'AC_CALL_CAP')
        require((self.project_cap_nano,self.L_cap_nano,self.first_cap_nano) ==
                (20000000000,2000000000,1000000000), 'Money caps unchanged', 'AC_CAPS')


def source_sha(root):
    root = Path(root)
    from agent_l_replay_live.protocol import source_sha as prior_source
    files = list((root/'src/agent_l_approval_confirm').glob('*.py'))
    files += [root/'scripts'/n for n in ('run_l_approval_confirm_offline.py','check_l_approval_confirm_offline.py')]
    return digest({'prior_core':prior_source(root),'confirmation':{
        str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}})
