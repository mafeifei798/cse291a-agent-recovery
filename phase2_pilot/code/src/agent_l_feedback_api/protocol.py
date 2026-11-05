"""64 total / 52 new generations; 314 history and unchanged monetary caps."""
from dataclasses import dataclass
from pathlib import Path
import hashlib
import json

from agent_recovery.contracts import digest, require
from agent_l_batch.protocol import Config as PriorConfig, Permit as PriorPermit, source_sha as prior_source, MODEL
from agent_l_feedback.protocol import history, HISTORY_SHA

UNITS = {'LC04': 10, 'LI01.PREFIX': 10, 'LI01.FULL': 10, 'LI01.CONSERVATIVE': 10,
         'LI01.CUTOFF': 10, 'LI01.CAL_RAW': 1, 'LI01.CAL_CORRECTED': 1}
REGISTRATION = {'revision': 'l-feedback-api-v1', 'units': UNITS, 'first_total_generation_cap': 64,
                'inherited_generations': 12, 'new_generation_cap': 52, 'new_GET_cap': 6,
                'inherited_GETs': 18, 'retired_units': ['LC01', 'LC02', 'LC03'],
                'normal_adjustment_limit': 1, 'cutoff_rechecks': 1, 'unit_seconds': 240,
                'feedback_protocol': 'l-feedback-v1', 'registration_is_permission': False}
REGISTRATION_SHA = digest(REGISTRATION)


def source_sha(root):
    root = Path(root)
    extra = [p for folder in ('agent_l_feedback', 'agent_l_feedback_api') for p in (root/'src'/folder).glob('*.py')]
    extra += [root/'scripts'/n for n in ('run_l_feedback_api.py', 'check_l_feedback_api.py', 'accept_l_feedback_api.py')]
    extra += [root/'tests'/n for n in ('test_l_feedback_api.py', 'test_l_api_native.py')]
    return digest({'prior_core': prior_source(root), 'feedback': {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(extra)}})


@dataclass(frozen=True)
class Config(PriorConfig):
    revision: str = 'l-feedback-api-v1'
    history_sha256: str = HISTORY_SHA
    registration_sha256: str = REGISTRATION_SHA

    def __post_init__(self):
        require(self.revision == 'l-feedback-api-v1' and self.model == MODEL and type(self.simulated) is bool
                and self.history_sha256 == HISTORY_SHA and self.registration_sha256 == REGISTRATION_SHA,
                'Exact feedback continuation required', 'LFA_CONFIG')
        for name, limit in [('project_cap_nano', 20000000000), ('L_cap_nano', 2000000000), ('first_cap_nano', 1000000000)]:
            require(type(getattr(self, name)) is int and 0 < getattr(self, name) <= limit,
                    'Money caps may only shrink', 'LFA_CONFIG')


class Permit(PriorPermit):
    def proof_source_sha(self, root):
        return source_sha(root)

    def proof_history_sha(self):
        return HISTORY_SHA

    def validate_live(self, c, root, acceptance, catalog, models):
        super().validate_live(c, root, acceptance, catalog, models)
        a = json.loads(Path(acceptance).read_text())
        require(a.get('feedback_protocol') == 'l-feedback-v1' and a.get('first_total_generation_cap') == 64
                and a.get('new_generation_cap') == 52 and a.get('all_recoveries_use_feedback_loop') is True,
                'New feedback target proof required', 'LFA_NATIVE_PROOF')
