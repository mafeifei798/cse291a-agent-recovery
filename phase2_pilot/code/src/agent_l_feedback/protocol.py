"""Pinned 314-attempt inheritance, for offline feedback checks only."""
from dataclasses import dataclass
from pathlib import Path
import hashlib
import json

from agent_recovery.contracts import digest, require
from agent_l_batch.protocol import Config as PriorConfig, MODEL

HISTORY_SHA = 'c318f71dc06708d21e2d8c9c3dc9c8ce841c9635f417710cd9cc89b6882c5df8'
UNITS = {'FBC01': 10}
REGISTRATION = {'revision': 'l-feedback-offline-v1', 'units': UNITS,
                'mode': 'fake-HTTP-and-FakeCPU-only', 'real_execution_registered': False,
                'normal_adjustment_limit': 1, 'unit_seconds': 240,
                'retired_units': ['LC01', 'LC02', 'LC03'], 'registration_is_permission': False}
REGISTRATION_SHA = digest(REGISTRATION)


def history(path, source):
    h = json.loads(Path(path).read_text())
    require(h.get('sha256') == HISTORY_SHA == digest({k: v for k, v in h.items() if k != 'sha256'}),
            'Exact 314 history required', 'LF_HISTORY')
    require(all(hashlib.sha256((Path(source)/n).read_bytes()).hexdigest() == v
                for n, v in h['source_files'].items()), 'Historical evidence changed', 'LF_HISTORY')
    require(len(h['receipts']) == len({r['call_id'] for r in h['receipts']}) == 314
            and h['project_dispatches'] == 2792 and h['known_project_nano'] == 250726250
            and h['L_known_nano'] == h['first_known_nano'] == 843400
            and h['first_generations_used'] == 12 and h['expected_key_spend_nano'] == '251021150'
            and sum(v['amount_nano'] for v in h['holds']) == 1003252000,
            'Missing cost or hold inheritance', 'LF_HISTORY')
    return h


@dataclass(frozen=True)
class Config(PriorConfig):
    revision: str = 'l-feedback-offline-v1'
    history_sha256: str = HISTORY_SHA
    registration_sha256: str = REGISTRATION_SHA

    def __post_init__(self):
        require(self.simulated is True and self.model == MODEL and self.revision == 'l-feedback-offline-v1'
                and self.history_sha256 == HISTORY_SHA and self.registration_sha256 == REGISTRATION_SHA,
                'This entry cannot authorize live work', 'LF_OFFLINE_ONLY')
        for name, limit in [('project_cap_nano', 20000000000), ('L_cap_nano', 2000000000), ('first_cap_nano', 1000000000)]:
            require(type(getattr(self, name)) is int and 0 < getattr(self, name) <= limit,
                    'Caps may only shrink', 'LF_CONFIG')
