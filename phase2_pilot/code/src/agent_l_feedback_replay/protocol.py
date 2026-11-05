"""350 real receipts are inherited unchanged; new work is simulation only."""
from dataclasses import dataclass
from pathlib import Path
import hashlib
import json

from agent_l_feedback_api.protocol import Config as PriorConfig
from agent_recovery.contracts import digest, require

HISTORY_SHA = 'bc6d420aaf0976c06b6b8bd8d2abb02c566adb9337533b349c6013077ba8d0f4'
UNITS = {f'FR02.{method}': 10 for method in ('FULL', 'CONSERVATIVE', 'CUTOFF')}
REGISTRATION = {'revision': 'feedback-replay-offline-v2', 'units': UNITS,
                'execution': 'independent per-branch simulation; no live permission',
                'normal_adjustment_limit': 1, 'recheck_per_stage': 1,
                'historical_real_calls': 350, 'real_generations_authorized': 0,
                'real_training_authorized': 0, 'unit_seconds': 240}
REGISTRATION_SHA = digest(REGISTRATION)


def history(path, root):
    h = json.loads(Path(path).read_text())
    require(h['sha256'] == HISTORY_SHA == digest({k: v for k, v in h.items() if k != 'sha256'}),
            '350 history digest changed', 'FR_HISTORY')
    require(all(hashlib.sha256((Path(root)/n).read_bytes()).hexdigest() == value
                for n, value in h['source_files'].items()), 'Historical source changed', 'FR_HISTORY')
    require(h['Bank_calls'] == len(h['receipts']) == len({r['call_id'] for r in h['receipts']}) == 350
            and h['known_project_nano'] == 254776350 and h['first_known_nano'] == 4893500
            and h['first_generations_used'] == 48 and h['project_dispatches'] == 2828
            and [v['amount_nano'] for v in h['holds']] == [503252000, 500000000],
            'History must retain costs, identities and holds', 'FR_HISTORY')
    return h


@dataclass(frozen=True)
class Config(PriorConfig):
    revision: str = 'feedback-replay-offline-v2'
    history_sha256: str = HISTORY_SHA
    registration_sha256: str = REGISTRATION_SHA

    def __post_init__(self):
        require(self.simulated is True and self.revision == 'feedback-replay-offline-v2'
                and self.history_sha256 == HISTORY_SHA and self.registration_sha256 == REGISTRATION_SHA,
                'Offline-only entry', 'FR_OFFLINE_ONLY')
        require((self.project_cap_nano, self.L_cap_nano, self.first_cap_nano) ==
                (20000000000, 2000000000, 1000000000), 'Do not change money caps', 'FR_CAPS')
