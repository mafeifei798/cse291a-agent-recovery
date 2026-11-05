"""Separate BR6 registration; this revision admits CPU/fake HTTP only."""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from agent_recovery.contracts import digest, require
from .bank_fault_protocol import BankFaultConfig, BankFaultPermit
from .bank_prompt_r6 import PROMPT_REVISION

SCENES = tuple('BR6-%02d' % i for i in range(1, 6))
ORDERS = (('FULL', 'CONSERVATIVE', 'CUTOFF'),
          ('CONSERVATIVE', 'CUTOFF', 'FULL'),
          ('CUTOFF', 'FULL', 'CONSERVATIVE'),
          ('FULL', 'CUTOFF', 'CONSERVATIVE'),
          ('CONSERVATIVE', 'FULL', 'CUTOFF'))
CAL_SCENES = (SCENES[0], SCENES[2], SCENES[4])
PLAN = tuple(dict(unit_id=scene + '.' + kind, scene_id=scene,
                  kind=kind, mode='SCOPED', call_cap=1 if kind.startswith('CAL_') else 10)
             for scene, order in zip(SCENES, ORDERS)
             for kind in ('PREFIX', *order, * (('CAL_RAW', 'CAL_CORRECTED') if scene in CAL_SCENES else ())))
UNITS = tuple((u['unit_id'], u['mode']) for u in PLAN)
UNIT_MAP = {u['unit_id']: u for u in PLAN}
REGISTRY = dict(schema_version='bank-br6-offline-registry-v1', scenes=list(SCENES),
    units=list(PLAN), recovery_methods=['FULL', 'CONSERVATIVE', 'CUTOFF'],
    fault='F_INCIDENTAL', fault_delta=dict(field='row_count', original=41188, delivered=41189),
    prompt_revision=PROMPT_REVISION, context_mode='SCOPED', new_call_cap=206,
    first_stage_call_cap=42, role_call_cap=5, unit_deadline_seconds=120,
    cutoff_rechecks_per_round=1, calibrations=6, calibration_analysis_only=True,
    same_batch_cap_nano=2_000_000_000, new_subcap_nano=1_000_000_000,
    pilot_cap_nano=3_000_000_000, project_cap_nano=20_000_000_000,
    inherited_bank_calls=129, historical_holds_released_nano=0,
    per_unit_training_requests=1, actual_training_authorized=False,
    real_api_authorized=False, cloud_authorized=False,
    offline_protocol_frozen=True, scientific_evaluation_frozen=False)
REGISTRY_SHA = digest(REGISTRY)
DATA_PATHS=('sr_v2/v0/data/raw/bank/bank-additional-full.csv',
            'sr_v2/v0/data/splits/bank/train_v1.json','sr_v2/v0/data/splits/bank/validation.json')


def validate_frozen(root):
    root=Path(root);folder=root/'phase2/br6_r1/frozen'
    registry=json.loads((folder/'registry.json').read_text())
    task=json.loads((folder/'task.json').read_text())
    budget=json.loads((folder/'budget.json').read_text())
    from .runtime import initial_inputs
    from .cpu import worker_code_text
    description,binding,_=initial_inputs()
    require(registry==json.loads(json.dumps({**REGISTRY,'sha256':REGISTRY_SHA}))
            and task['description']==description and task['data_binding']==binding
            and task['source_files']=={p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in DATA_PATHS}
            and task['worker_code_sha256']==hashlib.sha256(worker_code_text().encode()).hexdigest()
            and all(budget[k]==REGISTRY[reg] for k,reg in
                    [('project_cap_nano','project_cap_nano'),('pilot_cap_nano','pilot_cap_nano'),
                     ('same_batch_cap_nano','same_batch_cap_nano'),('new_subcap_nano','new_subcap_nano'),
                     ('max_fake_calls','new_call_cap'),('first_stage_call_cap','first_stage_call_cap')]),
            'Frozen registry, task or budget differs', 'BR6_FROZEN')


def source_pins(root):
    root = Path(root)
    files = set()
    for d in ('context_cutoff', 'agent_recovery', 'phase2_unified', 'sr_cpu_v2'):
        files.update((root / 'src' / d).glob('*.py'))
    files.add(root / 'scripts/run_bank_br6.py')
    files.update(root/p for p in DATA_PATHS)
    files.update((root/'phase2/br6_r1/frozen').glob('*.json'))
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}


@dataclass(frozen=True)
class BankBR6Config(BankFaultConfig):
    schema_version: str = 'bank-br6-launch-v1'
    batch_id: str = 'bank-fault-B01'
    runs: tuple = UNITS
    total_call_cap: int = 206
    registry_sha256: str = REGISTRY_SHA
    budget_revision: str = 'bank-budget-20261024-r3'
    batch_cap_nano: int = 2_000_000_000
    subcap_nano: int = 1_000_000_000
    first_stage_call_cap: int = 42
    prompt_revision: str = PROMPT_REVISION
    history129_sha256: str = ''
    controller_sources_sha256: str = ''

    def registry_policy(self):
        return ('bank-br6-launch-v1', 'bank-fault-B01', UNITS, 206)

    def expected_registry_sha256(self):
        return REGISTRY_SHA

    def allowed_budget_revisions(self):
        return ('bank-budget-20261024-r3',)

    def __post_init__(self):
        super().__post_init__()
        require(self.subcap_nano == 1_000_000_000 and type(self.subcap_nano) is int
                and self.first_stage_call_cap == 42 and type(self.first_stage_call_cap) is int
                and self.prompt_revision == PROMPT_REVISION
                and all(isinstance(v, str) and len(v) == 64 for v in
                        (self.history129_sha256, self.controller_sources_sha256)),
                'BR6 registration/history/source binding differs', 'BR6_CONFIG')


@dataclass(frozen=True)
class BankBR6Permit(BankFaultPermit):
    history129_sha256: str = ''
    controller_sources_sha256: str = ''

    def validate(self, config, *, fixture_only, now_utc=None):
        require(fixture_only is True and self.real_requests_authorized is False
                and self.training_authorized is False and self.key_read_authorized is False,
                'This preparation has no real API, key or training permission', 'BR6_LIVE_DISABLED')
        super().validate(config, fixture_only=fixture_only, now_utc=now_utc)
        require(isinstance(config, BankBR6Config)
                and self.history129_sha256 == config.history129_sha256
                and self.controller_sources_sha256 == config.controller_sources_sha256,
                'BR6 grant belongs to different history or sources', 'BR6_PERMIT')
