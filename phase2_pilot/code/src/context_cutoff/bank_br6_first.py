"""Separate, source-bound BR6-01 grant. Frozen offline registration is unchanged."""
from dataclasses import dataclass, asdict
import hashlib
import importlib.metadata
import json
from pathlib import Path
import sqlite3
from contextlib import closing
from time import monotonic, sleep
import sys
from urllib.parse import quote

from agent_recovery.contracts import digest, require
from .bank_br6_protocol import BankBR6Config, PLAN, UNITS, REGISTRY_SHA, source_pins
from .bank_fault_protocol import BankFaultPermit
from .bank_br6_budget import BankBR6Budget
from .bank_br6_calibration import BankBR6Gateway

FIRST_PLAN = tuple(u for u in PLAN if u['scene_id'] == 'BR6-01')
FIRST_IDS = tuple(u['unit_id'] for u in FIRST_PLAN)
GRANT = dict(schema_version='bank-br6-first-grant-v1', registration_sha256=REGISTRY_SHA,
             allowed_units=list(FIRST_IDS), maximum_new_calls=42, next_scene_authorized=False,
             project_cap_nano=20_000_000_000, pilot_cap_nano=3_000_000_000,
             same_batch_cap_nano=2_000_000_000, new_subcap_nano=1_000_000_000,
             inherited_bank_calls=129, holds_released_nano=0)
GRANT_SHA = digest(GRANT)
PACKAGES = ('numpy','scipy','pandas','scikit-learn','joblib','jsonschema','Jinja2','tokenizers')


def package_pins(root):
    root=Path(root).resolve(); pins=source_pins(root)
    paths=set((root/'src/sr_recovery_v2').glob('*.py'))
    paths.update((root/'sr_v2/v0/environment/tokenizer_files').rglob('*'))
    paths.update(root/p for p in ('scripts/run_bank_br6_first.py','scripts/accept_bank_br6_linux.py',
        # Pricing evidence is bound separately by config.price_evidence_sha256.
        # An optional cached catalog must not change the controller pin scope.
        'scripts/run_bank_fault_pilot.py','scripts/run_bank_pilot.py',
        'tests/test_context_cutoff_bank_br6_first.py','tests/test_context_cutoff_token_counter.py',
        'tests/test_context_cutoff_triton.py','tests/test_context_cutoff_cpu.py',
        'tests/test_context_cutoff_bank_fault.py','docs/BANK_BR6_FIRST_ENTRY.md'))
    for p in sorted(paths):
        if p.is_file(): pins[str(p.relative_to(root))]=hashlib.sha256(p.read_bytes()).hexdigest()
    return dict(sorted(pins.items()))


@dataclass(frozen=True)
class BankBR6FirstConfig(BankBR6Config):
    schema_version: str = 'bank-br6-first-launch-v1'
    first_grant_sha256: str = GRANT_SHA
    linux_acceptance_sha256: str = '0'*64

    def registry_policy(self):
        return ('bank-br6-first-launch-v1','bank-fault-B01',UNITS,206)

    def __post_init__(self):
        super().__post_init__()
        require(self.first_grant_sha256==GRANT_SHA and len(self.linux_acceptance_sha256)==64,
                'Separate first-only grant and target proof required','BR6_FIRST_CONFIG')


@dataclass(frozen=True)
class BankBR6FirstPermit(BankFaultPermit):
    history129_sha256: str = ''
    controller_sources_sha256: str = ''
    first_grant_sha256: str = ''
    linux_acceptance_sha256: str = ''

    def validate(self,config,*,fixture_only,now_utc=None):
        super().validate(config,fixture_only=fixture_only,now_utc=now_utc)
        require(isinstance(config,BankBR6FirstConfig)
            and self.history129_sha256==config.history129_sha256
            and self.controller_sources_sha256==config.controller_sources_sha256
            and self.first_grant_sha256==config.first_grant_sha256==GRANT_SHA
            and self.linux_acceptance_sha256==config.linux_acceptance_sha256,
            'First-only grant/source/history/target mismatch','BR6_FIRST_PERMIT')
        if fixture_only:
            require(not self.key_read_authorized and not self.training_authorized,
                    'Offline grant cannot carry key or training permission','BR6_FIRST_PERMIT')
        else:
            require(config.linux_acceptance_sha256!='0'*64
                    and self.async_usage_settlement_authorized is True,
                    'Live grant requires current Linux proof and settlement policy','BR6_FIRST_PERMIT')


class BankBR6FirstBudget(BankBR6Budget):
    _p3_execution_profile='bank-br6-first-permitted-206-v1'
    campaign_name='bank-br6-first-permitted-v1'

    def validate_execution_binding(self,binding):
        require(type(binding.get('simulated')) is bool,'Explicit execution scope required','BR6_FIRST_BINDING')

    def __init__(self,path,*,config,permit,**kwargs):
        permit.validate(config,fixture_only=kwargs.get('binding',{}).get('simulated'))
        require(str(Path(path).resolve())==config.authority_path,
                'Authority not in grant','BR6_FIRST_BINDING')
        path=Path(path).resolve()
        policy=digest(dict(grant=GRANT,config_sha256=config.config_sha256))
        if path.exists():
            with closing(sqlite3.connect('file:'+quote(str(path),safe='/')+'?mode=ro',uri=True)) as db:
                tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                require('br6_first_grant' in tables and db.execute('SELECT body FROM br6_first_grant').fetchall()==[(policy,)],
                        'Cannot adopt offline/old authority','BR6_FIRST_AUTHORITY')
        super().__init__(path,**kwargs)
        self.connection.execute('CREATE TABLE IF NOT EXISTS br6_first_grant(body TEXT PRIMARY KEY)')
        self.connection.execute('INSERT OR IGNORE INTO br6_first_grant VALUES(?)',(policy,))
        self._first_policy=policy

    def _first_check(self,unit):
        require(unit in FIRST_IDS,'Only BR6-01 is authorized; never open BR6-02','BR6_FIRST_SCOPE')
        require(self.connection.execute('SELECT body FROM br6_first_grant').fetchall()[0]['body']==self._first_policy,
                'Durable first grant changed','BR6_FIRST_AUTHORITY')

    def start_unit(self,unit_id):
        self._first_check(unit_id)
        return super().start_unit(unit_id)

    def reserve(self,record):
        with self._transaction():
            self._first_check(record.get('run_id'))
            if not any(c['call_id']==record.get('call_id') for c in self.calls()):
                require(len(self.calls())<42,'First-only cap is 42 even after scene acceptance','BR6_FIRST_CALL_CAP')
            return super().reserve(record)


class BankBR6FirstGateway(BankBR6Gateway):
    offline_only=False

    def __init__(self,*args,**kwargs):
        self._next_allowed=0
        super().__init__(*args,**kwargs)
        require(isinstance(self.ledger,BankBR6FirstBudget),'First authority required','BR6_FIRST_BINDING')

    def call(self,role,messages,identity,*,deadline_monotonic):
        require(identity.get('run_id') in FIRST_IDS,'First-only gateway','BR6_FIRST_SCOPE')
        wait=max(0,self._next_allowed-monotonic())
        require(monotonic()+wait<deadline_monotonic,'Pacing consumes fixed deadline','BR6_FIRST_PACING')
        if wait:sleep(wait)
        value=super().call(role,messages,identity,deadline_monotonic=deadline_monotonic)
        self._next_allowed=monotonic()+(0 if self.fixture_only else 2)
        return value


def fixture_configuration(output,*,root):
    from scripts.run_bank_br6 import fixture_configuration as old_fixture
    old,old_grant=old_fixture(output,root=root)
    body=old.to_dict();body.update(schema_version='bank-br6-first-launch-v1',
        controller_sources_sha256=digest(package_pins(root)))
    config=BankBR6FirstConfig(**body)
    grant=asdict(old_grant);grant.update(config_sha256=config.config_sha256,
        controller_sources_sha256=config.controller_sources_sha256,first_grant_sha256=GRANT_SHA,
        linux_acceptance_sha256=config.linux_acceptance_sha256,
        authorization_reference='BR6-01 CPU/fake HTTP preparation only; no real key, generation, fit or cloud')
    return config,BankBR6FirstPermit(**grant)


def validate_linux_acceptance(path,config,root):
    root=Path(root).resolve();raw=Path(path).read_bytes();a=json.loads(raw)
    require(sys.platform=='linux' and hashlib.sha256(raw).hexdigest()==config.linux_acceptance_sha256,
            'Current Linux acceptance required','BR6_FIRST_LINUX')
    require(a.get('schema_version')=='bank-br6-linux-acceptance-v1' and a.get('passed') is True
            and a.get('skipped')==0 and a.get('controller_sources_sha256')==digest(package_pins(root))
            and a.get('execution_root')==str(root) and a.get('python')==sys.version
            and a.get('packages')=={n:importlib.metadata.version(n) for n in PACKAGES}
            and a.get('tokenizers_version')=='0.22.1' and a.get('linux_child_reaped') is True
            and a.get('real_shaped_requests_counted',0)>0
            and a.get('actual_training')==a.get('actual_prediction')==a.get('real_api_requests')==0
            and a.get('real_credentials_read') is False and a.get('first_grant_sha256')==GRANT_SHA
            and a.get('fit_guard_probe',{}).get('passed') is True
            and a.get('fit_guard_probe',{}).get('model_fits')==0
            and a.get('fit_guard_probe',{}).get('blocked_apis',0)>0
            and a.get('budget_revision')==config.budget_revision,
            'Acceptance is stale, incomplete or for another package/runtime','BR6_FIRST_LINUX')
    return a
