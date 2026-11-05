"""Explicit r6 continuation protocol; preparation grants no live access."""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from agent_recovery.contracts import digest, require
from .bank_fault_protocol import BankFaultConfig, BankFaultPermit, REGISTRY_SHA, write_new
from .bank_prompt_r6 import PROMPT_REVISION
from .bank_r6_history import load_r6_history, read_fault_archives, RAW_PREFIX
from .bank_gateway import BankPilotGateway

HISTORY39_SHA = '1bf2ac8b0850639fdccb05bdc32a8e09f44f1a58a697c8f0f36205ffa6296271'


class BankR6PacedGateway(BankPilotGateway):
    """Single concurrency; pacing consumes the original unit deadline."""
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self._next_allowed=0

    def call(self,role,messages,identity,*,deadline_monotonic):
        from time import monotonic,sleep
        self.validate()
        wait=max(0,self._next_allowed-monotonic())
        require(monotonic()+wait<deadline_monotonic,'Pacing would exhaust fixed deadline','R6_PACING_DEADLINE')
        if wait:sleep(wait)
        result=super().call(role,messages,identity,deadline_monotonic=deadline_monotonic)
        self._next_allowed=monotonic()+(0 if self.fixture_only else 2)
        return result


def controller_pins(root):
    root = Path(root)
    files = set((root/'src/context_cutoff').glob('*.py'))
    files.update((root/'src/agent_recovery').glob('*.py'))
    files.update((root/'src/phase2_unified').glob('*.py'))
    files.update((root/'src/sr_cpu_v2').glob('*.py'))
    files.update(root/p for p in ('scripts/run_bank_fault_r6_resume.py',
        'scripts/accept_bank_r6_linux.py', 'scripts/run_bank_fault_pilot.py',
        'scripts/run_bank_r6_budget2_authorized_live.py'))
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}


@dataclass(frozen=True)
class BankR6ResumeConfig(BankFaultConfig):
    prompt_revision: str = PROMPT_REVISION
    history39_sha256: str = HISTORY39_SHA
    controller_sources_sha256: str = ''
    linux_acceptance_sha256: str = ''

    def allowed_budget_revisions(self):
        return ('bank-budget-20261024-r2','bank-budget-20261024-r3')

    def __post_init__(self):
        super().__post_init__()
        require(self.prompt_revision == PROMPT_REVISION and self.history39_sha256 == HISTORY39_SHA
                and len(self.controller_sources_sha256) == 64 and len(self.linux_acceptance_sha256) == 64,
                'r6 must bind exact sources, history and Linux acceptance', 'R6_CONFIG')


@dataclass(frozen=True)
class BankR6ResumePermit(BankFaultPermit):
    prompt_revision: str = PROMPT_REVISION
    history39_sha256: str = ''
    controller_sources_sha256: str = ''
    linux_acceptance_sha256: str = ''
    failed_prefix_new_attempt_authorized: bool = False

    def validate(self, config, *, fixture_only, now_utc=None):
        super().validate(config, fixture_only=fixture_only, now_utc=now_utc)
        require(isinstance(config, BankR6ResumeConfig)
                and self.prompt_revision == config.prompt_revision == PROMPT_REVISION
                and self.history39_sha256 == config.history39_sha256 == HISTORY39_SHA
                and self.controller_sources_sha256 == config.controller_sources_sha256
                and self.linux_acceptance_sha256 == config.linux_acceptance_sha256
                and self.failed_prefix_new_attempt_authorized is True,
                'Separate source-bound r6/new-attempt permission required', 'R6_PERMIT')


def remaining_plan(history):
    finished = {u['unit_id'] for u in history['original_units'] if u['state'] == 'finished'}
    from .bank_fault_protocol import SCENES, METHODS
    units = []
    for sid, mode, fault in SCENES:
        prefix = sid+'.PREFIX'
        if prefix in finished:
            continue  # Preserve all three already finished BF01 safe stops.
        units.append(dict(unit_id=prefix, mode=mode, kind='PREFIX', fault=fault,
                          resume_saved_prefix=prefix == 'BF02.PREFIX'))
        units.extend(dict(unit_id=sid+'.'+m, mode=mode, kind=m, fault=fault) for m in METHODS)
        if sid == 'BF02':
            units.append(dict(unit_id=sid+'.CAL', mode=mode, kind='CAL', fault=fault))
    require(len(units) == 13 and not finished.intersection(u['unit_id'] for u in units),
            'Continuation cannot repeat finished units', 'R6_PLAN')
    return dict(schema_version='bank-r6-remaining-plan-v1', units=units,
        old_finished_units=sorted(finished), old_fault_dispatches=21, maximum_additional_calls=141,
        original_total_call_cap=162, new_attempt_for_interrupted_prefix=True,
        old_deadline_is_not_reset=True, old_safe_stops_are_not_successes=True)


def resume_prefix(run, fault, frozen_root, *, root):
    """Restore the accepted prefix, not the failed response or expired attempt.

    Exactly three accepted model responses and one read tool are restored from
    the hash-pinned export. The failed fourth call stays in financial history.
    """
    from .bank_fault_runtime import BeforePublication
    from .bank_fault_artifacts import ENV_KEY, file_pin
    from .runtime import reference, PUBLICATION_KEY
    files = read_fault_archives(root)
    doc = json.loads(files[RAW_PREFIX+'runs/BF02.PREFIX/RUN_STATE.json'])
    restored=deepcopy(run.doc['llm_calls'])
    for index,call in enumerate(restored):
        origin=call.pop('offline_saved_response_origin',None)
        if origin:
            require(run.gateway.fixture_only and origin['original_call_sha256']==digest(doc['llm_calls'][index]),
                    'Saved response replay provenance differs','R6_PREFIX_CHECKPOINT')
            call['fixture_only']=origin['original_fixture_only']
    require(restored == doc['llm_calls'] and len(doc['llm_calls']) == 3
            and not any(t['name'] in ('write_config','train','write_report','publish') for t in doc['tool_calls']),
            'Only the accepted pre-Executor checkpoint may resume', 'R6_PREFIX_CHECKPOINT')
    run.episode_messages = [deepcopy(m) for m in run.doc['messages'] if m['role'] != 'system']
    run.role_messages = {}
    for m in run.episode_messages:
        run.role_messages.setdefault(m['agent_role'], []).append(m)
    run.latest = {role: next(m for m in reversed(run.episode_messages)
        if m['agent_role'] == role and m['role'] == 'assistant' and 'final' in json.loads(m['content']))
        for role in ('Analyst','Planner')}
    before = reference(run.store.read(ENV_KEY))
    run.store.write(ENV_KEY, json.dumps({'sha256':run.environment_sha256}, sort_keys=True,
        separators=(',',':')), before, 'controller-r6-new-attempt')
    try:
        run.role('Executor')
    except BeforePublication as barrier:
        pending = barrier.node
    else:
        raise RuntimeError('R6_MISSING_FREEZE')
    require(PUBLICATION_KEY not in run.store.snapshot()['files']
            and all(c['status'] == 'settled' for c in run.ledger.calls()),
            'Resume freeze cannot include unsettled new actions', 'R6_PREFIX_CHECKPOINT')
    run.doc.update(run.store.snapshot())
    run.doc['final'] = dict(outcome='safe_stop', reason='known-fault-pre-publication-freeze')
    from time import monotonic_ns
    run.doc['elapsed_ns'] = monotonic_ns()-run.started
    analyst = next(n for n in run.doc['nodes'] if n['result_id'] == run.latest['Analyst']['producer_result_id'])
    planner = next(n for n in run.doc['nodes'] if n['result_id'] == run.latest['Planner']['producer_result_id'])
    checkpoint = dict(schema_version='bank-fault-checkpoint-v1', registry_sha256=REGISTRY_SHA,
        scene_id='BF02',mode=run.mode,fault=fault,faulty_result_id=analyst['result_id'],
        planner_result_id=planner['result_id'],pending_publication_request=pending,
        document=deepcopy(run.doc),role_messages=deepcopy(run.role_messages),
        episode_messages=deepcopy(run.episode_messages),latest=deepcopy(run.latest),
        bundle_path=run.current_bundle,bundle_file_sha256=file_pin(run.current_bundle),
        guard=run.business_guard(planner['payload']),environment_sha256=run.environment_sha256,
        publication_executed=False,all_http_settled=True,history39_sha256=HISTORY39_SHA,
        ledger_authority_path=str(run.ledger.path.resolve()))
    frozen_root=Path(frozen_root); frozen_root.mkdir(parents=True,exist_ok=False)
    run.store.save_to(frozen_root/'state');write_new(frozen_root/'CHECKPOINT.json',checkpoint)
    pins={str(p.relative_to(frozen_root)):file_pin(p) for p in sorted(frozen_root.rglob('*')) if p.is_file()}
    manifest=dict(files=pins,checkpoint_sha256=digest(checkpoint),registry_sha256=REGISTRY_SHA)
    manifest['freeze_sha256']=digest(manifest);write_new(frozen_root/'MANIFEST.json',manifest)
    return manifest


def copy_partial_prefix(root, directory, *, fixture_only=False):
    files=read_fault_archives(root);prefix=RAW_PREFIX+'runs/BF02.PREFIX/'
    target=Path(directory);target.mkdir(parents=True,exist_ok=False)
    # Copy only local provenance bytes; no model deserialization or prediction.
    for name,data in files.items():
        if name == prefix+'store.sqlite' or name.startswith(prefix+'artifacts/'):
            p=target/name[len(prefix):];p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
    document=json.loads(files[prefix+'RUN_STATE.json'])
    if fixture_only:
        # This is a derived OFFLINE replay, not a relabelled real run. Raw
        # response bytes and original records stay pinned in the source zip.
        for call in document['llm_calls']:
            origin=dict(original_call_sha256=digest(call),original_fixture_only=call['fixture_only'],
                source='hash-pinned-real-response-readonly-replay',new_real_dispatch=False)
            call['fixture_only']=True;call['offline_saved_response_origin']=origin
    return document
