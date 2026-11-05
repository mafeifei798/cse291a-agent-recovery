"""One paid-accounted fake exchange with byte-identical saved request body."""
from copy import deepcopy
import hashlib

from agent_recovery.contracts import canonical_json, digest, require
from .bank_gateway import BankPilotGateway
from .bank_prompt_r6 import PROMPT_REVISION
from .bank_br6_protocol import UNIT_MAP
from .contracts import contract_digest


class BankBR6Gateway(BankPilotGateway):
    offline_only = True
    def __init__(self, *args, **kwargs):
        self._exact_source = None
        super().__init__(*args, **kwargs)
        require(not self.offline_only or self.fixture_only is True,
                'BR6 entry is offline only', 'BR6_LIVE_DISABLED')

    def call(self, role, messages, identity, *, deadline_monotonic):
        unit=identity.get('run_id')
        if unit in UNIT_MAP and UNIT_MAP[unit]['kind'].startswith('CAL_'):
            require(self._exact_source is not None, 'Calibration must use saved exact-wire entry', 'BR6_CAL_ENTRY')
        return super().call(role,messages,identity,deadline_monotonic=deadline_monotonic)

    def prepare_request(self, role, messages):
        prepared = super().prepare_request(role, messages)
        if self._exact_source is not None:
            source = self._exact_source
            require(role == 'Planner' and messages == source['prompt_messages']
                    and source['prompt_sha256'] == digest(messages)
                    and source['wire_audit'].get('prompt_revision') == PROMPT_REVISION
                    and canonical_json(prepared.request).encode() == canonical_json(source['wire_audit']['request']).encode(),
                    'Calibration wire differs before reservation/transport', 'BR6_CAL_WIRE')
        return prepared

    def calibrate(self, unit, source, *, deadline_monotonic):
        spec = UNIT_MAP[unit]
        require(spec['kind'] in ('CAL_RAW', 'CAL_CORRECTED') and self._exact_source is None,
                'Calibration is fixed and non-reentrant', 'BR6_CAL_WIRE')
        require(not any(c['run_id']==unit for c in self.ledger.calls()),
                'Each calibration slot may execute only once', 'BR6_CAL_ONCE')
        expected_parent = spec['scene_id'] + ('.PREFIX' if spec['kind'] == 'CAL_RAW' else '.CUTOFF')
        require(source['role'] == 'Planner' and source['call_id'].startswith(expected_parent+'.llm.'),
                'Calibration source belongs to another stage', 'BR6_CAL_SOURCE')
        paid=next((c for c in self.ledger.calls() if c['call_id']==source['call_id']),None)
        require(paid and paid['status']=='settled' and paid['run_id']==expected_parent
                and paid['evidence']['payload']==source['payload']
                and paid['evidence']['wire_audit']==source['wire_audit']
                and paid['sidecar']['original_messages']==source['prompt_messages'],
                'Calibration needs its exact settled source receipt', 'BR6_CAL_SOURCE')
        self._exact_source = deepcopy(source)
        cid = unit + '.llm.0000'
        try:
            response = self.call('Planner', deepcopy(source['prompt_messages']), dict(
                call_id=cid, attempt_id=cid+'.attempt', trial_key=unit+'.Planner',
                logical_run_key=unit, branch_id=unit, run_id=unit, result_id=cid+'.result',
                step_id='Planner', phase='replay'), deadline_monotonic=deadline_monotonic)
        finally:
            self._exact_source = None
        before = canonical_json(source['wire_audit']['request']).encode()
        after = canonical_json(response['audit']['request']).encode()
        require(before == after, 'Calibration wire changed during exchange', 'BR6_CAL_WIRE')
        return dict(schema_version='bank-br6-calibration-v1', unit_id=unit,
            scene_id=spec['scene_id'], source_kind=spec['kind'], call_id=cid,
            original_call_id=source['call_id'], original_context_sha256=source['prompt_sha256'],
            source_wire_sha256=hashlib.sha256(before).hexdigest(),
            repeated_wire_sha256=hashlib.sha256(after).hexdigest(),
            source_wire_request=source['wire_audit']['request'],
            same_wire_as_original=True, prompt_revision=PROMPT_REVISION,
            repeated_payload=response['payload'], source_payload=source['payload'],
            equivalent=contract_digest(source['payload']['final']) == contract_digest(response['payload']['final']),
            analysis_only=True, affects_recovery=False, fixture_only=self.fixture_only,
            new_calls=1, actual_training=0, actual_prediction=0)
