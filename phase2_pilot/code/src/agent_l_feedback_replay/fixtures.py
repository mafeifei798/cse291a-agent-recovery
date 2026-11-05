"""Saved decisions/metrics through fake HTTP; never load or fit an estimator."""
from copy import deepcopy
from pathlib import Path
import hashlib
import json

from agent_l_api.fixtures import Service as PriorService
from agent_l_v1.cpu import FakeCPU, binding_matches
from agent_recovery.contracts import canonical_json, require
from agent_recovery.p3_transport import HTTPResponse


class SavedService(PriorService):
    def __init__(self, local, frozen, mode='saved'):
        super().__init__(local)
        self.mode, self.audit = mode, []
        self.initial = next(c for c in frozen['llm_calls'] if c['role'] == 'Planner' and 'final' in c['raw'])
        self.adjusted = next(c for c in frozen['llm_calls'] if c['role'] == 'Planner'
                             and any(m.get('input_kind') == 'feedback' for m in c['messages']))
        self.reviews = [c for c in frozen['llm_calls'] if c['role'] == 'Reviewer']

    def post(self, request):
        response = super().post(request)
        wire, req = json.loads(response.body), json.loads(request.body)
        role = json.loads(req['messages'][0]['content'].split('\n', 1)[0])['role']
        values = [json.loads(m['content']).get('payload', {}) for m in req['messages'][1:] if m['role'] == 'user']
        raw = json.loads(wire['choices'][0]['message']['content'])
        source = None
        if role == 'Planner' and 'final' in raw:
            feedback = any(v.get('replay_of_consumed_adjustment') for v in values)
            source = self.adjusted if feedback else self.initial
            raw = deepcopy(source['raw'])
            if feedback and self.mode == 'changed_contract':
                raw = {'final': {'bundle': 'D8', 'recipe': 'LR'}}
            if not feedback and self.mode == 'initial_changed':
                raw = {'final': {'bundle': 'D0', 'recipe': 'RF'}}
        elif role == 'Reviewer':
            context = next(v for v in values if 'allowed_actions' in v)
            replay = context.get('replay_of_consumed_adjustment', False)
            source = self.reviews[0] if replay else self.reviews[-1]
            raw = deepcopy(source['raw'])
            raw['final']['evidence_id'] = context['evidence_id']
            if self.mode == 'revalidation_stop' and replay:
                raw['final'] = {'action': 'stop', 'evidence_id': context['evidence_id'], 'reason': 'Synthetic refusal.'}
            if self.mode == 'second_adjustment' and not replay:
                raw['final'].update(action='adjust', requested_selection={'bundle': 'D8', 'recipe': 'LR'})
            if self.mode == 'substitute_approval' and replay:
                raw['final']['requested_selection'] = {'bundle': 'D8', 'recipe': 'LR'}
        self.audit.append({'role': role, 'source_call_id': source['call_id'] if source else None,
                           'synthetic_mode': self.mode, 'receipt_ids_remapped': role == 'Reviewer',
                           'saved_response_not_new_model_inference': source is not None})
        wire['choices'][0]['message']['content'] = canonical_json(raw)
        return HTTPResponse(response.status, response.headers, canonical_json(wire).encode())


class SavedCPU(FakeCPU):
    """Recomputation is simulated; admissions verify saved bytes, not predictions."""
    def __init__(self, campaign, source, *, forbid_fake_fit=False):
        super().__init__()
        self.campaign, self.source = Path(campaign).resolve(), Path(source).resolve()
        self.origin = json.loads((self.campaign/'ORIGIN.json').read_text())
        self.saved_fits = [json.loads(p.read_text()) for p in sorted((self.campaign/'jobs').glob('fit-*.record.json'))]
        self.produced, self.admission_evidence = {}, []
        self.forbid_fake_fit = forbid_fake_fit

    def mapped(self, value):
        p = Path(value)
        for old, new in ((Path(self.origin['campaign_root']), self.campaign),
                         (Path(self.origin['source_root']), self.source)):
            if p.is_relative_to(old):
                return new/p.relative_to(old)
        require(False, 'Unrecognized saved artifact path', 'FR_SAVED_PATH')

    def check_binding(self, contract, kind, data):
        local = deepcopy(data)
        for k in ('raw', kind+'_train', kind+'_validation'):
            local[k]['path'] = str(self.mapped(local[k]['path']))
        binding_matches(contract, kind, local)

    def fit(self, contract, kind, data, deadline):
        require(not self.forbid_fake_fit, 'Even simulated fit forbidden in zero-fit case', 'FR_NO_FIT')
        self.check_binding(contract, kind, data)
        self.fit_count += 1
        match = next((r for r in self.saved_fits if r['spec']['contract'] == contract), None)
        metrics = deepcopy(match['response']['metrics']) if match else {
            'validation': {'average_precision': .23, 'roc_auc': .67, 'log_loss': .36, 'f1': 0., 'accuracy': .88}}
        result = {'fixture_only': True, 'producer_id': 'simulated-fit-'+str(self.fit_count),
                  'kind': kind, 'contract': deepcopy(contract), 'metrics': metrics,
                  'metric_source': 'saved training receipt' if match else 'explicit synthetic variant',
                  'actual_training': 0}
        self.produced[result['producer_id']] = deepcopy(result)
        return result

    def validate(self, model, desired, kind, data):
        require(model['contract'] == desired, 'Contract changed', 'L_ADMISSION_CONTRACT_STALE')
        self.check_binding(desired, kind, data)
        if model['producer_id'].startswith('simulated-fit-'):
            require(model == self.produced[model['producer_id']], 'Synthetic artifact changed', 'FR_ARTIFACT')
            return
        p = self.campaign/model['record_rel']
        require(p.resolve().is_relative_to(self.campaign)
                and hashlib.sha256(p.read_bytes()).hexdigest() == model['producer_record_sha256'],
                'Saved producer changed', 'FR_ARTIFACT')
        record = json.loads(p.read_text())
        require(record['response']['contract'] == desired and model['metrics'] == record['response']['metrics']
                and model['kind'] == kind and record['spec']['job_id'] == model['producer_id'],
                'Saved producer contract or metrics changed', 'FR_ARTIFACT')
        for artifact in record['response']['artifacts']:
            path = self.mapped(record['spec']['output_dir'])/artifact['name']
            require(path.stat().st_size == artifact['size_bytes']
                    and hashlib.sha256(path.read_bytes()).hexdigest() == artifact['sha256'],
                    'Saved artifact bytes changed', 'FR_ARTIFACT')

    def admit(self, model, desired, kind, data, deadline):
        self.validate(model, desired, kind, data)
        self.admissions += 1
        self.admission_evidence.append({'producer_id': model['producer_id'], 'kind': kind,
                                       'record_rel': model.get('record_rel'),
                                       'contract': deepcopy(desired), 'artifact_hashes_checked': True,
                                       'model_loads': 0, 'predict_calls': 0, 'fits': 0})
        return {**deepcopy(model), 'offline_hash_admission_only': True}
