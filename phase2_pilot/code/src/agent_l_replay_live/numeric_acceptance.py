"""No-fit check of saved producers using explicit hash-preserving path maps."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
from unittest.mock import patch

from context_cutoff import numeric_checker as checker
from agent_l_feedback_replay.fixtures import SavedCPU
from agent_l_feedback_replay.runtime import approved_stage
from agent_recovery.contracts import require


def verify_models(source, saved_campaign, frozen, output):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    guard = SavedCPU(saved_campaign, source)
    approval = approved_stage(frozen)
    models = [approval['initial_screen']['payload'], frozen['active']['screen']['payload'],
              frozen['active']['final']['payload']]
    data_ref = frozen['store_snapshot']['files']['inputs/data.json']
    data = json.loads((Path(saved_campaign)/'runs/LI01.PREFIX/artifacts/sha256'/data_ref['sha256']).read_text())
    original_safe = checker._safe_path
    mapping_events = []
    def mapped(value):
        p = Path(value)
        require(p.is_absolute() and '..' not in p.parts, 'Noncanonical numeric path', 'FRL_NUMERIC_PATH')
        if p.is_relative_to(output) or p.is_relative_to(guard.campaign) or p.is_relative_to(guard.source):
            target = p
        else:
            target = guard.mapped(p)
        target = original_safe(str(target))
        mapping_events.append({'logical': str(p), 'physical': str(target)})
        return target
    results = []
    for model in models:
        guard.validate(model, model['contract'], model['kind'], data)
        record = json.loads((Path(saved_campaign)/model['record_rel']).read_text())
        dest = output/model['producer_id']
        dest.mkdir()
        # The original training spec, response, artifacts and hashes stay intact.
        # Only filesystem resolution is redirected inside this bounded check.
        with patch.object(checker, '_safe_path', mapped):
            spec = checker.build_checker_spec(record['spec'], record['response'], dest,
                datetime.now(timezone.utc)+timedelta(seconds=120), 'accept-'+model['producer_id'])
            result = checker.run_check(spec, authorized=True)
        (dest/'RESULT.json').write_text(json.dumps(result, indent=2)+'\n')
        require(result['passed'] and result['business_correct'] and result['model_fits'] == 0
                and result['fit_guard']['installed'] and not result['fit_guard']['rejected_calls'],
                'Saved producer numeric verification failed', 'FRL_NUMERIC')
        results.append({'producer_id': model['producer_id'], 'kind': model['kind'],
                        'family': model['contract']['recipe']['model_family'], 'result': result})
    proof = {'passed': True, 'models': results, 'model_fits': 0,
             'model_predictions': sum(r['result']['model_predictions'] for r in results),
             'mapping_events': mapping_events, 'training_specs_and_artifacts_unchanged': True,
             'scope': 'Saved RF screen and LR screen/final, no fitting; explicit portable read-path mapping'}
    (output/'PROOF.json').write_text(json.dumps(proof, indent=2)+'\n')
    return proof
