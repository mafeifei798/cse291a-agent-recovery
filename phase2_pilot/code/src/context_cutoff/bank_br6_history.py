"""Archive-pinned 129-call history; old SQLite authorities remain read-only."""
from copy import deepcopy
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import zipfile

from agent_recovery.contracts import digest, require
from .bank_r6_history import load_r6_history

SOURCE = 'outputs/bank_r6_budget2_live_20261024_r1'
ARCHIVE_SHA = '4588c7af57b06f91345e3d8445d6829c28d3a9df7d6d658db9e42b37ec66c4f1'
AUTHORITY_SHA = '639a776c1a7dd9726fef0dd86ed2098a4a99ce7e45affcb4e233764cc3c483cb'
HISTORY129_SHA = '9ec85927cf554e01787b942e1a7279bc1dcf4a457427e04b9e8574c0a0d5a560'
PREFIX = 'project/outputs/bank_r6_budget2_real_20261024_r1/'


def load_history129(root):
    root = Path(root)
    prior = load_r6_history(root)
    path = root / SOURCE / 'bank-r6-budget2-evidence.zip'
    require(hashlib.sha256(path.read_bytes()).hexdigest() == ARCHIVE_SHA,
            'Latest real export changed', 'BR6_HISTORY')
    with zipfile.ZipFile(path) as z:
        manifest = json.loads(z.read('EVIDENCE_MANIFEST.json'))['files']
        require(len(manifest) == 998 and all(not Path(n).is_absolute() and '..' not in Path(n).parts
                and hashlib.sha256(z.read(n)).hexdigest() == h for n, h in manifest.items()),
                'Latest real export member changed', 'BR6_HISTORY')
        ledger = json.loads(z.read(PREFIX + 'LEDGER.json'))
        results = json.loads(z.read(PREFIX + 'RESULTS.json'))
        require(hashlib.sha256(z.read(PREFIX + 'authority.sqlite')).hexdigest() == AUTHORITY_SHA,
                'Latest authority pin changed', 'BR6_HISTORY')
    calls = ledger['calls']
    require(len(calls) == results['real_api_requests'] == 90 and results['failure'] is None
            and results['fixture_only'] is False and results['final_billing']['reconciled'] is True,
            'Complete real continuation is required', 'BR6_HISTORY')
    receipts = deepcopy(prior['receipts'])
    for c in calls:
        u = c['usage']
        cost = u['prompt_tokens'] * 150 + u['completion_tokens'] * 500
        require(c['dispatched'] is True and c['simulated'] is False and c['status'] == 'settled'
                and c['held_cost_nano_usd'] == 0 and c['known_cost_nano_usd'] == cost
                and u['total_tokens'] == u['prompt_tokens'] + u['completion_tokens']
                and c['evidence']['wire_audit']['status'] == 200,
                'Incomplete or mispriced inherited receipt', 'BR6_HISTORY')
        receipts.append(dict(call_id=c['call_id'], run_id=c['run_id'], step_id=c['step_id'],
            status='settled', cost_nano=cost, hold_nano=0, observed_cost_nano=cost,
            original_record_sha256=digest(c), source='r6-90'))
    u, b = ledger['unified_budget'], ledger['bank_budget']
    require(len(receipts) == len({r['call_id'] for r in receipts}) == 129
            and sum(r['cost_nano'] for r in receipts) == 30_073_000
            and sum(r['hold_nano'] for r in receipts) == 500_000_000
            and u['historical_held_nano'] == 3_252_000
            and u['project_known_nano'] == 209_759_100
            and u['project_held_nano'] == 503_252_000
            and u['project_total_nano'] == 713_011_100
            and u['pilot_total_nano'] == 530_073_000
            and b['total_nano'] == 526_283_450
            and u['project_accounted_dispatches'] == 2607
            and abs(Decimal(results['final_billing']['expected_key_spend_nano']) - Decimal(209_939_000)) <= 1,
            'Inherited counts, costs or holds differ', 'BR6_HISTORY')
    body = dict(schema_version='bank-br6-history129-v1', source_archive_sha256=ARCHIVE_SHA,
        source_authority_sha256=AUTHORITY_SHA, history39_sha256=prior['sha256'], receipts=receipts,
        inherited_bank_calls=129, inherited_same_batch_calls=111,
        inherited_bank_known_nano=30_073_000, inherited_bank_held_nano=500_000_000,
        inherited_same_batch_known_nano=26_283_450, inherited_same_batch_held_nano=500_000_000,
        historical_known_nano=179_686_100, historical_held_nano=3_252_000,
        project_accounted_dispatches=2607, project_known_nano=209_759_100,
        project_held_nano=503_252_000, project_occupied_nano=713_011_100,
        pilot_occupied_nano=530_073_000, same_batch_occupied_nano=526_283_450,
        expected_start_key_spend_nano=results['final_billing']['expected_key_spend_nano'],
        observed_failed_usage_nano=179_900, observed_failed_usage_is_inside_hold=True,
        holds_released_nano=0, old_authorities_mutated=False, provider_invoice_verified=False)
    body['sha256'] = digest(body)
    require(body['sha256']==HISTORY129_SHA,'History129 immutable digest differs','BR6_HISTORY')
    return body
