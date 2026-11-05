"""Read-only budget reallocation plan; this module cannot authorize dispatch.

Old allocations were future planning caps, not provider debits. Their removal
does not cancel an unknown historical charge or change any original ledger.
"""
from pathlib import Path
import hashlib
import json

from sr_recovery_v2.common import digest
from .contracts import require


PROJECT_CAP_NANO = 5_000_000_000
PILOT_CAP_NANO = 1_000_000_000
SOURCES = {
    'history': (
        'outputs/safety_reliability_continuation_v2_live_20261023/STATUS.json',
        'd9e246fdc7dab43a6a42a7d9d5be273a5a3204e119f49a5710a794089b572e2c'),
    'old_72': ('phase2/p0/frozen/budget.json',
               '98b0d57298cedba2999dccc322b3b9b11c211b6544c90579db804ed3ce534e5c'),
    'old_74': ('phase2/supplement_r1/frozen/budget.json',
               '816d2250e64f769d72fcc3563d1b8343cca07326961c4680a71bf223563d4966'),
    'old_74_unified_alias': ('phase2/unified_r1/frozen/budget.json',
                           '47e3a97524111a3a4276418ce741b82b83dc16449466c8bb683851ab2140fb3a'),
}


def balances(known_nano, held_nano, *, project_cap_nano=PROJECT_CAP_NANO,
             pilot_cap_nano=PILOT_CAP_NANO):
    """Integer-only planning arithmetic, keeping unknown liability occupied."""
    values = (known_nano, held_nano, project_cap_nano, pilot_cap_nano)
    require(all(type(value) is int and value >= 0 for value in values),
            'BUDGET_NONNEGATIVE_INTEGER_REQUIRED')
    require(project_cap_nano <= PROJECT_CAP_NANO and pilot_cap_nano <= PILOT_CAP_NANO,
            'BUDGET_PLAN_CAP_WIDENED')
    occupied = known_nano + held_nano
    require(occupied <= project_cap_nano, 'BUDGET_HISTORY_EXCEEDS_PROJECT_CAP')
    available = project_cap_nano - occupied
    require(pilot_cap_nano <= available, 'BUDGET_PILOT_EXCEEDS_AVAILABLE')
    return {
        'project_cap_nano': project_cap_nano,
        'pilot_cap_nano': pilot_cap_nano,
        'historical_known_nano': known_nano,
        'historical_held_nano': held_nano,
        'historical_total_nano': occupied,
        'available_after_known_and_held_nano': available,
        'available_after_pilot_cap_nano': available - pilot_cap_nano,
    }


def _read_source(root, name):
    relative, expected = SOURCES[name]
    raw = (root / relative).read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    require(actual == expected, 'BUDGET_SOURCE_HASH_CHANGED:' + name)
    value = json.loads(raw)
    require(isinstance(value, dict), 'BUDGET_SOURCE_OBJECT_REQUIRED')
    return value, {'name': name, 'path': relative, 'sha256': actual,
                   'size_bytes': len(raw)}


def build_plan(root):
    """Apply the user's planning reallocation in a new immutable configuration.

    The caller may save this document at a new path. No ledger is opened and no
    resource is acquired here; the $1 cap is not permission for a real run.
    """
    root = Path(root)
    sources = {name: _read_source(root, name) for name in SOURCES}
    history = sources['history'][0]
    billing = history['billing']
    require(history.get('status') == 'completed_and_DataHub_closed'
            and history.get('datahub_closed') is True, 'BUDGET_HISTORY_NOT_CLOSED')
    require((billing['project_known_nano'], billing['project_held_nano'],
             billing['project_total_nano']) == (179_686_100, 3_252_000, 182_938_100),
            'BUDGET_HISTORY_BALANCE_CHANGED')
    require(billing['project_generation_calls'] == 2478,
            'BUDGET_HISTORY_CALL_COUNT_CHANGED')
    old_72, old_74, unified = (sources[key][0] for key in
                               ('old_72', 'old_74', 'old_74_unified_alias'))
    require(old_72['campaign_cap_nano'] == 1_500_000_000
            and old_74['campaign_cap_nano'] == 2_500_000_000,
            'BUDGET_OLD_PLANNED_CAP_CHANGED')
    require(unified['campaign_cap_nano'] == old_74['campaign_cap_nano']
            and unified['allocation_id'] == 'phase2-supplement-future-evaluation'
            and unified['additional_live_allocation'] is False
            and unified['replaces_future_implementation_of'] == old_74['revision'],
            'BUDGET_UNIFIED_ALIAS_NOT_IDENTICAL_ALLOCATION')
    require(all(value['real_api_authorized'] is False
                for value in (old_72, old_74, unified)),
            'BUDGET_OLD_ALLOCATION_HAS_LIVE_AUTHORIZATION')
    plan = {
        'schema_version': 'context-cutoff-budget-plan-v1',
        'state': 'current_development_allocation_no_live_dispatch',
        'authorization_basis': '2026-10-24 user: cancel old unspent future allocations; pilot subcap $1 within project $5',
        'currency': 'USD', 'unit': 'nanoUSD',
        **balances(billing['project_known_nano'], billing['project_held_nano']),
        'historical_generation_calls': billing['project_generation_calls'],
        'known_amount_is_token_catalog_estimate': True,
        'provider_final_invoice_verified': False,
        'released_planned_allocations': [
            {'allocation_id': 'phase2-original-72-future-evaluation',
             'planned_cap_nano': old_72['campaign_cap_nano'],
             'source_names': ['old_72']},
            {'allocation_id': 'phase2-supplement-future-evaluation',
             'planned_cap_nano': old_74['campaign_cap_nano'],
             'source_names': ['old_74', 'old_74_unified_alias']},
        ],
        'released_planned_cap_nano': 4_000_000_000,
        'actual_charges_or_unknown_holds_released_nano': 0,
        'new_pilot_actual_api_cost_nano': 0,
        'old_ledgers_mutated': False,
        'pilot_cap_is_live_authorization': False,
        'real_api_authorized': False,
        'key_read_authorized': False,
        'training_authorized': False,
        'prediction_authorized': False,
        'cloud_authorized': False,
        'sources': [sources[name][1] for name in SOURCES],
    }
    require(sum(item['planned_cap_nano'] for item in plan['released_planned_allocations'])
            == plan['released_planned_cap_nano'], 'BUDGET_RELEASE_SUM')
    plan['plan_sha256'] = digest(plan)
    return plan
