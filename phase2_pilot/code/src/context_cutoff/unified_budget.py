"""One durable pilot ledger across runs, with pinned historical liability.

All admission and settlement remains in DurableP3Budget's SQLite transaction.
This wrapper adds an immutable inheritance record to that same database.  It
never opens, changes, or copies historical ledgers and cannot authorize a live
request.  Historical known amounts are catalog estimates, not an invoice.
"""
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
import sqlite3
from urllib.parse import quote

from agent_recovery.contracts import canonical_json, digest, require
from agent_recovery.p3_budget import DurableP3Budget, DEFAULT_LIMITS
from .budget_plan import build_plan, PROJECT_CAP_NANO, PILOT_CAP_NANO, SOURCES
from .budget_policy import LEGACY_BUDGET_REVISION, budget_policy


HISTORICAL_KNOWN_NANO = 179_686_100
HISTORICAL_HELD_NANO = 3_252_000
HISTORICAL_GENERATION_CALLS = 2478
INHERITANCE_PLAN_SHA256 = '0a1c71edf8222d74ea23c9b474594de6d18fd74f7914b07f5c56972cf8fc8842'


def _checked_plan(plan):
    require(isinstance(plan, dict), 'Inheritance must be an object',
            'UNIFIED_INHERITANCE_INVALID')
    value = deepcopy(plan)
    supplied = value.pop('plan_sha256', None)
    require(supplied == digest(value) == INHERITANCE_PLAN_SHA256,
            'Inheritance plan digest differs from the verified source plan',
            'UNIFIED_INHERITANCE_INVALID')
    require(value.get('schema_version') == 'context-cutoff-budget-plan-v1'
            and value.get('historical_known_nano') == HISTORICAL_KNOWN_NANO
            and value.get('historical_held_nano') == HISTORICAL_HELD_NANO
            and value.get('historical_total_nano') == HISTORICAL_KNOWN_NANO + HISTORICAL_HELD_NANO
            and value.get('historical_generation_calls') == HISTORICAL_GENERATION_CALLS
            and value.get('project_cap_nano') == PROJECT_CAP_NANO
            and value.get('pilot_cap_nano') == PILOT_CAP_NANO
            and value.get('known_amount_is_token_catalog_estimate') is True
            and value.get('provider_final_invoice_verified') is False
            and value.get('old_ledgers_mutated') is False
            and value.get('actual_charges_or_unknown_holds_released_nano') == 0,
            'Pinned historical accounting differs', 'UNIFIED_INHERITANCE_INVALID')
    sources = value.get('sources')
    require(isinstance(sources, list) and len(sources) == len(SOURCES),
            'All pinned inheritance sources are required', 'UNIFIED_INHERITANCE_INVALID')
    names = [item.get('name') for item in sources if isinstance(item, dict)]
    require(len(names) == len(SOURCES) and set(names) == set(SOURCES),
            'Inheritance source identities differ', 'UNIFIED_INHERITANCE_INVALID')
    for item in sources:
        path, expected_sha = SOURCES[item['name']]
        require(item.get('path') == path and item.get('sha256') == expected_sha,
                'Inheritance source pins differ', 'UNIFIED_INHERITANCE_INVALID')
    return {**value, 'plan_sha256': supplied}


class UnifiedPilotBudget(DurableP3Budget):
    """Shared authority for all pilot runs using one canonical SQLite path.

    ``root`` verifies the original read-only budget-plan sources. Alternatively
    ``inheritance_plan`` is the already-verified exported plan; its source pins,
    identities and balances are rechecked here. Pass the identical configuration
    on every open. A crash/pending-call reopen uses the original conservative
    P3 quarantine rule; opening another handle cannot release its reservation.
    """
    def __init__(self, path, *, binding, campaign_id='context-cutoff-pilot-v1',
                 root=None, inheritance_plan=None, limits=None,
                 project_cap_nano=None, pilot_cap_nano=None,
                 budget_revision=LEGACY_BUDGET_REVISION):
        require(not (root is not None and inheritance_plan is not None),
                'Choose source root or exported inheritance, not both',
                'UNIFIED_INHERITANCE_INVALID')
        plan = _checked_plan(inheritance_plan if inheritance_plan is not None
                             else build_plan(root or Path(__file__).resolve().parents[2]))
        policy = budget_policy(budget_revision)
        project_cap_nano = policy['project_cap_nano'] if project_cap_nano is None else project_cap_nano
        pilot_cap_nano = policy['pilot_cap_nano'] if pilot_cap_nano is None else pilot_cap_nano
        require(type(project_cap_nano) is int and 0 < project_cap_nano <= policy['project_cap_nano']
                and type(pilot_cap_nano) is int and 0 < pilot_cap_nano <= policy['pilot_cap_nano'],
                'Project and pilot caps may only shrink', 'UNIFIED_CAP_INVALID')
        history = HISTORICAL_KNOWN_NANO + HISTORICAL_HELD_NANO
        require(project_cap_nano > history, 'No remaining project liability capacity',
                'UNIFIED_CAP_INVALID')
        require(limits is None or isinstance(limits, dict),
                'Limits must be an object', 'CAMPAIGN_CONFIG_MISMATCH')
        configured = dict(limits or {})
        effective = min(pilot_cap_nano, project_cap_nano - history,
                        configured.get('max_cost_nano_usd', policy['pilot_cap_nano']))
        configured['max_cost_nano_usd'] = effective
        self.inheritance = dict(
            schema_version='context-cutoff-unified-inheritance-v1',
            plan_sha256=plan['plan_sha256'], sources=plan['sources'],
            historical_known_nano=HISTORICAL_KNOWN_NANO,
            historical_held_nano=HISTORICAL_HELD_NANO,
            historical_generation_calls=HISTORICAL_GENERATION_CALLS,
            project_cap_nano=project_cap_nano, pilot_cap_nano=pilot_cap_nano,
            effective_pilot_cap_nano=effective,
            known_amount_is_token_catalog_estimate=True,
            provider_final_invoice_verified=False,
            historical_holds_released_nano=0,
        )
        if budget_revision != LEGACY_BUDGET_REVISION:
            self.inheritance.update(budget_revision=budget_revision,
                                    budget_policy_sha256=policy['policy_sha256'])
        self._inheritance_text = canonical_json(self.inheritance)
        # A different revision must not quarantine or otherwise write an old
        # authority, including one with an in-flight call, during construction.
        existing = Path(path).resolve()
        if existing.exists():
            probe = sqlite3.connect('file:' + quote(str(existing), safe='/') + '?mode=ro', uri=True)
            try:
                tables = {row[0] for row in probe.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if 'ctx_inheritance' in tables:
                    row = probe.execute('SELECT body FROM ctx_inheritance WHERE singleton=1').fetchone()
                    require(row is not None and row[0] == self._inheritance_text,
                            'Persisted project cap or inheritance differs', 'UNIFIED_CONFIG_MISMATCH')
                elif 'p3_calls' in tables:
                    require(probe.execute('SELECT 1 FROM p3_calls LIMIT 1').fetchone() is None,
                            'Do not adopt an already used legacy ledger', 'UNIFIED_ADOPTION_NOT_EMPTY')
            finally:
                probe.close()
        super().__init__(path, campaign_id=campaign_id, binding=binding, limits=configured,
                         cost_cap_ceiling_nano_usd=policy['pilot_cap_nano'],
                         execution_profile=getattr(self,'_p3_execution_profile','p3-default'))
        try:
            self.connection.execute('''CREATE TABLE IF NOT EXISTS ctx_inheritance (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1), body TEXT NOT NULL
            )''')
            with self._transaction():
                old = self.connection.execute('SELECT body FROM ctx_inheritance WHERE singleton=1').fetchone()
                if old is None:
                    require(not self.calls(), 'Do not adopt an already used legacy ledger',
                            'UNIFIED_ADOPTION_NOT_EMPTY')
                    self._write('INSERT INTO ctx_inheritance VALUES(1,?)', (self._inheritance_text,))
                else:
                    require(old['body'] == self._inheritance_text,
                            'Persisted project cap or inheritance differs',
                            'UNIFIED_CONFIG_MISMATCH')
        except BaseException:
            self.connection.close()
            raise

    @contextmanager
    def _transaction(self):
        # The outer wrapper and inherited operation share exactly one BEGIN.
        # Errors reach the original transaction manager, including its durable
        # post-rollback fence. No cross-database accounting bridge is involved.
        if self.connection.in_transaction:
            yield
        else:
            with super()._transaction():
                yield

    def _check_inheritance(self):
        row = self.connection.execute('SELECT body FROM ctx_inheritance WHERE singleton=1').fetchone()
        if row is None or row['body'] != self._inheritance_text:
            self._error('UNIFIED_CONFIG_MISMATCH', 'Durable inheritance changed')

    def reserve(self, call_record):
        with self._transaction():
            self._check_inheritance()
            # A replayed successful payload can itself drive another tool
            # action. A global stop forbids that continuation too, while
            # snapshot()/calls() still allow read-only inspection.
            self._assert_active()
            call_id = call_record.get('call_id') if isinstance(call_record, dict) else None
            previous = self.connection.execute('SELECT 1 FROM p3_calls WHERE call_id=?', (call_id,)).fetchone()
            body = super().reserve(call_record)
            # This is a return-only claim. It is never added to the persisted
            # request or its fingerprint. Only the newly admitted owner may send.
            return {**body, 'admission': {
                'new_reservation': previous is None,
                'dispatch_allowed': previous is None and body['status'] == 'reserved',
            }}

    def mark_dispatched(self, call_id):
        with self._transaction():
            self._check_inheritance()
            return super().mark_dispatched(call_id)

    def settle(self, call_id, **kwargs):
        with self._transaction():
            self._check_inheritance()
            return super().settle(call_id, **kwargs)

    def stop(self, reason):
        """Persistent global stop, including a 429 with settled usage.

        No call identity is necessary: all unsettled requests retain their full
        reservation. No reset/resume or automatic reconciliation is exposed.
        """
        return self.quarantine(None, reason)

    def snapshot(self):
        with self._transaction():
            self._check_inheritance()
            result = super().snapshot()
            budget = result['budget']
            known = budget['known_cost_nano_usd']
            held = budget['held_cost_nano_usd']
            inherited = HISTORICAL_KNOWN_NANO + HISTORICAL_HELD_NANO
            result['unified_budget'] = {
                **deepcopy(self.inheritance),
                'pilot_known_nano': known, 'pilot_held_nano': held,
                'pilot_total_nano': known + held,
                'project_known_nano': HISTORICAL_KNOWN_NANO + known,
                'project_held_nano': HISTORICAL_HELD_NANO + held,
                'project_total_nano': inherited + known + held,
                'project_remaining_nano': self.inheritance['project_cap_nano'] - inherited - known - held,
                'pilot_remaining_nano': self.inheritance['pilot_cap_nano'] - known - held,
                'effective_remaining_nano': budget['remaining_cost_nano_usd'],
                'historical_generation_calls': HISTORICAL_GENERATION_CALLS,
                'new_calls_dispatched': budget['calls_dispatched'],
                'project_generation_calls': HISTORICAL_GENERATION_CALLS + result['real_api_requests'],
                'project_accounted_dispatches': HISTORICAL_GENERATION_CALLS + budget['calls_dispatched'],
                'pilot_simulated_calls': budget['calls_dispatched'] if self.binding['simulated'] else 0,
                'new_dispatches_are_simulated': self.binding['simulated'],
                'new_real_api_requests': result['real_api_requests'],
                'estimated_only': True,
                'old_ledgers_mutated': False,
            }
            return result
