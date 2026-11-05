"""Route-liability admission for the independent Bank C01/C02 pilot.

The tokenizer estimate is not a verified server count. A confirmed route-wide
billing ceiling therefore occupies budget until a receipt fits the tighter
4,000-input/768-output policy. This is a monetary risk reserve, never additional
prompt tokens or evidence of a provider invoice. All tables share the inherited
SQLite authority; no old ledger is adopted or rewritten.
"""
from copy import deepcopy
from pathlib import Path
import sqlite3
from urllib.parse import quote

from agent_recovery.contracts import canonical_json, digest, require
from .unified_budget import UnifiedPilotBudget
from .bank_launch import CONSERVATIVE_ADMISSION_MODE, CONSERVATIVE_RESERVE_NANO


from .budget_policy import CURRENT_BUDGET_REVISION, LEGACY_BUDGET_REVISION, budget_policy

BATCH_CAP_NANO = 1_000_000_000
REGISTERED_RUNS = ('C01', 'C02')


def _policy(value, binding):
    require(isinstance(value, dict), 'Route liability must be explicit',
            'BANK_ROUTE_LIABILITY_INVALID')
    policy = deepcopy(value)
    require(policy.get('schema_version') == 'bank-route-liability-v1'
            and isinstance(policy.get('model'), str) and policy['model']
            and isinstance(policy.get('endpoint'), str) and policy['endpoint']
            and policy['model'] == binding.get('model')
            and policy['endpoint'] == binding.get('endpoint')
            and type(policy.get('confirmed')) is bool
            and type(policy.get('simulated')) is bool
            and policy['simulated'] == binding.get('simulated'),
            'Route identity or evidence classification differs',
            'BANK_ROUTE_LIABILITY_INVALID')
    conservative = policy.get('admission_mode') == CONSERVATIVE_ADMISSION_MODE
    if conservative:
        require(policy.get('conservative_reserve_nano') == CONSERVATIVE_RESERVE_NANO
                and policy.get('reserve_is_provider_guarantee') is False
                and policy.get('successful_usage_releases_risk_by_authorized_policy') is True
                and policy.get('max_billable_input_tokens') == 500000
                and policy.get('max_billable_output_tokens') == 500000
                and policy.get('additional_nano_usd_per_call') is None
                and policy.get('all_billable_components_confirmed') is False,
                'Conservative risk acceptance is not a provider billing guarantee',
                'BANK_ROUTE_LIABILITY_INVALID')
    require(type(policy.get('max_billable_input_tokens')) is int
            and policy['max_billable_input_tokens'] >= 4000
            and policy.get('max_billable_output_tokens') == (500000 if conservative else 768)
            and type(policy['max_billable_output_tokens']) is int
            and binding.get('max_input_tokens') == 4000
            and binding.get('max_output_tokens') == 768,
            'Route ceilings must cover input policy and enforce output 768',
            'BANK_ROUTE_LIABILITY_INVALID')
    for key in ('input_nano_usd_per_token', 'output_nano_usd_per_token'):
        require(type(policy.get(key)) is int and policy[key] >= 0
                and policy[key] == binding.get(key),
                'Route rates differ from pinned ledger rates',
                'BANK_ROUTE_LIABILITY_INVALID')
    require(policy.get('price_evidence_ref') == binding.get('price_evidence')
            and isinstance(policy.get('price_evidence_ref'), str)
            and policy['price_evidence_ref'],
            'Price evidence must match the pinned ledger binding',
            'BANK_ROUTE_LIABILITY_INVALID')
    require(conservative or (type(policy.get('additional_nano_usd_per_call')) is int
            and policy['additional_nano_usd_per_call'] == 0),
            'Additional charges must explicitly be confirmed zero; other tariffs need a new adapter',
            'BANK_UNSUPPORTED_ADDITIONAL_CHARGE')
    require(type(policy.get('all_billable_components_confirmed')) is bool,
            'Unknown billing components cannot default to zero',
            'BANK_ROUTE_LIABILITY_INVALID')
    require(isinstance(policy.get('evidence_ref'), str)
            and isinstance(policy.get('source_sha256'), str)
            and len(policy['source_sha256']) == 64
            and all(char in '0123456789abcdef' for char in policy['source_sha256']),
            'Pinned route evidence is required', 'BANK_ROUTE_LIABILITY_INVALID')
    return policy


class BankPilotBudget(UnifiedPilotBudget):
    """One fixed batch, C01 SCOPED and C02 FULL_HISTORY, 20/10/5 caps.

    Configuration is evidence, not permission to read credentials or dispatch.
    The launch permit and credential gate must independently authorize that.
    """
    def registry_policy(self):
        return ({'C01':'SCOPED','C02':'FULL_HISTORY'},20)

    def __init__(self, path, *, binding, route_liability, batch_id='bank-B01',
                 batch_cap_nano=None, batch_call_cap=20,
                 run_call_cap=10, budget_revision=CURRENT_BUDGET_REVISION, **kwargs):
        self._bank_ready = False
        policy = budget_policy(budget_revision)
        registered,expected_call_cap=self.registry_policy()
        self.registered_runs=registered
        batch_cap_nano = policy['batch_cap_nano'] if batch_cap_nano is None else batch_cap_nano
        self.route_liability = _policy(route_liability, binding)
        require(isinstance(batch_id, str) and bool(batch_id)
                and type(batch_cap_nano) is int and 0 < batch_cap_nano <= policy['batch_cap_nano']
                and batch_call_cap == expected_call_cap and type(batch_call_cap) is int
                and run_call_cap == 10 and type(run_call_cap) is int,
                'Bank batch must keep the 20/10/5 pilot limits', 'BANK_BATCH_CONFIG_INVALID')
        self.batch_id = batch_id
        self.worstcase_per_call_nano = (
            self.route_liability['max_billable_input_tokens'] * binding['input_nano_usd_per_token']
            + self.route_liability['max_billable_output_tokens'] * binding['output_nano_usd_per_token'])
        if self.route_liability.get('admission_mode') == CONSERVATIVE_ADMISSION_MODE:
            self.worstcase_per_call_nano = CONSERVATIVE_RESERVE_NANO
        self.batch_config = dict(
            schema_version='bank-pilot-batch-v1', batch_id=batch_id,
            batch_cap_nano=batch_cap_nano, batch_call_cap=batch_call_cap,
            run_call_cap=run_call_cap, role_call_cap=5,
            registered_runs=registered,
            route_liability_sha256=digest(self.route_liability),
            route_liability=self.route_liability,
            worstcase_per_call_nano=self.worstcase_per_call_nano,
            tokenizer_server_count_verified=False,
            risk_reserve_is_prompt_tokens=False,
        )
        if budget_revision != LEGACY_BUDGET_REVISION:
            self.batch_config.update(budget_revision=budget_revision,
                                     budget_policy_sha256=policy['policy_sha256'])
        self._bank_config_text = canonical_json(self.batch_config)
        # Reject legacy/nonmatching used authorities before any read-write open
        # or CREATE TABLE. This protects even a mistakenly supplied old path.
        existing = Path(path).resolve()
        if existing.exists():
            probe = sqlite3.connect('file:' + quote(str(existing), safe='/') + '?mode=ro', uri=True)
            try:
                tables = {row[0] for row in probe.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                require('p3_calls' in tables, 'Existing file is not a supported budget authority',
                        'BANK_AUTHORITY_TYPE_UNSUPPORTED')
                used = probe.execute('SELECT 1 FROM p3_calls LIMIT 1').fetchone() is not None
                if used:
                    require({'ctx_bank_batch', 'ctx_bank_risks'} <= tables,
                            'Cannot adopt calls outside the Bank registration', 'BANK_ADOPTION_NOT_EMPTY')
                if 'ctx_bank_batch' in tables:
                    row = probe.execute('SELECT body FROM ctx_bank_batch WHERE singleton=1').fetchone()
                    require(row is not None and row[0] == self._bank_config_text,
                            'Batch, route liability or task registration changed', 'BANK_BATCH_CONFIG_MISMATCH')
            finally:
                probe.close()
        super().__init__(path, binding=binding, budget_revision=budget_revision, **kwargs)
        try:
            self.connection.executescript('''
                CREATE TABLE IF NOT EXISTS ctx_bank_batch (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1), body TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ctx_bank_risks (
                    call_id TEXT PRIMARY KEY, batch_id TEXT NOT NULL,
                    run_id TEXT NOT NULL, step_id TEXT NOT NULL,
                    normal_reserved_nano INTEGER NOT NULL,
                    worstcase_reserved_nano INTEGER NOT NULL,
                    extra_reserved_nano INTEGER NOT NULL,
                    policy_sha256 TEXT NOT NULL
                );
            ''')
            with self._transaction():
                old = self.connection.execute('SELECT body FROM ctx_bank_batch WHERE singleton=1').fetchone()
                if old is None:
                    require(not self.calls(), 'Cannot adopt calls outside the Bank registration',
                            'BANK_ADOPTION_NOT_EMPTY')
                    self._write('INSERT INTO ctx_bank_batch VALUES(1,?)', (self._bank_config_text,))
                else:
                    require(old['body'] == self._bank_config_text,
                            'Batch, route liability or task registration changed', 'BANK_BATCH_CONFIG_MISMATCH')
                ids = {row['call_id'] for row in self.connection.execute('SELECT call_id FROM ctx_bank_risks')}
                require(ids == {call['call_id'] for call in self.calls()},
                        'Every Bank call needs its route-risk row', 'BANK_RISK_ROW_MISSING')
            self._bank_ready = True
        except BaseException:
            self.connection.close()
            raise

    def _check_bank(self):
        if (canonical_json(self.batch_config) != self._bank_config_text
                or digest(self.route_liability) != self.batch_config['route_liability_sha256']
                or digest(self.binding) != self.config['binding_digest']):
            self._error('BANK_BATCH_CONFIG_MISMATCH', 'In-memory pinned Bank configuration changed')
        row = self.connection.execute('SELECT body FROM ctx_bank_batch WHERE singleton=1').fetchone()
        if row is None or row['body'] != self._bank_config_text:
            self._error('BANK_BATCH_CONFIG_MISMATCH', 'Pinned Bank configuration changed')
        calls = {call['call_id']:call for call in self.calls()}
        rows = [dict(row) for row in self.connection.execute('SELECT * FROM ctx_bank_risks')]
        if {row['call_id'] for row in rows} != set(calls):
            self._error('BANK_RISK_ROW_MISSING', 'Bank call/risk identities differ')
        for row in rows:
            call = calls[row['call_id']]
            if not (row['batch_id'] == self.batch_id
                    and row['run_id'] == call['run_id'] and row['run_id'] in self.registered_runs
                    and row['step_id'] == call['step_id']
                    and row['normal_reserved_nano'] == call['reserved_cost_nano_usd']
                    and row['worstcase_reserved_nano'] == self.worstcase_per_call_nano
                    and row['extra_reserved_nano'] == self.worstcase_per_call_nano - row['normal_reserved_nano']
                    and row['policy_sha256'] == self.batch_config['route_liability_sha256']):
                self._error('BANK_RISK_ROW_CHANGED', 'Immutable route risk differs from the call or policy')

    def _check_admissible_evidence(self):
        policy = self.route_liability
        conservative = policy.get('admission_mode') == CONSERVATIVE_ADMISSION_MODE
        if not (policy['confirmed'] and (policy['all_billable_components_confirmed'] or conservative)):
            self._error('BANK_ROUTE_LIABILITY_UNCONFIRMED', 'Route-wide billable ceilings remain unconfirmed')
        if not self.binding['simulated']:
            for key in ('evidence_ref', 'price_evidence_ref'):
                if not policy[key] or policy[key].startswith('fixture:'):
                    self._error('BANK_ROUTE_LIABILITY_UNCONFIRMED', 'Live admission cannot use fixture pricing or route evidence')

    def _risk_rows(self):
        calls = {call['call_id']: call for call in self.calls()}
        result = []
        for row in self.connection.execute('SELECT * FROM ctx_bank_risks ORDER BY rowid'):
            value = dict(row)
            call = calls[value['call_id']]
            value.update(status=call['status'],
                         extra_held_nano=0 if call['status'] == 'settled' else value['extra_reserved_nano'])
            result.append(value)
        return result

    def reserve(self, call_record):
        with self._transaction():
            self._check_inheritance()
            self._check_bank()
            self._check_admissible_evidence()
            require(isinstance(call_record, dict), 'Call record must be an object', 'CAMPAIGN_IDENTITY_MISMATCH')
            call_id = call_record.get('call_id')
            old = self.connection.execute('SELECT * FROM ctx_bank_risks WHERE call_id=?', (call_id,)).fetchone()
            if old is not None:
                # Inherited idempotency compares the complete original request.
                return super().reserve(call_record)
            self._assert_active()
            if call_record.get('run_id') not in self.registered_runs:
                self._error('BANK_RUN_NOT_REGISTERED', 'Only C01 and C02 are registered')
            if call_record.get('input_token_upper_bound') != 4000:
                self._error('BANK_INPUT_POLICY_BOUND_REQUIRED', 'Unverified counts cannot shrink the 4,000-token policy reserve')
            if call_record.get('step_id') not in ('Analyst', 'Planner', 'Executor'):
                self._error('BANK_ROLE_NOT_REGISTERED', 'Call must identify a registered agent role')
            calls, risks = self.calls(), self._risk_rows()
            base_known = sum(call['known_cost_nano_usd'] for call in calls)
            base_held = sum(call['held_cost_nano_usd'] for call in calls)
            extra_held = sum(row['extra_held_nano'] for row in risks)
            occupied = base_known + base_held + extra_held
            next_total = occupied + self.worstcase_per_call_nano
            config = self.batch_config
            tests = (
                (len(risks) + 1 <= config['batch_call_cap'], 'BANK_BATCH_CALL_CAP_EXCEEDED'),
                (sum(row['run_id'] == call_record['run_id'] for row in risks) + 1 <= config['run_call_cap'], 'BANK_RUN_CALL_CAP_EXCEEDED'),
                (sum(row['run_id'] == call_record['run_id'] and row['step_id'] == call_record['step_id'] for row in risks) + 1 <= config['role_call_cap'], 'BANK_ROLE_CALL_CAP_EXCEEDED'),
                (next_total <= config['batch_cap_nano'], 'BANK_BATCH_MONEY_CAP_EXCEEDED'),
                (next_total <= self.inheritance['effective_pilot_cap_nano'], 'BANK_PILOT_MONEY_CAP_EXCEEDED'),
                (self.inheritance['historical_known_nano'] + self.inheritance['historical_held_nano'] + next_total <= self.inheritance['project_cap_nano'], 'BANK_PROJECT_MONEY_CAP_EXCEEDED'),
            )
            for passed, code in tests:
                if not passed:
                    self._error(code, 'Full route liability exceeds pilot admission', budget=True)
            body = super().reserve(call_record)
            normal = body['reserved_cost_nano_usd']
            extra = self.worstcase_per_call_nano - normal
            require(extra >= 0, 'Route reserve cannot be below normal policy reserve', 'BANK_ROUTE_LIABILITY_INVALID')
            self._write('INSERT INTO ctx_bank_risks VALUES(?,?,?,?,?,?,?,?)',
                        (call_id, self.batch_id, call_record['run_id'], call_record['step_id'],
                         normal, self.worstcase_per_call_nano, extra,
                         self.batch_config['route_liability_sha256']))
            return body

    def mark_dispatched(self, call_id):
        with self._transaction():
            self._check_bank()
            self._check_admissible_evidence()
            row = self.connection.execute('SELECT 1 FROM ctx_bank_risks WHERE call_id=?', (call_id,)).fetchone()
            if row is None:
                self._error('BANK_RISK_ROW_MISSING', 'Dispatch needs durable route liability')
            return super().mark_dispatched(call_id)

    def _receipt_caps(self, body):
        if self.route_liability.get('admission_mode') == CONSERVATIVE_ADMISSION_MODE:
            return (self.route_liability['max_billable_input_tokens'],
                    self.route_liability['max_billable_output_tokens'])
        return super()._receipt_caps(body)

    def settle(self, call_id, **kwargs):
        with self._transaction():
            self._check_bank()
            # Strict mode retains 4,000/768 receipt bounds. In the separately
            # authorized conservative mode, independently validated usage may
            # use the 500K route envelope; local prompts/request output remain
            # 4,000/768. Successful release is accepted risk policy, not proof
            # that all provider tariff components have been identified.
            return super().settle(call_id, **kwargs)

    def stop(self, reason, *, call_id=None):
        # HTTP429 must be handled before settlement, retaining raw usage as
        # evidence without treating it as a normal successful receipt.
        if call_id is not None:
            return self.quarantine(call_id, reason)
        return super().stop(reason)

    def snapshot(self):
        if not self._bank_ready:
            return super().snapshot()
        with self._transaction():
            self._check_bank()
            # Re-read inside the same transaction as risk rows for a consistent
            # snapshot across concurrent active handles.
            result = super().snapshot()
            risks = self._risk_rows()
            extra = sum(row['extra_held_nano'] for row in risks)
            base = deepcopy(result['budget'])
            result['base_budget'] = base
            budget = result['budget']
            budget['held_cost_nano_usd'] += extra
            budget['held_extra_route_risk_nano_usd'] = extra
            budget['held_normal_cost_nano_usd'] = base['held_cost_nano_usd']
            budget['remaining_cost_nano_usd'] = max(0, base['remaining_cost_nano_usd'] - extra)
            unified = result['unified_budget']
            for key in ('pilot_held_nano', 'pilot_total_nano', 'project_held_nano', 'project_total_nano'):
                unified[key] += extra
            for key in ('project_remaining_nano', 'pilot_remaining_nano', 'effective_remaining_nano'):
                unified[key] -= extra
            total = base['known_cost_nano_usd'] + base['held_cost_nano_usd'] + extra
            result['bank_budget'] = dict(
                schema_version='bank-pilot-budget-snapshot-v1', batch_id=self.batch_id,
                batch_config=deepcopy(self.batch_config),
                route_liability=deepcopy(self.route_liability),
                route_liability_sha256=self.batch_config['route_liability_sha256'],
                worstcase_per_call_nano=self.worstcase_per_call_nano,
                base_known_nano=base['known_cost_nano_usd'],
                base_held_nano=base['held_cost_nano_usd'], extra_held_nano=extra,
                total_nano=total, batch_cap_nano=self.batch_config['batch_cap_nano'],
                remaining_nano=self.batch_config['batch_cap_nano'] - total,
                calls_reserved_or_spent=len(risks),
                calls_remaining=max(0, self.batch_config['batch_call_cap'] - len(risks)),
                run_call_counts={run:sum(row['run_id'] == run for row in risks) for run in self.registered_runs},
                risks=risks, estimated_only=True, risk_reserve_is_prompt_tokens=False,
                over_cap=total > self.batch_config['batch_cap_nano']
                    or unified['pilot_total_nano'] > self.inheritance['effective_pilot_cap_nano']
                    or unified['project_total_nano'] > self.inheritance['project_cap_nano'],
            )
            return result
