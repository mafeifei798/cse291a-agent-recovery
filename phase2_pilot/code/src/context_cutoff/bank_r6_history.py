"""Read-only, archive-pinned inheritance for all 39 real Bank calls.

Observed failed-call usage is kept inside its original full risk reserve.
Neither post-stop balance reconciliation nor a new prompt releases that hold.
"""
from collections import Counter
from copy import deepcopy
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import sqlite3
from urllib.parse import quote
import zipfile

from agent_recovery.contracts import digest, require
from .bank_fault_protocol import BankFaultBudget, load_inheritance, UNITS

REAL_ROOT = 'outputs/bank_fault_live_20261024'
RAW_PREFIX = 'project/outputs/bank_fault_real_20261024_r1/'
ARCHIVES = {
    'bank-fault-20261024-r1-evidence.zip': '0f18b610762dc0a83e3dc6e0fe0d459c756a6865d8acea757d337f41d705874a',
    'bank-fault-20261024-r1-poststop.zip': 'eb0d5f06c1e9f5fb718e8d6a09f3bd9d3a4b5ecdd93489cc6ea4dfd02dae4c82',
}


def read_fault_archives(root):
    """Verify original exports in memory; never extract/adopt an old SQLite DB."""
    result = {}
    for name, expected in ARCHIVES.items():
        path = Path(root) / REAL_ROOT / name
        require(hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                'Original fault export changed', 'R6_HISTORY_SOURCE')
        with zipfile.ZipFile(path) as archive:
            require(archive.testzip() is None, 'Export CRC changed', 'R6_HISTORY_SOURCE')
            manifest_name = 'EVIDENCE_MANIFEST.json' if 'evidence' in name else 'POSTSTOP_MANIFEST.json'
            manifest = json.loads(archive.read(manifest_name))
            pins = manifest['files'] if 'evidence' in name else manifest
            for rel, pin in pins.items():
                require(not Path(rel).is_absolute() and '..' not in Path(rel).parts,
                        'Unsafe evidence path', 'R6_HISTORY_SOURCE')
                data = archive.read(rel)
                require(hashlib.sha256(data).hexdigest() == pin,
                        'Original evidence member changed', 'R6_HISTORY_SOURCE')
                result[rel] = data
    return result


def load_r6_history(root):
    prior = load_inheritance(root)
    files = read_fault_archives(root)
    ledger = json.loads(files[RAW_PREFIX + 'LEDGER.json'])
    calls = ledger['calls']
    require(len(calls) == 21 and len({c['call_id'] for c in calls}) == 21
            and all(c['dispatched'] and c['simulated'] is False for c in calls),
            'All 21 original dispatches required', 'R6_HISTORY_SOURCE')
    receipts = [dict(**r, status='settled', hold_nano=0,
                     observed_cost_nano=r['cost_nano'], source='prior-18') for r in prior['receipts']]
    known = observed = held = 0
    risk = {r['call_id']: r for r in ledger['bank_budget']['risks']}
    for call in calls:
        settled = call['status'] == 'settled'
        usage = call['usage'] if settled else call['evidence']['observed_usage']
        require(usage and usage['total_tokens'] == usage['prompt_tokens'] + usage['completion_tokens'],
                'Observed inherited usage missing', 'R6_HISTORY_SOURCE')
        cost = usage['prompt_tokens'] * 150 + usage['completion_tokens'] * 500
        liability = call['held_cost_nano_usd'] + risk[call['call_id']]['extra_held_nano']
        require((settled and liability == 0 and call['known_cost_nano_usd'] == cost)
                or (not settled and call['known_cost_nano_usd'] == 0 and liability == 500_000_000),
                'Inherited settled/uncertain liability differs', 'R6_HISTORY_SOURCE')
        known += call['known_cost_nano_usd']; observed += cost; held += liability
        receipts.append(dict(call_id=call['call_id'], run_id=call['run_id'], step_id=call['step_id'],
            status=call['status'], cost_nano=call['known_cost_nano_usd'], hold_nano=liability,
            observed_cost_nano=cost, source='fault-21', original_record_sha256=digest(call)))
    post = json.loads(files['POSTSTOP_RECONCILIATION.json'])
    require(known == 3_654_050 and observed == 3_833_950 and held == 500_000_000
            and post['delta_reconciled'] is True and post['all_observed_usage_valid'] is True
            and abs(Decimal(post['key_spend_nano']) - Decimal(187_309_600)) <= 1
            and post['new_usage_cost_nano'] == observed,
            'Post-stop evidence differs', 'R6_HISTORY_SOURCE')
    require(len(receipts) == 39 and len({r['call_id'] for r in receipts}) == 39,
            'Exactly 39 distinct inherited identities required', 'R6_HISTORY_SOURCE')
    body = dict(schema_version='bank-r6-history39-v1', source_archives=deepcopy(ARCHIVES),
        prior18_sha256=prior['sha256'], receipts=receipts, inherited_generation_calls=39,
        prior_fault_calls=21, prior_bank_known_nano=3_789_550,
        prior_fault_known_nano=known, prior_fault_observed_nano=observed,
        prior_fault_hold_nano=held, historical_unknown_hold_nano=3_252_000,
        expected_start_key_spend_nano=post['key_spend_nano'],
        observed_failed_usage_is_inside_hold=True, holds_released_nano=0,
        original_units=deepcopy(ledger['fault_pilot']['units']),
        original_call_counts=dict(Counter(c['run_id'] for c in calls)),
        old_authorities_mutated=False, provider_final_invoice_verified=False)
    body['sha256'] = digest(body)
    return body


class BankR6ResumeBudget(BankFaultBudget):
    """New authority; old 39 IDs, calls, liability and batch caps remain spent.

    Inherits the original transactional dispatch, settlement and quarantine.
    Original databases are never opened read-write or cleared for continuation.
    """
    def allowed_budget_revisions(self):
        return ('bank-budget-20261024-r2','bank-budget-20261024-r3')

    def __init__(self, path, *, root, history39=None, **kwargs):
        self._resume_ready = False
        self._source_root = Path(root).resolve()
        verified = load_r6_history(root)
        require(history39 is None or history39 == verified, 'History39 changed', 'R6_HISTORY_SOURCE')
        self.history39 = verified
        self._history39_text = json.dumps(verified, sort_keys=True)
        path = Path(path).resolve()
        if path.exists():
            db = sqlite3.connect('file:' + quote(str(path), safe='/') + '?mode=ro', uri=True)
            try:
                tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                require('bf_r6_history' in tables and db.execute(
                    'SELECT body FROM bf_r6_history WHERE singleton=1').fetchone()[0] == self._history39_text,
                    'Never adopt an old or different authority', 'R6_AUTHORITY')
            finally:
                db.close()
        super().__init__(path, root=root, inheritance=load_inheritance(root), **kwargs)
        self.connection.execute('CREATE TABLE IF NOT EXISTS bf_r6_history '
                                '(singleton INTEGER PRIMARY KEY, body TEXT NOT NULL)')
        with self._transaction():
            old = self.connection.execute('SELECT body FROM bf_r6_history WHERE singleton=1').fetchone()
            if old is None:
                self._write('INSERT INTO bf_r6_history VALUES(1,?)', (self._history39_text,))
            else:
                require(old['body'] == self._history39_text, 'History changed', 'R6_HISTORY_SOURCE')
        self._resume_ready = True

    def _check_history39(self):
        require(self.connection.execute('SELECT body FROM bf_r6_history WHERE singleton=1').fetchone()['body']
                == self._history39_text, 'Durable history39 changed', 'R6_HISTORY_SOURCE')

    def start_unit(self, unit_id, *, resume_incomplete=False):
        old = next((u for u in self.history39['original_units'] if u['unit_id'] == unit_id), None)
        require(old is None or (old['state'] == 'running' and unit_id == 'BF02.PREFIX'
                and resume_incomplete is True), 'Old unit cannot run again', 'R6_OLD_UNIT')
        return super().start_unit(unit_id)

    def reserve(self, record):
        with self._transaction():
            self._check_history39(); self._assert_active()
            call_id = record.get('call_id')
            require(call_id not in {r['call_id'] for r in self.history39['receipts']},
                    'An inherited dispatch cannot be sent again', 'R6_OLD_CALL')
            if any(r['call_id'] == call_id for r in self.calls()):
                return super().reserve(record)
            old = [r for r in self.history39['receipts'] if r['source'] == 'fault-21']
            new = self.calls(); unit = record.get('run_id'); role = record.get('step_id')
            tests = (
                (21 + len(new) < 162, 'R6_TOTAL_CALL_CAP'),
                (sum(r['run_id'] == unit for r in old + new) < (1 if unit.endswith('.CAL') else 10), 'R6_UNIT_CALL_CAP'),
                (sum(r['run_id'] == unit and r['step_id'] == role for r in old + new) < 5, 'R6_ROLE_CALL_CAP'),
                (self.snapshot()['bank_budget']['remaining_nano'] >= self.worstcase_per_call_nano, 'R6_BATCH_MONEY_CAP'),
            )
            for passed, code in tests:
                if not passed:
                    self._error(code, 'Inherited liability or dispatches exhaust continuation', budget=True)
            return super().reserve(record)

    def recovery_source_calls(self):
        files = read_fault_archives(self._source_root)
        return json.loads(files[RAW_PREFIX + 'LEDGER.json'])['calls'] + self.calls()

    def identity_index(self, unit, proposed):
        ids = [r['call_id'] for r in self.history39['receipts'] if r['run_id'] == unit]
        ids += [r['call_id'] for r in self.calls() if r['run_id'] == unit]
        return max([proposed] + [int(i.rsplit('.', 1)[1]) + 1 for i in ids])

    def snapshot(self):
        result = super().snapshot()
        if not self._resume_ready:
            return result
        self._check_history39()
        h = self.history39; known = h['prior_fault_known_nano']; held = h['prior_fault_hold_nano']
        b, u = result['bank_budget'], result['unified_budget']
        b.update(inherited_fault_known_nano=known, inherited_fault_hold_nano=held, inherited_fault_dispatches=21)
        b['total_nano'] += known + held; b['remaining_nano'] -= known + held
        b['calls_reserved_or_spent'] += 21; b['calls_remaining'] = max(0, 162 - b['calls_reserved_or_spent'])
        for key in ('pilot_known_nano', 'project_known_nano'): u[key] += known
        for key in ('pilot_held_nano', 'project_held_nano'): u[key] += held
        for key in ('pilot_total_nano', 'project_total_nano'): u[key] += known + held
        for key in ('pilot_remaining_nano', 'project_remaining_nano'): u[key] -= known + held
        for key in ('project_generation_calls', 'project_accounted_dispatches'): u[key] += 21
        u.update(inherited_bank_generations=39, inherited_bank_known_nano=7_443_600,
                 source_history39_sha256=h['sha256'])
        u['effective_remaining_nano'] = min(b['remaining_nano'], u['pilot_remaining_nano'], u['project_remaining_nano'])
        result['budget']['remaining_cost_nano_usd'] = max(0, u['effective_remaining_nano'])
        b['over_cap'] = b['total_nano'] > b['batch_cap_nano'] or u['pilot_total_nano'] > 3_000_000_000 or u['project_total_nano'] > 20_000_000_000
        result['continuation'] = dict(history39=deepcopy(h), new_authority_calls=len(self.calls()),
            original_calls_kept_separate=True, old_authorities_mutated=False, holds_released_nano=0)
        return result
