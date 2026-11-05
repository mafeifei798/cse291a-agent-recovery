"""BR6's new SQLite authority, retaining every historical cost and hold."""
from copy import deepcopy
from contextlib import closing
import json
from pathlib import Path
import sqlite3
from time import time
from urllib.parse import quote

from agent_recovery.contracts import canonical_json, digest, require
from .bank_pilot_budget import BankPilotBudget
from .bank_br6_protocol import PLAN, UNIT_MAP, UNITS, REGISTRY_SHA, SCENES
from .bank_br6_history import load_history129


class BankBR6Budget(BankPilotBudget):
    _p3_execution_profile = 'bank-br6-offline-206-v1'
    campaign_name = 'bank-br6-offline-v1'

    def validate_execution_binding(self, binding):
        require(binding.get('simulated') is True,
                'BR6 preparation cannot admit real dispatch', 'BR6_LIVE_DISABLED')

    def registry_policy(self):
        return (dict(UNITS), 206)

    def __init__(self, path, *, root, history129=None, **kwargs):
        self._br6_ready = False
        history = load_history129(root)
        require(history129 is None or history129 == history, 'History129 differs', 'BR6_HISTORY')
        self.history129 = history
        self._history_text = canonical_json(history)
        path = Path(path).resolve()
        if path.exists():
            with closing(sqlite3.connect('file:' + quote(str(path), safe='/') + '?mode=ro', uri=True)) as db:
                tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                require('br6_history' in tables and db.execute('SELECT body FROM br6_history WHERE singleton=1').fetchone()[0]
                        == self._history_text, 'Never adopt an old/different authority', 'BR6_AUTHORITY')
        self.validate_execution_binding(kwargs.get('binding', {}))
        super().__init__(path, root=root, batch_id='bank-fault-B01', batch_cap_nano=2_000_000_000,
            batch_call_cap=206, run_call_cap=10, budget_revision='bank-budget-20261024-r3',
            limits=dict(call_cap=206, input_token_cap=206*4000, output_token_cap=206*768,
                        max_cost_nano_usd=1_000_000_000, slot_call_cap=5, logical_call_cap=10),
            campaign_id=self.campaign_name, **kwargs)
        self.connection.executescript('''
            CREATE TABLE IF NOT EXISTS br6_history(singleton INTEGER PRIMARY KEY,body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS bf_units(unit_id TEXT PRIMARY KEY,state TEXT NOT NULL,
                started REAL NOT NULL,deadline REAL NOT NULL,receipt TEXT);
            CREATE TABLE IF NOT EXISTS br6_gates(scene_id TEXT PRIMARY KEY,body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS br6_final_hold(singleton INTEGER PRIMARY KEY,amount INTEGER NOT NULL,body TEXT NOT NULL);
        ''')
        with self._transaction():
            old = self.connection.execute('SELECT body FROM br6_history WHERE singleton=1').fetchone()
            if old is None:
                require(not self.calls(), 'New history cannot adopt calls', 'BR6_AUTHORITY')
                self._write('INSERT INTO br6_history VALUES(1,?)', (self._history_text,))
            else:
                require(old['body'] == self._history_text, 'History changed', 'BR6_HISTORY')
        self._br6_ready = True

    def _check_history129(self):
        require(self.connection.execute('SELECT body FROM br6_history WHERE singleton=1').fetchone()['body']
                == self._history_text, 'Durable history changed', 'BR6_HISTORY')

    def gate(self, scene):
        row = self.connection.execute('SELECT body FROM br6_gates WHERE scene_id=?', (scene,)).fetchone()
        return json.loads(row['body']) if row else None

    def accept_scene(self, scene, audit):
        require(scene in SCENES and audit.get('passed') is True and audit.get('scene_id') == scene,
                'Independent scene gate failed', 'BR6_SCENE_AUDIT')
        saved=self.path.parent/(scene+'-INDEPENDENT_AUDIT.json')
        require(saved.is_file() and json.loads(saved.read_text())==audit,
                'Scene gate needs the saved independent receipt', 'BR6_SCENE_AUDIT')
        with self._transaction():
            self._assert_active()
            ids = [u['unit_id'] for u in PLAN if u['scene_id'] == scene]
            finished = {r['unit_id'] for r in self.units() if r['state'] == 'finished'}
            require(set(ids) <= finished, 'Scene units are incomplete', 'BR6_SCENE_AUDIT')
            body = canonical_json(dict(scene_id=scene, audit_sha256=digest(audit), passed=True,
                                       registry_sha256=REGISTRY_SHA))
            old = self.connection.execute('SELECT body FROM br6_gates WHERE scene_id=?', (scene,)).fetchone()
            require(old is None or old['body'] == body, 'Scene gate changed', 'BR6_SCENE_AUDIT')
            self._write('INSERT OR IGNORE INTO br6_gates VALUES(?,?)', (scene, body))

    def start_unit(self, unit_id):
        require(unit_id in UNIT_MAP, 'Unknown BR6 unit', 'BR6_REGISTRY')
        with self._transaction():
            self._assert_active(); self._check_history129()
            scene = UNIT_MAP[unit_id]['scene_id']
            preceding = SCENES[:SCENES.index(scene)]
            require(all(self.gate(s) for s in preceding), 'Previous independent gate missing', 'BR6_STAGE_GATE')
            require(not self.connection.execute('SELECT 1 FROM bf_units WHERE unit_id=?', (unit_id,)).fetchone(),
                    'Never reset a started unit deadline', 'BR6_UNIT_ALREADY_STARTED')
            # A unit may only start after the prior registered unit completed.
            prior = PLAN[:next(i for i,u in enumerate(PLAN) if u['unit_id'] == unit_id)]
            finished = {r['unit_id'] for r in self.units() if r['state'] == 'finished'}
            require(all(u['unit_id'] in finished for u in prior), 'Unit order differs from registration', 'BR6_UNIT_ORDER')
            began = time()
            self._write('INSERT INTO bf_units VALUES(?,?,?,?,NULL)', (unit_id, 'running', began, began+120))
        return began+120

    def units(self):
        return [dict(r) for r in self.connection.execute('SELECT * FROM bf_units ORDER BY rowid')]

    def finish_unit(self, unit_id, receipt):
        with self._transaction():
            row = self.connection.execute('SELECT * FROM bf_units WHERE unit_id=?', (unit_id,)).fetchone()
            body = canonical_json(receipt)
            require(row and (row['state'] == 'running' or row['receipt'] == body),
                    'Unit completion differs', 'BR6_UNIT_STATE')
            self._write('UPDATE bf_units SET state=?,receipt=? WHERE unit_id=?', ('finished', body, unit_id))

    def reserve(self, record):
        with self._transaction():
            self._check_history129(); self._assert_active()
            unit = record.get('run_id')
            require(unit in UNIT_MAP, 'Unknown registered call unit', 'BR6_REGISTRY')
            row = self.connection.execute('SELECT * FROM bf_units WHERE unit_id=?', (unit,)).fetchone()
            require(row and row['state'] == 'running' and time() < row['deadline'],
                    'Unit absent, completed or expired', 'BR6_UNIT_DEADLINE')
            cid = record.get('call_id')
            require(isinstance(cid, str) and cid.startswith(unit+'.llm.')
                    and cid not in {r['call_id'] for r in self.history129['receipts']},
                    'Old or foreign call cannot be dispatched', 'BR6_OLD_CALL')
            calls = self.calls()
            if any(c['call_id'] == cid for c in calls):
                return super().reserve(record)
            spec = UNIT_MAP[unit]
            if spec['kind'].startswith('CAL_'):
                require(record.get('step_id') == 'Planner', 'Calibration only calls Planner', 'BR6_CAL_ROLE')
            snap = self.snapshot(); b, u, sub = snap['bank_budget'], snap['unified_budget'], snap['br6_budget']
            tests = (
                (len(calls) < 206, 'BR6_CALL_CAP'),
                (sum(c['run_id'] == unit for c in calls) < spec['call_cap'], 'BR6_UNIT_CALL_CAP'),
                (sum(c['run_id'] == unit and c['step_id'] == record.get('step_id') for c in calls) < 5, 'BR6_ROLE_CAP'),
                (len(calls) < 42 or self.gate(SCENES[0]) is not None, 'BR6_FIRST_STAGE_CAP'),
                (sub['occupied_nano'] + self.worstcase_per_call_nano <= 1_000_000_000, 'BR6_SUB_MONEY_CAP'),
                (b['total_nano'] + self.worstcase_per_call_nano <= 2_000_000_000, 'BR6_SAME_BATCH_CAP'),
                (u['pilot_total_nano'] + self.worstcase_per_call_nano <= 3_000_000_000, 'BR6_PILOT_CAP'),
                (u['project_total_nano'] + self.worstcase_per_call_nano <= 20_000_000_000, 'BR6_PROJECT_CAP'),
            )
            for passed, code in tests:
                if not passed: self._error(code, 'Registered call or inherited liability cap reached', budget=True)
            return super().reserve(record)

    def retain_billing_hold(self, evidence):
        with self._transaction():
            b = self.snapshot()['bank_budget']
            amount = max(0, self.worstcase_per_call_nano-b['base_held_nano']-b['extra_held_nano'])
            self._write('INSERT OR IGNORE INTO br6_final_hold VALUES(1,?,?)', (amount, canonical_json(evidence)))

    def recovery_source_calls(self):
        return self.calls()  # Every new prefix belongs to this new authority.

    def identity_index(self, unit, proposed):
        ids = [c['call_id'] for c in self.calls() if c['run_id'] == unit]
        return max([proposed]+[int(i.rsplit('.',1)[1])+1 for i in ids])

    def snapshot(self):
        result = super().snapshot()
        if not self._br6_ready: return result
        with self._transaction():
            self._check_history129()
            h = self.history129
            b, u = result['bank_budget'], result['unified_budget']
            hold = self.connection.execute('SELECT amount FROM br6_final_hold WHERE singleton=1').fetchone()
            pending = hold['amount'] if hold else 0
            new_known = b['base_known_nano']
            new_held = b['base_held_nano']+b['extra_held_nano']+pending
            result['budget']['held_cost_nano_usd']+=pending
            result['budget']['remaining_cost_nano_usd']=max(0,result['budget']['remaining_cost_nano_usd']-pending)
            for k in ('pilot_known_nano', 'project_known_nano'): u[k] += h['inherited_bank_known_nano']
            for k in ('pilot_held_nano', 'project_held_nano'): u[k] += h['inherited_bank_held_nano']+pending
            for k in ('pilot_total_nano', 'project_total_nano'):
                u[k] += h['inherited_bank_known_nano']+h['inherited_bank_held_nano']+pending
            for k in ('pilot_remaining_nano', 'project_remaining_nano'):
                u[k] -= h['inherited_bank_known_nano']+h['inherited_bank_held_nano']+pending
            for k in ('project_generation_calls', 'project_accounted_dispatches'): u[k] += 129
            b['total_nano'] += h['same_batch_occupied_nano']+pending
            b['remaining_nano'] -= h['same_batch_occupied_nano']+pending
            b.update(inherited_same_batch_dispatches=111, inherited_same_batch_occupied_nano=526_283_450,
                     billing_pending_hold_nano=pending)
            result['br6_budget'] = dict(new_call_cap=206, first_stage_call_cap=42, subcap_nano=1_000_000_000,
                known_nano=new_known, held_nano=new_held, occupied_nano=new_known+new_held,
                remaining_nano=1_000_000_000-new_known-new_held, estimated_only=True)
            u.update(inherited_bank_generations=129, inherited_bank_known_nano=30_073_000,
                     inherited_bank_held_nano=500_000_000, source_history129_sha256=h['sha256'])
            u['effective_remaining_nano'] = min(result['br6_budget']['remaining_nano'], b['remaining_nano'],
                                               u['pilot_remaining_nano'], u['project_remaining_nano'])
            b['over_cap'] = (b['total_nano'] > 2_000_000_000 or u['pilot_total_nano'] > 3_000_000_000
                            or u['project_total_nano'] > 20_000_000_000
                            or result['br6_budget']['occupied_nano'] > 1_000_000_000)
            result['br6'] = dict(registry_sha256=REGISTRY_SHA, history129=deepcopy(h),
                units=self.units(), gates=[json.loads(r['body']) for r in
                    self.connection.execute('SELECT body FROM br6_gates ORDER BY rowid')])
        return result
