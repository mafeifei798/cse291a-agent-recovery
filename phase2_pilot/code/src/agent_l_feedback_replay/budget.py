"""Append-only approval and per-branch replay receipts, on a fresh authority."""
import json
from agent_l_batch.budget import Budget as PriorBudget
from agent_recovery.contracts import canonical_json, require
from .protocol import Config, HISTORY_SHA, REGISTRATION_SHA, UNITS


class Budget(PriorBudget):
    config_type = Config
    history_pin = HISTORY_SHA
    registration_pin = REGISTRATION_SHA
    unit_caps = UNITS
    new_call_cap = 10
    campaign_name = 'feedback-replay-offline-v2'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.connection.executescript('''
          CREATE TABLE fr_approvals(id TEXT PRIMARY KEY, body TEXT NOT NULL);
          CREATE TABLE fr_replays(unit TEXT NOT NULL, id TEXT NOT NULL, body TEXT NOT NULL,
            PRIMARY KEY(unit,id));
          CREATE TRIGGER fr_approval_immutable BEFORE UPDATE ON fr_approvals
            BEGIN SELECT RAISE(ABORT,'immutable approval'); END;
          CREATE TRIGGER fr_replay_immutable BEFORE UPDATE ON fr_replays
            BEGIN SELECT RAISE(ABORT,'immutable replay'); END;
        ''')

    def inherit_approval(self, approval):
        key, body = approval['logical_adjustment_id'], canonical_json(approval)
        with self._transaction():
            old = self.connection.execute('SELECT body FROM fr_approvals WHERE id=?', (key,)).fetchone()
            require(not old or old[0] == body, 'Approval identity changed', 'FR_APPROVAL_ID')
            if not old:
                self._write('INSERT INTO fr_approvals VALUES(?,?)', (key, body))

    def replay(self, unit, approval, result=None):
        self.require_time(unit)
        original = self.connection.execute('SELECT body FROM fr_approvals WHERE id=?',
                    (approval['logical_adjustment_id'],)).fetchone()
        require(original and original[0] == canonical_json(approval),
                'Unrecognized approval', 'FR_APPROVAL_ID')
        old = self.connection.execute('SELECT body FROM fr_replays WHERE unit=? AND id=?',
                                      (unit, approval['logical_adjustment_id'])).fetchone()
        if old:
            require(result is None or old[0] == canonical_json(result),
                    'Replay identity reused with different result', 'FR_REPLAY_BINDING')
            return json.loads(old[0])
        if result is not None:
            self._write('INSERT INTO fr_replays VALUES(?,?,?)',
                        (unit, approval['logical_adjustment_id'], canonical_json(result)))
        return result

    def snapshot(self):
        s = super().snapshot()
        s['L_budget'].update(first_generations_used=48+len(s['calls']),
                             first_total_generation_cap=64, simulated_increment_only=True)
        s['feedback_approvals'] = [json.loads(r[0]) for r in self.connection.execute('SELECT body FROM fr_approvals')]
        s['feedback_replays'] = [json.loads(r[0]) for r in self.connection.execute('SELECT body FROM fr_replays')]
        s['real_calls_and_spend_unchanged'] = True
        return s
