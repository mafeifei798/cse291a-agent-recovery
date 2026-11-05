"""356-history accounting plus immutable confirmation and replay receipts."""
import json

from agent_l_feedback_replay.budget import Budget as PriorBudget
from agent_l_batch.budget import Budget as AccountingBudget
from agent_recovery.contracts import canonical_json, require
from .protocol import Config, HISTORY_SHA, REGISTRATION_SHA


class Budget(PriorBudget):
    config_type = Config
    history_pin = HISTORY_SHA
    registration_pin = REGISTRATION_SHA
    campaign_name = 'approval-confirm-offline-v1'

    def __init__(self, *args, config, **kwargs):
        self.unit_caps = {'FR03.'+config.method:config.new_generation_cap}
        self.new_call_cap = config.new_generation_cap
        super().__init__(*args,config=config,**kwargs)
        self.connection.executescript('''
          CREATE TABLE ac_confirmations(unit TEXT NOT NULL,id TEXT NOT NULL,body TEXT NOT NULL,
              PRIMARY KEY(unit,id));
          CREATE TRIGGER ac_confirmation_immutable BEFORE UPDATE ON ac_confirmations
              BEGIN SELECT RAISE(ABORT,'immutable confirmation'); END;
          CREATE TRIGGER ac_confirmation_no_delete BEFORE DELETE ON ac_confirmations
              BEGIN SELECT RAISE(ABORT,'immutable confirmation'); END;
        ''')

    def reserve(self, record):
        # The inherited gateway recognizes older LI01 IDs only. Mark the new
        # FR03 calls as recovery replay without changing historical receipts.
        return super().reserve({**record,'phase':'replay'})

    def confirmation(self, unit, approval, input_digest, record=None):
        self._assert_active()
        self.require_time(unit)
        require(unit in self.unit_caps and approval['consumed'] == 1,
                'Registered consumed approval required', 'AC_CONFIRM_BINDING')
        original = self.connection.execute('SELECT body FROM fr_approvals WHERE id=?',
                                           (approval['logical_adjustment_id'],)).fetchone()
        require(original and original[0] == canonical_json(approval), 'Approval changed', 'AC_CONFIRM_BINDING')
        key = (unit,approval['logical_adjustment_id'])
        old = self.connection.execute('SELECT body FROM ac_confirmations WHERE unit=? AND id=?',key).fetchone()
        if old:
            saved = json.loads(old[0])
            require(saved['input_digest'] == input_digest and (record is None or saved == record),
                    'Confirmation replay inputs changed', 'AC_CONFIRM_BINDING')
            return saved
        if record is not None:
            require(record['input_digest'] == input_digest and record['logical_adjustment_id'] == key[1]
                    and record['origin_approval_id'] == approval['origin_approval_id']
                    and record['normal_adjustments_consumed'] == 0,
                    'Confirmation record changed', 'AC_CONFIRM_BINDING')
            self._write('INSERT INTO ac_confirmations VALUES(?,?,?)',(*key,canonical_json(record)))
        return record

    def snapshot(self):
        s = AccountingBudget.snapshot(self)
        s['L_budget'].update(first_generations_used=self.historical['first_generations_used']+len(s['calls']),
                            first_total_generation_cap=64,simulated_increment_only=True)
        s['feedback_approvals'] = [json.loads(r[0]) for r in self.connection.execute('SELECT body FROM fr_approvals')]
        s['feedback_replays'] = [json.loads(r[0]) for r in self.connection.execute('SELECT body FROM fr_replays')]
        s['approval_confirmations'] = [json.loads(r[0]) for r in self.connection.execute('SELECT body FROM ac_confirmations')]
        s['real_calls_and_spend_unchanged'] = True
        return s
