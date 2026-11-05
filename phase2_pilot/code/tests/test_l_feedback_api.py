"""New entry boundaries, same-freeze feedback and inherited accounting."""
from decimal import Decimal
from functools import partial
from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from agent_l_api.acceptance import SyntheticCounter, messages
from agent_l_api.budget import FakeClock
from agent_l_api.gateway import Gateway
from agent_l_api.model import bound_counter
from agent_l_batch.billing import Billing
from agent_l_feedback.model import Model
from agent_l_feedback_api.protocol import Config, Permit, UNITS, REGISTRATION, history
from agent_l_feedback_api.budget import Budget
from agent_l_feedback_api.launch import launch
from agent_l_feedback_api.fixtures import CampaignService
from agent_recovery.p3_transport import FakeHTTPSender, HTTPResponse

ROOT = Path(__file__).resolve().parents[1]
HISTORY = ROOT/'phase2/l_feedback_api_20261031_v1/HISTORY.json'
sys.path.insert(0, str(ROOT/'scripts'))
from check_l_feedback_api import check, check_stopped


class FeedbackEntryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.h = history(HISTORY, ROOT)
        self.clock = FakeClock()
        self.ledger = Budget(self.root/'authority.sqlite', config=Config(), historical=self.h, clock=self.clock)
        local = SyntheticCounter()
        self.service = CampaignService(local)
        self.service.unit = 'LC04'
        self.service.spend = Decimal(self.h['expected_key_spend_nano'])
        self.post = FakeHTTPSender([self.service.post]*53)
        self.get = FakeHTTPSender([self.service.get]*4)
        count, stats = bound_counter(local, simulated=True)
        self.provider = Mock(side_effect=AssertionError('No real key'))
        self.model = Model(self.post, token_counter=count, token_statistics=stats, credential_provider=self.provider)
        self.billing = Billing(self.ledger, fake_sender=self.get)
        self.gateway = Gateway(self.model, self.ledger, self.billing)
        self.network = patch('socket.socket', side_effect=AssertionError('No network'))
        self.network.start()
        self.billing.begin()
        self.ledger.start_unit('LC04')

    def tearDown(self):
        self.provider.assert_not_called()
        self.network.stop()
        self.ledger.close()
        self.temp.cleanup()

    def call(self, unit='LC04', n=0, role='Planner', cid=None):
        return self.gateway.call(role, messages(role), unit=unit, call_id=cid or unit+'.llm.'+str(n).zfill(4))

    def test_64_total_is_12_inherited_plus_52_new(self):
        self.assertEqual(sum(UNITS.values()), 52)
        self.assertEqual(REGISTRATION['first_total_generation_cap'], 64)
        for uid, cap in UNITS.items():
            if uid != 'LC04': self.ledger.start_unit(uid)
            self.service.unit = uid
            for n in range(cap): self.call(uid, n, 'Analyst' if cap > 1 and n < 5 else 'Planner')
            self.ledger.finish_unit(uid)
        self.assertEqual(self.post.request_count, 52)
        self.assertEqual(self.ledger.snapshot()['L_budget']['first_generations_used'], 64)
        with self.assertRaises(Exception): self.call('LI01.CAL_CORRECTED', 1)
        self.assertEqual(self.post.request_count, 52)

    def test_money_caps_and_both_holds_are_unchanged(self):
        b = self.ledger.snapshot()['L_budget']
        self.assertEqual((b['project_cap_nano'], b['L_cap_nano'], b['first_cap_nano']), (20000000000, 2000000000, 1000000000))
        self.assertEqual(b['project_known_nano'], 250726250)
        self.assertEqual(b['first_occupied_nano'], 500843400)
        self.assertEqual(self.ledger.config['limits']['max_cost_nano_usd'], 499156600)
        self.call()
        self.assertEqual(self.ledger.calls()[0]['reserved_cost_nano_usd'], 499156600)

    def test_all_old_clean_units_and_requests_are_fenced(self):
        for uid in ('LC01', 'LC02', 'LC03'):
            with self.assertRaises(Exception): self.ledger.start_unit(uid)
        with self.assertRaises(Exception): self.call(cid='LC02.llm.0005')
        self.assertEqual(self.post.request_count, 0)

    def test_old_provider_receipt_cannot_be_settled(self):
        def old(req):
            response = self.service.post(req)
            response.headers['x-litellm-call-id'] = self.h['receipts'][-1]['provider_request_id']
            return response
        self.post.responses = [old]
        with self.assertRaises(Exception): self.call()
        self.assertEqual(self.ledger.calls()[0]['held_cost_nano_usd'], 499156600)

    def test_duplicate_does_not_send_again(self):
        self.call(); self.assertTrue(self.call()['replayed'])
        self.assertEqual(self.post.request_count, 1)

    def test_deadline_cannot_refresh_or_accept_late_reply(self):
        before = self.ledger.bounds('LC04')
        with self.assertRaises(Exception): self.ledger.start_unit('LC04')
        def late(req):
            response = self.service.post(req); self.clock.sleep(241); return response
        self.post.responses = [late]
        with self.assertRaises(Exception): self.call()
        self.assertEqual(self.ledger.bounds('LC04'), before)
        self.assertEqual(self.ledger.calls()[0]['status'], 'uncertain')

    def test_429_stops_and_preserves_unresolved_risk(self):
        self.post.responses = [HTTPResponse(429, {}, b'{}')]
        with self.assertRaises(Exception): self.call()
        self.assertEqual(self.billing.finish()['state'], 'unknown_usage')
        self.assertEqual(self.ledger.snapshot()['L_budget']['project_held_nano'], 1502408600)
        with self.assertRaises(Exception): self.call(n=1)
        self.assertEqual(self.post.request_count, 1)

    def test_missing_usage_cannot_release_risk(self):
        self.post.responses = [HTTPResponse(200, {}, b'{"id":"missing","choices":[]}')]
        with self.assertRaises(Exception): self.call()
        self.assertEqual(self.ledger.calls()[0]['held_cost_nano_usd'], 499156600)

    def test_stale_history_and_default_live_permission_are_rejected(self):
        old = json.loads((ROOT/'phase2/l_api_resume_20261031_v1/HISTORY.json').read_text())
        with self.assertRaises(Exception): Budget(self.root/'old.sqlite', config=Config(), historical=old)
        with self.assertRaises(Exception): Permit().validate_live(Config(simulated=False), ROOT, None, None, None)

    def test_live_fails_before_provider_or_output_creation(self):
        from dataclasses import asdict
        c = self.root/'config.json'; p = self.root/'permit.json'; out = self.root/'no-live'
        c.write_text(json.dumps(asdict(Config(simulated=False, output_root=str(out)))))
        p.write_text(json.dumps(asdict(Permit())))
        with patch('br7_live.credentials.DataHubCredentialProvider') as provider:
            with self.assertRaises(Exception):
                launch(out, source_root=ROOT, history_path=HISTORY, live=True, native=True, authorized=True,
                       config_path=c, permit_path=p)
            provider.assert_not_called()
        self.assertFalse(out.exists())

    def test_same_freeze_three_methods_use_feedback_layer(self):
        out = self.root/'same-freeze'
        launch(out, source_root=ROOT, history_path=HISTORY, fixture_counter=True)
        proof = check(out, ROOT)
        self.assertEqual(proof['HTTP_generations'], 35)
        self.assertTrue(proof['all_recoveries_use_feedback_loop'])
        self.assertEqual(proof['recovery_rows']['LI01.CUTOFF']['new_fit_tasks'], 0)
        self.assertEqual(proof['recovery_rows']['LI01.CUTOFF']['readmissions'], 2)

    def test_spent_normal_allowance_is_not_reset_by_any_recovery(self):
        out = self.root/'prefix-adjusted'
        with patch('agent_l_feedback_api.fixtures.CampaignService', partial(CampaignService, prefix_adjustment=True)):
            launch(out, source_root=ROOT, history_path=HISTORY, fixture_counter=True)
        proof = check(out, ROOT)
        for row in proof['recovery_rows'].values():
            self.assertEqual(row['normal_remaining_before'], 0)
            self.assertEqual(row['normal_remaining_after'], 0)

    def test_invalid_review_stops_before_fault_and_is_still_paid(self):
        out = self.root/'invalid-review'
        with patch('agent_l_feedback_api.fixtures.CampaignService', partial(CampaignService, mode='reviewer_repeat')):
            with self.assertRaises(Exception): launch(out, source_root=ROOT, history_path=HISTORY, fixture_counter=True)
        proof = check_stopped(out, ROOT)
        self.assertEqual(proof['calls_recorded'], 6)
        self.assertGreater(proof['locally_priced_nano'], 0)
        self.assertFalse(proof['recovery_success_claimed'])
        l = json.loads((out/'LEDGER.json').read_text())
        self.assertEqual([u['unit'] for u in l['units']], ['LC04'])

    def test_batch_pending_keeps_completed_business_and_blocks_expansion(self):
        out = self.root/'pending'
        old = self.h['expected_key_spend_nano']
        def pending(service, request):
            return HTTPResponse(200, {}, json.dumps({'spend_nano': old, 'max_budget_nano': '50000000000'}).encode())
        with patch.object(CampaignService, 'get', pending):
            launch(out, source_root=ROOT, history_path=HISTORY, fixture_counter=True)
        proof = check(out, ROOT)
        self.assertEqual(proof['accounting_status'], 'pending')
        self.assertEqual(proof['completed_recoveries'], 3)

    def test_different_valid_contracts_do_not_require_equal_predictions(self):
        from check_l_api_pilot import compare_probabilities
        class Forbidden:
            def __sub__(self, other): raise AssertionError('Must not compare different contracts')
        result = compare_probabilities({'recipe': 'LR'}, {'recipe': 'RF'}, Forbidden(), Forbidden())
        self.assertFalse(result['same_contract'])
        self.assertIsNone(result['max_probability_error'])


if __name__ == '__main__':
    unittest.main()
