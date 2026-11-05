import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from dbagentlab.campaign import make_plan, make_extended_plan, execute
from dbagentlab.core import save


class CampaignTests(unittest.TestCase):
    def test_extended_suite_has_five_selected_faults_three_controls_and_timeout(self):
        plan=make_extended_plan(['plan'],1,17,False)
        pairs={(slot['case'],slot['fault']) for slot in plan['slots']}
        self.assertEqual(len(plan['slots']),9)
        self.assertIn(('inventory_chain','clean'),pairs)
        self.assertIn(('inventory_handoff','clean'),pairs)
        self.assertIn(('inventory_lock','clean'),pairs)
        self.assertEqual({f for _,f in pairs if f!='clean'},
                         {'chain_root','stale_blocker','wrong_plan','outcome_timeout','forged_fact','timeout'})

    def test_plan_has_fixed_condition_matrix_and_seeded_order(self):
        args=(['inventory_lock'],['clean','pid_swap','instruction'],['none','plan','always'],2,17,True)
        first=make_plan(*args)
        second=make_plan(*args)
        self.assertEqual(first['slots'],second['slots'])
        self.assertEqual(len(first['slots']),18)
        self.assertTrue(all(slot['restart']=='none' for slot in first['slots'] if slot['fault']=='clean'))
        self.assertTrue(all(slot['restart']=='full' for slot in first['slots'] if slot['fault']!='clean'))

    def test_modified_plan_stops_before_subprocess(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            save(root/'PLAN.json',{'slots':[]})
            (root/'PLAN.sha256').write_text('wrong')
            with patch('dbagentlab.campaign.subprocess.run') as run:
                with self.assertRaises(RuntimeError):
                    execute(root,100,1800)
            run.assert_not_called()

    def test_unsettled_slot_not_automatically_retried(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            plan=make_plan(['inventory_lock'],['clean'],['plan'],1,17,False)
            save(root/'PLAN.json',plan)
            (root/'PLAN.sha256').write_text(hashlib.sha256((root/'PLAN.json').read_bytes()).hexdigest())
            save(root/'STATE.json',{'model_calls':0,'slots':{'slot_001':{'status':'dispatching'}}})
            with patch('dbagentlab.campaign.subprocess.run') as run:
                with self.assertRaises(RuntimeError):
                    execute(root,100,1800)
            run.assert_not_called()
