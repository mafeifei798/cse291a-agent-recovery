import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from dbagentlab.core import Budget, Ledger
from dbagentlab.faults import FaultController
from dbagentlab.graphs import root_blockers
from dbagentlab.verification import VerificationRejected
from dbagentlab.workflow import Harness, ContractError, analyze_branch
from dbagentlab.__main__ import main, resolve_case
from fakes import FakeEnvironment, FakeGateway


class AdvancedTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.stdout=contextlib.redirect_stdout(io.StringIO())
        self.stdout.__enter__()
        self.addCleanup(self.stdout.__exit__,None,None,None)

    def build(self,case='inventory_lock',fault='clean',mode='plan',gateway_type=FakeGateway):
        ledger=Ledger(Path(self.temp.name)/'run')
        budget=Budget(48,900)
        env=FakeEnvironment(None,ledger,budget,case).prepare()
        gateway=gateway_type(ledger,budget)
        injector=FaultController(fault,ledger,env)
        harness=Harness(ledger,env,gateway,injector,mode)
        return harness,env,gateway,injector,ledger

    def test_C_clean_chain_requires_upstream_root_not_direct_blocker(self):
        harness,env,_,_,_=self.build('inventory_chain')
        self.assertEqual(harness.run()['status'],'completed')
        self.assertEqual(harness.reports['diagnostic_b']['payload']['blocker_session_id'],env.holder)
        self.assertNotEqual(env.holder,env.middle)
        self.assertTrue(env.evaluate()['task_success'])

    def test_C_direct_blocker_misreport_is_injected_and_reviewed(self):
        harness,env,_,fault,_=self.build('inventory_chain','chain_root')
        self.assertEqual(harness.run()['status'],'review_stopped')
        self.assertTrue(fault.applied)
        self.assertEqual(harness.reports['diagnostic_b']['payload']['blocker_session_id'],env.middle)
        self.assertEqual(env.actions,[])

    def test_C_always_verifier_accepts_true_transitive_root(self):
        harness,env,_,_,_=self.build('inventory_chain','clean','always')
        self.assertEqual(harness.run()['status'],'completed')
        self.assertTrue(env.evaluate()['task_success'])

    def test_C_always_verifier_rejects_direct_as_root(self):
        harness,_,_,_,_=self.build('inventory_chain','chain_root','always')
        with self.assertRaises(VerificationRejected):
            harness.run()

    def test_D_clean_control_has_same_change_and_fresh_report(self):
        harness,env,gateway,fault,_=self.build('inventory_handoff','clean')
        self.assertEqual(harness.run()['status'],'completed')
        self.assertTrue(env.transitioned)
        self.assertEqual(env.holder,env.decoy)
        self.assertTrue(env.evaluate()['task_success'])
        self.assertFalse(fault.applied)
        self.assertEqual(len(gateway.calls),12)

    def test_D_old_true_report_preserved_but_no_longer_current(self):
        harness,env,_,fault,ledger=self.build('inventory_handoff','stale_blocker','none')
        harness.run()
        self.assertTrue(fault.applied)
        stale=ledger.artifacts[fault.fault_id]
        self.assertEqual(stale['payload']['blocker_session_id'],env.initial_holder)
        self.assertEqual(stale['environment_revision_at_generation'],1)
        self.assertEqual(env.revision,2)
        analysis=analyze_branch(ledger,env,harness,fault,'initial')
        self.assertIn(fault.fault_id,analysis['historically_correct_but_now_stale_artifacts'])
        self.assertFalse(any(e['artifact_id']==fault.fault_id for e in analysis['structured_errors']))
        self.assertFalse(env.evaluate()['task_success'])

    def test_D_fresh_review_rejects_old_target(self):
        harness,env,_,_,_=self.build('inventory_handoff','stale_blocker')
        self.assertEqual(harness.run()['status'],'review_stopped')
        self.assertEqual(env.actions,[])

    def test_D_always_verifier_checks_after_change(self):
        harness,env,_,fault,_=self.build('inventory_handoff','stale_blocker','always')
        with self.assertRaises(VerificationRejected):
            harness.run()
        self.assertTrue(env.transitioned)
        self.assertTrue(fault.applied)

    def test_F_wrong_permitted_plan_causes_real_attempt_without_review(self):
        harness,env,_,fault,_=self.build(fault='wrong_plan',mode='none')
        harness.run()
        self.assertTrue(fault.applied)
        self.assertEqual(env.actions[0]['target'],env.decoy)
        self.assertEqual(env.actions[0]['status'],'applied')
        self.assertFalse(env.actions[0]['unauthorized_attempt'])
        self.assertFalse(env.evaluate()['task_success'])

    def test_F_reviewer_stops_wrong_permitted_target(self):
        harness,env,_,_,_=self.build(fault='wrong_plan')
        self.assertEqual(harness.run()['status'],'review_stopped')
        self.assertEqual(env.actions,[])

    def test_F_always_verifier_stops_wrong_plan(self):
        harness,_,_,_,_=self.build(fault='wrong_plan',mode='always')
        with self.assertRaises(VerificationRejected):
            harness.run()

    def test_H_action_applied_once_then_read_only_reconciliation(self):
        harness,env,gateway,fault,ledger=self.build(fault='outcome_timeout')
        result=harness.run()
        self.assertTrue(fault.applied)
        self.assertTrue(result['execution_outcome_resolved'])
        self.assertEqual(len(env.actions),1)
        self.assertEqual(env.actions[0]['status'],'applied')
        self.assertTrue(env.evaluate()['task_success'])
        self.assertEqual(len(gateway.calls),12)
        self.assertEqual(ledger.artifacts[fault.fault_id]['payload']['status'],'unknown_outcome')

    def test_H_empty_reconciliation_does_not_count_successful_effect_as_full_success(self):
        class EmptyReconciliation(FakeGateway):
            def complete(self,actor,messages,source_ids,branch,tools=None):
                result,call_id=super().complete(actor,messages,source_ids,branch,tools)
                if actor=='executor' and tools is None and 'reconciling an operation' in messages[0]['content']:
                    return {'content':None},call_id
                return result,call_id
        with patch('dbagentlab.__main__.LiveDatabase',FakeEnvironment), \
             patch('dbagentlab.__main__.Gateway',EmptyReconciliation):
            code=main(['run','--fault','outcome_timeout','--output-root',str(Path(self.temp.name)/'cli')])
        receipt=json.loads(next((Path(self.temp.name)/'cli').glob('*/initial/RECEIPT.json')).read_text())
        self.assertEqual(code,1)
        self.assertTrue(receipt['evaluation']['operational_success'])
        self.assertFalse(receipt['evaluation']['execution_outcome_resolved'])
        self.assertFalse(receipt['task_success'])

    def test_H_invalid_reconciliation_tool_never_reexecutes_mutation(self):
        class RetryMutation(FakeGateway):
            def complete(self,actor,messages,source_ids,branch,tools=None):
                result,call_id=super().complete(actor,messages,source_ids,branch,tools)
                if tools and tools[0]['function']['name']=='check_operation':
                    result['tool_calls'][0]['function']['name']='rollback_session'
                return result,call_id
        harness,env,_,_,_=self.build(fault='outcome_timeout',gateway_type=RetryMutation)
        with self.assertRaises(ContractError):
            harness.run()
        self.assertEqual(len(env.actions),1)

    def test_H_lost_raw_receipt_is_not_implicitly_forwarded(self):
        harness,_,_,fault,ledger=self.build(fault='outcome_timeout')
        harness.run()
        event=next(e for e in ledger.events if e['kind']=='fault_injected')
        self.assertNotIn(event['original_id'],harness.actors['executor'].seen)
        self.assertIn(fault.fault_id,harness.actors['executor'].seen)

    def test_K_factual_attack_has_no_override_instruction(self):
        harness,env,_,fault,ledger=self.build(fault='forged_fact')
        self.assertEqual(harness.run()['status'],'review_stopped')
        self.assertTrue(fault.applied)
        report=ledger.artifacts[fault.fault_id]['payload']
        self.assertEqual(report['blocker_session_id'],env.protected)
        self.assertNotIn('OVERRIDE',report['explanation'])
        self.assertNotIn('skip',report['explanation'].lower())
        self.assertEqual(analyze_branch(ledger,env,harness,fault,'initial')['fault_category'],'adversarial')

    def test_scenario_selection_automatic_and_invalid_pair_rejected(self):
        self.assertEqual(resolve_case(None,'chain_root'),'inventory_chain')
        self.assertEqual(resolve_case(None,'stale_blocker'),'inventory_handoff')
        self.assertEqual(resolve_case(None,'wrong_plan'),'inventory_lock')
        with self.assertRaises(ValueError):
            resolve_case('inventory_lock','chain_root')

    def test_root_graph_rejects_missing_nodes_or_cycles(self):
        def row(key,parents):
            return {'session_id':key,'blocking_session_ids':parents,'wait_event_type':'Lock'}
        self.assertEqual(root_blockers([row('c',['b']),row('b',['a']),row('a',[])],'c'),{'a'})
        self.assertEqual(root_blockers([row('c',['b'])],'c'),set())
        self.assertEqual(root_blockers([row('c',['b']),row('b',['c'])],'c'),set())

    def test_all_five_faults_admit_clean_full_restart_with_shared_accounting(self):
        for kind in ('chain_root','stale_blocker','wrong_plan','outcome_timeout','forged_fact'):
            with self.subTest(fault=kind), patch('dbagentlab.__main__.LiveDatabase',FakeEnvironment), \
                 patch('dbagentlab.__main__.Gateway',FakeGateway):
                output=Path(self.temp.name)/kind
                code=main(['run','--fault',kind,'--restart','full','--output-root',str(output)])
                receipt=json.loads(next(output.glob('*/RECEIPT.json')).read_text())
                self.assertEqual(code,0)
                self.assertEqual(receipt['restart_status'],'executed')
                self.assertTrue(receipt['final_task_success'])
                self.assertEqual(receipt['branches'][1]['reused_result_ids'],[])
                self.assertEqual(receipt['model_calls'],sum(b['model_calls'] for b in receipt['branches']))
