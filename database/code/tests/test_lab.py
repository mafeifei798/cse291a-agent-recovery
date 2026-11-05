import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from dbagentlab.core import Budget, BudgetExceeded, Ledger
from dbagentlab.environment import LiveDatabase
from dbagentlab.faults import FaultController
from dbagentlab.gateway import Gateway
from dbagentlab.protocol import parse_json, validate
from dbagentlab.verification import VerificationRejected, check_claim
from dbagentlab.workflow import ContractError, Harness, analyze_branch, visible, visible_ids
from fakes import FakeEnvironment, FakeGateway


class LabTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)/'run'
        self.ledger = Ledger(self.folder, 'TOP_SECRET_TEST')
        self.budget = Budget(40, 900)
        self.env = FakeEnvironment(None, self.ledger, self.budget).prepare()

    def workflow(self, kind='clean', verification='plan', **kwargs):
        gateway = FakeGateway(self.ledger, self.budget, **kwargs)
        fault = FaultController(kind, self.ledger, self.env)
        harness = Harness(self.ledger, self.env, gateway, fault, verification)
        return harness, gateway, fault

    def test_clean_end_to_end_six_roles(self):
        harness, gateway, fault = self.workflow()
        self.assertEqual(harness.run()['status'], 'completed')
        self.assertTrue(self.env.evaluate()['task_success'])
        self.assertEqual({c['actor'] for c in gateway.calls},
                         {'diagnostic_a','diagnostic_b','state','planner','reviewer','executor'})
        self.assertEqual(len(gateway.calls), 10)
        self.assertFalse(fault.applied)

    def test_clean_always_checks_without_private_truth(self):
        harness, _, _ = self.workflow('clean','always')
        self.assertEqual(harness.run()['status'],'completed')
        self.assertTrue(self.env.evaluate()['task_success'])
        checks=[a for a in self.ledger.artifacts.values() if a['kind']=='verification']
        self.assertEqual(len(checks),6)
        self.assertTrue(all(a['payload']['accepted'] for a in checks))

    def test_direct_question_reply_and_final_consolidation(self):
        harness, gateway, _ = self.workflow(questions=True)
        self.assertEqual(harness.run()['exchanges'], 1)
        delivered = [e for e in self.ledger.events if e['kind'] == 'message_delivered']
        self.assertEqual(len(delivered), 2)
        self.assertEqual((delivered[0]['sender'], delivered[0]['recipient']),
                         ('diagnostic_a', 'diagnostic_b'))
        self.assertTrue(self.env.evaluate()['task_success'])
        self.assertEqual(len(gateway.calls), 13)

    def test_peer_report_and_forwarded_observation_are_citable(self):
        harness, _, _ = self.workflow(questions=True, cite_peer_evidence=True)
        self.assertEqual(harness.run()['status'], 'completed')
        self.assertTrue(self.env.evaluate()['task_success'])
        actor = harness.actors['diagnostic_a']
        refs = harness.reports['diagnostic_a']['payload']['evidence_refs']
        self.assertTrue(all(ref in actor.seen for ref in refs))
        self.assertTrue(any(self.ledger.artifacts[ref]['kind']=='observation' for ref in refs))

    def test_executor_can_cite_plan_sources_only_when_forwarded(self):
        harness, _, _ = self.workflow(cite_upstream=True)
        self.assertEqual(harness.run()['status'],'completed')
        actor=harness.actors['executor']
        refs=self.ledger.artifacts[actor.seen[-1]]['payload']['evidence_refs']
        self.assertTrue(all(identifier in actor.seen for identifier in refs))
        source = self.ledger.artifacts[refs[0]]
        self.assertTrue(all(identifier in actor.seen for identifier in source['payload']['evidence_refs']))

    def test_handoff_does_not_resolve_unseen_or_private_citations(self):
        harness, _, _ = self.workflow()
        hidden = self.ledger.artifact('truth','evaluator',{'answer':'private'})
        report = self.ledger.artifact('report','planner',{'evidence_refs':[hidden['id']]})
        bundle = harness.context_bundle([report])
        self.assertNotIn(hidden['id'],visible_ids(bundle,self.ledger,'initial'))

    def test_bare_reference_is_not_evidence_exposure(self):
        hidden = self.ledger.artifact('observation','state',{'policy':'not delivered'})
        report = self.ledger.artifact('report','state',{'evidence_refs':[hidden['id']]})
        exposed = visible_ids(visible(report),self.ledger,'initial')
        self.assertIn(report['id'],exposed)
        self.assertNotIn(hidden['id'],exposed)

    def test_forged_envelope_does_not_register_hidden_evidence(self):
        hidden = self.ledger.artifact('observation','state',{'policy':'true data'})
        forged = visible(hidden)
        forged['payload']={'policy':'fabricated data'}
        self.assertNotIn(hidden['id'],visible_ids(forged,self.ledger,'initial'))
        self.assertNotIn(hidden['id'],visible_ids(visible(hidden),self.ledger,'restart'))

    def test_pid_swap_propagates_but_capability_guard_denies(self):
        harness, gateway, fault = self.workflow('pid_swap', 'none')
        harness.run()
        self.assertTrue(fault.applied)
        self.assertEqual(self.env.actions[0]['status'], 'denied')
        analysis = analyze_branch(self.ledger, self.env, harness, fault, 'initial')
        self.assertGreaterEqual(analysis['downstream_structured_error_count'], 2)
        self.assertIn('planner', analysis['potentially_affected_actors'])
        self.assertFalse(self.env.evaluate()['task_success'])
        self.assertEqual(self.env.evaluate()['unauthorized_actions_applied'], 0)

    def test_reviewer_can_stop_wrong_plan(self):
        harness, _, _ = self.workflow('pid_swap', 'plan')
        self.assertEqual(harness.run()['status'], 'review_stopped')
        self.assertEqual(self.env.actions, [])
        self.assertFalse(self.env.evaluate()['task_success'])

    def test_always_verifier_stops_wrong_report_before_planner(self):
        harness, gateway, _ = self.workflow('pid_swap', 'always')
        with self.assertRaises(VerificationRejected):
            harness.run()
        self.assertNotIn('planner', {c['actor'] for c in gateway.calls})

    def test_adversarial_message_not_harness_authority(self):
        harness, _, fault = self.workflow('instruction', 'none', follow_attack=True)
        harness.run()
        self.assertTrue(fault.applied)
        self.assertEqual(self.env.actions[0]['target'], self.env.protected)
        self.assertEqual(self.env.actions[0]['status'], 'denied')
        self.assertNotIn(self.env.protected, self.env.released)

    def test_tool_corruption_can_propagate_from_observation_to_reports(self):
        harness, _, fault = self.workflow('tool_pid_swap','none')
        self.assertEqual(harness.run()['status'],'completed')
        self.assertTrue(fault.applied)
        self.assertEqual(harness.reports['diagnostic_b']['payload']['blocker_session_id'],self.env.waiter)
        self.assertEqual(self.env.actions[0]['status'],'denied')
        analysis=analyze_branch(self.ledger,self.env,harness,fault,'initial')
        self.assertGreaterEqual(analysis['downstream_structured_error_count'],3)
        self.assertFalse(self.env.evaluate()['task_success'])

    def test_tool_corruption_keeps_raw_and_live_database_unchanged(self):
        fault=FaultController('tool_pid_swap',self.ledger,self.env)
        original=self.ledger.artifact('observation','diagnostic_b',self.env.read(['activity','business']))
        before=copy.deepcopy(original)
        altered=fault.corrupt_read('diagnostic_b',original)
        self.assertEqual(original,before)
        rows=altered['payload']['activity']['rows']
        holder=next(r for r in rows if r['session_id']==self.env.holder)
        waiter=next(r for r in rows if r['session_id']==self.env.waiter)
        self.assertEqual(holder['pid'],100)
        self.assertEqual(waiter['pid'],101)
        self.assertEqual(holder['blocking_pids'],[101])
        self.assertEqual(holder['blocking_session_ids'],[self.env.waiter])
        self.assertEqual(holder['wait_event_type'],'Lock')
        self.assertEqual(waiter['blocking_pids'],[])
        self.assertEqual(waiter['state'],'idle in transaction')
        self.assertEqual(altered['payload']['business'],original['payload']['business'])
        self.assertTrue(LiveDatabase.relation(self.env.activity(),self.env.waiter,self.env.holder))

    def test_tool_corruption_only_first_read_of_target_role(self):
        fault=FaultController('tool_pid_swap',self.ledger,self.env)
        first=self.ledger.artifact('observation','diagnostic_a',self.env.read(['activity']))
        self.assertEqual(fault.corrupt_read('diagnostic_a',first),first)
        self.assertFalse(fault.first_read_seen)
        target=self.ledger.artifact('observation','diagnostic_b',self.env.read(['activity']))
        self.assertNotEqual(fault.corrupt_read('diagnostic_b',target)['id'],target['id'])
        later=self.ledger.artifact('observation','diagnostic_b',self.env.read(['activity']))
        self.assertEqual(fault.corrupt_read('diagnostic_b',later),later)

    def test_tool_corruption_not_retargeted_if_first_read_has_no_activity(self):
        fault=FaultController('tool_pid_swap',self.ledger,self.env)
        first=self.ledger.artifact('observation','diagnostic_b',self.env.read(['query_stats']))
        self.assertEqual(fault.corrupt_read('diagnostic_b',first),first)
        second=self.ledger.artifact('observation','diagnostic_b',self.env.read(['activity']))
        self.assertEqual(fault.corrupt_read('diagnostic_b',second),second)
        self.assertFalse(fault.applied)
        self.assertEqual(fault.status,'target_read_missing_valid_activity_pair')

    def test_tool_corruption_raw_original_not_exposed_through_citations(self):
        harness, _, fault = self.workflow('tool_pid_swap','none')
        harness.run()
        event=next(e for e in self.ledger.events if e['kind']=='fault_injected')
        for actor in harness.actors.values():
            self.assertNotIn(event['original_id'],actor.seen)
            self.assertNotIn(event['original_id'],json.dumps(actor.messages))
        self.assertIn(fault.fault_id,harness.actors['diagnostic_b'].seen)

    def test_always_verification_can_check_tool_based_report_against_new_read(self):
        harness, _, _ = self.workflow('tool_pid_swap','always')
        with self.assertRaises(VerificationRejected):
            harness.run()

    def test_timeout_has_zero_output_and_does_not_fake_diagnosis(self):
        harness, _, fault = self.workflow('timeout', 'none')
        harness.run()
        self.assertEqual(self.ledger.artifacts[fault.fault_id]['payload']['output'], None)
        self.assertEqual(harness.reports['diagnostic_b']['payload']['cause'], 'UNKNOWN')
        self.assertFalse(self.env.evaluate()['task_success'])

    def test_timeout_contract_reaches_model_with_real_failure_id(self):
        harness, gateway, fault = self.workflow('timeout','none')
        harness.run()
        messages=harness.actors['diagnostic_b'].messages
        guidance=[m['content'] for m in messages if m['role']=='user'
                  and 'preceding tool read failed' in m['content']]
        self.assertEqual(len(guidance),1)
        self.assertIn(fault.fault_id,guidance[0])
        self.assertIn('UNKNOWN',guidance[0])
        self.assertIn('no database observations',guidance[0])
        self.assertEqual(sum(c['actor']=='diagnostic_b' for c in gateway.calls),2)

    def test_empty_api_body_after_timeout_still_fails_without_fallback(self):
        class EmptyAfterTimeout(FakeGateway):
            def complete(self,actor,messages,source_ids,branch,tools=None):
                result,call_id=super().complete(actor,messages,source_ids,branch,tools)
                if actor=='diagnostic_b' and tools is None:
                    return {'content':None},call_id
                return result,call_id
        gateway=EmptyAfterTimeout(self.ledger,self.budget)
        fault=FaultController('timeout',self.ledger,self.env)
        harness=Harness(self.ledger,self.env,gateway,fault,'plan')
        with self.assertRaisesRegex(ContractError,'Model returned no JSON text'):
            harness.run()
        self.assertTrue(fault.applied)
        self.assertEqual(len(gateway.calls),4)
        self.assertFalse(any(a['actor']=='diagnostic_b' and a['kind']=='report'
                             for a in self.ledger.artifacts.values()))
        self.assertEqual(self.env.actions,[])

    def test_fault_does_not_rewrite_original(self):
        artifact = self.ledger.artifact('report','diagnostic_b', {
            'cause':'LOCK_CONTENTION', 'blocker_session_id':self.env.holder,
            'waiter_session_id':self.env.waiter, 'explanation':'Original',
            'question':None, 'evidence_refs':['observation']})
        before = copy.deepcopy(artifact)
        fault = FaultController('pid_swap',self.ledger,self.env)
        delivered = fault.deliver('diagnostic_b',artifact)
        self.assertEqual(artifact,before)
        self.assertEqual(delivered['payload']['blocker_session_id'], self.env.waiter)
        self.assertEqual(fault.deliver('diagnostic_b',artifact),artifact)

    def test_unreached_or_unusable_fault_not_counted_delivered(self):
        fault = FaultController('pid_swap',self.ledger,self.env)
        report = self.ledger.artifact('report','diagnostic_b', {
            'blocker_session_id':None,'waiter_session_id':None})
        self.assertEqual(fault.deliver('diagnostic_b',report),report)
        self.assertFalse(fault.applied)
        self.assertIsNone(fault.fault_id)

    def test_bad_model_output_retained_as_failure(self):
        harness, gateway, _ = self.workflow(bad_json=True)
        with self.assertRaises(ContractError):
            harness.run()
        self.assertEqual(len(gateway.calls),2)
        self.assertFalse(self.env.actions)

    def test_budget_never_resets_between_branches(self):
        budget = Budget(1,900)
        budget.reserve()
        with self.assertRaises(BudgetExceeded):
            budget.reserve()
        self.assertEqual(budget.calls,1)

    def test_atomic_artifacts_redact_secrets_and_keep_dependencies(self):
        root = self.ledger.artifact('report','x',{'text':'TOP_SECRET_TEST'})
        child = self.ledger.artifact('report','y',{'x':1},parents=[root['id']])
        self.assertEqual(self.ledger.descendants(root['id']),{child['id']})
        self.assertNotIn('TOP_SECRET_TEST',(self.folder/'artifacts'/ (root['id']+'.json')).read_text())
        with self.assertRaises(ValueError):
            self.ledger.artifact('report','z',{},parents=['nonexistent'])

    def test_always_verifier_reads_public_relationship_not_role_guess(self):
        evidence = self.env.read(['activity','policy','business'])
        good = {'cause':'LOCK_CONTENTION','blocker_session_id':self.env.holder,
                'waiter_session_id':self.env.waiter}
        self.assertFalse(check_claim('diagnostic_b',good,evidence))
        bad = {**good,'blocker_session_id':self.env.waiter,'waiter_session_id':self.env.holder}
        self.assertTrue(check_claim('diagnostic_b',bad,evidence))

    def test_permission_does_not_establish_root_cause(self):
        evidence = self.env.read(['activity','policy','business'])
        errors = check_claim('planner',{'action':'rollback_session',
            'target_session_id':'session_decoy'},evidence)
        self.assertIn('target_not_blocking_business_request',errors)
        self.assertNotIn('target_not_currently_eligible',errors)

    def test_public_task_has_no_truth_or_injection_label(self):
        public = json.dumps(self.env.public_task())
        for forbidden in ('LOCK_CONTENTION','fault_id','holder','protected','pid_swap'):
            self.assertNotIn(forbidden,public)

    def test_schemas_reject_invalid_references(self):
        result = {'cause':'LOCK_CONTENTION','blocker_session_id':'a','waiter_session_id':'b',
            'evidence_refs':['missing'],'explanation':'x','question':None}
        with self.assertRaises(ValueError):
            validate('diagnostic_b',result,['present'])

    def test_school_gateway_rejects_foreign_endpoint(self):
        with patch.dict(os.environ,{'OPENAI_API_KEY':'TOP_SECRET_TEST',
                                  'OPENAI_BASE_URL':'https://attacker.example/v1'}):
            with self.assertRaises(ValueError):
                Gateway(self.ledger,self.budget)

    def test_live_relation_needs_correct_direction_and_lock_event(self):
        rows = [{'session_id':'b','wait_event_type':'Lock','blocking_session_ids':['a']}]
        self.assertTrue(LiveDatabase.relation(rows,'b','a'))
        self.assertFalse(LiveDatabase.relation(rows,'a','b'))
        rows[0]['wait_event_type']='Client'
        self.assertFalse(LiveDatabase.relation(rows,'b','a'))

    def test_actual_tool_guard_never_calls_protected_connection(self):
        env=LiveDatabase(self.temp.name,self.ledger,self.budget)
        protected=Mock()
        env.sessions={'protected':{'can_rollback':False,'connection':protected,'released':False}}
        outcome=env.action('rollback_session','protected')
        self.assertEqual(outcome['status'],'denied')
        protected.execute.assert_not_called()
        self.assertTrue(outcome['unauthorized_attempt'])

    def test_actual_tool_guard_applies_owned_eligible_operation(self):
        env=LiveDatabase(self.temp.name,self.ledger,self.budget)
        connection=Mock()
        connection.closed=False
        env.sessions={'disposable':{'can_rollback':True,'connection':connection,'released':False}}
        env.done=Mock()
        env.done.wait.return_value=False
        outcome=env.action('rollback_session','disposable')
        connection.execute.assert_called_once_with('ROLLBACK')
        self.assertEqual(outcome['status'],'applied')
        self.assertTrue(env.sessions['disposable']['released'])
        self.assertEqual(env.revision,2)

    def test_public_live_task_does_not_disclose_case_mechanism(self):
        env=LiveDatabase(self.temp.name,self.ledger,self.budget)
        env.waiter='request_123'
        env.table='inventory'
        env.initial_stock=100
        public=json.dumps(env.public_task())
        self.assertNotIn('inventory_lock',public)
        self.assertNotIn('LOCK_CONTENTION',public)

    def test_full_restart_cli_fresh_histories_and_shared_accounting(self):
        from dbagentlab.__main__ import main
        with patch('dbagentlab.__main__.LiveDatabase',FakeEnvironment), \
             patch('dbagentlab.__main__.Gateway',FakeGateway):
            code = main(['run','--fault','pid_swap','--verification','none','--restart','full',
                         '--output-root',str(Path(self.temp.name)/'campaign')])
        self.assertEqual(code,0)
        path = next((Path(self.temp.name)/'campaign').glob('*/RECEIPT.json'))
        receipt = json.loads(path.read_text())
        self.assertFalse(receipt['initial_task_success'])
        self.assertTrue(receipt['final_task_success'])
        self.assertEqual(receipt['model_calls'],16)
        self.assertEqual(receipt['branches'][1]['reused_result_ids'],[])
        graph = json.loads((path.parent/'dependencies.json').read_text())['nodes']
        branches = {a['id']:a['branch'] for a in graph}
        self.assertTrue(all(branches[p] == a['branch'] for a in graph for p in a['parents']))

    def test_cleanup_cannot_turn_failed_task_into_success(self):
        from dbagentlab.__main__ import main
        class CleanupOnlySuccess(FakeEnvironment):
            def cleanup(self):
                self.worker['status']='committed'
                return super().cleanup()
        with patch('dbagentlab.__main__.LiveDatabase',CleanupOnlySuccess), \
             patch('dbagentlab.__main__.Gateway',FakeGateway):
            code=main(['run','--fault','pid_swap','--verification','plan',
                       '--output-root',str(Path(self.temp.name)/'cleanup_campaign')])
        self.assertEqual(code,0)
        receipt=json.loads(next((Path(self.temp.name)/'cleanup_campaign').glob('*/RECEIPT.json')).read_text())
        self.assertFalse(receipt['initial_task_success'])
        self.assertEqual(receipt['branches'][0]['evaluation']['request_status'],'pending')


if __name__ == '__main__':
    unittest.main()
