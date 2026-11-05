import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from dbagentlab.core import Budget, Ledger
from dbagentlab.faults import FaultController
from dbagentlab.environment import LiveDatabase
from dbagentlab.workflow import Harness, ContractError
from dbagentlab.verification import VerificationRejected
from dbagentlab.campaign import make_extended_plan
from dbagentlab.summarize import aggregate
from dbagentlab.__main__ import main
from fakes import FakeEnvironment, FakeGateway


def raw_activity_packets(messages):
    found=[]
    def visit(value):
        if isinstance(value,dict):
            if 'artifact_id' in value and 'activity' in value.get('payload',{}):
                found.append(value)
            for item in value.values():
                visit(item)
        elif isinstance(value,list):
            for item in value:
                visit(item)
    for message in messages:
        if message['role'] in ('user','tool'):
            try:
                visit(json.loads(message['content']))
            except (ValueError,TypeError):
                pass
    return found


class RoleSeparationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        redirect=contextlib.redirect_stdout(io.StringIO())
        redirect.__enter__()
        self.addCleanup(redirect.__exit__,None,None,None)

    def build(self,mode='none',fault_kind='clean',gateway_type=FakeGateway):
        ledger=Ledger(Path(self.temp.name)/'run')
        budget=Budget(48,900)
        env=FakeEnvironment(None,ledger,budget).prepare()
        gateway=gateway_type(ledger,budget)
        fault=FaultController(fault_kind,ledger,env)
        harness=Harness(ledger,env,gateway,fault,mode,diagnostic_experts=1,role_policy='separated')
        return harness,env,gateway,fault,ledger

    def test_policy_excludes_released_blocker_after_handoff(self):
        env = LiveDatabase.__new__(LiveDatabase)
        env.sessions = {
            'old': {'pid': 1, 'can_rollback': True, 'released': True},
            'new': {'pid': 2, 'can_rollback': True, 'released': False},
            'protected': {'pid': 3, 'can_rollback': False, 'released': False},
        }
        policy = {row['session_id']: row for row in env.policy()}
        self.assertEqual(policy['old']['allowed_actions'], [])
        self.assertEqual(policy['new']['allowed_actions'], ['rollback_session'])
        self.assertEqual(policy['protected']['allowed_actions'], [])

    def test_clean_reports_only_workflow_can_complete(self):
        harness,env,gateway,_,_=self.build()
        self.assertEqual(harness.run()['status'],'completed')
        self.assertTrue(env.evaluate()['task_success'])
        self.assertEqual(len(gateway.calls),6)

    def test_raw_activity_is_not_expanded_to_state_planner_executor(self):
        harness,_,_,_,ledger=self.build()
        harness.run()
        diagnostic_packets=raw_activity_packets(harness.actors['diagnostic_b'].messages)
        self.assertTrue(diagnostic_packets)
        source=diagnostic_packets[0]['artifact_id']
        for role in ('state','planner','executor'):
            actor=harness.actors[role]
            self.assertEqual(raw_activity_packets(actor.messages),[])
            self.assertNotIn(source,actor.seen)
        self.assertIn(source,json.dumps(harness.actors['planner'].messages))
        self.assertIn(source,ledger.artifacts)

    def test_state_query_scope_has_only_policy_and_business(self):
        class CheckScope(FakeGateway):
            def complete(self,actor,messages,source_ids,branch,tools=None):
                if actor=='state' and tools:
                    allowed=tools[0]['function']['parameters']['properties']['views']['items']['enum']
                    assert allowed==['policy','business']
                return super().complete(actor,messages,source_ids,branch,tools)
        harness,env,_,_,_=self.build(gateway_type=CheckScope)
        harness.run()
        self.assertTrue(env.evaluate()['task_success'])

    def test_state_cannot_bypass_scope_with_tool_arguments(self):
        class IllegalActivityRead(FakeGateway):
            def complete(self,actor,messages,source_ids,branch,tools=None):
                result,identifier=super().complete(actor,messages,source_ids,branch,tools)
                if actor=='state' and tools:
                    result['tool_calls'][0]['function']['arguments']=json.dumps({'views':['policy','business','activity']})
                return result,identifier
        harness,_,_,_,ledger=self.build(gateway_type=IllegalActivityRead)
        with self.assertRaisesRegex(ContractError,'evidence scopes'):
            harness.run()
        self.assertFalse(any(a['actor']=='state' and a['kind']=='observation' for a in ledger.artifacts.values()))

    def test_peer_exchange_does_not_forward_raw_diagnostic_observation(self):
        class AskState(FakeGateway):
            asked=False
            def complete(self,actor,messages,source_ids,branch,tools=None):
                result,identifier=super().complete(actor,messages,source_ids,branch,tools)
                if actor=='diagnostic_b' and tools is None and not self.asked:
                    self.asked=True
                    payload=json.loads(result['content'])
                    payload['question']={'to':'state','text':'Is this target permitted?'}
                    result['content']=json.dumps(payload)
                return result,identifier
        harness,env,_,_,ledger=self.build(gateway_type=AskState)
        self.assertEqual(harness.run()['exchanges'],1)
        self.assertTrue(env.evaluate()['task_success'])
        self.assertEqual(raw_activity_packets(harness.actors['state'].messages),[])
        messages=[a for a in ledger.artifacts.values() if a['kind']=='message']
        self.assertTrue(messages)
        self.assertTrue(all(not a['payload']['supporting_evidence'] for a in messages))

    def test_reviewer_can_independently_read_fresh_activity(self):
        harness,env,_,_,_=self.build(mode='plan')
        harness.run()
        self.assertTrue(env.evaluate()['task_success'])
        self.assertTrue(raw_activity_packets(harness.actors['reviewer'].messages))
        self.assertFalse(raw_activity_packets(harness.actors['planner'].messages))

    def test_upstream_ids_are_not_silently_treated_as_direct_reads(self):
        class CiteUnseen(FakeGateway):
            def complete(self,actor,messages,source_ids,branch,tools=None):
                result,identifier=super().complete(actor,messages,source_ids,branch,tools)
                if actor=='planner' and tools is None:
                    report_id=next(i for i in source_ids if self.ledger.artifacts[i]['actor']=='diagnostic_b')
                    unseen=self.ledger.artifacts[report_id]['payload']['evidence_refs'][0]
                    payload=json.loads(result['content'])
                    payload['evidence_refs']=[unseen]
                    result['content']=json.dumps(payload)
                return result,identifier
        harness,_,_,_,_=self.build(gateway_type=CiteUnseen)
        with self.assertRaisesRegex(ContractError,'unexposed IDs'):
            harness.run()

    def test_citable_id_contract_is_present_for_every_actor(self):
        harness,_,_,_,_=self.build()
        harness.run()
        for role in ('diagnostic_b','state','planner','executor'):
            messages=harness.actors[role].messages
            contracts=[json.loads(m['content']) for m in messages if m['role']=='user'
                       and m['content'].startswith('{') and 'citable_artifact_ids' in m['content']]
            self.assertTrue(contracts)

    def test_h_reconciliation_does_not_open_lock_view_to_executor(self):
        harness,env,_,_,ledger=self.build(fault_kind='outcome_timeout')
        self.assertTrue(harness.run()['execution_outcome_resolved'])
        self.assertTrue(env.evaluate()['task_success'])
        checks=[a for a in ledger.artifacts.values() if a['kind']=='operation_check']
        self.assertEqual(set(checks[0]['payload']['observations']),{'policy','business'})
        self.assertFalse(raw_activity_packets(harness.actors['executor'].messages))

    def test_public_permission_guard_still_denies_protected_target(self):
        harness,env,_,fault,_=self.build(fault_kind='forged_fact')
        harness.run()
        self.assertTrue(fault.applied)
        self.assertEqual(env.actions[0]['status'],'denied')
        self.assertEqual(env.evaluate()['unauthorized_actions_applied'],0)

    def test_always_verification_remains_an_explicit_comparison(self):
        harness,_,_,_,_=self.build(mode='always',fault_kind='tool_pid_swap')
        with self.assertRaises(VerificationRejected):
            harness.run()

    def test_full_restart_preserves_role_policy(self):
        output=Path(self.temp.name)/'cli'
        with patch('dbagentlab.__main__.LiveDatabase',FakeEnvironment),patch('dbagentlab.__main__.Gateway',FakeGateway):
            code=main(['run','--role-policy','separated','--diagnostic-experts','1',
                       '--verification','none','--fault','wrong_plan','--restart','full',
                       '--output-root',str(output)])
        receipt=json.loads(next(output.glob('*/RECEIPT.json')).read_text())
        self.assertEqual(code,0)
        self.assertEqual(receipt['role_policy'],'separated')
        self.assertTrue(all(b['role_policy']=='separated' for b in receipt['branches']))
        self.assertTrue(receipt['final_task_success'])

    def test_campaign_and_summary_separate_role_policies(self):
        plan=make_extended_plan(['none'],1,17,False,[1],['shared','separated'])
        self.assertEqual(len(plan['slots']),18)
        self.assertEqual({slot['role_policy'] for slot in plan['slots']},{'shared','separated'})
        rows=[]
        for policy in ('shared','separated'):
            rows.append({'role_policy':policy,'diagnostic_experts':1,'code_version':'test',
                'case':'inventory_lock','condition':'clean','verification':'none','restart':'none',
                'branch':'initial','task_success':True,'fixture_valid':True,'fault_delivery_status':'disabled',
                'direct_exposure_calls':0,'downstream_structured_errors':0,'unauthorized_attempts':0,
                'unauthorized_applied':0,'model_calls':6})
        self.assertEqual(len(aggregate(rows)),2)
