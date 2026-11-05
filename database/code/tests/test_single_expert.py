import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from dbagentlab.core import Budget, Ledger
from dbagentlab.campaign import make_extended_plan
from dbagentlab.faults import FaultController
from dbagentlab.workflow import Harness, ContractError
from dbagentlab.summarize import aggregate
from dbagentlab.__main__ import main
from fakes import FakeEnvironment, FakeGateway


class SingleExpertTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        redirect=contextlib.redirect_stdout(io.StringIO())
        redirect.__enter__()
        self.addCleanup(redirect.__exit__,None,None,None)

    def build(self,mode='none',kind='clean',gateway_type=FakeGateway):
        ledger=Ledger(Path(self.temp.name)/'run')
        budget=Budget(48,900)
        env=FakeEnvironment(None,ledger,budget).prepare()
        gateway=gateway_type(ledger,budget)
        fault=FaultController(kind,ledger,env)
        harness=Harness(ledger,env,gateway,fault,mode,diagnostic_experts=1)
        return harness,env,gateway,fault

    def test_single_diagnostician_without_reviewer_is_four_roles_six_calls(self):
        harness,env,gateway,_=self.build()
        self.assertEqual(harness.run()['status'],'completed')
        self.assertTrue(env.evaluate()['task_success'])
        self.assertEqual(len(gateway.calls),6)
        self.assertEqual({c['actor'] for c in gateway.calls},{'diagnostic_b','state','planner','executor'})

    def test_single_with_reviewer_is_five_roles_eight_calls(self):
        harness,env,gateway,_=self.build('plan')
        harness.run()
        self.assertTrue(env.evaluate()['task_success'])
        self.assertEqual(len(gateway.calls),8)
        self.assertNotIn('diagnostic_a',{c['actor'] for c in gateway.calls})

    def test_combined_diagnostician_can_read_union_of_five_views(self):
        class AllViews(FakeGateway):
            def complete(self,actor,messages,source_ids,branch,tools=None):
                response,identifier=super().complete(actor,messages,source_ids,branch,tools)
                if tools and actor=='diagnostic_b':
                    schema=tools[0]['function']['parameters']['properties']['views']
                    assert schema['maxItems']==5
                    response['tool_calls'][0]['function']['arguments']=json.dumps({'views':schema['items']['enum']})
                return response,identifier
        harness,env,_,_=self.build(gateway_type=AllViews)
        harness.run()
        self.assertTrue(env.evaluate()['task_success'])

    def test_disabled_diagnostic_a_cannot_be_called_via_question(self):
        class AskInactive(FakeGateway):
            def complete(self,actor,messages,source_ids,branch,tools=None):
                response,identifier=super().complete(actor,messages,source_ids,branch,tools)
                if actor=='diagnostic_b' and tools is None:
                    payload=json.loads(response['content'])
                    payload['question']={'to':'diagnostic_a','text':'Please investigate'}
                    response['content']=json.dumps(payload)
                return response,identifier
        harness,_,gateway,_=self.build(gateway_type=AskInactive)
        with self.assertRaisesRegex(ContractError,'inactive investigator'):
            harness.run()
        self.assertNotIn('diagnostic_a',{c['actor'] for c in gateway.calls})

    def test_single_can_still_ask_state_without_starting_second_diagnostician(self):
        class AskState(FakeGateway):
            sent=False
            def complete(self,actor,messages,source_ids,branch,tools=None):
                response,identifier=super().complete(actor,messages,source_ids,branch,tools)
                if actor=='diagnostic_b' and tools is None and not self.sent:
                    self.sent=True
                    payload=json.loads(response['content'])
                    payload['question']={'to':'state','text':'Confirm allowed actions'}
                    response['content']=json.dumps(payload)
                return response,identifier
        harness,env,gateway,_=self.build(gateway_type=AskState)
        self.assertEqual(harness.run()['exchanges'],1)
        self.assertTrue(env.evaluate()['task_success'])
        self.assertEqual(len(gateway.calls),9)
        self.assertNotIn('diagnostic_a',{c['actor'] for c in gateway.calls})

    def test_single_tool_corruption_keeps_permissions_and_injection_active(self):
        harness,env,gateway,fault=self.build(kind='tool_pid_swap')
        harness.run()
        self.assertTrue(fault.applied)
        self.assertFalse(env.evaluate()['task_success'])
        self.assertEqual(env.actions[0]['status'],'denied')
        self.assertNotIn('diagnostic_a',{c['actor'] for c in gateway.calls})

    def test_single_count_persists_through_full_restart(self):
        output=Path(self.temp.name)/'cli'
        with patch('dbagentlab.__main__.LiveDatabase',FakeEnvironment),patch('dbagentlab.__main__.Gateway',FakeGateway):
            code=main(['run','--fault','wrong_plan','--verification','none','--diagnostic-experts','1',
                       '--restart','full','--output-root',str(output)])
        receipt=json.loads(next(output.glob('*/RECEIPT.json')).read_text())
        self.assertEqual(code,0)
        self.assertEqual(receipt['diagnostic_experts'],1)
        self.assertEqual(receipt['model_calls'],12)
        self.assertTrue(receipt['final_task_success'])
        self.assertTrue(all(b['diagnostic_experts']==1 for b in receipt['branches']))

    def test_campaign_records_single_and_paired_count_conditions(self):
        single=make_extended_plan(['none'],1,17,False,[1])
        paired=make_extended_plan(['none'],1,17,False,[1,2])
        self.assertEqual(len(single['slots']),9)
        self.assertTrue(all(s['diagnostic_experts']==1 for s in single['slots']))
        self.assertEqual(len(paired['slots']),18)
        self.assertEqual({s['diagnostic_experts'] for s in paired['slots']},{1,2})

    def test_summary_never_pools_expert_counts(self):
        rows=[]
        for count in (1,2):
            rows.append({'code_version':'test','diagnostic_experts':count,'case':'inventory_lock',
                'condition':'clean','verification':'none','restart':'none','branch':'initial',
                'task_success':True,'fixture_valid':True,'fault_delivery_status':'disabled',
                'direct_exposure_calls':0,'downstream_structured_errors':0,'unauthorized_attempts':0,
                'unauthorized_applied':0,'model_calls':6 if count==1 else 8})
        self.assertEqual(len(aggregate(rows)),2)
