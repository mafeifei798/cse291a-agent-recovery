import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import urllib.error
from unittest.mock import patch
from dbagentlab.core import Budget, BudgetExceeded, Ledger
from dbagentlab.gateway import Gateway


class Reply:
    def __init__(self, body):
        self.body = json.dumps(body).encode()
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def read(self, *args):
        return self.body


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.ledger = Ledger(Path(self.temp.name)/'run')
        self.budget = Budget(2,900)
        with patch.dict(os.environ,{'OPENAI_API_KEY':'SECRET_VALUE_FOR_TEST',
            'OPENAI_BASE_URL':'https://tritonai-api.ucsd.edu/v1'}):
            self.gateway = Gateway(self.ledger,self.budget)

    def test_check_does_not_send_inference_or_reserve_calls(self):
        with patch.object(self.gateway.opener,'open',return_value=Reply({
                'data':[{'id':'api-glm-5.3-flash'}]})) as opened:
            self.assertTrue(self.gateway.check())
        self.assertEqual(self.budget.calls,0)
        self.assertTrue(opened.call_args.args[0].full_url.endswith('/models'))

    def test_http_error_not_retried_and_secret_redacted(self):
        error = urllib.error.HTTPError('url',429,'limited',{},io.BytesIO(b'SECRET_VALUE_FOR_TEST'))
        with patch.object(self.gateway.opener,'open',side_effect=error) as opened:
            with self.assertRaises(RuntimeError):
                self.gateway.complete('planner',[],[],'initial')
        self.assertEqual(opened.call_count,1)
        self.assertIsNone(self.gateway.calls[0]['usage'])
        for path in self.ledger.folder.rglob('*.json'):
            self.assertNotIn('SECRET_VALUE_FOR_TEST',path.read_text())

    def test_truncation_preserves_known_usage_and_raw_response(self):
        body = {'choices':[{'finish_reason':'length','message':{'content':'{incomplete'}}],
                'usage':{'prompt_tokens':40,'completion_tokens':60,'total_tokens':100}}
        with patch.object(self.gateway.opener,'open',return_value=Reply(body)):
            with self.assertRaises(RuntimeError):
                self.gateway.complete('planner',[],[],'initial')
        self.assertEqual(self.gateway.calls[0]['usage']['total_tokens'],100)
        self.assertTrue((self.ledger.folder/'calls/call_001.response.json').exists())

    def test_call_budget_stops_before_dispatch(self):
        self.budget.calls=2
        with patch.object(self.gateway.opener,'open') as opened:
            with self.assertRaises(BudgetExceeded):
                self.gateway.complete('planner',[],[],'restart')
        opened.assert_not_called()

    def test_transport_timeout_keeps_unknown_outcome(self):
        with patch.object(self.gateway.opener,'open',side_effect=TimeoutError('test timeout')) as opened:
            with self.assertRaises(TimeoutError):
                self.gateway.complete('planner',[],[],'initial')
        self.assertEqual(opened.call_count,1)
        self.assertEqual(self.gateway.calls[0]['status'],'unknown_outcome')
        self.assertIsNone(self.gateway.calls[0]['usage'])
