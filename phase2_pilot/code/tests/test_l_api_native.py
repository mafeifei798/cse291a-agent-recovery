"""Real spawn/reap with finite offline HTTP recipes, shortened test deadlines."""
import time
import unittest
from agent_recovery.p3_deadline import BoundedHTTPSender,WireRecipe
from agent_recovery.p3_transport import HTTPRequest,fixture_binding,fake_http_response


class NativeHTTPDeadlineTests(unittest.TestCase):
    def check_recipe(self,kind):
        sender=BoundedHTTPSender(recipes=[WireRecipe(kind,response=fake_http_response({'final':{'x':1}}),delay_s=2 if kind!='dns_hang' else 0)],
            terminate_grace_s=.1,cleanup_timeout_s=.6)
        binding=fixture_binding();end=time.monotonic()+.35
        request=HTTPRequest('POST',binding.endpoint+'/chat/completions',b'{}',.35)
        with self.assertRaises(Exception) as caught:sender.send(request,binding=binding,deadline_monotonic=end,intent_committed=True)
        receipt=sender.cleanup_receipts[-1]
        self.assertEqual(getattr(caught.exception,'code',None),'P3_HTTP_TIMEOUT',receipt)
        self.assertTrue(receipt['worker_started'],receipt);self.assertTrue(receipt['timed_out'],receipt)
        self.assertTrue(receipt['reaped']);self.assertFalse(receipt['cleanup_failed'])
        self.assertEqual(sender.real_request_count,0)

    def test_DNS_hang_reaped(self):self.check_recipe('dns_hang')
    def test_slow_body_reaped(self):self.check_recipe('slow_body')
    def test_TERM_resistant_reaped(self):self.check_recipe('ignore_term')
    def test_late_success_not_accepted(self):self.check_recipe('late_success')


if __name__=='__main__':unittest.main()
