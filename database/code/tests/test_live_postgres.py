"""Opt-in integration test; never makes model calls. Uses new isolated databases."""
import os
from pathlib import Path
import tempfile
import unittest
from dbagentlab.core import Budget, Ledger
from dbagentlab.environment import LiveDatabase
from dbagentlab.graphs import root_blockers


@unittest.skipUnless(os.environ.get('DBAGENTLAB_TEST_STAGE1'),
                     'Set DBAGENTLAB_TEST_STAGE1 to enable real PostgreSQL integration')
class LivePostgresTests(unittest.TestCase):
    def test_four_real_fixtures_and_operation_status(self):
        for case in ('inventory_lock','inventory_chain','inventory_handoff','manufacturing_lock'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                ledger=Ledger(Path(temporary)/'run')
                env=LiveDatabase(os.environ['DBAGENTLAB_TEST_STAGE1'],ledger,Budget(1,90),case)
                try:
                    env.prepare()
                    if case=='inventory_handoff':
                        old=env.holder
                        env.rotate_blocker()
                        self.assertNotEqual(env.holder,old)
                    self.assertEqual(root_blockers(env.activity(),env.waiter),{env.holder})
                    operation=env.action('rollback_session',env.holder)
                    self.assertEqual(operation['status'],'applied')
                    self.assertEqual(env.check_operation(operation['operation_id'])['recorded_status'],'applied')
                    self.assertTrue(env.evaluate()['task_success'])
                finally:
                    cleanup=env.cleanup()
                self.assertTrue(cleanup['verified'])
