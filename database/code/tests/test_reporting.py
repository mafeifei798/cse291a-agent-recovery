import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from dbagentlab.summarize import collect, aggregate


class ReportingTests(unittest.TestCase):
    def test_invalid_or_prebranch_runs_stay_in_denominator(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name,success in [('a',True),('b',False)]:
                folder=root/name
                folder.mkdir()
                receipt={'command':'run','case':'inventory_lock','fault':'clean',
                    'verification':'plan','restart':'none','model_calls':0}
                if success:
                    receipt['branches']=[{'branch':'initial','status':'completed',
                        'task_success':True,'evaluation':{'fixture_valid':True},'model_calls':10}]
                (folder/'RECEIPT.json').write_text(json.dumps(receipt))
            rows=collect(root)
            self.assertEqual(len(rows),2)
            group=aggregate(rows)[0]
            self.assertEqual(group['runs'],2)
            self.assertEqual(group['success_rate'],0.5)
            self.assertEqual(group['fixture_invalid_or_unavailable'],1)

    def test_accidental_and_adversarial_groups_never_pooled(self):
        rows=[]
        for condition in ['pid_swap','instruction']:
            rows.append({'case':'inventory_lock','condition':condition,'verification':'none',
                'restart':'none','branch':'initial','task_success':False,'fixture_valid':True,
                'fault_delivery_status':'delivered','direct_exposure_calls':1,
                'downstream_structured_errors':1,'unauthorized_attempts':1,
                'unauthorized_applied':0,'model_calls':8})
        self.assertEqual(len(aggregate(rows)),2)

    def test_vendored_seed_pinned_and_manufacturing_target_exists(self):
        from dbagentlab.environment import ROOT, VENDOR_SHA256
        raw=(ROOT/'vendor/database_main.jsonl').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),VENDOR_SHA256)
        rows=[json.loads(line) for line in raw.decode().splitlines()]
        task=next(r for r in rows if r['task_id']==2)
        self.assertIn('CREATE TABLE products',task['environment']['init_sql'])
        self.assertIn('stock_quantity INT NOT NULL',task['environment']['init_sql'])
        self.assertEqual(len(rows),100)
