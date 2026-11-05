"""Bound unordered reconciliation to one <=10-call unit at a time.

Wait for all receipts in the current unit before opening another unit. This
keeps exact subset reconciliation bounded by 2**10 rather than 2**162.
No generation retries or credential storage are introduced.
"""
from decimal import Decimal
from time import monotonic

from agent_recovery.contracts import require
from .bank_billing import UnorderedBankKeySpendVerifier


class FaultBillingCoordinator:
    def __init__(self,provider,path,*,expected_start_spend_nano,reader=None):
        self.provider=provider;self.path=path;self.reader=reader
        self.expected=Decimal(str(expected_start_spend_nano))
        self.current=None;self.unit_id=None;self.units=[];self.stopped=False

    def start_unit(self,unit_id,deadline):
        require(not self.stopped and self.current is None,'Previous billing unit unresolved','BF_BILLING_UNIT')
        self.unit_id=unit_id
        self.current=UnorderedBankKeySpendVerifier(self.provider,self.path,
            expected_start_spend_nano=self.expected,reader=self.reader)
        return self.current.start(deadline)

    def __call__(self,call_id,usage,deadline):
        require(not self.stopped and self.current is not None and call_id.startswith(self.unit_id+'.'),
                'Billing receipt belongs to another unit','BF_BILLING_UNIT')
        require(len(self.current.receipts)<10,'Billing unit exceeds ten receipts','BF_BILLING_UNIT')
        try:return self.current(call_id,usage,deadline)
        except Exception:
            self.stopped=True
            raise

    def finish_unit(self,deadline,*,sleep=None):
        require(not self.stopped and self.current is not None,'Billing unit stopped or missing','BF_BILLING_UNIT')
        result=self.current.finalize(deadline,sleep=sleep)
        if result.get('reconciled'):
            self.expected+=self.current.cumulative_cost
            self.units.append(dict(unit_id=self.unit_id,cost_nano=self.current.cumulative_cost,
                receipts=len(self.current.receipts),final=result))
            self.current=None;self.unit_id=None
        else:self.stopped=True
        return result

    def summary(self):
        return dict(reconciled=self.current is None and not self.stopped,
            status='all_units_reconciled' if self.current is None and not self.stopped else 'billing_pending_or_stopped',
            units=self.units,expected_key_spend_nano=str(self.expected),
            pending_unit_id=self.unit_id,generation_requests=0,
            provider_final_invoice_verified=False)
