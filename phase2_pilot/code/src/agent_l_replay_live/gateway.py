"""Preserve full settled usage on duplicate notifications; never resend."""
from copy import deepcopy
from agent_l_api.gateway import Gateway as PriorGateway


class Gateway(PriorGateway):
    def call(self, *args, **kwargs):
        result = super().call(*args, **kwargs)
        if result.get('replayed') and 'usage' not in result:
            record = next(c for c in self.ledger.calls() if c['call_id'] == kwargs['call_id'])
            result = {**result, 'usage': deepcopy(record['usage']), 'call_id': record['call_id']}
        return result
