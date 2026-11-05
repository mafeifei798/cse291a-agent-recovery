from agent_l_approval_confirm.runtime import ReplayLoop as SharedLoop,approved_stage
from agent_l_approval_confirm.model import Model


class ReplayLoop(SharedLoop):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.doc['real_entry_revision']='l-compare-offline-v1'
