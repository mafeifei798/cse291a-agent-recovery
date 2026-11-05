from agent_l_approval_confirm.runtime import ReplayLoop as SharedLoop, approved_stage
from agent_l_approval_confirm.model import Model


class ReplayLoop(SharedLoop):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.doc.update(real_entry_revision='confirm-entry-v1',cpu_fixture_only=self.cpu.fixture_only,
            llm_fixture_only=self.model.fixture_only,offline_replay_only=self.cpu.fixture_only and self.model.fixture_only)
