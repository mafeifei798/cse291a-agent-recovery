from agent_l_feedback_replay.runtime import ReplayLoop as PriorLoop, approved_stage, Model


class ReplayLoop(PriorLoop):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.doc.update(cpu_fixture_only=self.cpu.fixture_only, llm_fixture_only=self.model.fixture_only,
                        offline_replay_only=self.cpu.fixture_only and self.model.fixture_only,
                        real_entry_revision='stage-replay-entry-v1')
