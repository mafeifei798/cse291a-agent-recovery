from agent_l_feedback_replay.budget import Budget as ReplayBudget
from .protocol import Config, REGISTRATION_SHA, HISTORY_SHA


class Budget(ReplayBudget):
    config_type = Config
    registration_pin = REGISTRATION_SHA
    history_pin = HISTORY_SHA
    campaign_name = 'stage-replay-entry-v1'

    def __init__(self, *args, config, **kwargs):
        self.unit_caps = {'FR02.'+config.method: config.new_generation_cap}
        self.new_call_cap = config.new_generation_cap
        super().__init__(*args, config=config, **kwargs)

    def snapshot(self):
        s = super().snapshot()
        s['L_budget']['simulated_increment_only'] = self.launch_config.simulated
        s['real_calls_and_spend_unchanged'] = self.launch_config.simulated
        return s
