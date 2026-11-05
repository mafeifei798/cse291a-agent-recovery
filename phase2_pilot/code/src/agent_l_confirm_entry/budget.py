from agent_l_approval_confirm.budget import Budget as ConfirmationBudget
from .protocol import Config, REGISTRATION_SHA, HISTORY_SHA, UNIT


class Budget(ConfirmationBudget):
    config_type = Config
    registration_pin = REGISTRATION_SHA
    history_pin = HISTORY_SHA
    campaign_name = 'confirm-entry-v1'

    def __init__(self,*args,config,**kwargs):
        super().__init__(*args,config=config,**kwargs)
        self.unit_caps = {UNIT:config.new_generation_cap}

    def snapshot(self):
        result = super().snapshot()
        result['L_budget']['simulated_increment_only'] = self.launch_config.simulated
        result['real_calls_and_spend_unchanged'] = self.launch_config.simulated
        return result
