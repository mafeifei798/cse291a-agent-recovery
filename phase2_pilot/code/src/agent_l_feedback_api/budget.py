from agent_l_batch.budget import Budget as PriorBudget
from .protocol import Config, HISTORY_SHA, REGISTRATION_SHA, UNITS


class Budget(PriorBudget):
    config_type = Config
    history_pin = HISTORY_SHA
    registration_pin = REGISTRATION_SHA
    unit_caps = UNITS
    new_call_cap = 52
    campaign_name = 'l-feedback-api-v1'

    def snapshot(self):
        s = super().snapshot()
        s['L_budget'].update(first_total_generation_cap=64,
                             first_generations_used=12+len(s['calls']),
                             new_generation_cap=52)
        return s
