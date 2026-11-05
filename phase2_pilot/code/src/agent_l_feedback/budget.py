from agent_l_batch.budget import Budget as PriorBudget
from .protocol import Config, HISTORY_SHA, REGISTRATION_SHA, UNITS


class Budget(PriorBudget):
    config_type = Config
    history_pin = HISTORY_SHA
    registration_pin = REGISTRATION_SHA
    unit_caps = UNITS
    new_call_cap = 10
    campaign_name = 'l-feedback-offline-v1'
