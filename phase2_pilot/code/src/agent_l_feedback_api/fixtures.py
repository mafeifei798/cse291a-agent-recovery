"""Force a normal feedback round in the new clean fixture, never in live work."""
from agent_l_feedback.fixtures import ScenarioCPU, Service


class CampaignCPU(ScenarioCPU):
    def __init__(self):
        super().__init__('adjust_accept')


class CampaignService(Service):
    def __init__(self, local, *, prefix_adjustment=False, mode='adjust_accept'):
        super().__init__(local, mode)
        self.prefix_adjustment = prefix_adjustment

    def post(self, request):
        self.initial = {'bundle': 'D1', 'recipe': 'RF' if self.unit == 'LC04' or
                        self.unit == 'LI01.PREFIX' and self.prefix_adjustment else 'LR'}
        return super().post(request)
