"""Actual elapsed-time implementation of the frozen controlled-tool deadline.

This clock is for the synthetic tool event only. HTTP deadlines and uncertain
provider consumption are owned by the P3 transport/campaign.
"""
from time import monotonic, sleep
from .contracts import require
from .p1_delivery import P1DeliveryHooks


class MonotonicToolClock:
    evidence_kind = "actual_monotonic_controlled_tool_clock"

    def __init__(self):
        self.origin = monotonic()
        self.waits = []

    @property
    def seconds(self):
        return monotonic() - self.origin

    def advance_to(self, target):
        before = self.seconds
        require(target >= 0, "Invalid monotonic target", "INVALID_TRIGGER")
        while self.seconds < target:
            sleep(max(0, target - self.seconds))
        after = self.seconds
        self.waits.append({"target_s": target, "started_s": before, "finished_s": after,
                           "actual_wait_s": after - before})
        return after


class P3DeliveryHooks(P1DeliveryHooks):
    def __init__(self, *args, clock=None, **kwargs):
        super().__init__(*args, clock=clock or MonotonicToolClock(), **kwargs)
