"""Reuse strict native tools; old producers keep their own immutable root."""
from copy import deepcopy
from pathlib import Path
import json

from agent_l_v1.cpu import ActualCPU
from agent_l_v3.cpu import TimedCPU
from agent_recovery.contracts import require


class NativeCPU(TimedCPU):
    def __init__(self, directory, saved_campaign, *, training_authorized=False, authorized=False):
        super().__init__(directory, authorized=authorized, fit_limit=3)
        self.training_authorized = training_authorized
        self.saved_campaign = Path(saved_campaign).resolve()
        # This adapter writes nothing in the old producer root.
        self.old_validator = object.__new__(ActualCPU)
        self.old_validator.root = self.saved_campaign

    def fit(self, *args, **kwargs):
        require(self.training_authorized is True, 'This run forbids training', 'FRL_TRAINING_DISABLED')
        value = super().fit(*args, **kwargs)
        return {**value, 'producer_campaign_root': str(self.root)}

    def validate(self, model, desired, kind, data):
        origin = Path(model.get('producer_campaign_root', self.saved_campaign)).resolve()
        if origin == self.root:
            return super().validate(model, desired, kind, data)
        require(origin == self.saved_campaign, 'Unrecognized producer root', 'FRL_PRODUCER_ROOT')
        return ActualCPU.validate(self.old_validator, model, desired, kind, data)

    def admit(self, model, desired, kind, data, deadline):
        train = self.validate(model, desired, kind, data)
        check_rel = self._check(train, deadline)
        self.admissions += 1
        return {**deepcopy(model), 'producer_campaign_root': str(self.saved_campaign),
                'admission_numeric_record_rel': check_rel}
