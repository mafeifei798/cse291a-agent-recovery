from agent_l_replay_live.cpu import NativeCPU
from agent_l_feedback_replay.fixtures import SavedCPU
from agent_recovery.contracts import require


class NoFitCPU(NativeCPU):
    def __init__(self,*args,**kwargs):
        require(kwargs.get('training_authorized',False) is False,'No training capability','ACE_NO_TRAINING')
        super().__init__(*args,**kwargs)

    def fit(self,*args,**kwargs):
        require(False,'Contract changed; fresh training needs separate authorization','ACE_RETRAIN_REQUIRED')


class NoFitSavedCPU(SavedCPU):
    def fit(self,*args,**kwargs):
        require(False,'Contract changed; no simulated or real fit in this entry','ACE_RETRAIN_REQUIRED')
