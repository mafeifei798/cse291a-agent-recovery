"""Same strict CPU and independent numerical checker for all three methods."""
from copy import deepcopy
from pathlib import Path
import json

from agent_l_replay_live.cpu import NativeCPU as PreviousCPU
from agent_l_v1.cpu import ActualCPU
from agent_l_feedback_replay.runtime import approved_stage
from agent_recovery.contracts import require


def models_in(frozen):
    return [approved_stage(frozen)['initial_screen']['payload'],
            frozen['active']['screen']['payload'],frozen['active']['final']['payload']]


def verify_native_origin(campaign, frozen):
    """Hashes/bindings only, before credentials or model deserialization."""
    root = Path(json.loads((Path(campaign)/'ORIGIN.json').read_text())['campaign_root']).resolve()
    require(root.is_dir(),'Original producer directory required','CMPE_NATIVE_ORIGIN')
    v = object.__new__(ActualCPU);v.root=root
    ref = frozen['store_snapshot']['files']['inputs/data.json']
    data = json.loads((Path(campaign)/'runs/LI01.PREFIX/artifacts/sha256'/ref['sha256']).read_text())
    for m in models_in(frozen):ActualCPU.validate(v,m,m['contract'],m['kind'],data)
    return root


class NativeCPU(PreviousCPU):
    def __init__(self,*args,**kwargs):
        # Equal capability for every method; current offline runs never construct this.
        require(kwargs.get('authorized') is True and kwargs.get('training_authorized') is True,
            'Separate real training authorization required','CMPE_CPU_PERMISSION')
        super().__init__(*args,**kwargs)
        self.admission_evidence=[]

    def fit(self,contract,kind,data,deadline):
        value=super().fit(contract,kind,data,deadline)
        # ActualCPU checks exact executed columns and invokes the no-fit checker.
        require(value['contract']==contract and not value['fixture_only'],'Strict native result required','CMPE_CPU_RESULT')
        return value

    def admit(self,model,desired,kind,data,deadline):
        train=self.validate(model,desired,kind,data)
        rel=self._check(train,deadline)
        self.admissions+=1
        origin=Path(model.get('producer_campaign_root',self.saved_campaign)).resolve()
        self.admission_evidence.append({'producer_id':model['producer_id'],'kind':kind,
            'record_rel':model['record_rel'],'producer_record_sha256':model['producer_record_sha256'],
            'contract':deepcopy(desired),'producer_campaign_root':str(origin),
            'admission_numeric_record_rel':rel,'artifact_hashes_checked':True,'fits':0})
        return {**deepcopy(model),'producer_campaign_root':str(origin),'admission_numeric_record_rel':rel}
