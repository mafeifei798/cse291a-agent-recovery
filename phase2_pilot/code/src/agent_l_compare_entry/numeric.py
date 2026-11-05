"""Offline metric recomputation: saved arrays only, no load/fit/predict calls."""
import csv
import json
from pathlib import Path

from agent_l_feedback_replay.fixtures import SavedCPU
from context_cutoff.numeric_checker import binary_metrics
from agent_recovery.contracts import require
from .cpu import models_in


def verify_arrays(source,campaign,frozen):
    import numpy as np
    guard=SavedCPU(campaign,source)
    ref=frozen['store_snapshot']['files']['inputs/data.json']
    data=json.loads((Path(campaign)/'runs/LI01.PREFIX/artifacts/sha256'/ref['sha256']).read_text())
    with guard.mapped(data['raw']['path']).open(newline='') as f:
        all_labels=[int(row['y']=='yes') for row in csv.DictReader(f,delimiter=';')]
    rows=[]
    for model in models_in(frozen):
        guard.validate(model,model['contract'],model['kind'],data)
        record=json.loads((Path(campaign)/model['record_rel']).read_text())
        folder=guard.mapped(record['spec']['output_dir']);split_results={}
        for split in ('train','validation'):
            ids=json.loads((folder/(split+'_row_ids.json')).read_text())
            split_doc=json.loads(guard.mapped(data[model['kind']+'_'+split]['path']).read_text())
            require(ids==split_doc['row_ids'],'Saved row ordering changed','CMPE_ARRAY_ROWS')
            labels=np.load(folder/(split+'_labels.npy'),allow_pickle=False)
            probs=np.load(folder/(split+'_probabilities.npy'),allow_pickle=False)
            predictions=np.load(folder/(split+'_predictions.npy'),allow_pickle=False)
            expected=np.array([all_labels[int(r.rsplit(':',1)[-1])-1] for r in ids],dtype=np.int8)
            require(labels.dtype==np.int8 and probs.dtype==np.float64 and predictions.dtype==np.int8
                and labels.shape==probs.shape==predictions.shape==expected.shape
                and np.array_equal(labels,expected) and np.array_equal(predictions,(probs>=.5).astype(np.int8)),
                'Labels/probability/prediction arrays disagree','CMPE_ARRAYS')
            metrics=binary_metrics(labels.tolist(),probs.tolist())
            saved=record['response']['metrics'][split]
            require(set(saved)==set(metrics) and all(abs(saved[k]-metrics[k])<=1e-10 for k in metrics),
                'Independent arithmetic disagrees','CMPE_ARRAY_METRICS')
            split_results[split]={'rows':len(ids),'metrics':metrics,'labels_match_raw':True}
        rows.append({'producer_id':model['producer_id'],'contract':model['contract'],'splits':split_results})
    return {'passed':True,'models':rows,'model_loads':0,'model_fits':0,'model_predictions':0,
        'saved_arrays_only':True,'pipeline_prediction_verified':False,
        'scope':'Saved-array arithmetic and raw-label check; does not prove the model regenerates those arrays'}
