"""Pinned, method-equivalent offline cohort, referencing both sealed protocols."""
from copy import deepcopy
from pathlib import Path

from phase2_offline.common import digest, read, require, sha
from phase2_supplement.pack import load_pack as load_supplement

ROOT=Path(__file__).resolve().parents[2]
DEFAULT=ROOT/'phase2/unified_r1/frozen'
SUPPLEMENT_SHA='49252f39457d0bf5e7588fe450caca2aee91f215cacf8d83609adfd3b584ef28'


def load_pack(path=None):
    original=load_supplement()
    require(original['freeze_sha256']==SUPPLEMENT_SHA,'SEALED_SUPPLEMENT_CHANGED')
    base=Path(path or DEFAULT)
    require(not base.is_symlink(),'UNIFIED_PACK_SYMLINK')
    base=base.resolve();freeze=read(base/'FREEZE.json')
    require(freeze['revision']=='phase2-unified-r1','UNIFIED_REVISION')
    require(freeze['digest']==digest({k:v for k,v in freeze.items() if k!='digest'}),'UNIFIED_FREEZE_DIGEST')
    files={'registration.json','rules.json','budget.json','references.json'}
    require({x['path'] for x in freeze['files']}==files,'UNIFIED_FROZEN_FILE_SET')
    for item in freeze['files']:
        p=base/item['path']
        require(p.is_file() and not p.is_symlink() and p.stat().st_size==item['size_bytes'] and sha(p)==item['sha256'],'UNIFIED_FROZEN_BYTES_CHANGED')
    require({str(p.relative_to(base)) for p in base.rglob('*') if p.is_file()}==files|{'FREEZE.json'},'UNREGISTERED_UNIFIED_FILE')
    expected=[]
    for old in original['rows']:
        row=deepcopy(old);row['reference_row_id']=old['row_id']
        row['row_id']=old['row_id'].replace('p2supp-','p2unified-',1)
        if row['prefix_row_id']:row['prefix_row_id']=row['prefix_row_id'].replace('p2supp-','p2unified-',1)
        expected.append(row)
    rows=read(base/'registration.json')['rows']
    require(rows==expected and len(rows)==74,'UNIFIED_EXACT_REFERENCE_MATRIX')
    rules=read(base/'rules.json');budget=read(base/'budget.json');refs=read(base/'references.json')
    require(refs['supplement_sha256']==SUPPLEMENT_SHA and refs['eval_pack_sha256']==original['old_eval_pack_sha256'],'UNIFIED_REFERENCE_BINDING')
    require(refs['old_72_registry_sha256']==sha(ROOT/'phase2/p0/frozen/registration.json') and refs['old_74_registry_sha256']==sha(ROOT/'phase2/supplement_r1/frozen/registration.json'),'SEALED_REGISTRY_CHANGED')
    require(rules['durability']=={'authoritative_sqlite_from_first_node':True,'single_kernel_for_all_methods':True,'raw_before_selection':True,'dispatch_intent_before_client':True,'budget_settlement_before_acceptance':True,'publication_atomic_group':True,'unknown_never_automatically_reissued':True},'UNIFIED_DURABILITY_CONTRACT')
    require(all(rules[k]==original['rules'][k] for k in original['rules']),'WORKFLOW_OR_EXPERIMENT_RULE_CHANGED')
    require(budget['campaign_call_cap']==sum(r['call_cap'] for r in rows)==1180 and budget['project_cap_nano']==5_000_000_000,'UNIFIED_LIMITS')
    require(all(budget[k]==original['budget'][k] for k in original['budget']),'UNIFIED_BUDGET_NOT_RAISED')
    require(budget['additional_live_allocation'] is False and budget['allocation_id']=='phase2-supplement-future-evaluation','UNIFIED_NOT_ADDITIONAL_SPEND')
    require(all(budget[k] is False for k in ('real_api_authorized','training_authorized','prediction_authorized','cloud_authorized')),'UNIFIED_OFFLINE_ONLY')
    value=deepcopy(original)
    value.update(path=str(base),revision='phase2-unified-r1',freeze_sha256=sha(base/'FREEZE.json'),
        rows=rows,registration=read(base/'registration.json'),rules=rules,budget=budget,references=refs,
        supplement_rules=rules,sealed_supplement_sha256=SUPPLEMENT_SHA,
        eval_pack_path=str(ROOT/'phase2/p0/frozen'),eval_pack_sha256=original['old_eval_pack_sha256'])
    return value
