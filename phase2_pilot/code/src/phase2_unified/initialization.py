"""Prepare real new-task inputs and an empty CPU-artifact-mode scene.

This initializer copies pinned raw/split bytes only. It starts no worker and
does not parse labels, import an estimator, train, predict or load a model.
The 74-row fixture runner continues to use its unchanged fixture initializer.
"""
from copy import deepcopy
from pathlib import Path

from phase2_offline.bindings import bind_task_inputs
from phase2_offline.common import save
from .cpu import (EVAL_PACK_SHA256,PROTOCOL_SHA256,load_eval_binding,digest,
                  require,CPUContractError,sha)


def prepare_cpu_scene(pack,row,files):
    """Bind an exact registered initial row; returns ``scene, dag``.

    ``files`` must be fresh. Use ``DurableKernel(..., artifact_mode='cpu_artifacts')``
    with the returned scene. The caller must separately obtain authorization
    before executing the planned CPU work.
    """
    require(pack.get('freeze_sha256')==PROTOCOL_SHA256,'CPU_INITIALIZATION_PROTOCOL')
    require(pack.get('eval_pack_sha256')==EVAL_PACK_SHA256,'CPU_INITIALIZATION_EVAL_PIN')
    require(row in pack.get('rows',[]),'CPU_INITIALIZATION_REGISTERED_ROW_REQUIRED')
    require(row['kind'] in ('control','prefix','e2e','consumption_prefix'),'CPU_INITIALIZATION_FROZEN_SCENE_REQUIRED')
    dataset=row['dataset_id'];task_id=row['task_id']
    binding=load_eval_binding(task_id=task_id,dataset_id=dataset,
        expected_pack_sha256=pack['eval_pack_sha256'],pack_path=pack['eval_pack_path'],
        protocol_sha256=pack['freeze_sha256'])
    bound=bind_task_inputs(pack['eval_pack_path'],task_id=task_id,dataset_id=dataset,
        expected_pack_sha256=pack['eval_pack_sha256'],output=files)
    task=deepcopy(bound['task']);dag=deepcopy(binding.document()['dag'])
    require(dag==pack['dag'] and digest(task)==digest(pack['tasks'][task_id]),'CPU_INITIALIZATION_TASK_OR_DAG_CHANGED')
    task['nodes']=deepcopy(dag['nodes'])
    sources=deepcopy(bound['sources']);history=deepcopy(bound['task']['source_history'])
    require(all(s.get('fixture_only') is False for s in sources+history),'CPU_INITIALIZATION_REAL_SOURCE_REQUIRED')
    require(all(a.get('fixture_only') is False for a in bound['artifacts']),'CPU_INITIALIZATION_REAL_ARTIFACT_REQUIRED')
    count=binding.document()['splits']['train_v1']['row_count']
    require(next(s['payload']['row_count'] for s in sources if s['object_key']=='data:train')==count,'CPU_INITIALIZATION_ROW_COUNT')
    require(count==(20000 if dataset=='adult' else 18000),'CPU_INITIALIZATION_NEW_ROWS_REQUIRED')
    scene={'revision':dag['revision'],'fixture_only':False,'domain':'macro','workflow_id':dag['workflow_id'],
        'source_aliases':{},'prefix_mode':'phase2_empty_new_task_cpu_inputs_no_execution','task':task,
        'results':[],'artifact_manifest':deepcopy(bound['artifacts']),'current_sources':sources,
        'source_history':history,'call_evidence':[],'tool_receipts':[],'attempts':[],
        'input_producers':deepcopy(bound['input_producers']),
        'evaluation_binding':{'pack_sha256':pack['freeze_sha256'],'evaluation_pack_sha256':pack['eval_pack_sha256'],
            'task_id':task_id,'task_sha256':bound['receipt']['task_sha256'],
            'data_binding':deepcopy(task['data_binding']),'new_input_binding_sha256':sha(Path(files)/'binding_receipt.json'),
            'dataset_rows_executed':False,'fixture_only':False,'actual_training':0,'actual_model_prediction':0,
            'planned_training_row_count':count,'guard_artifact_mode_required':'cpu_artifacts'},
        'run_state':{'run_id':row['row_id']+'.cpu-inputs','scene_id':row['row_id']+'.cpu-inputs.scene',
            'task_id':task_id,'lifecycle':'running','selected_by_node':{n:None for n in dag['topological_order']},
            'active_attempt_ids':[],'unsettled_call_ids':[],'business_effects':[],
            'published_manifest':None,'published_report_index':None,'failed_candidate_result_ids':[]}}
    save(Path(files)/'cpu_initialization_receipt.json',{'schema_version':'phase2-cpu-initialization-v1','passed':True,
        'task_id':task_id,'dataset_id':dataset,'protocol_sha256':pack['freeze_sha256'],
        'evaluation_pack_sha256':pack['eval_pack_sha256'],'scene_sha256':digest(scene),
        'dag_sha256':digest(dag),'planned_training_rows':count,'materialized_input_files':len(bound['artifacts']),
        'required_artifact_mode':'cpu_artifacts','initial_results':0,'workers_started':0,
        'actual_training':0,'actual_model_prediction':0,'model_loads':0,'test_row_manifest_materialized':False})
    return scene,dag
