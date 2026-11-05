"""Independent version-aware numerical-check entry; inert until explicitly run.

Binding checks and small fixture arithmetic use Python's standard library.
Saved-model checking is a separately authorized future path. It reuses the
existing independent checker's numerical assertions, not production answers.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime,timezone
import csv
import hashlib
import json
import math
from pathlib import Path
import time

PIN='401830a27619259a184aaf9c488587eddd565e6d7f95b93122b0a1afab68a5a1'
LEGACY_PIN='643acd951eb135d484e4b32ff63de4e670d66a7f50a7da5f304505a6f471f6b2'
PROTOCOL_PIN='3d66f337dde6cd6aebda205584c4c7b8cade8d06f614f105056e496f49b4ef2a'
ROOT=Path(__file__).resolve().parents[2]
CHECK_LIMITS={'cpu_threads':1,'address_space_bytes':8*1024**3,'rss_monitor_bytes':8*1024**3,
    'max_artifact_bytes':128*1024**2,'total_disk_bytes':4*1024**3,'wall_seconds':120,
    'network_enabled':False,'gpu_enabled':False}


class NumericContractError(ValueError):
    pass


def _need(condition,code):
    if not condition: raise NumericContractError(code)


def _canonical(v):
    return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()


def _digest(v):
    return hashlib.sha256(_canonical(v)).hexdigest()


def _read(path):
    return json.loads(Path(path).read_text())


def _file(root,relative,entry):
    rel=Path(relative);_need(not rel.is_absolute() and '..' not in rel.parts,'NUMERIC_PATH_ESCAPE')
    path=root/rel
    _need(path.resolve().is_relative_to(root.resolve()) and not any(p.is_symlink() for p in [path,*path.parents] if p==root or root in p.parents),'NUMERIC_SYMLINK_OR_ESCAPE')
    raw=path.read_bytes()
    _need(len(raw)==entry.get('bytes',entry.get('size_bytes')) and hashlib.sha256(raw).hexdigest()==entry['sha256'],'NUMERIC_FILE_PIN')
    return raw


def validate_checker_spec(spec):
    """Independently derive expected rows/task from pinned bytes, not CPU binding."""
    _need(spec.get('schema_version')=='phase2-independent-numeric-v1','NUMERIC_SCHEMA')
    _need(spec.get('spec_sha256')==_digest({k:v for k,v in spec.items() if k!='spec_sha256'}),'NUMERIC_SPEC_SHA')
    _need(spec.get('protocol_sha256')==PROTOCOL_PIN and hashlib.sha256((ROOT/'phase2/unified_r1/frozen/FREEZE.json').read_bytes()).hexdigest()==PROTOCOL_PIN,'NUMERIC_PROTOCOL_PIN')
    _need(spec.get('limits')==CHECK_LIMITS,'NUMERIC_RESOURCE_LIMITS')
    if spec.get('deadline_utc') is None:
        _need(spec.get('binding_only') is True,'NUMERIC_FIXED_DEADLINE_REQUIRED')
    else:
        deadline=datetime.fromisoformat(spec['deadline_utc'].replace('Z','+00:00'))
        _need(deadline.tzinfo is not None and spec.get('binding_only') is False,'NUMERIC_DEADLINE_TIMEZONE')
    base=Path(spec['evaluation_pack_root']).resolve()
    freeze_raw=(base/'FREEZE.json').read_bytes()
    _need(spec['evaluation_pack_sha256']==PIN and hashlib.sha256(freeze_raw).hexdigest()==PIN,'NUMERIC_EVALUATION_PIN')
    frozen={e['path']:e for e in json.loads(freeze_raw)['files']}
    taskdoc=json.loads(_file(base,'tasks/macro_tasks.json',frozen['tasks/macro_tasks.json']))
    found=[t for t in taskdoc['tasks'] if t['task_id']==spec['task_id']]
    _need(len(found)==1,'NUMERIC_EXACT_TASK')
    task=found[0];dataset=spec['dataset_id'];version=spec['train_version']
    _need(dataset in ('adult','bank') and task['task_id']==f'phase2-{dataset}-eval-01'
        and task['public_request']['dataset_id']==dataset,'NUMERIC_TASK_DATASET')
    _need(version in (1,2),'NUMERIC_TRAIN_VERSION')
    manifest_raw=_file(base,'data/manifest.json',frozen['data/manifest.json'])
    _need(hashlib.sha256(manifest_raw).hexdigest()==task['data_binding']['manifest_sha256']==spec['data_manifest_sha256'],'NUMERIC_MANIFEST_PIN')
    manifest={e['path']:e for e in json.loads(manifest_raw)['files']}
    splits={}
    for name in ('train_v1','train_v2','validation','test'):
        relative=f'splits/{dataset}/{name}.json'
        splits[name]=json.loads(_file(base/'data',relative,manifest[relative]))
        split=splits[name]
        _need(split['row_count']==len(split['row_ids'])==len(set(split['row_ids'])) and _digest(split['row_ids'])==split['row_ids_digest'],'NUMERIC_SPLIT_DIGEST')
    train=splits[f'train_v{version}'];validation=splits['validation']
    _need(train['row_ids_digest']==task['data_binding'][f'train_v{version}_row_digest']==spec['train_row_ids_digest'],'NUMERIC_TRAIN_ROW_BINDING')
    _need(validation['row_ids_digest']==spec['validation_row_ids_digest'],'NUMERIC_VALIDATION_ROW_BINDING')
    _need(not(set(train['row_ids']) & set(validation['row_ids'])) and not(set(train['row_ids']) & set(splits['test']['row_ids']))
        and not(set(validation['row_ids']) & set(splits['test']['row_ids'])),'NUMERIC_SPLIT_LEAKAGE')
    schema=json.loads(_file(base/'data','schema_and_preprocessing.json',manifest['schema_and_preprocessing.json']))['datasets'][dataset]
    raw_name=f'raw/{dataset}/'+('adult.data' if dataset=='adult' else 'bank-additional-full.csv')
    _file(base/'data',raw_name,manifest[raw_name])
    source_path=f'tasks/authority/macro-{dataset}-01.sources.json'
    authorities=json.loads(_file(base,source_path,frozen[source_path]))['sources']
    selected=spec.get('selected_result_ids',{})
    _need(len(selected.values())==len(set(selected.values())),'NUMERIC_SELECTED_IDS_UNIQUE')
    _need(spec.get('private_test_access')=='checker_only' and spec.get('agent_test_labels_available') is False,'NUMERIC_TEST_ACCESS')
    _need(spec.get('legacy_test_sources')=={'root':str(ROOT/'sr_v2/v0'),'freeze_sha256':LEGACY_PIN},'NUMERIC_PRIVATE_TEST_SOURCE')
    _need(spec.get('inputs',{}).get('dataset_id')==dataset and spec['inputs'].get('train_version')==version,'NUMERIC_INPUT_BINDING')
    _need(spec.get('job_id')=='numeric.'+_digest(selected)[:20]
        and spec.get('output_dir')==str(Path(spec['artifact_root']).resolve()/'numeric-check-job'),'NUMERIC_JOB_BINDING')
    _need(spec.get('selected_payloads_sha256')==_digest(spec['inputs'].get('selected_payloads')),'NUMERIC_SELECTED_PAYLOAD_SHA')
    _need(selected==spec['inputs'].get('selected_result_ids'),'NUMERIC_SELECTED_IDS_MIRROR')
    return {'base':base,'task':task,'dataset_id':dataset,'train_version':version,'train':train,'validation':validation,
        'splits':splits,'schema':schema,'manifest':manifest,'authorities':authorities,'frozen':frozen}


def build_checker_spec(binding, *, selected_payloads, selected_result_ids, artifacts, artifact_root,
                       train_version=1, evaluate_test=False, expected_parameters=None,deadline=None):
    b=binding.document()
    spec={'schema_version':'phase2-independent-numeric-v1','tool':'independent_check',
        'task_id':b['task_id'],'dataset_id':b['dataset_id'],'evaluation_pack_root':b['pack_root'],
        'evaluation_pack_sha256':b['evaluation_pack_sha256'],'protocol_sha256':b['protocol_sha256'],
        'data_manifest_sha256':b['data_manifest_sha256'],'train_version':train_version,
        'train_row_ids_digest':b['splits'][f'train_v{train_version}']['row_ids_digest'],
        'validation_row_ids_digest':b['splits']['validation']['row_ids_digest'],
        'selected_result_ids':deepcopy(selected_result_ids),'selected_payloads_sha256':_digest(selected_payloads),
        'artifact_root':str(Path(artifact_root).resolve()),'artifacts':deepcopy(artifacts),
        'job_id':'numeric.'+_digest(selected_result_ids)[:20],
        'output_dir':str(Path(artifact_root).resolve()/'numeric-check-job'),
        'deadline_utc':deadline.isoformat() if isinstance(deadline,datetime) else deadline,
        'binding_only':deadline is None,'limits':deepcopy(CHECK_LIMITS),
        'private_test_access':'checker_only','agent_test_labels_available':False,
        'legacy_test_sources':{'root':str(ROOT/'sr_v2/v0'),'freeze_sha256':LEGACY_PIN},
        'inputs':{'dataset_id':b['dataset_id'],'train_version':train_version,'selected_payloads':deepcopy(selected_payloads),
            'selected_result_ids':deepcopy(selected_result_ids),'evaluate_test':bool(evaluate_test),
            'expected_parameters':deepcopy(expected_parameters or {})}}
    spec['spec_sha256']=_digest(spec);validate_checker_spec(spec)
    return spec


def fixture_metrics(labels,probabilities):
    """Independent tied-score arithmetic; no numpy/model/predict invocation."""
    _need(isinstance(labels,list) and isinstance(probabilities,list) and len(labels)==len(probabilities)>0,'NUMERIC_ARRAY_SHAPE')
    _need(all(type(y) is int and y in (0,1) for y in labels),'NUMERIC_BINARY_LABELS')
    _need(all(type(p) in (int,float) and math.isfinite(p) and 0<=p<=1 for p in probabilities),'NUMERIC_PROBABILITIES')
    positives=sum(labels); negatives=len(labels)-positives
    _need(positives>0 and negatives>0,'NUMERIC_TWO_CLASSES_REQUIRED')
    scores=sorted(set(probabilities),reverse=True);tp=seen=0;ap=0.
    for score in scores:
        group=[y for y,p in zip(labels,probabilities) if p==score];delta=sum(group)
        tp+=delta;seen+=len(group);ap+=delta/positives*tp/seen
    auc=sum(1 if pos>neg else .5 if pos==neg else 0 for pos,y in zip(probabilities,labels) if y
        for neg,z in zip(probabilities,labels) if not z)/(positives*negatives)
    hard=[int(p>=.5) for p in probabilities]
    tp=sum(y==1 and p==1 for y,p in zip(labels,hard));fp=sum(y==0 and p==1 for y,p in zip(labels,hard));fn=sum(y==1 and p==0 for y,p in zip(labels,hard))
    return {'average_precision':ap,'roc_auc':auc,'f1':2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0.,
        'accuracy':sum(y==p for y,p in zip(labels,hard))/len(labels)}


def check_fixture_arrays(spec, *, labels, probabilities, reported_metrics):
    validated=validate_checker_spec(spec);metrics=fixture_metrics(labels,probabilities)
    _need(set(reported_metrics)==set(metrics),'NUMERIC_METRIC_KEYS')
    _need(all(type(reported_metrics[k]) in (int,float) and math.isfinite(reported_metrics[k]) and abs(reported_metrics[k]-v)<=1e-8 for k,v in metrics.items()),'NUMERIC_RECOMPUTED_METRICS')
    return {'passed':True,'fixture_only':True,'evidence':'small synthetic arrays; not Adult/Bank predictions',
        'task_id':spec['task_id'],'evaluation_pack_sha256':PIN,'train_rows_bound':validated['train']['row_count'],
        'validation_rows_bound':validated['validation']['row_count'],'array_rows':len(labels),'metrics':metrics,
        'model_fits':0,'model_loads':0,'model_predictions':0,'real_api_calls':0}


def _read_rows(v0,dataset,schema,required_ids,manifest,audit):
    """Independent raw parser; no production _locked_data and no old task lookup."""
    import numpy as np
    import pandas as pd
    needed={rid.split(':')[1] for rid in required_ids}
    values={};columns=schema['raw_column_order']
    sources={e['sha256']:(v0/'data'/relative,relative,e) for relative,e in manifest.items() if relative.startswith('raw/')}
    if not needed<=sources.keys():
        legacy=ROOT/'sr_v2/v0';freeze_raw=(legacy/'FREEZE.json').read_bytes()
        audit.require(hashlib.sha256(freeze_raw).hexdigest()==LEGACY_PIN,'CHECKER_PRIVATE_LEGACY_FREEZE')
        frozen={e['path']:e for e in json.loads(freeze_raw)['files']}
        legacy_raw=(legacy/'data/manifest.json').read_bytes()
        audit.require(hashlib.sha256(legacy_raw).hexdigest()==frozen['sr_v2/v0/data/manifest.json']['sha256'],'CHECKER_PRIVATE_LEGACY_MANIFEST')
        for e in json.loads(legacy_raw)['files']:
            if e['path'].startswith('raw/') and e['sha256'] in needed and e['sha256'] not in sources:
                sources[e['sha256']]=(legacy/'data'/e['path'],e['path'],e)
    wanted=set(required_ids)
    for raw_sha in needed:
        audit.require(raw_sha in sources,'NUMERIC_RAW_SOURCE_NOT_PINNED')
        path,relative,entry=sources[raw_sha];raw=path.read_bytes()
        audit.require(hashlib.sha256(raw).hexdigest()==raw_sha and len(raw)==entry['bytes'],'NUMERIC_RAW_SOURCE_BYTES')
        if dataset=='bank':
            rows=csv.reader(raw.decode().splitlines(),delimiter=';')
            audit.require(next(rows)==columns,'NUMERIC_RAW_COLUMNS')
        else:
            rows=csv.reader(line for line in raw.decode().splitlines() if line.strip() and not line.lstrip().startswith('|'))
        for at,row in enumerate(rows,1):
            rid=f'sha256:{raw_sha}:row:{at}'
            if rid not in wanted:continue
            row=[v.strip() for v in row]
            if dataset=='adult' and relative.endswith('adult.test'):row[-1]=row[-1].rstrip('.')
            audit.require(len(row)==len(columns),'NUMERIC_RAW_ROW_WIDTH',rid)
            audit.require(row[-1] in ({'>50K','<=50K'} if dataset=='adult' else {'yes','no'}),'NUMERIC_RAW_LABEL',rid)
            values[rid]=row
    audit.require(set(values)==wanted,'NUMERIC_ALL_LOCKED_ROWS')
    frame=pd.DataFrame([values[r] for r in required_ids],columns=columns)
    labels=(frame[schema['label_column']]==schema['positive_label']).to_numpy(dtype=np.int8)
    frame=frame[schema['input_column_order']].copy()
    for column in schema['numeric_column_order']:
        frame[column]=pd.to_numeric(frame[column].replace('?',np.nan),errors='raise').astype(float)
    for column in schema['categorical_column_order']:
        frame[column]=frame[column].astype(object)
        if schema.get('missing_literal') is not None:frame[column]=frame[column].replace(schema['missing_literal'],schema['missing_category'])
    return frame,labels


def run_saved_check(spec, *, authorized=False):
    """Future real saved-artifact audit; not run by offline fixture tests.

    Loads own-run trusted fitted objects and predicts for independent comparison,
    but never fits. Explicit authorization is required for this path.
    """
    _need(authorized is True, 'NUMERIC_MODEL_LOAD_NOT_AUTHORIZED')
    validate_checker_spec(spec)
    _need(spec['binding_only'] is False,'NUMERIC_BINDING_ONLY_NO_EXECUTION')
    _need(datetime.now(timezone.utc)<datetime.fromisoformat(spec['deadline_utc'].replace('Z','+00:00')),'NUMERIC_DEADLINE_EXPIRED')
    _need(set(spec['inputs'].get('expected_parameters',{}))=={'lr','rf'},'NUMERIC_CURRENT_RECIPES_REQUIRED')
    return _run_saved_check(spec)

def _run_saved_check(spec):
    """No fitting, no model prompts, no network, and test metrics remain private."""
    from sr_cpu_v2.check_worker import (_Audit, _Files, _locked_json, _metrics, _same_array,
        _same_sparse, _pipeline_named, _check_transformer)
    started = time.monotonic()
    audit = _Audit()
    statistics = {"models_loaded": 0, "model_fits": 0, "prediction_max_absolute_error": {},
                  "test_evaluated": False, "test_matrix_written": False, "real_api_requests": 0}
    try:
        import numpy as np
        import joblib
        from scipy import sparse
        from sklearn.linear_model import LogisticRegression
        from sklearn.ensemble import RandomForestClassifier

        audit.require(spec.get("tool") == "independent_check", "CHECK_TOOL_ID")
        files = _Files(spec, audit)
        checked = validate_checker_spec(spec)
        v0 = checked["base"]
        frozen = checked["frozen"]
        manifest = checked["manifest"]
        schemas = {"datasets": {checked["dataset_id"]: checked["schema"]}}
        inputs = spec["inputs"]
        dataset = inputs["dataset_id"]
        audit.require(dataset in ("adult", "bank"), "DATASET_ID")
        schema = schemas["datasets"][dataset]
        train_version = inputs["train_version"]
        train_name = train_version if isinstance(train_version, str) and train_version.startswith("train_") else "train_v" + str(train_version)
        audit.require(train_name in ("train_v1", "train_v2"), "TRAIN_VERSION")
        train_split = _locked_json(v0, f"splits/{dataset}/{train_name}.json", manifest, audit)
        val_split = _locked_json(v0, f"splits/{dataset}/validation.json", manifest, audit)
        train_ids, val_ids = train_split["row_ids"], val_split["row_ids"]
        audit.require(set(train_ids).isdisjoint(val_ids), "TRAIN_VALIDATION_DISJOINT")
        all_x, all_y = _read_rows(v0, dataset, schema, train_ids + val_ids, manifest, audit)
        train_x, val_x = all_x.iloc[:len(train_ids)].copy(), all_x.iloc[len(train_ids):].copy()
        train_y, val_y = all_y[:len(train_ids)], all_y[len(train_ids):]
        payloads = inputs["selected_payloads"]
        prepare = payloads["prepare"]
        audit.require(prepare["dataset_id"] == dataset and str(prepare["train_version"]) == train_name.rsplit("v", 1)[1], "PREPARE_DATASET_VERSION")
        audit.require(prepare["training_row_ids_digest"] == _digest(train_ids) and
                      prepare["validation_row_ids_digest"] == _digest(val_ids), "PREPARE_ROW_PROVENANCE")
        source_path = f"tasks/authority/macro-{dataset}-01.sources.json"
        source_raw = (v0 / source_path).read_bytes()
        audit.require(hashlib.sha256(source_raw).hexdigest() == frozen[source_path]["sha256"], "NEW_EVAL_RECIPE_AUTHORITY_PIN")
        source_doc = json.loads(source_raw)
        recipe_options = {}
        for source in source_doc["sources"]:
            if source["object_key"] in ("recipe:lr", "recipe:rf"):
                recipe_options.setdefault(source["object_key"].split(":")[1], []).append(source["payload"]["parameters"])
        models, preprocessors, recomputed = {}, {}, {}
        for lower, family in (("lr", "LR"), ("rf", "RF")):
            pf = prepare["families"][lower]
            fit, prediction, summary = payloads["fit_" + lower], payloads["predict_" + lower], payloads["summary_" + lower]
            plan = payloads["plan_" + lower]
            parameters = plan.get("parameters", plan.get("model_parameters"))
            audit.require(parameters in recipe_options[lower] and fit["parameters"] == parameters,
                          "LOCKED_RECIPE_PARAMETERS", family)
            expected_recipes = inputs.get("expected_parameters", {})
            if lower in expected_recipes or family in expected_recipes:
                audit.require(parameters == expected_recipes.get(lower, expected_recipes.get(family)), "CURRENT_RECIPE_PARAMETERS", family)
            rows = files.json(pf["rows_artifact_id"])
            audit.require(rows["train_row_ids"] == train_ids and rows["validation_row_ids"] == val_ids,
                          "PERSISTED_ROW_IDS", family)
            audit.require(fit["training_row_ids_digest"] == _digest(train_ids) and
                          fit["matrix_artifact_id"] == pf["train_matrix_artifact_id"], "FIT_TRAIN_PROVENANCE", family)
            selected_ids = inputs["selected_result_ids"]
            audit.require(files.manifest[pf["preprocessor_artifact_id"]]["producer_result_id"] == selected_ids["prepare"] and
                          files.manifest[fit["model_artifact_id"]]["producer_result_id"] == selected_ids["fit_" + lower],
                          "TRUSTED_CURRENT_RUN_FITTED_PRODUCERS", family)
            preprocessor = joblib.load(files.path(pf["preprocessor_artifact_id"]))
            _check_transformer(preprocessor, train_x, schema, family, audit)
            transformed_train = preprocessor.transform(train_x).tocsr()
            transformed_val = preprocessor.transform(val_x).tocsr()
            train_matrix = sparse.load_npz(files.path(pf["train_matrix_artifact_id"]))
            val_matrix = sparse.load_npz(files.path(pf["val_matrix_artifact_id"]))
            _same_sparse(train_matrix, transformed_train, audit, "TRAIN_MATRIX", family)
            _same_sparse(val_matrix, transformed_val, audit, "VALIDATION_MATRIX", family)
            saved_train_y = np.load(files.path(pf["train_y_artifact_id"]), allow_pickle=False)
            saved_val_y = np.load(files.path(pf["val_y_artifact_id"]), allow_pickle=False)
            audit.require(saved_train_y.dtype == np.int8 and saved_val_y.dtype == np.int8 and
                          np.array_equal(saved_train_y, train_y) and np.array_equal(saved_val_y, val_y), "LABELS_FROM_LOCKED_ROWS", family)
            stats = files.json(pf["transform_stats_artifact_id"])
            audit.require(stats.get("feature_names", stats.get("feature_names_out")) == preprocessor.get_feature_names_out().tolist(), "TRANSFORM_STATS_FEATURE_NAMES", family)
            audit.require(stats["input_columns"] == schema["input_column_order"] and
                          stats["numeric_columns"] == schema["numeric_column_order"] and
                          stats["categorical_columns"] == schema["categorical_column_order"] and
                          stats["excluded_columns"] == schema["excluded_columns"] and
                          stats["fit_on"] == "training_only" and stats["test_rows_used"] is False,
                          "TRANSFORM_STATS_COLUMNS_SCOPE", family)
            audit.require(stats["training_row_ids_digest"] == _digest(train_ids) and
                          stats["validation_row_ids_digest"] == _digest(val_ids) and
                          stats["train_shape"] == list(transformed_train.shape) and
                          stats["validation_shape"] == list(transformed_val.shape), "TRANSFORM_STATS_ROW_MATRIX_PROVENANCE", family)
            medians = np.nanmedian(train_x[schema["numeric_column_order"]].to_numpy(dtype=float), axis=0)
            _same_array(np.asarray(stats["numeric_imputer_medians"], dtype=float), medians, audit, "TRANSFORM_STATS_MEDIANS", family)
            expected_categories = [sorted(train_x[c].fillna(schema["missing_category"]).unique().tolist())
                                   for c in schema["categorical_column_order"]]
            audit.require(stats["category_values"] == expected_categories, "TRANSFORM_STATS_CATEGORIES", family)
            if family == "LR":
                _, numeric_steps = _pipeline_named(preprocessor, "numeric")
                from sklearn.preprocessing import StandardScaler
                fitted_scaler = next(x for x in numeric_steps if isinstance(x, StandardScaler))
                for stat_key, fitted_value in (("mean", fitted_scaler.mean_), ("var", fitted_scaler.var_), ("scale", fitted_scaler.scale_)):
                    _same_array(np.asarray(stats["scaler"][stat_key], dtype=float), np.asarray(fitted_value), audit,
                                "TRANSFORM_STATS_SCALER", family + ":" + stat_key)
            else:
                audit.require(stats["scaler"] is None, "RF_HAS_NO_SCALER_STATS")
            model = joblib.load(files.path(fit["model_artifact_id"]))
            audit.require(isinstance(model, LogisticRegression if lower == "lr" else RandomForestClassifier), "MODEL_CLASS", family)
            audit.require(model.get_params(deep=False) == parameters, "FITTED_MODEL_PARAMETERS", family)
            audit.require(model.classes_.tolist() == [0, 1] and model.n_features_in_ == transformed_val.shape[1], "MODEL_CLASSES_FEATURES", family)
            audit.require(prediction["model_artifact_id"] == fit["model_artifact_id"] and
                          prediction["validation_row_ids_digest"] == _digest(val_ids), "PREDICT_PROVENANCE", family)
            saved_probs = np.load(files.path(prediction["prediction_artifact_id"]), allow_pickle=False)
            probabilities = model.predict_proba(transformed_val)[:, 1]
            audit.require(saved_probs.dtype == np.float64 and saved_probs.shape == (len(val_y),) and
                          np.isfinite(saved_probs).all() and np.all((saved_probs >= 0) & (saved_probs <= 1)), "PROBABILITY_CONSTRAINTS", family)
            statistics["prediction_max_absolute_error"][family] = _same_array(saved_probs, probabilities, audit, "PREDICTIONS_RECOMPUTED", family)
            metrics = _metrics(val_y, probabilities)
            raw_receipt = files.json(summary["metrics_artifact_id"])
            audit.require(raw_receipt["prediction_artifact_id"] == prediction["prediction_artifact_id"] and
                          raw_receipt["model_artifact_id"] == fit["model_artifact_id"] and
                          raw_receipt["validation_row_ids_digest"] == _digest(val_ids) and
                          raw_receipt["row_count"] == len(val_ids) and raw_receipt["threshold"] == 0.5,
                          "RAW_METRICS_PROVENANCE", family)
            audit.require(summary["prediction_artifact_id"] == prediction["prediction_artifact_id"] and
                          summary["model_artifact_id"] == fit["model_artifact_id"] and
                          summary["validation_row_ids_digest"] == _digest(val_ids), "SUMMARY_PROVENANCE", family)
            raw_metrics = raw_receipt["metrics"]
            for key, value in metrics.items():
                audit.require(abs(raw_metrics[key] - value) <= 1e-8, "RAW_METRICS_RECOMPUTED", family + ":" + key)
                if inputs.get("allow_delivered_summary_fault") and family == "LR" and key == "average_precision":
                    audit.require(abs(summary["metrics"][key] - value) > 1e-8, "DELIVERED_AP_FAULT_REALLY_PRESENT", family)
                else:
                    audit.require(abs(summary["metrics"][key] - value) <= 1e-8, "DELIVERED_METRICS", family + ":" + key)
            recomputed[family] = metrics
            models[family], preprocessors[family] = model, preprocessor
            statistics["models_loaded"] += 1
        expected_family = "LR" if recomputed["LR"]["average_precision"] >= recomputed["RF"]["average_precision"] - 1e-6 else "RF"
        statistics["validation_metrics"] = recomputed
        statistics["expected_selected_family"] = expected_family
        report, publish = payloads.get("report", {}), payloads.get("publish", {})
        if inputs.get("allow_delivered_summary_fault"):
            audit.require(inputs.get("prefix_publish_status") == "validation_rejected" and
                          inputs.get("prefix_refusal", {}).get("classification") == "semantic", "PREFIX_FAULT_GUARD_REJECTED")
        if not inputs.get("allow_delivered_summary_fault"):
            audit.require(report.get("selected_family") == expected_family, "REPORT_SELECTION")
            chosen = expected_family.lower()
            expected_references = {"model_artifact_id": payloads["fit_" + chosen]["model_artifact_id"],
                                   "prediction_artifact_id": payloads["predict_" + chosen]["prediction_artifact_id"]}
            for key, value in expected_references.items():
                audit.require(report.get(key) == value, "REPORT_CHOSEN_ARTIFACT_REFERENCE", key)
            audit.require(report.get("validation_row_ids_digest") == _digest(val_ids), "REPORT_VALIDATION_ROW_PROVENANCE")
            for key, value in recomputed[expected_family].items():
                audit.require(abs(report["metrics"][key] - value) <= 1e-8, "REPORT_CHOSEN_METRICS", key)
            report_artifact = report.get("report_artifact_id")
            if report_artifact is not None:
                saved_report = files.json(report_artifact)
                audit.require(saved_report == {k: v for k, v in report.items() if k != "report_artifact_id"}, "SAVED_REPORT_EQUALS_DELIVERED_REPORT")
                for key, value in expected_references.items():
                    audit.require(saved_report.get(key) == value, "SAVED_REPORT_ARTIFACT_REFERENCE", key)
                audit.require(saved_report.get("selected_family") == expected_family, "SAVED_REPORT_SELECTION")
            if publish:
                publish_manifest = files.json(publish["candidate_artifact_id"])
                audit.require(publish.get("publish_manifest") == publish_manifest, "PUBLISH_PAYLOAD_EQUALS_MANIFEST_BYTES")
                audit.require(publish_manifest.get("selected_family") == expected_family, "PUBLISH_SELECTION")
                for key, value in expected_references.items():
                    audit.require(publish.get(key) == value and publish_manifest.get(key) == value, "PUBLISHED_ARTIFACT_REFERENCE", key)
                audit.require(publish_manifest.get("report_artifact_id") == report_artifact and
                              publish_manifest.get("validation_row_ids_digest") == _digest(val_ids), "PUBLISHED_REPORT_PROVENANCE")
                for key, value in recomputed[expected_family].items():
                    audit.require(abs(publish_manifest["metrics"][key] - value) <= 1e-8, "PUBLISHED_METRICS", key)
        if inputs.get("evaluate_test"):
            audit.require(bool(publish) and not inputs.get("allow_delivered_summary_fault"), "TEST_ONLY_AFTER_VALID_PUBLISH")
            test_split = _locked_json(v0, f"splits/{dataset}/test.json", manifest, audit)
            test_ids = test_split["row_ids"]
            audit.require(set(test_ids).isdisjoint(train_ids) and set(test_ids).isdisjoint(val_ids), "TEST_DISJOINT")
            test_x, test_y = _read_rows(v0, dataset, schema, test_ids, manifest, audit)
            probabilities = []
            for at in range(0, len(test_ids), 1024):
                matrix = preprocessors[expected_family].transform(test_x.iloc[at:at + 1024])
                probabilities.append(models[expected_family].predict_proba(matrix)[:, 1])
            statistics["private_test_metrics"] = _metrics(test_y, np.concatenate(probabilities))
            statistics["test_evaluated"] = True
            statistics["test_rows"] = len(test_ids)
        statistics["verified_artifact_count"] = len(files.verified)
        statistics["dataset_id"] = dataset
        statistics["train_rows"] = len(train_ids)
        statistics["validation_rows"] = len(val_ids)
    except Exception as exc:
        if not audit.issues:
            audit.issues.append({"code": "CHECK_EXCEPTION", "ref": "", "detail": f"{type(exc).__name__}: {exc}"})
    statistics["elapsed_seconds"] = time.monotonic() - started
    return {"passed": not audit.issues, "checks": audit.checks, "issues": audit.issues, "statistics": statistics}


def main(argv=None):
    """Independent checker CLI, routed by the new bounded Linux supervisor."""
    import argparse
    import os
    import sys
    parser=argparse.ArgumentParser()
    parser.add_argument('--spec',required=True);parser.add_argument('--response',required=True)
    parser.add_argument('--supervisor-permit',required=True)
    args=parser.parse_args(argv)
    spec=_read(args.spec);validate_checker_spec(spec)
    response_path=Path(args.response).resolve()
    _need(response_path==Path(spec['output_dir']).resolve()/'job_response.json','NUMERIC_RESPONSE_PATH_BINDING')
    from .supervisor import validate_worker_permit
    validate_worker_permit(spec,_read(args.supervisor_permit))
    def deny_network(event,details):
        if event.startswith('socket.'):raise RuntimeError('NUMERIC_WORKER_NETWORK_DISABLED')
    sys.addaudithook(deny_network)
    report=run_saved_check(spec,authorized=True)
    response={'status':'success' if report['passed'] else 'failed','tool':'independent_check',
        'job_id':spec['job_id'],'spec_sha256':spec['spec_sha256'],'payload':report,'artifacts':[]}
    temporary=response_path.with_name(response_path.name+'.tmp.'+str(os.getpid()))
    with temporary.open('x') as handle:
        json.dump(response,handle,sort_keys=True,allow_nan=False);handle.write('\n');handle.flush();os.fsync(handle.fileno())
    os.replace(temporary,response_path)
    return 0 if report['passed'] else 2


if __name__=='__main__':raise SystemExit(main())


