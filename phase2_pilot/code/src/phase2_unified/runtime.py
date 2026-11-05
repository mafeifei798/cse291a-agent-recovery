"""Uniform durable workflow driver. All tools and LLMs remain injected fixtures.

FULL, LAZY, EAGER and VERIFY_RETRY execute through the same authoritative SQLite
kernel from their first node. Policies differ in checks and invalidation, never
in persistence strength, acceptance transactions or publication ownership.
"""
from __future__ import annotations

from contextlib import closing
from copy import deepcopy
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import sqlite3
from time import monotonic_ns, process_time_ns

from phase2_offline.runtime import (RuntimeStop, SYNTHETIC_USAGE, _case, _call_record,
    _copy_scene, _initial, _source_update, write_json)
from phase2_offline.artifacts import seal_artifacts
from phase2_supplement.runtime import _evidence, _inject, _consumer_path
from phase2_supplement.consumer import (consumption_inputs, record_consumption,
    verify_consumptions, evaluate_unresolved)
from sr_recovery_timing.core import RecoveryTimer
from sr_recovery_v2.common import ProtocolError, digest, closure_ids, source_fingerprint, utc_parse
from sr_recovery_v2.fake import execute_fake, input_projection
from sr_recovery_v2.runner import FakeClock, real_clock
from .kernel import DurableKernel, PROTOCOL


def _as_scene(doc):
    return {'revision':doc['dag']['revision'], 'fixture_only':True, 'domain':doc['domain'],
        'workflow_id':doc['dag']['workflow_id'], 'source_aliases':deepcopy(doc['source_aliases']),
        'prefix_mode':'phase2_unified_durable_fixture', 'task':deepcopy(doc['task']),
        'results':deepcopy(doc['results']), 'artifact_manifest':deepcopy(doc['artifacts']),
        'current_sources':deepcopy(doc['sources']), 'source_history':deepcopy(doc['source_history']),
        'call_evidence':deepcopy(doc['calls']), 'tool_receipts':deepcopy(doc['tool_receipts']),
        'input_producers':deepcopy(doc['input_producers']), 'run_state':deepcopy(doc['state']),
        'evaluation_binding':deepcopy(doc['metadata']['evaluation_binding']),
        'supplement_evidence':deepcopy(doc['supplement_evidence']),
        'published_state':{'objects':deepcopy(doc['objects']), 'effects':deepcopy(doc['effects'])},
        'notice':deepcopy(doc.get('notice'))}


def _guard(kernel, node, timer, evidence, *, full=False):
    began, cpu = monotonic_ns(), process_time_ns()
    with timer.span('common_pre_dispatch_guard', node):
        value = kernel.check(node, full=full)
    evidence['verification_checks'].append({'node_id':node,'checkpoint':value['checkpoint'],
        'guard_id':value['guard_id'],'classification':value['classification'],
        'wall_ns':monotonic_ns()-began,'controller_cpu_ns':process_time_ns()-cpu,
        'full_version_diagnosis':full,'exact_rule_upper_bound':True,'model_calls':0,
        'scope':'whole_row_current_kernel'})
    return value


def _source_change(kernel, pack, row, files, evidence, barrier):
    scene = _as_scene(kernel.snapshot())
    old = deepcopy(next(s for s in scene['current_sources'] if s['object_key']=='recipe:rf'))
    if old['version'] != 1: raise ProtocolError('SOURCE_UPDATE_ALREADY_APPLIED')
    _source_update(scene, 'N2', files, pack['tasks'][row['task_id']]['source_history'])
    new = deepcopy(next(s for s in scene['current_sources'] if s['object_key']=='recipe:rf'))
    evidence['source_update_events'].append({'barrier':barrier,'node_id':'publish',
        'object_key':'recipe:rf','before':old,'after':new,
        'selected_by_node_at_barrier':deepcopy(scene['run_state']['selected_by_node']),
        'fault_identity_visible_to_method':False})
    kernel.update_sources(scene['current_sources'],scene['source_history'],evidence,
                          row['row_id']+'.source_update')


def _correction(kernel, guard, evidence, timer):
    kind = guard['classification']
    if kind not in ('stale','semantic'): return False
    doc = kernel.snapshot()
    if doc['state']['counters'][kind+'_used'] >= 1: return False
    issues = guard['issues']
    if kind=='stale':
        # All methods diagnose the whole selected graph after a local refusal.
        full = _guard(kernel, guard['node_id'], timer, evidence, full=True)
        issues = [i for i in full['issues'] if i['code'] in ('STALE_EFFECTIVE_READ','PROVABLE_MIXED_READ_VERSIONS')]
    ids = [rid for issue in issues for rid in issue.get('related_result_ids',[])]
    if not ids and guard.get('candidate_result_id'): ids=[guard['candidate_result_id']]
    if not ids: return False
    if not doc['metadata']['initial_result_ids']:
        kernel.annotate({'metadata':{**doc['metadata'],'initial_result_ids':[r['result_id'] for r in doc['results']]}},
            doc['state']['branch_id']+'.first_correction_retention_anchor')
    phase = kind + '-repair'
    with timer.span('invalidation_and_compensation',phase):
        plan = kernel.invalidate(ids,phase=phase,reason='public_guard_'+kind,correction_class=kind)
    evidence['corrections'].append({**plan,'guard_id':guard['guard_id'],
        'diagnosis_source':'public_guard_evidence_only','allowance_before':0,'allowance_after':1})
    return True


def _begin_recovery(kernel, row, evidence, timer):
    doc=kernel.snapshot(); notice=doc.get('notice')
    if not notice or notice['faulty_result_id'] not in {r['result_id'] for r in doc['results']}:
        raise ProtocolError('FAULT_IDENTITY_REQUIRED')
    if row['strategy']=='EAGER':
        # This is an explicit paid bookkeeping scan, never model context.
        guard=_guard(kernel,doc['dag']['topological_order'][-1],timer,evidence,full=True)
        stale=[rid for i in guard['issues'] if i['code'] in ('STALE_EFFECTIVE_READ','PROVABLE_MIXED_READ_VERSIONS') for rid in i.get('related_result_ids',[])]
    else: stale=[]
    seeds=[notice['faulty_result_id']]+stale
    with timer.span('invalidation_and_compensation','initial-recovery'):
        plan=kernel.invalidate(seeds,phase='recovery',reason='supplied_fault_identity',full=row['strategy']=='FULL')
    evidence['corrections'].append({**plan,'diagnosis_source':'supplied_same_fault_identity',
                                   'allowance_consumed':False})


def _default_cpu_receipt(pack,row,node,attempt,snapshot,package,files,now):
    from .cpu import load_eval_binding,build_tool_spec,dispatch,FakeWorkerClient
    binding=load_eval_binding(task_id=row['task_id'],dataset_id=row['dataset_id'],protocol_sha256=pack['freeze_sha256'])
    spec=build_tool_spec(binding,node,attempt,snapshot,attempt.get('trusted_artifact_bindings',snapshot['artifact_bindings']),
        attempt['deadline_utc'],files/'cpu-jobs'/attempt['attempt_id'],artifact_root=files)
    client=FakeWorkerClient(payload=package['result']['payload'],artifacts=package['artifacts'],
        parameters=package['tool_receipts'][0].get('parameters',{}),finished_utc=now)
    return {'spec':spec,'receipt':dispatch(spec,client=client,now=now)}


def _checked_cpu_evidence(value,now):
    from .cpu import dispatch
    class RecordedResponse:
        def execute(self,spec):return deepcopy(value['receipt'])
    receipt=dispatch(value['spec'],client=RecordedResponse(),now=now)
    if receipt.get('fixture_only') is not True or any(receipt.get(k)!=0 for k in ('actual_training','actual_model_prediction','model_loads')):
        raise ProtocolError('OFFLINE_PROVIDER_CANNOT_EXECUTE_SCIENTIFIC_WORK')
    return {'spec':deepcopy(value['spec']),'receipt':receipt}


def _loop(kernel,pack,row,files,timer,hook,case,evidence,clock,cpu_gateway,cpu_records,
          *,verify,inject,repairable,already_updated=False,tool_provider=None):
    updated=already_updated
    while True:
        doc=kernel.snapshot(); state=doc['state']; pending=[n for n in doc['dag']['topological_order'] if not state['selected_by_node'][n]]
        if not pending: return 'completed_correct',None
        node_id=pending[0]; node=next(n for n in doc['dag']['nodes'] if n['node_id']==node_id)
        attempt=None; dispatched=False; package=None
        try:
            if monotonic_ns()-timer.started >= row.get('fixed_deadline_seconds',1800)*10**9 or case.get('kind')=='fixed_deadline':
                raise RuntimeStop('FIXED_DEADLINE_EXPIRED')
            if node_id=='publish' and row['scenario']=='LATE_N2' and not updated:
                with timer.span('source_update'):
                    _source_change(kernel,pack,row,files,evidence,'before_first_publish_attempt')
                updated=True
            guard=_guard(kernel,node_id,timer,evidence)
            if guard['classification']!='passed':
                if repairable and _correction(kernel,guard,evidence,timer): continue
                kernel.annotate({'supplement_evidence':evidence,'prefix_refusal':guard},
                    row['row_id']+'.refusal.'+guard['guard_id'])
                return ('prefix_frozen' if inject and evidence['injected_faults'] and not verify else 'validation_rejected'),None
            state=kernel.snapshot()['state']
            if state['counters']['physical_calls']+node['llm_calls_per_execution']>row['call_cap']: raise RuntimeStop('ROW_CALL_CAP')
            if state['counters']['cpu_jobs']+node['cpu_jobs_per_execution']>row['cpu_job_cap']: raise RuntimeStop('ROW_CPU_CAP')
            phase=state['stage']; event=row['row_id']+'.intent.'+str(len(kernel.snapshot()['attempts']))+'.'+node_id
            with timer.span('persist_dispatch_intent',node_id):
                attempt=kernel.start_node(node_id,phase,event,clock())
            snap=attempt['input_snapshot']; reservation=None
            if node['llm_calls_per_execution']:
                reservation=hook(_call_record(row,node_id,attempt,snap,'before'))
            with timer.span('persist_dispatch_started',node_id):
                kernel.mark_dispatched(attempt['attempt_id'],reservation,clock())
            dispatched=True
            dispatch_started_ns=monotonic_ns()
            with timer.span('dispatch_and_fixture_execution',node_id):
                fault='report_ap_wrong' if node_id=='report' and case.get('kind') in ('semantic_retry','semantic_exhausted') and (not state['counters']['semantic_used'] or case['kind']=='semantic_exhausted') else None
                provider=tool_provider or execute_fake
                provided=provider(kernel.snapshot(),node_id,attempt,files,fault=fault)
                package=provided.get('package') if isinstance(provided,dict) and 'package' in provided else provided
                supplied_cpu=provided.get('cpu_evidence') if isinstance(provided,dict) and 'package' in provided else None
                if inject and row['scenario'] in ('EARLY_RF','LATE_N2'): _inject(package,pack,row,evidence)
                if node['cpu_jobs_per_execution']:
                    kernel._stage_artifacts(package)
                    call=cpu_gateway or _default_cpu_receipt
                    cpu_records.append(_checked_cpu_evidence(supplied_cpu,clock()) if supplied_cpu else
                        call(pack,row,node_id,attempt,snap,package,files,clock()))
            transport_failure=case.get('kind') in ('timeout','late_response','http_429') and node_id==case.get('node_id','inspect')
            settlement=None; stop=None
            if node['llm_calls_per_execution']:
                after=_call_record(row,node_id,attempt,snap,'after',status='uncertain' if transport_failure else 'completed',
                    usage=None if transport_failure else deepcopy(SYNTHETIC_USAGE),
                    http_status=429 if transport_failure and case['kind']=='http_429' else 200)
                try: settlement=hook(after)
                except RuntimeStop as exc:
                    stop=exc; settlement=deepcopy(getattr(exc,'transport_event',after))
                    settlement.update(stage='after',status='uncertain' if exc.unknown_usage else settlement.get('status','completed'))
                    if exc.unknown_usage: settlement['usage']=None
            unknown=bool(transport_failure or (stop and stop.unknown_usage))
            began,cpu=monotonic_ns(),process_time_ns()
            with timer.span('result_validation_and_commit',node_id):
                settled=kernel.finish_node(attempt['attempt_id'],package,clock(),budget_settlement=settlement,
                    verify=verify,forced_unknown=unknown,forced_late=(case.get('kind')=='late_response' and transport_failure) or
                        monotonic_ns()-timer.started >= row.get('fixed_deadline_seconds',1800)*10**9 or
                        monotonic_ns()-dispatch_started_ns >= 120*10**9,evidence=evidence,
                    cpu_evidence=cpu_records[-1] if node['cpu_jobs_per_execution'] else None)
            guard=settled['guard']
            if guard:
                evidence['verification_checks'].append({'node_id':node_id,'checkpoint':guard['checkpoint'],
                    'guard_id':guard['guard_id'],'classification':guard['classification'],
                    'wall_ns':monotonic_ns()-began,'controller_cpu_ns':process_time_ns()-cpu,
                    'full_version_diagnosis':guard['full_version_diagnosis'],'exact_rule_upper_bound':True,
                    'model_calls':0,'scope':'whole_row_current_kernel',
                    'timing_scope':'guard_plus_uniform_durable_acceptance_not_pure_guard'})
            if unknown or settled['late']:
                return 'uncertain' if unknown else 'budget_or_time_stopped',{'code':stop.code if stop else 'HTTP_429' if case.get('kind')=='http_429' else 'TOTAL_DEADLINE_EXPIRED','unknown_usage':unknown}
            if stop: raise stop
            if case.get('kind')=='natural_prefix_failure' and node_id==case.get('node_id','inspect'):
                return 'validation_rejected',{'code':'SYNTHETIC_NATURAL_PREFIX_FAILURE','unknown_usage':False}
            if guard and guard['classification']!='passed':
                if repairable and _correction(kernel,guard,evidence,timer): continue
                kernel.annotate({'supplement_evidence':evidence,'prefix_refusal':guard,
                    'prefix_candidate_result':package['result']},row['row_id']+'.candidate_refusal.'+guard['guard_id'])
                return ('prefix_frozen' if inject and evidence['injected_faults'] and not verify else 'validation_rejected'),None
        except (RuntimeStop,ProtocolError) as exc:
            if attempt:
                current=kernel.snapshot(); active=current['state']['active_attempt_ids']
                if attempt['attempt_id'] in active:
                    kernel.abandon(attempt['attempt_id'],getattr(exc,'code',str(exc)),unknown=bool(dispatched and node['llm_calls_per_execution']),
                        raw_package={k:deepcopy(v) for k,v in package.items() if k!='artifact_contents'} if package else None,
                        cpu_evidence=cpu_records[-1] if package and node['cpu_jobs_per_execution'] and cpu_records else None)
            unknown=bool(getattr(exc,'unknown_usage',False) or (attempt and dispatched and node['llm_calls_per_execution'] and kernel.snapshot()['state']['unsettled_call_ids']))
            return 'uncertain' if unknown else 'budget_or_time_stopped',{'code':getattr(exc,'code',str(exc)),'unknown_usage':unknown}


def _numeric_check(kernel,pack,row,files,timer,clock):
    from .cpu import load_eval_binding
    from .numeric import build_checker_spec,check_fixture_arrays
    doc=kernel.snapshot(); state=doc['state']
    deadline=state['deadline_utc']
    if utc_parse(clock())>=utc_parse(deadline) or monotonic_ns()-timer.started>=row['fixed_deadline_seconds']*10**9:
        raise RuntimeStop('FIXED_DEADLINE_EXPIRED')
    selected={n:rid for n,rid in state['selected_by_node'].items() if rid}
    byid={r['result_id']:r for r in doc['results']}
    payloads={n:byid[rid]['payload'] for n,rid in selected.items()}
    artifacts={a['artifact_id']:a for a in doc['artifacts']}
    def value(aid):
        art=artifacts[aid];path=(files/art['uri']).resolve()
        if not path.is_relative_to(files.resolve()) or path.is_symlink():raise ValueError('NUMERIC_FIXTURE_PATH_ESCAPE')
        raw=path.read_bytes()
        if len(raw)!=art['size_bytes'] or hashlib.sha256(raw).hexdigest()!=art['sha256']:raise ValueError('NUMERIC_FIXTURE_ARTIFACT_CHANGED')
        return json.loads(raw)
    began,cpu=monotonic_ns(),process_time_ns()
    with timer.span('independent_numeric_checker'):
        binding=load_eval_binding(task_id=row['task_id'],dataset_id=row['dataset_id'],protocol_sha256=pack['freeze_sha256'])
        version=next(s['version'] for s in doc['sources'] if s['object_key']=='data:train')
        spec=build_checker_spec(binding,selected_payloads=payloads,selected_result_ids=selected,
            artifacts=doc['artifacts'],artifact_root=files,train_version=version,deadline=deadline)
        families={}
        for family in ('lr','rf'):
            matrix=value(payloads['prepare']['families'][family]['matrix_artifact_id'])
            prediction=value(payloads['predict_'+family]['prediction_artifact_id'])
            if prediction['row_ids']!=matrix['val_row_ids'] or prediction['model_artifact_id']!=payloads['fit_'+family]['model_artifact_id']:
                raise ValueError('NUMERIC_FIXTURE_PREDICTION_BINDING_MISMATCH')
            families[family]=check_fixture_arrays(spec,labels=matrix['val_y'],
                probabilities=prediction['positive_probabilities'],reported_metrics=payloads['summary_'+family]['metrics'])
        if utc_parse(clock())>=utc_parse(deadline) or monotonic_ns()-timer.started>=row['fixed_deadline_seconds']*10**9:
            raise RuntimeStop('FIXED_DEADLINE_EXPIRED')
        receipt={'passed':True,'fixture_only':True,'spec':spec,'families':families,
            'deadline_utc':deadline,'actual_training':0,'actual_model_prediction':0,'model_loads':0,
            'workflow_cpu_jobs_added':0,'model_calls_added':0,'evaluation_dataset_rows_executed':False,
            'wall_ns':monotonic_ns()-began,'controller_cpu_ns':process_time_ns()-cpu,
            'scope':'external_independent_synthetic_array_checker_in_whole_row_window'}
        kernel.annotate({'independent_numeric_check':receipt},row['row_id']+'.numeric_checker')
    return receipt


def _freeze_scene(kernel,row,evidence,status):
    scene=_as_scene(kernel.snapshot())
    if status=='prefix_frozen':
        target=evidence['injected_faults'][0]
        scene['notice']={'record_type':'Notice','revision':scene['revision'],'fixture_only':True,
            'run_id':scene['run_state']['run_id'],'notice_id':row['row_id']+'.notice','faulty_result_id':target['result_id']}
        scene['prefix_evidence']={'condition':row['scenario'],'fault_node':target['node_id'],
            'faulty_result_id':target['result_id'],'kind':'unified_fresh_fault_prefix','fixture_only':True}
    scene['run_state']['lifecycle']='frozen_recoverable'
    scene['supplement_evidence']=deepcopy(evidence)
    if 'prefix_refusal' in kernel.snapshot(): scene['prefix_refusal']=deepcopy(kernel.snapshot()['prefix_refusal'])
    if 'prefix_candidate_result' in kernel.snapshot(): scene['prefix_candidate_result']=deepcopy(kernel.snapshot()['prefix_candidate_result'])
    return scene


def run_row(pack,row,output_dir,*,scene=None,dispatch_hook=None,fake_case=None,cpu_gateway=None,tool_provider=None):
    """Fresh fixture-only row. Existing output never dispatches a second time."""
    output=Path(output_dir).resolve()
    if output.exists() and any(output.iterdir()): raise ValueError('ROW_OUTPUT_ALREADY_EXISTS')
    output.mkdir(parents=True,exist_ok=True); files=output/'files'; files.mkdir()
    case=_case(fake_case); transport=[]; cpu_records=[]
    def hook(event):
        recorded=deepcopy(event)
        try:
            returned=dispatch_hook(event) if dispatch_hook else None
            if isinstance(returned,dict): recorded=deepcopy(returned)
            # The durable kernel requires the actual settlement event, including
            # public before/after binding; ledger hooks may return only a subset.
            recorded={**deepcopy(event),**recorded}
            return recorded
        except RuntimeStop as exc:
            recorded=deepcopy(getattr(exc,'transport_event',event))
            recorded={**deepcopy(event),**recorded,'runtime_stop':{'code':exc.code,'unknown_usage':exc.unknown_usage}}
            if exc.unknown_usage: recorded.update(status='uncertain',usage=None)
            exc.transport_event=deepcopy(recorded)
            raise
        finally:
            transport.append(recorded); write_json(output/'transport_events.json',transport)
    timer=RecoveryTimer(row['row_id'],row['strategy'] if row['strategy'] in ('FULL','LAZY','EAGER') else 'FULL',execution_mode='offline_fake_store')
    with timer.span('clone_and_setup'):
        if row['kind'] in ('recovery','consumption_recovery'):
            if scene is None: raise ValueError('RECOVERY_PREFIX_REQUIRED')
            initial=_copy_scene(scene,files); dag=deepcopy(pack['dag'])
            if initial['evaluation_binding']['pack_sha256']!=pack['freeze_sha256']: raise ValueError('PREFIX_PACK_BINDING_MISMATCH')
            if initial['task']['task_id']!=row['task_id'] or initial['prefix_evidence']['condition']!=row['scenario']: raise ValueError('PREFIX_TASK_OR_SCENARIO_MISMATCH')
        else: initial,dag=_initial(pack,row,files)
        for artifact in initial['artifact_manifest']:
            (files/artifact['uri']).chmod(0o444)
        timer.bind_inputs(scene_digest=digest(initial),dag_digest=digest(dag))
    evidence=deepcopy(initial.get('supplement_evidence') or _evidence())
    if row['kind'] in ('recovery','consumption_recovery'):
        evidence['inherited_verification_checks']=deepcopy(evidence['verification_checks'])
        evidence['verification_checks']=[]
    evidence['verification_checks_scope']='whole_row_current_kernel'
    evidence['durability_protocol']=PROTOCOL
    clock=FakeClock(real_clock()); qualified=False; frozen=None; outcome=None
    with DurableKernel(output/'workflow.sqlite',files) as kernel:
        with timer.span('durable_kernel_setup'):
            kernel.create(initial,dag,row,clock())
        if row['kind'] in ('recovery','consumption_recovery'):
            with timer.span('initial_recovery_plan'):
                _begin_recovery(kernel,row,evidence,timer)
        verify=row['strategy']=='VERIFY_RETRY'
        inject=row['kind']=='prefix' or row['kind']=='e2e'
        with timer.span('workflow_execution'):
            status,error=_loop(kernel,pack,row,files,timer,hook,case,evidence,clock,cpu_gateway,cpu_records,
                verify=verify,inject=inject,repairable=verify or row['kind'] in ('recovery','consumption_recovery'),tool_provider=tool_provider)
        if row['kind']=='e2e' and row['strategy'] in ('FULL','LAZY') and status=='prefix_frozen':
            initial_execution=kernel.export()
            frozen=_freeze_scene(kernel,row,evidence,status)
            kernel.annotate({'notice':frozen['notice'],'initial_execution':initial_execution,'initial_snapshot':frozen,
                'metadata':{**kernel.snapshot()['metadata'],'initial_result_ids':[r['result_id'] for r in kernel.snapshot()['results']]}},row['row_id']+'.handoff')
            _begin_recovery(kernel,row,evidence,timer)
            status,error=_loop(kernel,pack,row,files,timer,hook,case,evidence,clock,cpu_gateway,cpu_records,
                verify=False,inject=False,repairable=True,already_updated=bool(evidence['source_update_events']),tool_provider=tool_provider)
        if status=='completed_correct':
            _numeric_check(kernel,pack,row,files,timer,clock)
        if row['kind']=='consumption_prefix' and status=='completed_correct':
            kernel.annotate({'supplement_evidence':evidence},row['row_id']+'.before_consumer')
            kernel.stop('completed_correct')
            published=kernel.export()
            with timer.span('external_consumer_receipt'):
                path=_consumer_path(row,output)
                receipt=record_consumption(path,event_id=row['row_id']+'.external.consume',**consumption_inputs(published,files))
                report=verify_consumptions(path)
                evidence['consumer_evidence']={'journal_path':str(path),'journal_relative_path':path.relative_to(output.parent.parent.resolve()).as_posix(),
                    'journal_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'receipt':receipt,'verification':report,
                    'journal_receipt_count':report['receipt_count'],'journal_chain_sha256':report['chain_sha256'],
                    'simulated_external_consumer':True,'historical_publication_was_valid':True,'external_action_sent':False}
            _source_change(kernel,pack,row,files,evidence,'after_valid_publication_and_external_consumption')
            frozen=_freeze_scene(kernel,row,evidence,'consumed_prefix_frozen')
            plan=next(r for r in frozen['results'] if r['result_id']==frozen['run_state']['selected_by_node']['plan_rf'])
            frozen['notice']={'record_type':'Notice','revision':frozen['revision'],'fixture_only':True,
                'run_id':frozen['run_state']['run_id'],'notice_id':row['row_id']+'.notice','faulty_result_id':plan['result_id']}
            frozen['prefix_evidence']={'condition':'CONSUMED_N2','fault_node':None,'faulty_result_id':plan['result_id'],
                'kind':'valid_publication_consumed_then_source_changed','historical_output_wrong':False,'fixture_only':True}
            frozen['consumer_journal']={'journal_relative_path':evidence['consumer_evidence']['journal_relative_path'],
                'sha256':evidence['consumer_evidence']['journal_sha256'],'receipt_count':report['receipt_count'],'chain_sha256':report['chain_sha256']}
            outcome=evaluate_unresolved(report,kernel.snapshot()['sources'],local_correct=False)
            status='consumed_prefix_frozen';qualified=True
        elif row['kind']=='consumption_recovery':
            with timer.span('external_consumer_verification'):
                path=_consumer_path(row,output,initial); anchor=initial['consumer_journal']
                report=verify_consumptions(path,expected_count=anchor['receipt_count'],expected_head=anchor['chain_sha256'],expected_raw_sha256=anchor['sha256'])
                if not report['passed']: raise ValueError('CONSUMER_JOURNAL_ANCHOR_MISMATCH')
                outcome=evaluate_unresolved(report,kernel.snapshot()['sources'],local_correct=status=='completed_correct')
                evidence['consumer_evidence']={**evidence['consumer_evidence'],'verification_after_recovery':report}
                if status=='completed_correct': status='completed_local_unresolved_external'
        elif status=='prefix_frozen':
            frozen=_freeze_scene(kernel,row,evidence,status);qualified=True
        committed_cpu=kernel.snapshot().get('cpu_gateway_receipts',[])
        uncommitted_cpu=[r for r in cpu_records if r not in committed_cpu]
        final_values={'supplement_evidence':evidence,'transport_receipts':transport,'cpu_gateway_receipts':committed_cpu,
            'unaccepted_cpu_gateway_receipts':uncommitted_cpu,
            'phase2_unified_pack_sha256':pack['freeze_sha256'],'supplement_only':True,'unified_only':True}
        if outcome is not None: final_values['consumption_outcome']=outcome
        with timer.span('durable_terminal_and_export'):
            kernel.annotate(final_values,row['row_id']+'.final_annotations')
            kernel.stop(status,error)
            export=kernel.export()
            export['execution_trace']=[{'node_id':a['node_id'],'attempt_id':a['attempt_id'],'result_id':a['result_id'],
                'status':a['status'],'accepted':any(r['result_id']==a['result_id'] and d['selected'] for d in export['kernel_evidence']['dispatches'] if d['attempt_id']==a['attempt_id'] for r in export['results'])} for a in export['attempts']]
            if qualified: write_json(output/'scene.json',frozen)
            write_json(output/'export.json',export);seal_artifacts(output,export)
            write_json(output/'terminal.json',{'row_id':row['row_id'],'terminal_status':status,'fixture_only':True,'worker_pids':[],'worker_launches':0})
            write_json(output/'transport_events.json',transport);write_json(output/'cpu_gateway_receipts.json',committed_cpu)
            if uncommitted_cpu:write_json(output/'unaccepted_cpu_gateway_receipts.json',uncommitted_cpu)
    def closure():
        with closing(sqlite3.connect((output/'workflow.sqlite').resolve().as_uri()+'?mode=ro&immutable=1',uri=True)) as db:
            raw=json.loads(db.execute('SELECT payload FROM document WHERE id=1').fetchone()[0])
        if digest(raw['state'])!=export['kernel_evidence']['state_digest'] or digest(raw)!=export['kernel_evidence']['document_digest']:
            raise ValueError('AUTHORITATIVE_DATABASE_EXPORT_MISMATCH')
        if raw['state']['status']!='terminal' or raw['state']['active_attempt_ids']: raise ValueError('DATABASE_NOT_CLOSED')
        unknown=raw['state']['unsettled_call_ids']
        return {'terminal_status':status,'durable_terminal':True,'active_attempt_ids':[],
            'worker_pids':[],'worker_launches':0,'worker_reaping_required':False,
            'unsettled_call_ids':unknown,'held_cost_nano_usd':len(unknown)*1_924_000,
            'durable_database_probe':True,'database_path':'workflow.sqlite','database_relative_path':'workflow.sqlite',
            'database_sha256':hashlib.sha256((output/'workflow.sqlite').read_bytes()).hexdigest(),
            'database_state_digest':digest(raw['state']),
            'same_kernel_from_first_node':True}
    timing=timer.finish(closure);write_json(output/'timing.json',timing)
    selected={rid for rid in export['state']['selected_by_node'].values() if rid}
    original=set(export['metadata']['initial_result_ids']); local=status in ('completed_correct','completed_local_unresolved_external')
    retained=sorted(selected & original) if local else []
    checks=evidence['verification_checks'];counters=export['state']['counters']
    item={**{k:row[k] for k in ('row_id','kind','strategy','scenario','task_id')},
        'fixture_only':True,'mode':'offline_fixture','unified_only':True,'supplement_only':True,
        'pack_sha256':pack['freeze_sha256'],'pack_freeze_sha256':pack['freeze_sha256'],
        'output_dir':str(output),'status':status,'terminal_status':status,
        'completed_correct':status=='completed_correct','local_completed_correct':local,
        'qualified':qualified,'safe_stop':status in ('verification_stop','permission_denied_safe','conflict_safe'),
        'failed':status in ('uncertain','validation_rejected','budget_or_time_stopped'),
        'scene_path':str(output/'scene.json') if qualified else None,'prefix_digest':export.get('prefix_digest'),
        'call_count':counters['physical_calls'],'cpu_jobs':counters['cpu_jobs'],
        'reused_result_ids':retained,'reused_nodes':sorted(r['node_id'] for r in export['results'] if r['result_id'] in retained),
        'recomputed_nodes':[a['node_id'] for a in export['attempts'] if a['status']!='not_dispatched'],
        'correction_counts':{k:counters[k] for k in ('semantic_used','stale_used')},
        'verification_check_count':len(checks),'verification_wall_ns':sum(c['wall_ns'] for c in checks),
        'verification_controller_cpu_ns':sum(c['controller_cpu_ns'] for c in checks),
        'complete_guard_check_count':len(checks),'complete_guard_wall_ns':sum(c['wall_ns'] for c in checks),
        'complete_guard_controller_cpu_ns':sum(c['controller_cpu_ns'] for c in checks),
        'verification_checks_scope':'whole_row_current_kernel',
        'source_update_reached':bool(evidence['source_update_events']),
        'consumer_evidence_present':evidence['consumer_evidence'] is not None,
        'unresolved_external_effects_count':outcome['unresolved_external_effects_count'] if outcome else 0,
        'actual_training':0,'actual_model_prediction':0,'real_api_requests':0,'new_actual_api_cost_nano_usd':0,
        'timing_complete':timing['closed'],'recovery_wall_ns':timing['summary']['recovery_wall_ns'],
        'error':error,'fixture_data_not_actual_eval_rows':True,'cpu_gateway_job_count':len(committed_cpu),
        'unaccepted_cpu_gateway_job_count':len(uncommitted_cpu),
        'durability_protocol':PROTOCOL,'same_kernel_from_first_node':True,
        'independent_numeric_check_passed':bool(export.get('independent_numeric_check',{}).get('passed')),
        'independent_numeric_fixture_only':True,
        'transaction_count':export['kernel_evidence']['transaction_count']}
    item['evidence_sha256']={name:hashlib.sha256((output/name).read_bytes()).hexdigest() for name in
        ('workflow.sqlite','export.json','timing.json','terminal.json','artifact_manifest.json','transport_events.json','cpu_gateway_receipts.json','unaccepted_cpu_gateway_receipts.json','scene.json') if (output/name).is_file()}
    write_json(output/'item.json',item)
    return item
