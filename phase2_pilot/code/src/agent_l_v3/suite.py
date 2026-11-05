"""Bounded same-version CPU campaign; no inference gateway or cloud code."""
from pathlib import Path

from agent_l_v1.core import prepare_inputs, DATA, PROFILE, save
from agent_l_v1.cpu import FakeCPU
from agent_l_v1.suite import changed_inputs
from context_cutoff.runtime import new_fixture_ledger
from context_cutoff.contracts import require
from sr_recovery_v2.common import canonical
from .cpu import TimedCPU
from .runtime import UnifiedLoop
from .recovery import recover, METHODS
from .timing import Timing


def execute_suite(directory, source_root, *, native=False, authorized=False):
    root = Path(directory).resolve(); root.mkdir(parents=True, exist_ok=False)
    save(root/'ORIGIN.json', {'campaign_root': str(root), 'source_root': str(Path(source_root).resolve())})
    cpu = TimedCPU(root, authorized=authorized, fit_limit=39) if native else FakeCPU()
    summary = {'revision':'agent-l-unified-v3', 'tier':'L', 'status':'running',
        'cpu_fixture_only':not native, 'llm_fixture_only':True, 'real_API_calls':0, 'key_reads':0,
        'new_cloud':0, 'GPU':False, 'M_H':False, 'threshold':.5, 'threshold_tuning':False,
        'cases':{}, 'scenes':{}, 'physical_scripted_calls':0, 'rule_evaluations':0,
        'native_fit_limit':39, 'stochastic_repetitions':False}
    campaign_timing = Timing()

    def case(relative, operation):
        dest = root/relative; dest.parent.mkdir(parents=True, exist_ok=True)
        timing = Timing(); cpu.timing = timing
        before_fits, before_admissions, before_records = cpu.fit_count, cpu.admissions, len(cpu.records)
        result = None; ledger = None
        try:
            with timing.span('whole_branch'):
                try:
                    with timing.span('fixture_ledger_setup'):
                        ledger = new_fixture_ledger(dest.with_suffix('.fixture-ledger.sqlite'), 'l3-'+relative.replace('/','.'))
                    result = operation(dest, ledger, timing)
                finally:
                    if ledger is not None:
                        with timing.span('fixture_ledger_export_close'):
                            calls = len(ledger.calls()); summary['physical_scripted_calls'] += calls
                            save(dest/'FIXTURE_LEDGER_SNAPSHOT.json', ledger.snapshot()); ledger.close()
        finally:
            # Failed runs retain their elapsed envelope too. Never retry in place.
            save(dest.with_suffix('.TIMING.json'), timing.document())
        row = {'outcome':result['outcome'], 'new_fits':cpu.fit_count-before_fits,
            'new_admissions':cpu.admissions-before_admissions, 'new_scripted_calls':result['new_scripted_calls'],
            'rule_evaluations':result['new_rule_evaluations'], 'normal_adjustments':result['optimization_spent'],
            'quality_goal_met':result.get('quality_goal_met'), 'fine_tracking':result['fine_tracking'],
            'decision_backend':result['decision_backend'], 'record_rels':[r['record_rel'] for r in cpu.records[before_records:]],
            'timing_rel':str(dest.with_suffix('.TIMING.json').relative_to(root))}
        if 'final' in result['active']:
            row.update(final_producer_id=result['active']['final']['payload']['producer_id'],
                       final_metrics=result['active']['final']['payload']['metrics']['validation'])
        if 'recovery' in result: row['recovery'] = result['recovery']
        summary['cases'][relative] = row
        summary['rule_evaluations'] += row['rule_evaluations']
        return result

    try:
        with campaign_timing.span('whole_campaign'):
            with campaign_timing.span('shared_input_preparation'):
                inputs = prepare_inputs(source_root, root/'inputs')
                inputs['profile']['source_raw_sha256'] = inputs['data']['raw']['sha256']
                save(root/'INPUTS.json', inputs)

            def initial(dest, ledger, timing, *, fine=True, fixed=False, goal=1.25, initial_bundle='D1', fault=False, update=False, freeze=False):
                engine = UnifiedLoop(dest, str(dest.relative_to(root)).replace('/','.'), cpu, ledger,
                                     timing=timing, fine_tracking=fine, fixed_rule=fixed)
                try:
                    engine.initialize(inputs, goal=goal, initial_bundle=initial_bundle)
                    accepted = engine.run(fault=fault)
                    if not accepted: return engine.export('review_stop', recovery_completed=False)
                    if update:
                        with timing.span('external_data_update'):
                            data_before, old_data = engine.read(DATA); profile_before, old_profile = engine.read(PROFILE)
                            updated = changed_inputs(old_data, dest.parent/'updated-data')
                            data_after = engine.store.write(DATA, canonical(updated), data_before, 'external-data-owner')['after']
                            profile_after = engine.store.write(PROFILE, canonical({**old_profile,'source_raw_sha256':updated['raw']['sha256']}), profile_before,'external-data-owner')['after']
                            engine.doc['external_source_update'] = {'barrier':'after_old_training_before_freeze',
                                'data_before':data_before, 'data_after':data_after, 'profile_before':profile_before,
                                'profile_after':profile_after, 'old_raw_sha256':old_data['raw']['sha256'], 'new_raw_sha256':updated['raw']['sha256']}
                    if freeze: return engine.freeze()
                    engine.publish(); return engine.export('completed_execution')
                finally: engine.close()

            case('controls/agent-tracked', lambda d,l,t:initial(d,l,t))
            case('controls/agent-safety-only', lambda d,l,t:initial(d,l,t,fine=False))
            case('controls/fixed-rule-safety-only', lambda d,l,t:initial(d,l,t,fine=False,fixed=True))
            # Development-only goals deliberately exercise both terminal review paths.
            case('reviews/adjust-accept', lambda d,l,t:initial(d,l,t,goal=1.6,initial_bundle='D0'))
            case('reviews/adjust-stop', lambda d,l,t:initial(d,l,t,goal=3.,initial_bundle='D0'))
            for scene in ('incidental','decision','data-update'):
                relative = 'scenes/'+scene
                fault = 'DECISION_ELIGIBILITY' if scene == 'decision' else 'INCIDENTAL_ROW_COUNT'
                frozen = case(relative+'/prefix', lambda d,l,t:initial(d,l,t,fault=fault,update=scene=='data-update',freeze=True))
                summary['scenes'][scene] = {'checkpoint_sha256':frozen['checkpoint_sha256'], 'methods':{}}
                prefix = root/relative/'prefix'
                for method in METHODS:
                    result = case(relative+'/'+method, lambda d,l,t:recover(prefix,frozen,d,method,cpu,l,t))
                    summary['scenes'][scene]['methods'][method] = result['recovery']
                if scene == 'data-update':
                    for method in METHODS:
                        case(relative+'/protected-'+method, lambda d,l,t:recover(prefix,frozen,d,method,cpu,l,t,protect_external=True))
            require(cpu.fit_count == 39 and cpu.admissions == 2, 'L3_TOTAL_WORK')
            require(summary['physical_scripted_calls'] == 120 and summary['rule_evaluations'] == 6, 'L3_CALL_COUNTS')
            require(summary['cases']['reviews/adjust-stop']['outcome'] == 'review_stop', 'L3_STOP_PATH')
            summary.update(status='complete', training_jobs=cpu.fit_count, numerical_readmissions=cpu.admissions,
                scientific_success_rate_claimed=False, model_API_cost=0, token_usage='synthetic-not-measured')
            if native:
                save(root/'CPU_RECORD_INDEX.json',[{'record_rel':r['record_rel'], 'schema':r['record']['spec']['schema_version'],
                    'job_id':r['record']['spec']['job_id']} for r in cpu.records])
    except BaseException as exc:
        summary.update(status='failed', error={'type':type(exc).__name__, 'message':str(exc)}, training_launches=cpu.fit_count)
        raise
    finally:
        save(root/'SUMMARY.json', summary)
        if campaign_timing.events: save(root/'CAMPAIGN_TIMING.json', campaign_timing.document())
    return summary
