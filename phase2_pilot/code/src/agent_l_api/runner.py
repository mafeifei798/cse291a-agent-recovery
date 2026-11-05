"""Eight registered units, same freeze and one non-rollback budget authority."""
from pathlib import Path
import json

from agent_l_v1.core import prepare_inputs,save
from agent_l_v1.cpu import FakeCPU
from agent_l_v3.cpu import TimedCPU
from agent_l_v3.timing import Timing
from agent_recovery.contracts import require,digest
from .runtime import APILoop
from .recovery import recover
from .gateway import POSTING_WAIT_SECONDS


def run(root,source,ledger,gateway,billing,*,native=False,authorized=False,service=None,
        clean_units=('LC01','LC02'),revision='l-api-first-v1',loop_type=APILoop,fake_cpu_type=FakeCPU):
    root=Path(root).resolve();root.mkdir(parents=True,exist_ok=False)
    save(root/'ORIGIN.json',{'campaign_root':str(root),'source_root':str(Path(source).resolve())})
    inputs=prepare_inputs(source,root/'inputs');save(root/'INPUTS.json',inputs)
    cpu=TimedCPU(root,authorized=authorized,fit_limit=18) if native else fake_cpu_type()
    summary={'revision':revision,'status':'running','tier':'L','HTTP_fixture_only':gateway.model.fixture_only,
        'CPU_fixture_only':cpu.fixture_only,'units':{},'real_API_calls':0 if gateway.model.fixture_only else None,
        'old_bank_calls':ledger.historical.get('Bank_calls',302),'M_H':False,'threshold':.5,'threshold_tuning':False}
    def unit(uid,body,remaining=240.):
        ledger.start_unit(uid,remaining)
        if service:service.unit=uid
        timing=Timing();cpu.timing=timing;before_fits=cpu.fit_count;before_admit=cpu.admissions;before_records=len(cpu.records)
        try:
            with timing.span('whole_unit'):
                billing.start(uid)
                result=body(timing)
                ledger.require_time(uid)
                ledger.finish_unit(uid)
            summary['units'][uid]={'outcome':result.get('outcome','calibration_only'),'new_fits':cpu.fit_count-before_fits,
                'new_admissions':cpu.admissions-before_admit,'record_rels':[r['record_rel'] for r in cpu.records[before_records:]],
                'result':result}
            return result
        finally:
            if timing.events:
                doc=timing.document();doc['model_latency_is_scripted_not_API']=gateway.model.fixture_only
                save(root/(uid+'.TIMING.json'),doc)
    def initial(uid,timing,fault=False):
        e=loop_type(root/'runs'/uid,uid,cpu,ledger,gateway=gateway,unit=uid,timing=timing)
        try:
            e.initialize(inputs);accepted=e.run(fault=fault)
            if not accepted:return e.export('review_stop')
            if fault:return e.freeze()
            e.publish();return e.export('completed_execution')
        except Exception as exc:
            if not (e.directory/'RESULT.json').exists():
                e.export('failed_execution',error={'code':getattr(exc,'code',type(exc).__name__),'message':str(exc)})
            raise
        finally:e.close()
    try:
        for uid in clean_units:unit(uid,lambda t:initial(uid,t))
        require(any(summary['units'][u]['outcome']=='completed_execution' for u in clean_units),
            'Neither clean task completed; do not start injection','LAPI_CLEAN_GATE')
        frozen=unit('LI01.PREFIX',lambda t:initial('LI01.PREFIX',t,'INCIDENTAL_ROW_COUNT'))
        require(frozen['outcome']=='frozen_before_publish','No fault freeze reached','LAPI_FREEZE_GATE')
        for method in ('FULL','CONSERVATIVE','CUTOFF'):
            uid='LI01.'+method
            unit(uid,lambda t:recover(root/'runs/LI01.PREFIX',frozen,root/'runs'/uid,method,cpu,ledger,gateway,t,loop_type=loop_type),frozen['remaining_seconds'])
        # Repeat the exact final Planner request once, never feed its answer back.
        for suffix,parent in [('RAW',frozen),('CORRECTED',summary['units']['LI01.CUTOFF']['result'])]:
            uid='LI01.CAL_'+suffix
            source_call=next(c for c in parent['llm_calls'][parent['inherited_call_count']:] if c['role']=='Planner' and 'final' in c['raw'])
            def calibration(t):
                result=gateway.call('Planner',source_call['messages'],unit=uid,call_id=uid+'.llm.0000',exact_wire=source_call['wire_audit']['request'])
                evidence={'outcome':'calibration_only','source_call_id':source_call['call_id'],'analysis_only':True,
                    'same_wire_sha256':digest(result['wire_audit']['request']),
                    'equivalent_selection':result['payload']==source_call['raw'],'affects_recovery':False,
                    'source_payload':source_call['raw'],'repeated_payload':result['payload']}
                save(root/(uid+'.json'),evidence);return evidence
            unit(uid,calibration)
        summary.update(status='complete',training_jobs=cpu.fit_count,readmissions=cpu.admissions,
            fake_HTTP_generations=len(ledger.calls()) if gateway.model.fixture_only else 0,
            real_API_calls=0 if gateway.model.fixture_only else len(ledger.calls()))
        return summary
    except Exception as exc:
        ledger.quarantine(None,getattr(exc,'code',type(exc).__name__))
        summary.update(status='hard_stop',error={'code':getattr(exc,'code',type(exc).__name__),'message':str(exc)},training_jobs=cpu.fit_count)
        raise
    finally:
        save(root/'SUMMARY.json',summary);save(root/'LEDGER.json',ledger.snapshot())
        save(root/'BILLING.json',billing.snapshot() if hasattr(billing,'snapshot') else
            {'receipts':billing.receipts,'expected_nano':str(billing.expected),'provider_invoice_verified':False,
             'posting_wait_offsets_seconds':list(POSTING_WAIT_SECONDS),'posting_waits':billing.waits})
        if native:save(root/'CPU_RECORD_INDEX.json',[{'record_rel':r['record_rel'],'schema':r['record']['spec']['schema_version'],'job_id':r['record']['spec']['job_id']} for r in cpu.records])
