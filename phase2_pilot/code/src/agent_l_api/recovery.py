"""Public L recovery path; no validation-only probes or FULL dependency scan."""
from pathlib import Path
from agent_l_v1.core import DATA,CODE
from context_cutoff.store import FileProvenanceStore
from agent_recovery.contracts import require
from sr_recovery_v2.common import digest,closure_ids
from .runtime import APILoop


def recover(prefix,frozen,dest,method,cpu,ledger,gateway,timing,*,loop_type=APILoop):
    require(method in ('FULL','CONSERVATIVE','CUTOFF'),'Unknown recovery','LAPI_METHOD')
    require(digest({k:v for k,v in frozen.items() if k!='checkpoint_sha256'})==frozen['checkpoint_sha256'],'Freeze changed','LAPI_FREEZE')
    with timing.span('freeze_validation_and_clone'):
        with FileProvenanceStore(Path(prefix)/'store.sqlite',Path(prefix)/'artifacts') as source:
            require(source.snapshot()==frozen['store_snapshot'],'Frozen store changed','LAPI_FREEZE')
            source.save_to(dest)
    unit='LI01.'+method
    e=loop_type(dest,unit,cpu,ledger,gateway=gateway,unit=unit,timing=timing,document=frozen)
    try:
        old=frozen['active']['contract'];before=cpu.fit_count
        roots={n['result_id'] for n in frozen['store_snapshot']['nodes'] if n['role']=='Analyst'}
        invalid=[]
        if method!='FULL':
            with timing.span('dependency_invalidation'):invalid=closure_ids(roots,frozen['store_snapshot']['nodes'])
        analyst=e.role('Analyst');e.doc['active']['analyst']=analyst
        planner=e.role('Planner',[('facts',analyst,analyst['payload']['final'])]);bound=e.bind(planner)
        equal=bound['payload']['contracts']==old['payload']['contracts']
        data_ref,data=e.read(DATA);code_ref,_=e.read(CODE);screen=None;supplier=None
        if method=='CUTOFF' and equal:
            for k in ('screen','final'):
                origin=frozen['active'][k]
                require(set(origin['parent_result_ids'])<={old['result_id'],frozen['active']['review']['result_id']},'Bypass dependency','LAPI_OTHER_INPUT')
                require(all(frozen['store_snapshot']['files'].get(r['file_id'])==r for r in origin['file_reads']),
                    'Other source is stale','LAPI_OTHER_INPUT')
            origin=frozen['active']['screen']
            model=cpu.admit(origin['payload'],bound['payload']['contracts']['screen'],'screen',data,e.deadline)
            screen=e.node('admission','executor',model,[bound['result_id']],[data_ref,code_ref],origin_result_id=origin['result_id'])
            def supplier(b,r):
                origin=frozen['active']['final']
                model=cpu.admit(origin['payload'],b['payload']['contracts']['final'],'final',data,e.deadline)
                return e.node('admission','executor',model,[b['result_id'],r['result_id']],[data_ref,code_ref],origin_result_id=origin['result_id'])
        accepted=e.finish(analyst,bound,retained_screen=screen,retained_final=supplier)
        if accepted:e.publish()
        retained=[e.doc['active'][k]['payload']['producer_id'] for k in ('screen','final') if accepted and
            e.doc['active'][k]['payload']['producer_id']==frozen['active'][k]['payload']['producer_id']]
        decision={'method':method,'checkpoint_sha256':frozen['checkpoint_sha256'],'faulty_result_id':frozen['faults'][-1]['faulty_result_id'],
            'equivalent_contracts':equal,'cutoff_rechecks':int(method=='CUTOFF'),'new_fit_count':cpu.fit_count-before,
            'retained_producer_ids':retained,'invalidated_result_ids':invalid,
            'normal_remaining_before':1-frozen['optimization_spent'],'normal_remaining_after':1-e.doc['optimization_spent'],
            'validation_only_probes_in_timed_path':False,'FULL_dependency_scan':False}
        return e.export('completed_execution' if accepted else 'review_stop',recovery=decision)
    except Exception as exc:
        if not (e.directory/'RESULT.json').exists():
            e.export('failed_execution',error={'code':getattr(exc,'code',type(exc).__name__),'message':str(exc)})
        raise
    finally:e.close()
