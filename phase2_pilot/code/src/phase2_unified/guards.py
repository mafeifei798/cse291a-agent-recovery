"""Persistently selected artifact guard; routing alone launches no computation.

Fixture and real CPU artifact formats use their existing independent gates.
The future CPU path hashes NPZ/NPY/joblib bytes and reads metadata; it does not
load a model or call fit/predict. The public offline runner fixes fixture mode.
"""
from sr_recovery_v2.common import ProtocolError

MODES=('fixture','cpu_artifacts')


class GuardDispatcher:
    def __init__(self,mode='fixture'):
        if mode not in MODES:raise ProtocolError('UNKNOWN_ARTIFACT_MODE')
        self.mode=mode

    def __call__(self,view,node_id,checkpoint='pre_dispatch',candidate=None,full=False,artifact_root=None):
        if view.get('metadata',{}).get('guard_artifact_mode')!=self.mode:
            raise ProtocolError('GUARD_ARTIFACT_MODE_BINDING_MISMATCH')
        expected=self.mode=='fixture'
        if candidate is not None:
            if candidate.get('fixture_only') is not expected:
                raise ProtocolError('MIXED_ARTIFACT_MODE_RESULT')
            artifacts={a['artifact_id']:a for a in view.get('artifacts',[])}
            receipts={r['receipt_id']:r for r in view.get('tool_receipts',[])}
            if any(artifacts.get(aid,{}).get('fixture_only') is not expected for aid in candidate.get('artifact_refs',[])):
                raise ProtocolError('MIXED_ARTIFACT_MODE_OUTPUT_ARTIFACT')
            if any(receipts.get(rid,{}).get('fixture_only') is not expected for rid in candidate.get('tool_receipt_ids',[])):
                raise ProtocolError('MIXED_ARTIFACT_MODE_TOOL_RECEIPT')
        if self.mode=='fixture':
            from sr_recovery_v2.guard import diagnose
        else:
            from sr_cpu_v2.guard import diagnose
        guard=diagnose(view,node_id,checkpoint=checkpoint,candidate=candidate,full=full,artifact_root=artifact_root)
        if guard.get('fixture_only') is not expected:
            raise ProtocolError('GUARD_MODE_EVIDENCE_MISMATCH')
        return guard

    def project(self,view,node_id,artifact_root):
        """Return agent metadata projection and separate trusted-tool bindings.

        CPU mode never JSON-parses raw CSV, NPY or estimator bytes into prompts.
        Only trusted tools get the full actual-ancestry artifact allowlist.
        """
        if view.get('metadata',{}).get('guard_artifact_mode')!=self.mode:
            raise ProtocolError('GUARD_ARTIFACT_MODE_BINDING_MISMATCH')
        if self.mode=='fixture':
            from sr_recovery_v2.fake import input_projection
            body=input_projection(view,node_id,artifact_root)
            return body,body['artifact_bindings']
        from copy import deepcopy
        from sr_recovery_v2.common import digest,canonical,node_map
        node=node_map(view['dag'])[node_id]
        results={r['result_id']:r for r in view['results']}
        registry={a['artifact_id']:a for a in view['artifacts']}
        sources={s['object_key']:s for s in view['sources']}
        parents=[results[view['state']['selected_by_node'][p]] for p in node['parents']]
        direct=[deepcopy(sources[k]) for k in node['direct_source_keys']]
        visible={aid for p in parents for aid in p['artifact_refs']}
        visible.update(aid for source in direct for aid in source['artifact_refs'])
        body={'run_id':view['state']['run_id'],'node_id':node_id,'request':deepcopy(view['task']['request']),
            'parent_inputs':[{'result_id':p['result_id'],'node_id':p['node_id'],'payload':deepcopy(p['payload']),
                'payload_digest':digest(p['payload']),'artifact_refs':deepcopy(p['artifact_refs']),
                'effective_reads':deepcopy(p['effective_reads'])} for p in parents],
            'direct_source_inputs':direct,'artifact_bindings':[deepcopy(registry[a]) for a in sorted(visible)]}
        body['rendered_messages']=[{'role':'system','content':'Follow the fixed structured contract from the cited metadata; raw files are trusted-tool inputs only.'},
            {'role':'user','content':canonical(body)}]
        allowed=set(visible);visited=set()
        def visit(result):
            if result['result_id'] in visited:return
            visited.add(result['result_id']);allowed.update(result['artifact_refs'])
            for source in result.get('input_snapshot',{}).get('direct_source_inputs',[]):allowed.update(source['artifact_refs'])
            for rid in result['parent_result_ids']:visit(results[rid])
        for parent in parents:visit(parent)
        return body,[deepcopy(registry[a]) for a in sorted(allowed)]
