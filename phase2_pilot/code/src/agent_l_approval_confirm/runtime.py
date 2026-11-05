"""Confirm an old approval, then execute it without spending a second round."""
from copy import deepcopy
import json
import math

from agent_l_feedback_replay.runtime import approved_stage, SOURCE_KEYS
from agent_l_replay_live.runtime import ReplayLoop as PriorLoop
from agent_l_feedback.runtime import FeedbackLoop
from agent_l_v1.runtime import AgentLoop
from agent_l_v1.core import BUNDLES, RECIPES, REGISTRY, TASK
from agent_recovery.contracts import require
from sr_recovery_v2.common import canonical, digest
from .model import NORMAL, CONFIRM, validate_confirmation

CONFIRMATION_FILE = 'work/approval-confirmation.json'


class ReplayLoop(PriorLoop):
    def __init__(self, *args, **kwargs):
        super().__init__(*args,**kwargs)
        self.confirmation_binding = None
        self.doc.update(feedback_protocol_revision='approval-confirm-v1',
                        real_entry_revision='approval-confirm-offline-v1',approval_confirmation_events=[])

    def _call(self, role, messages, *, fault=False):
        messages = deepcopy(messages)
        if role == 'Reviewer':
            system = json.loads(messages[0]['content'])
            system['review_operation'] = CONFIRM if self.replay_stage == 'approval_confirmation' else NORMAL
            if system['review_operation'] == CONFIRM:
                require(self.confirmation_binding is not None,'Missing controller confirmation binding','AC_CONFIRM_BINDING')
                system['confirmation_binding'] = deepcopy(self.confirmation_binding)
            messages[0]['content'] = canonical(system)
        return super()._call(role,messages,fault=fault)

    def candidate_context(self, role, inputs):
        if self.replay_stage is None:
            return FeedbackLoop.candidate_context(self,role,inputs)
        self.check_approval_sources()
        registry_ref,registry = self.read(REGISTRY)
        task_ref,task = self.read(TASK)
        require(registry == {'bundles':BUNDLES,'recipes':RECIPES},'Registry changed','FR_MENU')
        analyst,bound = self.doc['active']['analyst'],self.doc['active']['contract']
        eligible = set(analyst['payload']['final']['eligible_features'])
        candidates = [{'selection':{'bundle':b,'recipe':r},'feature_columns':deepcopy(columns),
                       'recipe_definition':deepcopy(recipe)} for b,columns in registry['bundles'].items()
                      if len(columns) <= task['feature_cap'] and set(columns) <= eligible
                      for r,recipe in registry['recipes'].items()]
        tried = deepcopy(self.approval['tried_before_approval'])
        payload = {'current_selection':deepcopy(bound['payload']['selection']),
            'legal_candidates':candidates,'tried_selections':tried,
            'untried_candidates':[c['selection'] for c in candidates if c['selection'] not in tried],
            'feature_cap':task['feature_cap'],'source_ref':registry_ref,
            'logical_adjustment_id':self.approval['logical_adjustment_id'],
            'origin_approval_id':self.approval['origin_approval_id'],
            'normal_adjustments_remaining':0,'normal_adjustment_already_spent':True}
        parents = [analyst['result_id'],bound['result_id']]
        suggested = self.approval['original_feedback']['payload']['final']['requested_selection']
        require(suggested in payload['untried_candidates'],'Original approval is no longer legal','FR_MENU')
        if role == 'Reviewer':
            require(self.replay_stage == 'approval_confirmation','Wrong confirmation stage','AC_OPERATION')
            screen,view = next((n,v) for kind,n,v in inputs if kind == 'screen')
            ap,base = view['metrics']['average_precision'],view['constant_AP']
            require(math.isfinite(ap) and math.isfinite(base) and base > 0
                    and ap < task['quality_AP_ratio_goal']*base,
                    'Original approval condition no longer holds','FR_APPROVAL_CONDITION')
            payload.update(operation=CONFIRM,context_kind='approval_confirmation',
                approval_id=self.approval['origin_approval_id'],evidence_id=screen['result_id'],
                approved_selection=deepcopy(suggested),allowed_actions=['confirm','stop'],
                current_average_precision=ap,current_constant_AP=base,
                original_adjustment_condition_still_holds=True,new_adjustment_authorized=False)
            parents.append(screen['result_id'])
        else:
            require(self.replay_stage == 'adjustment_replay','Wrong replay stage','AC_OPERATION')
            confirmation = next(n for kind,n,_ in inputs if kind == 'confirmed_approval')
            require(confirmation['payload']['final']['operation'] == CONFIRM
                    and confirmation['payload']['final']['action'] == 'confirm',
                    'Confirmed old approval required','AC_CONFIRM_BINDING')
            payload.update(operation='execute_confirmed_approval',context_kind='confirmed_adjustment_handoff',
                confirmation_result_id=confirmation['result_id'],approved_adjustment_in_progress=True,
                additional_adjustments_remaining=0,reviewer_suggestion=deepcopy(suggested))
            parents.append(confirmation['result_id'])
        context = self.node('confirmation_options' if role == 'Reviewer' else 'feedback_options',
                            'controller',payload,parents,[registry_ref,task_ref])
        self.doc['feedback_contexts'].append({'role':role,'node_id':context['result_id'],'payload':deepcopy(payload)})
        return context,payload

    def role(self, role, inputs=(), *, fault=False):
        confirm = role == 'Reviewer' and self.replay_stage == 'approval_confirmation'
        handoff = role == 'Planner' and any(k == 'confirmed_approval' for k,_,_ in inputs)
        if not (confirm or handoff):
            return super().role(role,inputs,fault=fault)
        context,payload = self.candidate_context(role,inputs)
        kind = 'approval_confirmation' if confirm else 'confirmed_adjustment_handoff'
        result = AgentLoop.role(self,role,[(kind,context,payload),*inputs],fault=fault)
        self.doc['feedback_contexts'][-1]['decision_node_id'] = result['result_id']
        return result

    def replay_binding(self, analyst, initial, screen):
        self.check_approval_sources()
        require(initial['payload']['contracts'] == self.approval['initial_contract']['payload']['contracts'],
                'Initial contract changed','FR_INITIAL_CONTRACT_CHANGED')
        body = {'operation':CONFIRM,'approval_digest':digest(self.approval),
                'facts':analyst['payload'],'contract':initial['payload'],
                'analyst_id':analyst['result_id'],'initial_contract_id':initial['result_id'],
                'screen_result_id':screen['result_id'],'screen_producer_id':screen['payload']['producer_id'],
                'screen_contract':screen['payload']['contract'],'metrics':screen['payload']['metrics'],
                'sources':self.approval['source_bindings']}
        return digest(body)

    def confirm_existing(self, analyst, initial, screen):
        binding = self.replay_binding(analyst,initial,screen)
        expected = {'approval_id':self.approval['origin_approval_id'],
                    'evidence_id':screen['result_id'],'logical_adjustment_id':self.approval['logical_adjustment_id'],
                    'input_digest':binding}
        cached = self.ledger.confirmation(self.unit,self.approval,binding)
        if cached:
            reviewed = cached['confirmation_node']
            actual = next((n for n in self.store.snapshot()['nodes'] if n['result_id'] == reviewed['result_id']),None)
            require(actual == reviewed,'Cached confirmation node changed','AC_CONFIRM_BINDING')
        else:
            self.replay_stage,self.confirmation_binding = 'approval_confirmation',expected
            try:
                reviewed = self.role('Reviewer',[
                    ('contract',initial,{'selection':initial['payload']['selection']}),
                    ('screen',screen,self.screen_view(initial,screen))])
                validate_confirmation(reviewed['payload'],expected)
                self.check_approval_sources()
                record = {'logical_adjustment_id':self.approval['logical_adjustment_id'],
                    'origin_approval_id':self.approval['origin_approval_id'],'unit':self.unit,
                    'operation':CONFIRM,'input_digest':binding,'confirmation_node':deepcopy(reviewed),
                    'normal_adjustments_consumed':0,'optimization_spent_before':1,'optimization_spent_after':1}
                self.ledger.confirmation(self.unit,self.approval,binding,record)
                current = self.store.snapshot()['files'].get(CONFIRMATION_FILE)
                self.store.write(CONFIRMATION_FILE,canonical(reviewed['payload']['final']),current,reviewed['result_id'])
                self.doc['approval_confirmation_events'].append(deepcopy(record))
            finally:
                self.replay_stage,self.confirmation_binding = None,None
        choice = validate_confirmation(reviewed['payload'],expected)['final']
        require(choice['action'] == 'confirm','Existing approval explicitly declined','AC_CONFIRM_DECLINED')
        self.doc['active']['approval_confirmation'] = reviewed
        return reviewed,binding

    def replay_approved(self, analyst, initial_bound, screen):
        reviewed,binding = self.confirm_existing(analyst,initial_bound,screen)
        cached = self.ledger.replay(self.unit,self.approval)
        if cached:
            require(cached['input_digest'] == binding and cached['confirmation_result_id'] == reviewed['result_id'],
                    'Replay inputs changed','FR_REPLAY_BINDING')
            actual = next((n for n in self.store.snapshot()['nodes'] if n['result_id'] == cached['bound']['result_id']),None)
            require(actual == cached['bound'],'Cached replay contract changed','FR_REPLAY_BINDING')
            return deepcopy(cached['bound'])
        self.replay_stage = 'adjustment_replay'
        try:
            planner = self.role('Planner',[
                ('facts',analyst,analyst['payload']['final']),
                ('confirmed_approval',reviewed,reviewed['payload']['final'])])
            bound = self.bind(planner)
            require(self.doc['optimization_spent'] == 1,'Adjustment allowance reset','FR_QUOTA')
            record = {'logical_adjustment_id':self.approval['logical_adjustment_id'],'unit':self.unit,
                'input_digest':binding,'bound':deepcopy(bound),'origin_approval_id':self.approval['origin_approval_id'],
                'confirmation_result_id':reviewed['result_id'],'operation':'execute_confirmed_approval',
                'stage':'adjustment-1','new_normal_adjustments_consumed':0,
                'optimization_spent_before':1,'optimization_spent_after':1}
            self.ledger.replay(self.unit,self.approval,record)
            self.doc['stage_replays'].append(deepcopy(record))
            return bound
        finally:
            self.replay_stage = None
