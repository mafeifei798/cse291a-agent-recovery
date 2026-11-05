"""Explicit r6 prompts and tighter delivered-input constraints.

Only messages already selected by the runtime are inspected. No file, truth,
credential, budget or network lookup occurs here. The r5 output decoder and
the independent business guard remain unchanged. Columns are never repaired.
"""
from copy import deepcopy

from agent_recovery.contracts import canonical_json, digest, require
from agent_recovery.p3_transport import _strict_json
from .bank_gateway import BankTritonModel
from .triton import validate_payload

PROMPT_REVISION = 'bank-agent-prompts-r6'
OUTPUT_DECODER_REVISION = 'bank-agent-output-r5'
EXECUTOR_ORDER = ('write_config', 'train', 'write_report', 'publish')
MARKER = '\nContext contract for this call (' + PROMPT_REVISION + '):\n'


def _final_message(messages, agent_role):
    for message in reversed(messages[1:]):
        if message.get('role') != 'assistant' or message.get('agent_role') != agent_role:
            continue
        value = _strict_json(message['content'])
        if isinstance(value, dict) and set(value) == {'final'}:
            validate_payload(agent_role, value)
            return message, value['final']
    require(False, 'Current delivered upstream result is missing', 'BANK_R6_UPSTREAM')


def bound_context(role, messages):
    require(isinstance(messages, list) and messages and messages[0].get('role') == 'system',
            'Host system message required', 'BANK_R6_CONTEXT')
    host = _strict_json(messages[0]['content'])
    require(isinstance(host, dict) and host.get('role') == role,
            'Host role and requested role differ', 'BANK_R6_HOST_ROLE')
    context = dict(prompt_revision=PROMPT_REVISION, current_agent_role=role,
                   role_authority='host-call-not-historical-message-metadata')
    if role == 'Planner':
        source, facts = _final_message(messages, 'Analyst')
        features, unavailable = facts['feature_columns'], facts['unavailable_before_call']
        require(features and len(set(features)) == len(features)
                and all(isinstance(f, str) and f for f in features)
                and len(set(unavailable)) == len(unavailable),
                'Ambiguous delivered column list', 'BANK_R6_FACTS')
        permitted = [f for f in features if f not in unavailable]
        require(permitted, 'No delivered feature is available', 'BANK_R6_NO_FEATURES')
        context.update(analyst_message_id=source['message_id'], analyst_message_sha256=digest(source),
            declared_feature_columns=deepcopy(features),
            declared_unavailable_before_call=deepcopy(unavailable),
            permitted_feature_columns=permitted, label_column=facts['label_column'],
            selection_rule='nonempty ordered subset; no invented or remembered columns',
            provenance_scope='delivered Analyst message only; not independent task truth')
    elif role == 'Executor':
        source, contract = _final_message(messages, 'Planner')
        consumed = []
        for message in messages[1:]:
            if message.get('role') != 'tool' or message.get('agent_role') != 'Executor':
                continue
            value = _strict_json(message['content'])
            require(isinstance(value, dict) and value.get('tool') in EXECUTOR_ORDER,
                    'Unexpected Executor tool receipt', 'BANK_R6_TOOL_RECEIPT')
            consumed.append(value['tool'])
        require(len(consumed) <= len(EXECUTOR_ORDER) and tuple(consumed) == EXECUTOR_ORDER[:len(consumed)],
                'Executor receipts are repeated or out of order', 'BANK_R6_TOOL_ORDER')
        action = ({'tool': EXECUTOR_ORDER[len(consumed)], 'arguments': {}}
                  if len(consumed) < len(EXECUTOR_ORDER) else {'final': {'status': 'published'}})
        context.update(planner_message_id=source['message_id'], planner_message_sha256=digest(source),
            planner_contract_sha256=digest(contract),
            executed_feature_columns=deepcopy(contract['feature_columns']),
            completed_executor_tools=consumed, next_output=action,
            contract_rule='execute the supplied contract verbatim; never drop or add a column')
    else:
        require(role == 'Analyst', 'Unknown host role', 'BANK_R6_HOST_ROLE')
    return context


class BankPromptR6Model(BankTritonModel):
    """Opt-in revision; no existing Bank entry switches to it implicitly."""
    prompt_revision = PROMPT_REVISION

    def __init__(self, sender, **kwargs):
        requested = kwargs.pop('analyst_protocol_revision', OUTPUT_DECODER_REVISION)
        require(requested == OUTPUT_DECODER_REVISION,
                'r6 retains the strict r5 role decoder', 'BANK_R6_DECODER')
        super().__init__(sender, analyst_protocol_revision=OUTPUT_DECODER_REVISION, **kwargs)

    def context_protocol_text(self, role, prompt_messages):
        context = bound_context(role, prompt_messages)
        text = self.protocol_text(role)
        if role == 'Planner':
            text += (' The permitted_feature_columns list below is exhaustive for this task. '
                     'Choose a nonempty ordered subset of that list, not every column you know '
                     'from Bank. Do not add marital, contact or any other column unless it is '
                     'explicitly permitted here. The host rejects the whole out-of-scope contract; '
                     'it never clips your feature list. Preserve your selected column order. '
                     'You may still choose either approved model recipe.')
        elif role == 'Executor':
            text += (' You are Executor on this call. Analyst and Planner in the history are '
                     'other roles, not your identity. Return the next_output object below directly. '
                     'Do not copy source_role, agent_role, message_id or content into your response. '
                     'Do not invent a tool result. Only host-delivered Executor tool receipts '
                     'advance the tool sequence. The host rejects any wrong-role envelope.')
        return text + MARKER + canonical_json(context)

    def validate_model_payload(self, role, payload, trace):
        # Decode exactly as r5: a wrong actor never gets relabelled or unwrapped.
        value = super().validate_model_payload(role, payload, trace)
        context = bound_context(role, trace['sidecar']['original_messages'])
        trace['prompt_revision'] = PROMPT_REVISION
        if role == 'Planner':
            selected = value['final']['feature_columns']
            permitted = context['permitted_feature_columns']
            unexpected = [f for f in selected if f not in permitted]
            trace['planner_feature_constraint'] = dict(passed=bool(selected) and not unexpected,
                analyst_message_id=context['analyst_message_id'],
                analyst_message_sha256=context['analyst_message_sha256'],
                permitted_feature_columns=permitted, selected_feature_columns=deepcopy(selected),
                out_of_scope_columns=unexpected, columns_rewritten=False,
                independent_truth_consulted=False)
            require(bool(selected) and not unexpected,
                    'Planner selected a column outside its delivered input', 'BANK_R6_FEATURE_SCOPE')
        elif role == 'Executor':
            trace['executor_action_constraint'] = dict(passed=value == context['next_output'],
                host_role='Executor', next_output=context['next_output'],
                role_relabelled=False, action_rewritten=False)
            require(value == context['next_output'], 'Executor action is out of sequence', 'BANK_R6_TOOL_ORDER')
        return value
