"""Two explicit wire forms; execution authority always comes from the host."""
from copy import deepcopy
from agent_recovery.contracts import ContractError,digest,require
from agent_recovery.p3_transport import _strict_json
from .triton import validate_payload

REVISION='bank-agent-output-r5'

def decode_output(role,value):
    raw=deepcopy(value)
    wrapped=isinstance(raw,dict) and set(raw)=={'source_role','agent_role','message_id','content'}
    if wrapped:
        require(raw['source_role']=='assistant' and raw['agent_role']==role
                and isinstance(raw['message_id'],str) and 0<len(raw['message_id'])<=256
                and isinstance(raw['content'],str) and 0<len(raw['content'])<=2*1024*1024,
                'Response envelope does not match the bound role','CTX_MODEL_SCHEMA')
        try:value=_strict_json(raw['content'])
        except (ValueError,TypeError,RecursionError):
            raise ContractError('CTX_MODEL_SCHEMA','Envelope content is not strict JSON') from None
    payload=validate_payload(role,value)
    evidence=dict(revision=REVISION,wire_form='message-envelope' if wrapped else 'canonical',
        raw_payload_sha256=digest(raw),canonical_payload_sha256=digest(payload),
        host_role=role,model_message_id_ignored=wrapped,unwrap_depth=1 if wrapped else 0,
        role_tool_and_business_checks_unchanged=True)
    return payload,evidence
