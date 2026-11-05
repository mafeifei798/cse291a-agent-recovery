"""Explicit synthetic fixtures for the Bank launch entry; no credentials."""
from datetime import datetime,timedelta,timezone
import json
from pathlib import Path

from agent_recovery.contracts import digest
from agent_recovery.p3_transport import FakeHTTPSender,fake_http_response
from .bank_launch import BankLaunchConfig,BankLaunchPermit
from .runtime import ScriptedAgent
from .triton import MODEL


def fixture_config(root):
    root=Path(root).resolve()
    expiry=(datetime.now(timezone.utc)+timedelta(hours=2)).strftime('%Y-%m-%dT%H:%M:%SZ')
    return BankLaunchConfig(authority_path=str(root/'authority.sqlite'),runs_root=str(root/'runs'),
        route_input_billable_cap=500000,route_output_billable_cap=768,
        input_nano_usd_per_token=150,output_nano_usd_per_token=500,
        price_evidence_sha256=digest('fixture:bank-prices'),route_evidence_sha256=digest('fixture:bank-route'),
        source_proof_expires_utc=expiry,price_evidence_ref='fixture:bank-prices',
        route_evidence_ref='fixture:bank-route',source_proof_status='synthetic',
        additional_nano_usd_per_call=0,all_billable_components_confirmed=True)


def fixture_permit(config):
    return BankLaunchPermit(authorized=True,config_sha256=config.config_sha256,
        authority_path=config.authority_path,history_plan_sha256=config.history_plan_sha256,
        price_evidence_sha256=config.price_evidence_sha256,route_evidence_sha256=config.route_evidence_sha256,
        price_cap_confirmed=True,route_cap_confirmed=True,authority_confirmed=True,
        credential_read_authorized=True,key_read_authorized=False,training_authorized=False,
        real_requests_authorized=False,credential_source='synthetic',
        authorization_reference='fixture:explicit-offline-launch-only',expires_utc=config.source_proof_expires_utc)


def budget_binding(config,*,simulated=True):
    return dict(input_nano_usd_per_token=config.input_nano_usd_per_token,
        output_nano_usd_per_token=config.output_nano_usd_per_token,
        cached_input_nano_usd_per_token=None,price_evidence=config.price_evidence_ref,
        simulated=simulated,max_input_tokens=4000,max_output_tokens=768,
        model=config.model,endpoint=config.endpoint)


def scripted_sender(counter):
    requests=[]
    def respond(wire):
        request=json.loads(wire.body)
        original=[]
        for at,message in enumerate(request['messages']):
            if at==0:
                original.append(dict(role='system',content=message['content'].split('\n\n',1)[0]))
            else:
                data=json.loads(message['content'])
                original.append(dict(role=data['source_role'],agent_role=data['agent_role'],content=data['content']))
        role=json.loads(original[0]['content'])['role']
        payload=ScriptedAgent().respond(role,original)
        requests.append(request)
        return fake_http_response(payload,model=MODEL,request_id='fixture-bank-'+str(len(requests)),
            prompt_tokens=counter.estimate_request(request).prompt_tokens,completion_tokens=50)
    return FakeHTTPSender([respond]*20),requests
