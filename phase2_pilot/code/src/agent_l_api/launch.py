"""Capability gate precedes credential construction, budget creation or sends."""
from dataclasses import asdict
import json
from pathlib import Path

from agent_recovery.contracts import require
from agent_recovery.p3_transport import FakeHTTPSender,BoundTokenCounter,P3Binding,LiveRuntimePermit
from agent_recovery.p3_deadline import BoundedHTTPSender
from context_cutoff.token_counter import MultiMessageGLM53TokenCounter
from .protocol import Config,Permit,history,MODEL
from .budget import Budget,FakeClock
from .model import Model,bound_counter
from .gateway import Gateway,Billing
from .fixtures import Service
from .runner import run


def launch(output,*,source_root,extension_root,history_path,native=False,authorized=False,
           live=False,config_path=None,permit_path=None,acceptance=None,catalog=None):
    root=Path(output).resolve();source=Path(source_root).resolve();extension=Path(extension_root).resolve()
    require(not root.exists(),'No in-place run/retry','LAPI_OUTPUT_EXISTS')
    config=Config() if not live else Config(**json.loads(Path(config_path).read_text()))
    permit=Permit() if not live else Permit(**json.loads(Path(permit_path).read_text()))
    h=history(history_path)
    if live:
        require(native and authorized,'Live tasks need explicit CPU permit','LAPI_LIVE_PERMISSION')
        permit.validate_live(config,extension,acceptance,catalog)
    else:require(config.simulated,'Fake path cannot adopt live capability','LAPI_LIVE_PERMISSION')
    local=MultiMessageGLM53TokenCounter.from_directory(extension/'sr_v2/v0/environment/tokenizer_files')
    counter,statistics=bound_counter(local,simulated=not live)
    root.mkdir(parents=True)
    ledger=Budget(root/'authority.sqlite',config=config,historical=h,clock=None if live or native else FakeClock())
    service=None
    try:
        if live:
            from br7_live.credentials import DataHubCredentialProvider
            provider=DataHubCredentialProvider(str(root/'CREDENTIAL_ACCESS.jsonl'))
            b=P3Binding(binding_ref='l-api-'+config.sha256,model=MODEL,allowed_response_models=(MODEL,),simulated=False,
                real_requests_authorized=True,input_nano_usd_per_token=150,output_nano_usd_per_token=500,
                price_evidence='l-api-catalog:'+config.catalog_sha256,capability_evidence='l-api-native:'+config.acceptance_sha256,
                token_admission_evidence=counter.evidence_ref,reasoning_effort='low',temperature=0,output_token_parameter='max_tokens',
                supported_parameters=('model','messages','n','stream','response_format','max_tokens','temperature','reasoning_effort'))
            rp=LiveRuntimePermit(True,b.binding_digest,permit.authorization_reference)
            model=Model(BoundedHTTPSender(),token_counter=counter,token_statistics=statistics,live_binding=b,
                runtime_permit=rp,credential_provider=provider,timeout_s=120)
            billing=Billing(ledger,credential_provider=provider)
            # This one catalog request was made by the separately permitted
            # preparation step, not repeated here. Import it into the GET cap.
            seq,_=ledger.begin_http('CATALOG','GET','catalog','CATALOG.IMPORT');ledger.end_http(seq)
        else:
            service=Service(local)
            post=FakeHTTPSender([service.post]*62);get=FakeHTTPSender([service.get]*95)
            model=Model(post,token_counter=counter,token_statistics=statistics,timeout_s=120)
            billing=Billing(ledger,fake_sender=get)
            seq,_=ledger.begin_http('CATALOG','GET','catalog','CATALOG.FAKE')
            from agent_recovery.p3_transport import HTTPRequest
            get.send(HTTPRequest('GET','https://tritonai-api.ucsd.edu/public/model_hub',b'',12));ledger.end_http(seq)
        gateway=Gateway(model,ledger,billing)
        return run(root/'campaign',source,ledger,gateway,billing,native=native,authorized=authorized,service=service)
    finally:ledger.close()
