"""Independent entry; fake HTTP + fake CPU by default, no credential fallback."""
import json
from decimal import Decimal
from pathlib import Path
from agent_recovery.contracts import require
from agent_recovery.p3_transport import FakeHTTPSender,P3Binding,LiveRuntimePermit
from agent_recovery.p3_deadline import BoundedHTTPSender
from agent_l_api.budget import FakeClock
from agent_l_api.gateway import Gateway
from agent_l_api.model import Model,bound_counter
from agent_l_api.fixtures import Service
from agent_l_api.runner import run
from context_cutoff.token_counter import MultiMessageGLM53TokenCounter
from .protocol import Config,Permit,history,MODEL
from .budget import Budget
from .billing import Billing

def launch(output,*,source_root,history_path,live=False,native=False,authorized=False,
           config_path=None,permit_path=None,acceptance=None,catalog=None,models=None,fixture_counter=False,
           profile='batch-v1'):
    require(profile in ('batch-v1','resume-v2','feedback-v3'),'Unknown entry profile','LB_PROFILE')
    config_type,permit_type,history_loader,budget_type,model_type=Config,Permit,history,Budget,Model
    clean_units=('LC03','LC02');revision='l-api-batch-v1';call_cap=61
    service_type=Service;run_options={}
    if profile=='resume-v2':
        from agent_l_resume.protocol import Config as config_type,Permit as permit_type,history as history_loader
        from agent_l_resume.budget import Budget as budget_type
        from agent_l_resume.model import Model as model_type
        clean_units=('LC02',);revision='l-api-resume-v2';call_cap=52
    elif profile=='feedback-v3':
        from agent_l_feedback_api.protocol import Config as config_type,Permit as permit_type,history as history_loader
        from agent_l_feedback_api.budget import Budget as budget_type
        from agent_l_feedback.model import Model as model_type
        from agent_l_feedback.runtime import FeedbackLoop
        from agent_l_feedback_api.fixtures import CampaignService as service_type,CampaignCPU
        clean_units=('LC04',);revision='l-feedback-api-v1';call_cap=52
        run_options={'loop_type':FeedbackLoop,'fake_cpu_type':CampaignCPU}
    root=Path(output).resolve();source=Path(source_root).resolve()
    require(not root.exists(),'Independent output must be new','LB_OUTPUT_EXISTS')
    config=config_type() if not live else config_type(**json.loads(Path(config_path).read_text()))
    if live:
        require(native and authorized and config.output_root==str(root),'New explicit CPU/output capability required','LB_LIVE_PERMISSION')
        permit_type(**json.loads(Path(permit_path).read_text())).validate_live(config,source,acceptance,catalog,models)
    else:require(not native or authorized,'Native CPU needs explicit permission','LB_CPU_PERMISSION')
    h=history_loader(history_path,source)
    if fixture_counter:
        require(not live and not native,'Fixture counter cannot authorize live/native work','LB_FIXTURE_COUNTER')
        from agent_l_api.acceptance import SyntheticCounter
        local=SyntheticCounter()
    else:local=MultiMessageGLM53TokenCounter.from_directory(source/'sr_v2/v0/environment/tokenizer_files')
    counter,statistics=bound_counter(local,simulated=not live)
    root.mkdir(parents=True,exist_ok=False)
    ledger=budget_type(root/'authority.sqlite',config=config,historical=h,clock=None if native or live else FakeClock())
    billing=None;service=None;business=None;error=None
    def write(name,value):(root/name).write_text(json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n')
    try:
        if live:
            from br7_live.credentials import DataHubCredentialProvider
            provider=DataHubCredentialProvider(str(root/'CREDENTIAL_ACCESS.jsonl'))
            binding=P3Binding(binding_ref='l-batch-'+config.sha256,model=MODEL,allowed_response_models=(MODEL,),
                simulated=False,real_requests_authorized=True,input_nano_usd_per_token=150,output_nano_usd_per_token=500,
                price_evidence='l-batch:'+config.catalog_sha256,capability_evidence='l-batch:'+config.acceptance_sha256,
                token_admission_evidence=counter.evidence_ref,reasoning_effort='low',temperature=0,output_token_parameter='max_tokens',
                supported_parameters=('model','messages','n','stream','response_format','max_tokens','temperature','reasoning_effort'))
            model=model_type(BoundedHTTPSender(),token_counter=counter,token_statistics=statistics,live_binding=binding,
                runtime_permit=LiveRuntimePermit(True,binding.binding_digest,permit_type(**json.loads(Path(permit_path).read_text())).authorization_reference),
                credential_provider=provider,timeout_s=120)
            billing=Billing(ledger,credential_provider=provider)
        else:
            service=service_type(local);service.spend=Decimal(h['expected_key_spend_nano'])
            model=model_type(FakeHTTPSender([service.post]*call_cap),token_counter=counter,token_statistics=statistics)
            billing=Billing(ledger,fake_sender=FakeHTTPSender([service.get]*4))
        billing.begin()
        gateway=Gateway(model,ledger,billing)
        business=run(root/'campaign',source,ledger,gateway,billing,native=native,authorized=authorized,
            service=service,clean_units=clean_units,revision=revision,**run_options)
        return business
    except Exception as exc:
        error={'code':getattr(exc,'code',type(exc).__name__),'message':str(exc)}
        raise
    finally:
        try:
            if billing is not None and ledger.batch_state()=='running':billing.finish()
            elif ledger.batch_state()=='initial':ledger.batch_transition('preflight_failed',{'error':error})
            write('BATCH_ACCOUNTING.json',billing.snapshot() if billing else {'mode':'preflight_failed','error':error})
            write('LEDGER.json',ledger.snapshot())
            write('ENTRY_RESULT.json',{'business_status':business['status'] if business else 'stopped',
                'accounting_status':ledger.batch_state(),'error':error,'old_LC01_restarted':False,
                'real_API_calls':0 if config.simulated else len(ledger.calls()),'CPU_fixture_only':not native,
                'historical_Bank_attempts':h['Bank_calls'],'old_LC03_restarted':False,
                'old_LC02_restarted':False,
                'old_holds_released':False,'automatic_expansion_allowed':False,
                'external_preflight_GET_reserve':2})
        finally:ledger.close()
