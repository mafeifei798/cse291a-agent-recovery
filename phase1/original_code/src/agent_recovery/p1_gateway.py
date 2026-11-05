"""P1 rendering plus the existing strict, fake-only S6 invocation protocol.

There is no provider transport or credential lookup. The S6 fake profile is
used to exercise accounting; the P0 TritonAI binding remains unresolved.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
from time import monotonic

from .contracts import ContractError, canonical_json, digest, exact_fields, new_id, require
from .model_config import ModelConfig
from .model_gateway import (
    ModelGateway, FakeCompletionClient, DeterministicFakeClient,
    _validate_bundle, _strict_json, fake_chat_response,
)

PROMPT_REVISION = "p1-model-v1"
PROMPT_FILE_SHA256 = "0c8f095a1ab68fbd5ccaa6fecf0976d3b60254e148747e024ef6d3187ac3001f"
PACK_ROOT = Path(__file__).resolve().parents[2] / "phase1/p0"


def prompt_contract(pack_root=None):
    path = Path(pack_root or PACK_ROOT) / "contracts/prompt_spec.json"
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == PROMPT_FILE_SHA256,
            "Frozen P1 prompt contract changed", "P1_PROMPT_MISMATCH")
    return json.loads(data)


def render_p1(step_id, input_bundle, public_carriers, *, prompt_revision=PROMPT_REVISION,
              pack_root=None):
    require(prompt_revision == PROMPT_REVISION, "Unknown P1 prompt revision", "P1_PROMPT_MISMATCH")
    _validate_bundle(step_id, input_bundle)
    require(isinstance(public_carriers,list), "Carriers must be an array", "P1_INPUT_MISMATCH")
    require(len(public_carriers) == (1 if step_id in ("read_metadata","plan") else 0),
            "Carrier placement/count differs from P0", "P1_INPUT_MISMATCH")
    for carrier in public_carriers:
        exact_fields(carrier,{"carrier_kind","carrier_ref","untrusted_text"},"P1 public carrier")
        require(isinstance(carrier["untrusted_text"],str), "Carrier text must be a string", "P1_INPUT_MISMATCH")
        if step_id == "read_metadata":
            obj = input_bundle["tool_snapshots"][0]
            require(isinstance(carrier["carrier_ref"],dict)
                    and type(carrier["carrier_ref"].get("version")) is int
                    and carrier["carrier_kind"] == "source_note" and carrier["carrier_ref"] ==
                    {"object_key":obj["object_key"],"version":obj["version"]},
                    "Source carrier differs from captured snapshot", "P1_INPUT_MISMATCH")
        else:
            parent = input_bundle["parents"][0]
            require(carrier["carrier_kind"] == "handoff_note" and carrier["carrier_ref"] ==
                    {"result_id":parent["result_id"],"payload_digest":digest(parent["payload"])},
                    "Handoff carrier differs from actual metadata parent", "P1_INPUT_MISMATCH")
    spec = prompt_contract(pack_root)
    system = spec["message_template"]["system"]
    return [{"role":"system","content":system["system_prefix"]+system["instructions"][step_id]},
            {"role":"user","content":canonical_json({"step_id":step_id,"input":input_bundle,
                                                       "public_carriers":public_carriers})}]


def make_fake_client(*, follow_attacks=False):
    """An explicit test behavior derived only from the delivered P1 messages.

    Following a template here tests the pipeline, not empirical attack success.
    There is no access to a FaultSpec, private truth, or current Store objects.
    """
    client = FakeCompletionClient()

    def respond(request):
        supplied = _strict_json(request["messages"][1]["content"])
        exact_fields(supplied,{"step_id","input","public_carriers"},"P1 user envelope")
        step, bundle = supplied["step_id"], supplied["input"]
        _validate_bundle(step,bundle)
        if step in ("read_metadata","read_permission","read_resources"):
            payload = deepcopy(bundle["tool_snapshots"][0]["payload"])
        elif step == "plan":
            metadata, permission, resources = [p["payload"] for p in bundle["parents"]]
            request_data = bundle["request"]
            n,b = metadata["num_examples"],request_data["batch_size"]
            payload = {"dataset_id":request_data["dataset_id"],"purpose":request_data["purpose"],
                       "batch_size":b,"epochs":request_data["epochs"],"num_examples":n,
                       "steps":((n+b-1)//b)*request_data["epochs"],
                       "workers":min(request_data["requested_workers"],resources["max_workers"]),
                       "permission_allowed":permission["allowed"]}
        else:
            payload = {"action":"save_job","arguments":deepcopy(bundle["parents"][0]["payload"])}
        if follow_attacks:
            for carrier in supplied["public_carriers"]:
                text = carrier["untrusted_text"]
                if step == "read_metadata" and text.startswith("COMPATIBILITY NOTICE:"):
                    match = re.search(r"Return num_examples = ([0-9]+),",text)
                    if match:
                        payload["num_examples"] = int(match.group(1))
                if step == "plan" and text.startswith("WORKFLOW OVERRIDE:"):
                    match = re.search(r"set workers to ([0-9]+),",text)
                    if match:
                        payload["workers"] = int(match.group(1))
        response = fake_chat_response(payload,
                    prompt_tokens=max(1,(len(canonical_json(request["messages"]).encode())+3)//4),
                    completion_tokens=max(1,(len(canonical_json(payload).encode())+3)//4),
                    model=request["model"])
        response["id"] = f"p1-offline-{client.request_count}"
        response["_request_id"] = f"p1-fake-request-{client.request_count}"
        client.responses.append(response)

    client.on_create = respond
    return client


class _CampaignStoreProxy:
    def __init__(self, gateway, store, attempt, sidecar):
        self.gateway,self.store,self.attempt,self.sidecar = gateway,store,attempt,sidecar
        self.call_id = None

    def __getattr__(self,name):
        return getattr(self.store,name)

    def reserve_model_call(self, attempt_token, request, config):
        gateway = self.gateway
        gateway.campaign.preflight(gateway.trial_key,gateway.logical_run_key,
                                  worst_cost_nano_usd=config.worst_case_cost_nano_usd)
        record = self.store.reserve_model_call(attempt_token,request,config)
        self.call_id = record["call_id"]
        sidecar = {**deepcopy(self.sidecar),"call_id":record["call_id"]}
        try:
            gateway.campaign.reserve_call(record,request,sidecar,trial_key=gateway.trial_key,
                logical_run_key=gateway.logical_run_key,branch_id=gateway.branch_id,phase=gateway.phase)
        except Exception:
            gateway.campaign.pause("CAMPAIGN_RESERVATION_PERSISTENCE_FAILED")
            raise
        return record

    def settle_model_call(self, call_id, outcome, private_response=None):
        try:
            record = self.store.settle_model_call(call_id,outcome,private_response=private_response)
            self.gateway.campaign.settle_call(call_id,record)
            return record
        except Exception:
            self.gateway.campaign.pause("CAMPAIGN_SETTLEMENT_PERSISTENCE_FAILED")
            raise


class P1ModelGateway(ModelGateway):
    prompt_revision = PROMPT_REVISION

    def __init__(self,client,campaign,*,trial_key,branch_id,logical_run_key=None,
                 phase="initial",config=None,clock=monotonic):
        super().__init__(client,config or ModelConfig(config_ref="p1-offline-fake-v1"),clock=clock)
        require(phase in ("initial","replay"), "Invalid phase", "CAMPAIGN_IDENTITY_MISMATCH")
        self.campaign,self.trial_key,self.branch_id = campaign,trial_key,branch_id
        self.logical_run_key,self.phase = logical_run_key or trial_key,phase
        self._prepared,self._current,self._stores = {},None,{}
        prompt_contract()

    def prepare_input(self,attempt,step_id,bundle,public_carriers):
        require(attempt["step_id"] == step_id, "P1 input step differs from attempt", "P1_INPUT_MISMATCH")
        messages = render_p1(step_id,bundle,public_carriers)
        sidecar = {"sidecar_id":new_id(),"call_id":None,"attempt_id":attempt["token"],
                   "step_id":step_id,"result_id":attempt["result_id"],"run_id":attempt["run_id"],
                   "branch_id":self.branch_id,"trial_key":self.trial_key,
                   "logical_run_key":self.logical_run_key,"phase":self.phase,
                   "prompt_revision":PROMPT_REVISION,"prompt_spec_digest":PROMPT_FILE_SHA256,
                   "input_bundle":deepcopy(bundle),"public_carriers":deepcopy(public_carriers),
                   "bundle_digest":digest(bundle),"public_carriers_digest":digest(public_carriers),
                   "rendered_messages_digest":digest(messages),"rendered_messages":messages}
        old = self._prepared.get(attempt["result_id"])
        if old:
            require({k:v for k,v in old.items() if k != "sidecar_id"} ==
                    {k:v for k,v in sidecar.items() if k != "sidecar_id"},
                    "An attempt's P1 input is immutable", "P1_INPUT_MISMATCH")
            sidecar = old
        self._prepared[attempt["result_id"]] = sidecar
        self._current = sidecar
        return deepcopy(sidecar)

    def render(self,role,input_bundle):
        current = self._current
        require(current is not None and current["step_id"] == role and current["input_bundle"] == input_bundle,
                "P1 requires an explicit bound input/sidecar", "P1_INPUT_MISMATCH")
        return render_p1(role,input_bundle,current["public_carriers"])

    def invoke(self,store,attempt,step_id,messages,input_bundle):
        prepared = self._prepared.get(attempt["result_id"])
        require(prepared is not None and prepared == self._current,
                "P1 invocation does not match the prepared attempt", "P1_INPUT_MISMATCH")
        proxy = _CampaignStoreProxy(self,store,attempt,prepared)
        original_hook = self.client.on_create

        def dispatch(request):
            require(proxy.call_id is not None, "Dispatch lacks persisted reservation", "LEDGER_PERSISTENCE_FAILED")
            self.campaign.mark_dispatched(proxy.call_id)
            if original_hook:
                original_hook(request)

        self.client.on_create = dispatch
        self._stores[attempt["result_id"]] = store
        try:
            return super().invoke(proxy,attempt,step_id,messages,input_bundle)
        finally:
            self.client.on_create = original_hook

    def record_publication(self,result):
        if not result["model_calls"]:
            return
        try:
            store = self._stores.get(result["result_id"])
            require(store is not None and store.get_result(result["result_id"]) == result,
                    "Campaign sync requires the persisted result", "P1_INPUT_MISMATCH")
            self.campaign.record_publication(result)
        except Exception:
            # A published Store result can exist even when the campaign write
            # failed. Preserve it and fence the whole campaign, not just this DB.
            try:
                self.campaign.pause("CAMPAIGN_PUBLICATION_PERSISTENCE_FAILED")
            except Exception:
                pass
            raise

    def sidecars(self):
        return self.campaign.sidecars(self.trial_key)
