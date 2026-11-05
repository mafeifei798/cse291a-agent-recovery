"""Permitted Bank transport with an explicit unverified-token-count mode.

The ordinary 4K request ceiling is local policy. It is NOT evidence about
server tokenization. BankPilotBudget separately reserves the complete pinned
route liability, and the credential gate checks that reserve at dispatch.
"""
from copy import deepcopy
from time import monotonic

from agent_recovery.contracts import require
from agent_recovery.p3_transport import BoundTokenCounter, P3Binding, LiveRuntimePermit, fixture_binding
from .bank_launch import (ADMISSION_MODE, CONSERVATIVE_ADMISSION_MODE, BankLaunchConfig,
                          BankLaunchPermit, BankCredentialGate)
from .bank_pilot_budget import BankPilotBudget
from .triton import TritonAgentModel, MODEL


class BankTritonModel(TritonAgentModel):
    def __init__(self, sender, *, config, permit, ledger, local_counter, credential_provider,
                 analyst_protocol_revision='legacy'):
        require(isinstance(config, BankLaunchConfig) and isinstance(permit, BankLaunchPermit)
                and isinstance(ledger, BankPilotBudget), 'Bound Bank launch objects required', 'BANK_ENTRY')
        self.bank_config, self.bank_permit, self.bank_ledger = config, permit, ledger
        require(analyst_protocol_revision in ('legacy','bank-analyst-output-r3','bank-agent-contract-r4','bank-agent-output-r5'),
                'Unknown Analyst protocol revision','BANK_PROTOCOL')
        self.analyst_protocol_revision=analyst_protocol_revision
        fixture = sender.simulated is True
        self.bank_gate = BankCredentialGate(config, permit, ledger, credential_provider, fixture_only=fixture)
        reference = ('fixture:' if fixture else '') + 'bank-pilot:route-liability:' + config.config_sha256

        def policy_counter(request):
            estimate = local_counter.estimate_request(request)
            require(0 < estimate.prompt_tokens <= config.local_input_policy_tokens,
                    'Full local context exceeds policy; never truncate', 'BANK_LOCAL_CONTEXT_LIMIT')
            return config.local_input_policy_tokens

        policy_counter.admission_mode = config.admission_mode
        def statistics(request):
            value = local_counter.request_statistics(request)
            value.update(admission_mode=config.admission_mode, local_input_policy_tokens=4000,
                admission_field_is_server_upper_bound=False, server_wrapping_verified=False,
                route_liability_sha256=ledger.batch_config['route_liability_sha256'],
                worstcase_liability_nano=ledger.worstcase_per_call_nano)
            return value
        binding = fixture_binding() if fixture else P3Binding(
            binding_ref='bank-pilot-' + config.config_sha256, model=MODEL,
            allowed_response_models=(MODEL,), simulated=False, real_requests_authorized=True,
            input_nano_usd_per_token=config.input_nano_usd_per_token,
            output_nano_usd_per_token=config.output_nano_usd_per_token,
            price_evidence=config.price_evidence_ref, capability_evidence=config.route_evidence_ref,
            token_admission_evidence=reference, reasoning_effort='low', temperature=0,
            output_token_parameter='max_tokens',
            supported_parameters=('model','messages','n','stream','response_format','max_tokens','temperature','reasoning_effort'))
        runtime_permit = None if fixture else LiveRuntimePermit(
            authorized=True, binding_digest=binding.binding_digest,
            authorization_reference=permit.authorization_reference)
        super().__init__(sender, token_counter=BoundTokenCounter(reference, policy_counter),
            token_statistics=statistics, live_binding=binding, runtime_permit=runtime_permit,
            credential_provider=self.bank_gate, timeout_s=config.absolute_deadline_s)

    def protocol_text(self, role):
        text=super().protocol_text(role)
        if role=='Analyst' and self.analyst_protocol_revision=='bank-analyst-output-r3':
            return text+' Output protocol clarification: source_role, agent_role, message_id and content are historical message metadata, NEVER output fields. Do not generate a new message envelope or invent a message ID. Your response must itself be the action or final object, not a quoted JSON string. After read_file succeeds, parse the JSON facts in the tool result content and place that object directly under final. For a final response, the ONLY outer key is final and its value is an object; for a tool request, the ONLY outer keys are tool and arguments. Do not wrap either object inside content. Keep every factual value exactly as read.'
        if self.analyst_protocol_revision in ('bank-agent-contract-r4','bank-agent-output-r5'):
            text += (' Output protocol clarification: source_role, agent_role, message_id and content '
                'are historical message metadata, NEVER output fields. Do not generate a new '
                'message envelope or invent a message ID. Your response must itself be the action '
                'or final object, not a quoted JSON string. '
                'For a final response, the ONLY outer key is final and its value is an object; '
                'for a tool request, the ONLY outer keys are tool and arguments. Do not wrap '
                'either object inside content. Keep every factual value exactly as read.')
        if role=='Analyst' and self.analyst_protocol_revision in ('bank-agent-contract-r4','bank-agent-output-r5'):
            text += (' After read_file succeeds, parse the JSON facts in the tool result content '
                     'and place that object directly under final.')
        if role=='Planner' and self.analyst_protocol_revision in ('bank-agent-contract-r4','bank-agent-output-r5'):
            text += (' Contract clarification: recipe MUST have exactly the two keys model_family '
                'and parameters. The complete allowed recipe objects are '
                '{"model_family":"logistic_regression","parameters":{"C":1.0,"max_iter":200}} '
                'or {"model_family":"random_forest","parameters":{"n_estimators":40,"max_depth":8,"n_jobs":1}}. '
                'Do NOT use model or hyperparameters as keys. Select feature_columns ONLY from '
                'the supplied Analyst feature_columns, excluding its unavailable_before_call; '
                'do not infer any additional columns from remembered Bank datasets. Copy all '
                'data_binding hash strings and code_sha256 literally from task. Return the '
                'complete contract directly under final, with no message metadata.')
        return text

    def validate_model_payload(self,role,payload,trace):
        if self.analyst_protocol_revision!='bank-agent-output-r5':
            return super().validate_model_payload(role,payload,trace)
        from .bank_output_protocol import decode_output
        canonical,evidence=decode_output(role,payload)
        trace['output_protocol']=evidence
        return canonical

    def _receipt_usage_caps(self, prepared):
        if self.bank_config.admission_mode == CONSERVATIVE_ADMISSION_MODE:
            return (self.bank_config.route_input_billable_cap,
                    self.bank_config.route_output_billable_cap)
        return super()._receipt_usage_caps(prepared)

    def _live_authorized(self):
        # This mode does not create DeploymentTokenEvidence or relax its
        # verified-tokenizer route. It has its own permit and monetary reserve.
        self.bank_gate._validate()
        require(self.bank_config.admission_mode in (ADMISSION_MODE, CONSERVATIVE_ADMISSION_MODE)
                and self.bank_ledger.binding['simulated'] is False,
                'Bank authority does not admit live liability mode', 'BANK_LIVE_DISABLED')
        self.bank_ledger._check_admissible_evidence()
        super()._live_authorized()


class BankPilotGateway:
    """Single owner of accounting; no implicit retry or automatic batch growth."""
    manages_accounting = True

    def __init__(self, model, ledger, config, permit, *, billing_verifier=None):
        require(isinstance(model, BankTritonModel) and isinstance(ledger, BankPilotBudget)
                and model.bank_ledger is ledger and model.bank_config == config
                and model.bank_permit == permit, 'Exact Bank objects must match', 'BANK_ENTRY')
        self.model, self.ledger, self.config, self.permit = model, ledger, config, permit
        self.fixture_only = model.fixture_only
        require(billing_verifier is None or callable(billing_verifier),
                'Billing verifier must be callable', 'BANK_BILLING_VERIFIER')
        require(self.fixture_only or config.admission_mode != CONSERVATIVE_ADMISSION_MODE
                or callable(billing_verifier),
                'Conservative live admission needs per-response billing reconciliation',
                'BANK_BILLING_VERIFIER')
        self.billing_verifier = billing_verifier
        self.validate()

    def validate(self):
        self.model.bank_gate._validate()
        require(self.ledger.snapshot()['status'] == 'active', 'Bank authority is stopped', 'BANK_STOPPED')

    def prepare_request(self, role, messages):
        """Default wire preparation; specialized calibration may verify it."""
        return self.model.prepare(role, deepcopy(messages))

    def call(self, role, messages, identity, *, deadline_monotonic):
        self.validate()
        require(identity.get('run_id') in dict(self.config.runs)
                and identity.get('step_id') == role, 'Run/role not registered', 'BANK_RUN_NOT_REGISTERED')
        require(monotonic() < deadline_monotonic <= monotonic()+120,
                'Original run deadline is expired or extended', 'BANK_DEADLINE')
        prepared = self.prepare_request(role, messages)
        record = {**identity, 'input_token_upper_bound':prepared.input_token_upper_bound,
                  'request':prepared.request, 'sidecar':prepared.sidecar}
        admitted = self.ledger.reserve(record)
        if not admitted['admission']['dispatch_allowed']:
            evidence = admitted.get('evidence') or {}
            require(admitted['status']=='settled' and evidence.get('kind')=='bank-success-v1',
                    'Repeated call is pending or failed', 'BANK_DUPLICATE_BLOCKED')
            return dict(payload=deepcopy(evidence['payload']), usage=deepcopy(admitted['usage']),
                sidecar=deepcopy(prepared.sidecar), replayed=True, audit=deepcopy(evidence['wire_audit']),
                token_count_comparison=deepcopy(evidence['token_count_comparison']),
                gateway_call_id=evidence.get('gateway_call_id'))
        call_id = identity['call_id']
        def before_send():
            self.ledger.mark_dispatched(call_id)
            if self.fixture_only:
                # Exercise the real ordering with an explicitly synthetic
                # provider. FakeHTTPSender never receives a credential.
                credential = self.model.bank_gate()
                require(isinstance(credential,str) and bool(credential), 'Synthetic credential missing', 'BANK_CREDENTIAL')
                credential = None
        exchange = None
        try:
            self.model.bank_gate.arm(call_id)
            exchange = self.model.exchange(prepared,before_send=before_send,
                deadline_monotonic=deadline_monotonic)
            local_count=prepared.sidecar['local_token_statistics']['prompt_tokens']
            comparison=dict(local_prompt_tokens=local_count,
                response_prompt_tokens=exchange.usage['prompt_tokens'],
                difference_tokens=exchange.usage['prompt_tokens']-local_count,
                response_usage_is_synthetic=self.fixture_only,
                server_wrapping_verified=False,admission_mode=self.config.admission_mode,
                provider_invoice_verified=False,
                all_billable_components_confirmed=self.config.all_billable_components_confirmed)
            billing_evidence = None
            if self.billing_verifier is not None:
                billing_evidence = self.billing_verifier(call_id, exchange.usage, deadline_monotonic)
                require(isinstance(billing_evidence, dict),
                        'Billing verifier did not return evidence', 'BANK_BILLING_UNCONFIRMED')
            self.ledger.settle(call_id,provider_request_id=exchange.provider_request_id,
                raw_usage=exchange.usage['raw'],normalized_usage=exchange.usage,
                evidence=dict(kind='bank-success-v1',payload=exchange.payload,
                    wire_audit=exchange.audit,gateway_call_id=exchange.gateway_call_id,
                    token_count_comparison=comparison,
                    billing_reconciliation=billing_evidence,
                    simulated=self.fixture_only))
        except Exception as exc:
            code = getattr(exc,'code',type(exc).__name__)
            # In this unverified-count pilot only strictly successful receipts
            # release risk. Even a 429 with usage is retained for reconciliation.
            # Save observed usage, not an invented successful settlement.
            row = next(c for c in self.ledger.calls() if c['call_id']==call_id)
            if row.get('evidence') is None:
                self.ledger.attach_evidence(call_id,dict(kind='bank-error-unreconciled-v1',
                    error=code,observed_usage=getattr(exc,'usage',None) or
                        (exchange.usage if exchange is not None else None),
                    request_id=getattr(exc,'request_id',None) or
                        (exchange.provider_request_id if exchange is not None else None),
                    wire_audit=getattr(exc,'audit',None) or
                        (exchange.audit if exchange is not None else None),
                    billing_check=getattr(exc,'billing_check',None),simulated=self.fixture_only))
            self.ledger.stop(code,call_id=call_id)
            raise
        return dict(payload=deepcopy(exchange.payload),usage=deepcopy(exchange.usage),
            sidecar=deepcopy(prepared.sidecar),replayed=False,audit=deepcopy(exchange.audit),
            token_count_comparison=comparison,
            gateway_call_id=exchange.gateway_call_id)
