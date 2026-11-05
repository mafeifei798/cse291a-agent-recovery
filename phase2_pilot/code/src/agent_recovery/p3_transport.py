"""Explicit P3 wire protocol; default fixtures never open a socket.

The live sender is deliberately dormant. A non-fixture binding, matching
runtime permit and explicitly injected credential provider are all required
before either credential access or a physical HTTPS request is possible.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
import base64
import hashlib
import http.client
import json
import math
import socket
import ssl
from time import monotonic
from typing import Callable
from urllib.parse import urlsplit

from .contracts import ContractError, canonical_json, digest, require
from .model_gateway import _strict_json, fake_chat_response, schema_for_step

P0_FREEZE_ID = "p0-v1-5aa953e9e83924eb"
P0_CONTENT_DIGEST = "5aa953e9e83924eb6f2266f478eec833a843e13d40b548df9b540ea0ad6f19c2"
TRITONAI_ENDPOINT = "https://tritonai-api.ucsd.edu/v1"
_REQUIRED_PARAMETERS = {"model", "messages", "n", "stream", "response_format"}
_OPTIONAL_PARAMETERS = {"temperature", "max_completion_tokens", "max_tokens", "reasoning_effort"}
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_CAPTURED_HEADERS = {"x-litellm-call-id", "x-request-id", "request-id", "content-type"}


def _response_request_ids(headers):
    """Keep gateway and upstream identities separate; never use body.id as a header ID."""
    def present(name):
        value = headers.get(name)
        return value if isinstance(value, str) and value.strip() else None
    gateway = present("x-litellm-call-id")
    provider = present("x-request-id") or present("request-id")
    return gateway, provider, gateway or provider


@dataclass(frozen=True)
class P3Binding:
    binding_ref: str = "p3-offline-http-fixture-v1"
    p0_freeze_id: str = P0_FREEZE_ID
    p0_content_digest: str = P0_CONTENT_DIGEST
    endpoint: str = TRITONAI_ENDPOINT
    model: str = "fixture-gpt-4.1-mini"
    allowed_response_models: tuple[str, ...] = ("fixture-gpt-4.1-mini",)
    simulated: bool = True
    real_requests_authorized: bool = False
    max_input_tokens: int = 4000
    max_output_tokens: int = 768
    timeout_s: int = 120
    input_nano_usd_per_token: int = 400
    output_nano_usd_per_token: int = 1600
    cached_input_nano_usd_per_token: int | None = None
    price_evidence: str = "fixture:simulated-standard-token-rates"
    capability_evidence: str = "fixture:chat-json-schema-capability"
    token_admission_evidence: str = "fixture:utf8-byte-plus-framing-upper-bound"
    supported_parameters: tuple[str, ...] = (
        "model", "messages", "n", "stream", "max_completion_tokens",
        "response_format", "temperature",
    )
    output_token_parameter: str = "max_completion_tokens"
    temperature: int | float | None = 0
    reasoning_effort: str | None = None

    def __post_init__(self):
        require(self.p0_freeze_id == P0_FREEZE_ID and self.p0_content_digest == P0_CONTENT_DIGEST,
                "P3 binding does not reference the frozen P0", "P3_BINDING_ERROR")
        require(self.endpoint == TRITONAI_ENDPOINT,
                "P3 endpoint is not the verified TritonAI endpoint", "P3_BINDING_ERROR")
        require(type(self.simulated) is bool and type(self.real_requests_authorized) is bool,
                "Invalid authorization flags", "P3_BINDING_ERROR")
        require(not self.simulated or not self.real_requests_authorized,
                "Fixture binding cannot authorize real requests", "P3_BINDING_ERROR")
        for name in ("binding_ref", "model", "price_evidence", "capability_evidence", "token_admission_evidence"):
            require(isinstance(getattr(self, name), str) and bool(getattr(self, name).strip()),
                    "Binding requires explicit evidence and identity", "P3_BINDING_ERROR")
        require(type(self.allowed_response_models) is tuple and bool(self.allowed_response_models)
                and all(isinstance(v, str) and bool(v) for v in self.allowed_response_models)
                and len(set(self.allowed_response_models)) == len(self.allowed_response_models),
                "Response model identities must be an immutable explicit list", "P3_BINDING_ERROR")
        require(type(self.supported_parameters) is tuple
                and len(set(self.supported_parameters)) == len(self.supported_parameters)
                and set(self.supported_parameters) <= _REQUIRED_PARAMETERS | _OPTIONAL_PARAMETERS
                and _REQUIRED_PARAMETERS <= set(self.supported_parameters),
                "Unsupported or missing wire parameters", "P3_BINDING_ERROR")
        require(self.output_token_parameter in ("max_completion_tokens", "max_tokens")
                and self.output_token_parameter in self.supported_parameters,
                "Output token parameter is not verified", "P3_BINDING_ERROR")
        require(self.temperature is None or (type(self.temperature) in (int, float)
                and self.temperature == 0 and "temperature" in self.supported_parameters),
                "Sampling configuration is not supported", "P3_BINDING_ERROR")
        require(self.reasoning_effort is None or (type(self.reasoning_effort) is str
                and self.reasoning_effort == "low"
                and "reasoning_effort" in self.supported_parameters),
                "Reasoning effort is not supported", "P3_BINDING_ERROR")
        for name, cap in (("max_input_tokens", 4000), ("max_output_tokens", 768), ("timeout_s", 120)):
            value = getattr(self, name)
            require(type(value) is int and 0 < value <= cap,
                    "P3 caps exceed the frozen limits", "P3_BINDING_ERROR")
        for value in (self.input_nano_usd_per_token, self.output_nano_usd_per_token):
            require(type(value) is int and value >= 0, "Invalid verified token rate", "P3_BINDING_ERROR")
        cache = self.cached_input_nano_usd_per_token
        require(cache is None or (type(cache) is int and 0 <= cache <= self.input_nano_usd_per_token),
                "Cached rate must not exceed the reservation rate", "P3_BINDING_ERROR")
        evidence = (self.price_evidence, self.capability_evidence, self.token_admission_evidence)
        if self.simulated:
            require(all(v.startswith("fixture:") for v in evidence)
                    and self.model.startswith("fixture-"),
                    "Simulated evidence and model must be visibly marked", "P3_BINDING_ERROR")
        else:
            require(all(not v.startswith("fixture:") for v in evidence)
                    and not self.model.startswith("fixture-"),
                    "Live binding cannot use fixture evidence", "P3_BINDING_ERROR")

    @property
    def worst_case_cost_nano_usd(self):
        return (self.max_input_tokens * self.input_nano_usd_per_token
                + self.max_output_tokens * self.output_nano_usd_per_token)

    @property
    def binding_digest(self):
        return digest(self.to_dict())

    def to_dict(self):
        value = asdict(self)
        value["allowed_response_models"] = list(self.allowed_response_models)
        value["supported_parameters"] = list(self.supported_parameters)
        return value

    @classmethod
    def from_dict(cls, value):
        value = deepcopy(value)
        for name in ("allowed_response_models", "supported_parameters"):
            if isinstance(value.get(name), list):
                value[name] = tuple(value[name])
        try:
            return cls(**value)
        except TypeError as exc:
            raise ContractError("P3_BINDING_ERROR", "P3 binding fields differ") from exc


def fixture_binding(**changes):
    """Synthetic rates are test inputs; these are not a TritonAI price quote."""
    return P3Binding(**changes)


@dataclass(frozen=True)
class BoundTokenCounter:
    """Caller supplies the verified tokenizer plus request/framing upper bound."""
    evidence_ref: str
    counter: Callable[[dict], int]


def input_token_upper_bound(request, binding, counter=None):
    if binding.simulated:
        return len(canonical_json(request).encode("utf-8")) + 256 + 128 * len(request["messages"])
    require(isinstance(counter, BoundTokenCounter)
            and counter.evidence_ref == binding.token_admission_evidence
            and callable(counter.counter),
            "Live token admission needs an explicitly bound verified counter", "P3_TOKEN_COUNTER_REQUIRED")
    value = counter.counter(deepcopy(request))
    require(type(value) is int and value > 0,
            "Verified token counter returned an invalid bound", "P3_TOKEN_COUNTER_ERROR")
    return value


def build_p3_request(step_id, messages, binding):
    require(isinstance(binding, P3Binding), "Missing P3 binding", "P3_BINDING_ERROR")
    require(isinstance(messages, list) and len(messages) == 2
            and all(isinstance(m, dict) and set(m) == {"role", "content"}
                    and isinstance(m["content"], str) for m in messages)
            and [m["role"] for m in messages] == ["system", "user"],
            "P3 expects the two frozen P1 messages", "P3_REQUEST_ERROR")
    request = {"model": binding.model, "messages": deepcopy(messages), "n": 1, "stream": False,
               binding.output_token_parameter: binding.max_output_tokens,
               "response_format": {"type": "json_schema", "json_schema": {
                   "name": step_id, "strict": True, "schema": schema_for_step(step_id)}}}
    if binding.temperature is not None:
        request["temperature"] = binding.temperature
    if binding.reasoning_effort is not None:
        request["reasoning_effort"] = binding.reasoning_effort
    require(set(request) <= set(binding.supported_parameters),
            "A requested parameter has not been verified", "P3_REQUEST_ERROR")
    return request


@dataclass(frozen=True)
class HTTPRequest:
    method: str
    url: str
    body: bytes
    timeout_s: float


@dataclass(frozen=True)
class HTTPResponse:
    status: int
    headers: dict
    body: bytes


def fake_http_response(payload=None, *, raw=None, model="fixture-gpt-4.1-mini",
                       request_id="req-p3-http-fixture", status=200, prompt_tokens=100,
                       completion_tokens=50, headers=None):
    """Encode one explicit synthetic response; no provider access or fallback."""
    require(raw is None or payload is None, "Choose raw response or payload", "P3_FIXTURE_ERROR")
    if raw is None:
        raw = fake_chat_response(payload, model=model, prompt_tokens=prompt_tokens,
                                 completion_tokens=completion_tokens)
    # Legacy fixture helpers attach local SDK metadata. Those keys do not
    # belong to the provider's HTTP body: the P3 client derives them from the
    # actual response header and captured wire bytes after receipt.
    raw = deepcopy(raw)
    raw.pop("_request_id", None)
    raw.pop("_p3_http", None)
    return HTTPResponse(status, headers if headers is not None else {
        "content-type": "application/json", "x-request-id": request_id},
        canonical_json(raw).encode("utf-8"))


def _status_error(status):
    return ("P3_HTTP_AUTH" if status in (401, 403)
            else "P3_HTTP_RATE_LIMIT" if status == 429
            else "P3_HTTP_SERVER_ERROR" if 500 <= status <= 599
            else "P3_HTTP_REDIRECT" if 300 <= status <= 399 else "P3_HTTP_STATUS_ERROR")


@dataclass(frozen=True)
class LiveRuntimePermit:
    authorized: bool = False
    binding_digest: str = ""
    authorization_reference: str = ""

    def validate(self, binding):
        require(type(self.authorized) is bool and self.authorized
                and not binding.simulated and binding.real_requests_authorized
                and self.binding_digest == binding.binding_digest
                and isinstance(self.authorization_reference, str)
                and bool(self.authorization_reference.strip()),
                "Real HTTP requires an explicit matching runtime authorization", "P3_LIVE_DISABLED")


class P3HTTPError(ContractError):
    def __init__(self, code, *, dispatched=False, http_status=None, request_id=None,
                 usage=None, raw_response=None, ambiguous=True):
        # Exceptions supplied by an HTTP implementation may contain secrets;
        # neither their text nor authorization material enter this exception.
        super().__init__(code, "P3 HTTP exchange failed: " + code)
        self.dispatched = dispatched
        self.http_status = http_status
        self.request_id = request_id
        self.usage = deepcopy(usage)
        self.raw_response = deepcopy(raw_response)
        self.ambiguous = ambiguous


def parse_p3_usage(response):
    raw = response.get("usage") if isinstance(response, dict) else None
    require(isinstance(raw, dict), "Usage is missing", "P3_USAGE_ERROR")
    for name in ("prompt_tokens", "completion_tokens", "total_tokens"):
        require(type(raw.get(name)) is int and raw[name] >= 0,
                "Invalid usage token count", "P3_USAGE_ERROR")
    require(raw["total_tokens"] == raw["prompt_tokens"] + raw["completion_tokens"],
            "Usage total is inconsistent", "P3_USAGE_ERROR")
    details = []
    for key in ("prompt_tokens_details", "completion_tokens_details"):
        value = raw.get(key, {})
        if value is None:
            value = {}
        require(isinstance(value, dict), "Invalid usage token details", "P3_USAGE_ERROR")
        details.append(value)
    cached, reasoning = details[0].get("cached_tokens", 0), details[1].get("reasoning_tokens", 0)
    require(type(cached) is int and 0 <= cached <= raw["prompt_tokens"]
            and type(reasoning) is int and 0 <= reasoning <= raw["completion_tokens"],
            "Cached or reasoning count is inconsistent", "P3_USAGE_ERROR")
    # Unknown fields remain in raw, including provider-specific billing fields.
    return {"prompt_tokens": raw["prompt_tokens"], "completion_tokens": raw["completion_tokens"],
            "total_tokens": raw["total_tokens"], "cached_input_tokens": cached,
            "reasoning_tokens": reasoning, "raw": deepcopy(raw)}


def cost_from_usage(usage, binding):
    require(isinstance(usage, dict) and "raw" in usage
            and parse_p3_usage({"usage": usage["raw"]}) == usage,
            "Cost requires validated raw usage", "P3_USAGE_ERROR")
    cached_rate = binding.cached_input_nano_usd_per_token
    if cached_rate is None:
        cached_rate = binding.input_nano_usd_per_token
    return ((usage["prompt_tokens"] - usage["cached_input_tokens"]) * binding.input_nano_usd_per_token
            + usage["cached_input_tokens"] * cached_rate
            + usage["completion_tokens"] * binding.output_nano_usd_per_token)


class FakeHTTPSender:
    simulated = True
    real_request_count = 0

    def __init__(self, responses=(), *, on_send=None):
        self.responses = list(responses)
        self.requests = []
        self.on_send = on_send

    @property
    def request_count(self):
        return len(self.requests)

    def send(self, request, *, authorization=None, runtime_permit=None, binding=None):
        # Authentication is intentionally never captured, even in tests.
        self.requests.append(deepcopy(request))
        if self.on_send:
            self.on_send(deepcopy(request))
        if not self.responses:
            raise RuntimeError("No fake HTTP response fixture remains")
        response = self.responses.pop(0)
        if callable(response):
            response = response(deepcopy(request))
        if isinstance(response, Exception):
            raise response
        require(isinstance(response, HTTPResponse), "Fake sender needs HTTPResponse fixtures", "P3_FIXTURE_ERROR")
        return deepcopy(response)


class StdlibHTTPSender:
    """One HTTPS exchange, no redirects, retries or implicit environment reads.

    Remaining wall time bounds each socket phase and read. A stdlib blocking
    DNS lookup (and a slowly delivered HTTP header) cannot be forcibly cancelled
    safely here; the client also rejects any response returned past deadline.
    That limitation must be checked before a future live pilot is authorized.
    """
    simulated = False

    def __init__(self):
        self.request_count = 0

    @property
    def real_request_count(self):
        return self.request_count

    def send(self, request, *, authorization=None, runtime_permit=None, binding=None):
        require(isinstance(binding, P3Binding) and isinstance(runtime_permit, LiveRuntimePermit),
                "Live HTTP is disabled without runtime authorization", "P3_LIVE_DISABLED")
        runtime_permit.validate(binding)
        require(isinstance(authorization, str) and bool(authorization)
                and "\r" not in authorization and "\n" not in authorization,
                "An explicit safe credential is required", "P3_CREDENTIAL_ERROR")
        require(request.url == binding.endpoint + "/chat/completions" and request.method == "POST",
                "Live request is outside its bound endpoint", "P3_REQUEST_ERROR")
        parsed = urlsplit(request.url)
        deadline = monotonic() + request.timeout_s

        def remaining():
            value = deadline - monotonic()
            if value <= 0:
                raise TimeoutError("P3 HTTP total deadline expired")
            return value

        context = ssl.create_default_context()
        connection = http.client.HTTPSConnection(parsed.hostname, timeout=remaining(), context=context)
        self.request_count += 1
        try:
            connection.connect()
            connection.sock.settimeout(remaining())
            connection.request("POST", parsed.path, body=request.body,
                               headers={"Authorization": "Bearer " + authorization,
                                        "Content-Type": "application/json", "Accept": "application/json"})
            connection.sock.settimeout(remaining())
            response = connection.getresponse()
            remaining()
            chunks, length = [], 0
            while True:
                # Connection: close may detach its socket after headers, while
                # the response still owns the underlying socket until EOF.
                active_socket = connection.sock
                if active_socket is None:
                    active_socket = getattr(getattr(response.fp, "raw", None), "_sock", None)
                if active_socket is not None:
                    active_socket.settimeout(remaining())
                else:
                    remaining()
                chunk = response.read1(min(65536, _MAX_RESPONSE_BYTES + 1 - length))
                remaining()
                if not chunk:
                    break
                chunks.append(chunk)
                length += len(chunk)
                if length > _MAX_RESPONSE_BYTES:
                    raise P3HTTPError("P3_RESPONSE_TOO_LARGE", dispatched=True)
            body = b"".join(chunks)
            # Do not retain cookie, authorization or arbitrary proxy headers.
            headers = {key.lower(): value for key, value in response.getheaders()
                       if key.lower() in _CAPTURED_HEADERS}
            return HTTPResponse(response.status, headers, body)
        finally:
            connection.close()


class P3HTTPClient:
    def __init__(self, binding, sender, *, token_counter=None, credential_provider=None,
                 runtime_permit=None):
        from .p3_deadline import BoundedHTTPSender
        require(isinstance(binding, P3Binding), "Missing P3 binding", "P3_BINDING_ERROR")
        require(type(sender) in (FakeHTTPSender, StdlibHTTPSender, BoundedHTTPSender),
                "HTTP sender must be explicitly selected", "P3_TRANSPORT_ERROR")
        require(binding.simulated == sender.simulated,
                "Fixture/live sender does not match binding", "P3_TRANSPORT_ERROR")
        self.binding, self.sender = binding, sender
        self.token_counter, self.credential_provider = token_counter, credential_provider
        self.runtime_permit = runtime_permit
        self.requests = []
        self.traces = []
        self.transport = "p3_fake_http" if binding.simulated else "p3_https"
        self.simulated = binding.simulated

    @property
    def request_count(self):
        return self.sender.request_count

    @property
    def real_request_count(self):
        return self.sender.real_request_count

    def create(self, request, *, timeout_s, before_send=None, deadline_monotonic=None):
        if deadline_monotonic is None:
            started = monotonic()
        else:
            require(type(timeout_s) in (int, float) and math.isfinite(timeout_s)
                    and 0 < timeout_s <= self.binding.timeout_s
                    and type(deadline_monotonic) in (int, float)
                    and math.isfinite(deadline_monotonic)
                    and deadline_monotonic <= monotonic() + timeout_s + 0.001,
                    "HTTP client cannot extend the invocation deadline", "P3_REQUEST_ERROR")
            # Gateway persistence, dispatch intent and worker startup all use
            # this same origin. No new 120-second window begins at spawn.
            started = deadline_monotonic - timeout_s
        trace = {"transport": self.transport, "simulated": self.simulated,
                 "binding_digest": self.binding.binding_digest,
                 "method": None, "url": None, "timeout_s": None,
                 "request_sha256": None, "request_body_b64": None, "request_bytes": 0,
                 "response_sha256": None, "response_body_b64": None, "response_bytes": 0,
                 "status": None, "headers": {}, "request_id": None,
                 "body_response_id": None, "dispatch_index": None,
                 "dispatched": False, "error_code": None, "elapsed_s": None}
        self.traces.append(trace)
        try:
            return self._create(request, timeout_s=timeout_s, trace=trace, started=started,
                                before_send=before_send)
        except ContractError as exc:
            if trace["elapsed_s"] is None:
                elapsed = monotonic() - started
                trace["elapsed_s"] = elapsed if math.isfinite(elapsed) and elapsed >= 0 else None
            trace["error_code"] = exc.code
            if isinstance(exc, P3HTTPError) and isinstance(exc.raw_response, dict):
                exc.raw_response["_p3_http"] = deepcopy(trace)
            raise

    def _create(self, request, *, timeout_s, trace, started, before_send):
        binding = self.binding
        require(before_send is None or callable(before_send),
                "Before-send callback must be explicitly callable", "P3_REQUEST_ERROR")
        require(type(timeout_s) in (int, float) and 0 < timeout_s <= binding.timeout_s,
                "HTTP deadline exceeds the binding", "P3_REQUEST_ERROR")
        try:
            step = request["response_format"]["json_schema"]["name"]
            expected = build_p3_request(step, request["messages"], binding)
        except (KeyError, TypeError) as exc:
            raise ContractError("P3_REQUEST_ERROR", "Invalid P3 request envelope") from exc
        try:
            matches = canonical_json(request) == canonical_json(expected)
        except (ValueError, TypeError, OverflowError, RecursionError):
            matches = False
        require(matches, "Request differs from its fixed binding", "P3_REQUEST_ERROR")
        require(input_token_upper_bound(request, binding, self.token_counter) <= binding.max_input_tokens,
                "Input token admission exceeds its cap", "P3_INPUT_LIMIT")
        authorization = None
        if not binding.simulated:
            require(isinstance(self.runtime_permit, LiveRuntimePermit),
                    "Live HTTP requires a runtime permit", "P3_LIVE_DISABLED")
            self.runtime_permit.validate(binding)
            require(callable(self.credential_provider), "No credential provider was injected", "P3_CREDENTIAL_ERROR")
            try:
                authorization = self.credential_provider()
            except Exception as exc:
                raise P3HTTPError("P3_CREDENTIAL_ERROR", ambiguous=False) from None
            require(isinstance(authorization, str) and bool(authorization)
                    and "\r" not in authorization and "\n" not in authorization,
                    "Invalid explicit credential", "P3_CREDENTIAL_ERROR")
        wire = HTTPRequest("POST", binding.endpoint + "/chat/completions",
                           canonical_json(request).encode("utf-8"), float(timeout_s))
        self.requests.append(deepcopy(request))
        trace.update({"request_sha256": hashlib.sha256(wire.body).hexdigest(),
                      "method": wire.method, "url": wire.url, "timeout_s": wire.timeout_s,
                      "request_body_b64": base64.b64encode(wire.body).decode("ascii"),
                      "request_bytes": len(wire.body)})
        preflight_elapsed = monotonic() - started
        if (not math.isfinite(preflight_elapsed) or preflight_elapsed < 0
                or preflight_elapsed >= timeout_s):
            trace["elapsed_s"] = preflight_elapsed if math.isfinite(preflight_elapsed) else None
            raise P3HTTPError("P3_HTTP_TIMEOUT", dispatched=False, ambiguous=False)
        # Admission and authorization can fail without touching the dispatch
        # ledger. Persist intent only after all preflight is finished; if this
        # write fails, neither a sender attempt nor a physical request occurs.
        if before_send is not None:
            try:
                before_send()
            except ContractError:
                raise
            except Exception:
                raise P3HTTPError("P3_DISPATCH_PERSISTENCE_ERROR", dispatched=False,
                                  ambiguous=False) from None
        trace.update({"dispatched": True, "dispatch_index": self.sender.request_count + 1})
        from .p3_deadline import BoundedHTTPSender
        before_cleanup_count = len(getattr(self.sender, "cleanup_receipts", []))
        try:
            if type(self.sender) is BoundedHTTPSender:
                response = self.sender.send(wire, authorization=authorization,
                    runtime_permit=self.runtime_permit, binding=binding,
                    deadline_monotonic=started + timeout_s, intent_committed=True)
            else:
                response = self.sender.send(wire, authorization=authorization,
                                            runtime_permit=self.runtime_permit, binding=binding)
        except P3HTTPError:
            raise
        except (TimeoutError, socket.timeout):
            raise P3HTTPError("P3_HTTP_TIMEOUT", dispatched=True) from None
        except Exception:
            raise P3HTTPError("P3_NETWORK_ERROR", dispatched=True) from None
        finally:
            receipts = getattr(self.sender, "cleanup_receipts", [])
            if len(receipts) > before_cleanup_count:
                trace["cleanup_receipt"] = deepcopy(receipts[-1])
        require(type(response.status) is int and isinstance(response.headers, dict)
                and isinstance(response.body, bytes), "Invalid HTTP fixture response", "P3_TRANSPORT_ERROR")
        headers = {str(k).lower(): v for k, v in response.headers.items()
                   if str(k).lower() in _CAPTURED_HEADERS}
        gateway_call_id, provider_request_id, request_id = _response_request_ids(headers)
        trace.update({"response_sha256": hashlib.sha256(response.body).hexdigest(),
                      "response_body_b64": base64.b64encode(response.body).decode("ascii"),
                      "response_bytes": len(response.body), "status": response.status,
                      "headers": deepcopy(headers), "request_id": request_id})
        # Existing upstream-only traces retain their original shape and values.
        # Gateway traces make the two namespaces explicit, while the legacy
        # request_id (and ledger receipt key) remains the normalized identity.
        if gateway_call_id is not None:
            trace.update(gateway_call_id=gateway_call_id, provider_request_id=provider_request_id)
        if len(response.body) > _MAX_RESPONSE_BYTES:
            raise P3HTTPError("P3_RESPONSE_TOO_LARGE", dispatched=True,
                              http_status=response.status, request_id=request_id)
        try:
            raw = _strict_json(response.body.decode("utf-8"))
            require(isinstance(raw, dict), "HTTP JSON envelope must be an object", "P3_RESPONSE_JSON_ERROR")
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise P3HTTPError(_status_error(response.status) if response.status != 200
                              else "P3_RESPONSE_JSON_ERROR", dispatched=True,
                              http_status=response.status, request_id=request_id) from None
        raw["_request_id"] = request_id
        trace["body_response_id"] = raw.get("id")
        raw["_p3_http"] = deepcopy(trace)
        try:
            usage = parse_p3_usage(raw)
        except ContractError:
            usage = None
        elapsed = monotonic() - started
        trace["elapsed_s"] = elapsed if math.isfinite(elapsed) and elapsed >= 0 else None
        raw["_p3_http"] = deepcopy(trace)
        if not math.isfinite(elapsed) or elapsed < 0 or elapsed >= timeout_s:
            raise P3HTTPError("P3_HTTP_TIMEOUT", dispatched=True, http_status=response.status,
                              request_id=request_id, usage=usage, raw_response=raw,
                              ambiguous=usage is None)
        if response.status != 200:
            code = _status_error(response.status)
            raise P3HTTPError(code, dispatched=True, http_status=response.status,
                              request_id=request_id, usage=usage, raw_response=raw,
                              ambiguous=usage is None)
        if usage is None:
            raise P3HTTPError("P3_USAGE_ERROR", dispatched=True, http_status=200,
                              request_id=request_id, raw_response=raw)
        if request_id is None or not isinstance(raw.get("id"), str) or not raw["id"]:
            raise P3HTTPError("P3_RESPONSE_ID_ERROR", dispatched=True, http_status=200,
                              request_id=request_id, usage=usage, raw_response=raw, ambiguous=False)
        if "error" in raw:
            raise P3HTTPError("P3_PROVIDER_ERROR", dispatched=True, http_status=200,
                              request_id=request_id, usage=usage, raw_response=raw, ambiguous=False)
        if raw.get("model") not in binding.allowed_response_models:
            raise P3HTTPError("P3_RESPONSE_MODEL_ERROR", dispatched=True, http_status=200,
                              request_id=request_id, usage=usage, raw_response=raw, ambiguous=False)
        if (usage["prompt_tokens"] > binding.max_input_tokens
                or usage["completion_tokens"] > binding.max_output_tokens):
            raise P3HTTPError("P3_USAGE_LIMIT", dispatched=True, http_status=200,
                              request_id=request_id, usage=usage, raw_response=raw, ambiguous=False)
        return deepcopy(raw)
