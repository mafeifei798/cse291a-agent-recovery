"""Local, CPU-only GLM-5.3-Flash prompt estimates with explicit provenance.

The pinned upstream tokenizer is not evidence about UCSD's serving deployment.
Estimates cannot become live admission bounds without separate, explicit
deployment and response-format wrapping evidence. This module never downloads
files, imports model code, reads credentials, or makes network requests.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
from typing import Callable

from .contracts import ContractError, canonical_json, digest, require
from .p3_transport import BoundTokenCounter, TRITONAI_ENDPOINT

REPOSITORY = "zai-org/GLM-5.3-Flash"
REVISION = "46a050bec13002ad29ee795c16e61cf4fa3c4a9c"
MODEL = "api-glm-5.3-flash"
TOKENIZERS_VERSION = "0.22.1"
MANIFEST_NAME = "artifact_manifest.json"
MANIFEST_SCHEMA = "glm53-local-assets-v1"
PINNED_FILES = {
    "tokenizer.json": {
        "sha256": "19e773648cb4e65de8660ea6365e10acca112d42a854923df93db4a6f333a82d",
        "size_bytes": 20217442,
    },
    "tokenizer_config.json": {
        "git_blob_sha1": "e375fa0a4e16660ce0e2026e39374d35dad4c079",
        "size_bytes": 761,
    },
    "chat_template.jinja": {
        "git_blob_sha1": "14180451f166c1dab87081d8c3ee2a347f9d9d81",
        "size_bytes": 10830,
    },
}
_REQUEST_KEYS = {
    "model", "messages", "n", "stream", "response_format", "max_tokens",
    "max_completion_tokens", "reasoning_effort", "temperature",
}
_REQUIRED_KEYS = {"model", "messages", "n", "stream", "response_format", "reasoning_effort"}
_CODE = "GLM53_TOKENIZER_ERROR"
_DEPLOYMENT_CODE = "GLM53_DEPLOYMENT_EVIDENCE_REQUIRED"


def expected_manifest() -> dict:
    """Return the non-secret manifest required alongside the three local files."""
    return {"schema_version": MANIFEST_SCHEMA, "repository": REPOSITORY,
            "revision": REVISION, "files": deepcopy(PINNED_FILES)}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def _strict_object(data: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate artifact field", _CODE)
            result[key] = value
        return result
    try:
        value = json.loads(data, object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError) as exc:
        raise ContractError(_CODE, "Invalid local artifact JSON") from exc
    require(isinstance(value, dict), "Artifact JSON must be an object", _CODE)
    return value


def _local_bytes(directory: Path, name: str, *, expected_size: int | None = None) -> bytes:
    path = directory / name
    require(not path.is_symlink() and path.is_file(), "A local artifact is missing or linked", _CODE)
    size = path.stat().st_size
    require(size <= (expected_size if expected_size is not None else 65536),
            "Local artifact exceeds its pinned size", _CODE)
    data = path.read_bytes()
    require(expected_size is None or len(data) == expected_size,
            "Local artifact size differs from its pin", _CODE)
    return data


def _load_encoder(data: bytes) -> Callable[[str], list[int]]:
    try:
        import tokenizers
    except ImportError as exc:
        raise ContractError(_CODE, "The local tokenizers dependency is required") from exc
    require(getattr(tokenizers, "__version__", None) == TOKENIZERS_VERSION,
            "The local tokenizers runtime does not match the verified version", _CODE)
    try:
        tokenizer = tokenizers.Tokenizer.from_str(data.decode("utf-8"))
        tokenizer.no_truncation()
        tokenizer.no_padding()
        # The complete chat template already includes the required special tokens.
        def encode(text):
            return tokenizer.encode(text, add_special_tokens=False).ids
        encode.tokenizers_version = TOKENIZERS_VERSION
        return encode
    except Exception as exc:
        raise ContractError(_CODE, "The verified local tokenizer could not be loaded") from exc


def _template(template_text: str):
    try:
        from jinja2 import StrictUndefined, TemplateError
        from jinja2.sandbox import ImmutableSandboxedEnvironment
        from jinja2.utils import Namespace
    except ImportError as exc:
        raise ContractError(_CODE, "The local jinja2 dependency is required") from exc
    environment = ImmutableSandboxedEnvironment(
        trim_blocks=True, lstrip_blocks=True, undefined=StrictUndefined,
        extensions=["jinja2.ext.loopcontrols"],
    )
    environment.globals.clear()
    environment.globals.update({"namespace": Namespace, "range": range})

    def raise_exception(message):
        # Avoid including user input or arbitrary template messages in logs.
        raise TemplateError("GLM chat template rejected the messages")

    def tojson(value, ensure_ascii=False, indent=None, separators=None, sort_keys=False):
        return json.dumps(value, ensure_ascii=ensure_ascii, indent=indent,
                          separators=separators, sort_keys=sort_keys, allow_nan=False)

    environment.globals["raise_exception"] = raise_exception
    environment.filters["tojson"] = tojson
    try:
        return environment.from_string(template_text)
    except Exception as exc:
        raise ContractError(_CODE, "The local chat template could not be compiled") from exc


@dataclass(frozen=True)
class TokenEstimate:
    prompt_tokens: int
    classification: str
    repository: str
    revision: str | None
    tokenizer_sha256: str | None
    tokenizer_config_sha256: str | None
    template_sha256: str
    response_format_digest: str
    tokenizers_version: str | None
    server_wrapping_verified: bool = False
    suitable_for_live_admission: bool = False

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class DeploymentTokenEvidence:
    """Reviewed serving evidence, not a switch that public upstream docs satisfy.

    ``extra_prompt_tokens_status`` must explicitly describe a proven absence of
    additional prompt tokens, or a verified upper bound covering every listed
    response-format digest (including the complete JSON Schema where present).
    No such UCSD evidence is supplied by this module.
    """
    evidence_ref: str
    verification_status: str
    endpoint: str
    model: str
    repository: str
    revision: str
    tokenizer_sha256: str
    tokenizer_config_sha256: str
    template_sha256: str
    deployment_evidence_ref: str
    reasoning_effort: str
    response_format_digests: tuple[str, ...]
    extra_prompt_tokens_status: str
    extra_prompt_tokens_upper_bound: int | None
    extra_prompt_tokens_evidence_ref: str


class GLM53LocalTokenCounter:
    """Render the full pinned chat template; do not tokenize the wire JSON."""

    def __init__(self, encoder: Callable[[str], list[int]], template_text: str):
        # An injected encoder is useful for deterministic offline tests, but is
        # never eligible to create a verified live bound.
        require(callable(encoder) and isinstance(template_text, str) and template_text,
                "An explicit encoder and chat template are required", _CODE)
        self._encoder = encoder
        self._compiled_template = _template(template_text)
        self._assets_verified = False
        self._template_sha256 = _sha256(template_text.encode("utf-8"))
        self._tokenizer_sha256 = None
        self._tokenizer_config_sha256 = None
        self._tokenizers_version = None

    @classmethod
    def from_directory(cls, directory: str | Path):
        """Load only explicit pinned local files. No implicit network fallback."""
        directory = Path(directory)
        require(not directory.is_symlink() and directory.is_dir(),
                "An explicit local artifact directory is required", _CODE)
        manifest = _strict_object(_local_bytes(directory, MANIFEST_NAME))
        require(manifest == expected_manifest(), "Local artifact manifest differs from its pins", _CODE)
        artifacts = {}
        for name, pin in PINNED_FILES.items():
            data = _local_bytes(directory, name, expected_size=pin["size_bytes"])
            for algorithm, expected in pin.items():
                if algorithm == "sha256":
                    actual = _sha256(data)
                elif algorithm == "git_blob_sha1":
                    actual = _git_blob_sha1(data)
                else:
                    continue
                require(actual == expected, "Local artifact content differs from its pin", _CODE)
            artifacts[name] = data
        _strict_object(artifacts["tokenizer_config.json"])
        try:
            template_text = artifacts["chat_template.jinja"].decode("utf-8")
        except UnicodeError as exc:
            raise ContractError(_CODE, "Local chat template must be UTF-8") from exc
        encoder = _load_encoder(artifacts["tokenizer.json"])
        require(getattr(encoder, "tokenizers_version", None) == TOKENIZERS_VERSION,
                "The local encoder has no verified runtime identity", _CODE)
        counter = cls(encoder, template_text)
        counter._assets_verified = True
        counter._tokenizers_version = TOKENIZERS_VERSION
        counter._tokenizer_sha256 = _sha256(artifacts["tokenizer.json"])
        counter._tokenizer_config_sha256 = _sha256(artifacts["tokenizer_config.json"])
        return counter

    def _validated(self, request: dict) -> dict:
        require(isinstance(request, dict) and _REQUIRED_KEYS <= set(request)
                and set(request) <= _REQUEST_KEYS,
                "Request contains missing or unsupported token-accounting fields", _CODE)
        require(request["model"] == MODEL and type(request["n"]) is int and request["n"] == 1
                and request["stream"] is False and request["reasoning_effort"] == "low",
                "Only the explicit first-stage Flash low-reasoning request is supported", _CODE)
        output_keys = set(request) & {"max_tokens", "max_completion_tokens"}
        require(len(output_keys) == 1 and type(request[next(iter(output_keys))]) is int
                and request[next(iter(output_keys))] > 0,
                "One explicit output-token cap is required", _CODE)
        if "temperature" in request:
            require(type(request["temperature"]) in (int, float) and 0 <= request["temperature"] <= 1,
                    "Unsupported temperature", _CODE)
        messages = request["messages"]
        require(isinstance(messages, list) and len(messages) == 2
                and all(isinstance(m, dict) and set(m) == {"role", "content"}
                        and isinstance(m["content"], str) for m in messages)
                and [m["role"] for m in messages] == ["system", "user"],
                "Only the two frozen text messages can be counted", _CODE)
        response_format = request["response_format"]
        require(isinstance(response_format, dict), "Response format must be explicit", _CODE)
        kind = response_format.get("type")
        require((kind == "json_object" and set(response_format) == {"type"})
                or (kind == "json_schema" and set(response_format) == {"type", "json_schema"}
                    and isinstance(response_format["json_schema"], dict)
                    and set(response_format["json_schema"]) == {"name", "strict", "schema"}
                    and isinstance(response_format["json_schema"]["name"], str)
                    and response_format["json_schema"]["strict"] is True
                    and isinstance(response_format["json_schema"]["schema"], dict)),
                "Unsupported response-format shape", _CODE)
        # Check JSON serializability without using the serialized wire as a prompt.
        try:
            canonical_json(request)
        except (ValueError, TypeError) as exc:
            raise ContractError(_CODE, "Request is not finite JSON") from exc
        return deepcopy(request)

    def render_request(self, request: dict) -> str:
        request = self._validated(request)
        try:
            return self._compiled_template.render(
                messages=request["messages"], tools=None, add_generation_prompt=True,
                reasoning_effort=request["reasoning_effort"],
                clear_thinking=False,
            )
        except Exception as exc:
            raise ContractError(_CODE, "The local chat template rejected this request") from exc

    def estimate_request(self, request: dict) -> TokenEstimate:
        request = self._validated(request)
        rendered = self.render_request(request)
        try:
            ids = self._encoder(rendered)
            require(isinstance(ids, list) and ids and all(type(x) is int and x >= 0 for x in ids),
                    "Local tokenizer returned invalid token IDs", _CODE)
        except Exception as exc:
            raise ContractError(_CODE, "Local prompt tokenization failed") from exc
        return TokenEstimate(
            prompt_tokens=len(ids), classification="upstream_estimate",
            repository=REPOSITORY,
            revision=REVISION if self._assets_verified else None,
            tokenizer_sha256=self._tokenizer_sha256,
            tokenizer_config_sha256=self._tokenizer_config_sha256,
            template_sha256=self._template_sha256,
            response_format_digest=digest(request["response_format"]),
            tokenizers_version=self._tokenizers_version,
        )

    def make_bound_counter(self, evidence: DeploymentTokenEvidence) -> BoundTokenCounter:
        require(self._assets_verified and self._tokenizers_version == TOKENIZERS_VERSION
                and isinstance(evidence, DeploymentTokenEvidence),
                "Only verified local assets plus reviewed deployment evidence can bind admission",
                _DEPLOYMENT_CODE)
        require(evidence.verification_status == "verified"
                and evidence.endpoint == TRITONAI_ENDPOINT and evidence.model == MODEL
                and evidence.repository == REPOSITORY and evidence.revision == REVISION
                and evidence.tokenizer_sha256 == self._tokenizer_sha256
                and evidence.tokenizer_config_sha256 == self._tokenizer_config_sha256
                and evidence.template_sha256 == self._template_sha256
                and evidence.reasoning_effort == "low",
                "Deployment tokenizer/template identity is unverified or different", _DEPLOYMENT_CODE)
        for reference in (evidence.evidence_ref, evidence.deployment_evidence_ref,
                          evidence.extra_prompt_tokens_evidence_ref):
            require(isinstance(reference, str) and bool(reference.strip())
                    and reference.strip().lower() not in {"unknown", "unverified", "pending"}
                    and not reference.startswith("fixture:"),
                    "Deployment and wrapping evidence must have explicit reviewed references", _DEPLOYMENT_CODE)
        digests = evidence.response_format_digests
        require(type(digests) is tuple and bool(digests)
                and all(isinstance(x, str) and len(x) == 64
                        and all(c in "0123456789abcdef" for c in x) for x in digests)
                and len(digests) == len(set(digests)),
                "Every response-format wrapper needs a verified digest", _DEPLOYMENT_CODE)
        extra = evidence.extra_prompt_tokens_upper_bound
        require(type(extra) is int and extra >= 0 and
                ((evidence.extra_prompt_tokens_status == "verified_absent" and extra == 0)
                 or (evidence.extra_prompt_tokens_status == "verified_upper_bound" and extra > 0)),
                "Unknown schema/server wrapping cannot default to zero", _DEPLOYMENT_CODE)

        def bound(request):
            estimate = self.estimate_request(request)
            require(estimate.response_format_digest in digests,
                    "This response format is outside the reviewed wrapping evidence", _DEPLOYMENT_CODE)
            return estimate.prompt_tokens + extra

        return BoundTokenCounter(evidence.evidence_ref, bound)


def make_bound_counter(counter: GLM53LocalTokenCounter,
                       evidence: DeploymentTokenEvidence) -> BoundTokenCounter:
    require(isinstance(counter, GLM53LocalTokenCounter), "A local GLM counter is required", _DEPLOYMENT_CODE)
    return counter.make_bound_counter(evidence)
