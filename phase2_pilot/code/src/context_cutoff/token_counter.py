"""Count the complete agent wire conversation with pinned GLM CPU assets.

This extends only the new context/cutoff adapter. The original two-message
counter, its historical checks and all archived results remain unchanged.
The local template count is exact for the pinned tokenizer and rendered text;
it is not proof of TritonAI's tokenizer, message framing or schema wrapping.
No function downloads assets, reads a credential or sends a request.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import math

from agent_recovery.contracts import ContractError, canonical_json, digest, require
from agent_recovery.glm53_tokenizer import GLM53LocalTokenCounter, MODEL
from agent_recovery.p3_transport import BoundTokenCounter

_CODE = "CTX_MULTIMESSAGE_TOKENIZER_ERROR"
_KEYS = {"model", "messages", "n", "stream", "max_tokens", "max_completion_tokens",
         "temperature", "reasoning_effort", "response_format"}
_REQUIRED = {"model", "messages", "n", "stream", "reasoning_effort", "response_format"}


class MultiMessageGLM53TokenCounter(GLM53LocalTokenCounter):
    """Reuse pinned loading/encoding; render every actual wire message in order.

    ``from_directory`` is inherited and validates the same manifest, hashes,
    tokenizer runtime and immutable local files as the historical counter.
    ``make_bound_counter`` is also inherited: live admission still requires
    separately reviewed DeploymentTokenEvidence. Public tokenizer assets alone
    cannot satisfy that evidence. ``make_fixture_bound_counter`` cannot be
    mistaken for that live evidence because its reference begins ``fixture:``.
    """

    def _validated(self, request):
        require(isinstance(request, dict) and _REQUIRED <= set(request)
                and set(request) <= _KEYS, "Missing or unsupported wire fields", _CODE)
        require(request["model"] == MODEL and type(request["n"]) is int
                and request["n"] == 1 and request["stream"] is False
                and request["reasoning_effort"] == "low", "Unsupported model or request mode", _CODE)
        output_keys = set(request) & {"max_tokens", "max_completion_tokens"}
        require(len(output_keys) == 1 and type(request[next(iter(output_keys))]) is int
                and 0 < request[next(iter(output_keys))] <= 768,
                "One bounded output-token cap is required", _CODE)
        if "temperature" in request:
            value = request["temperature"]
            require(type(value) in (int, float) and math.isfinite(value) and value == 0,
                    "The new agent adapter fixes temperature at zero", _CODE)
        messages = request["messages"]
        require(isinstance(messages, list) and bool(messages)
                and all(isinstance(m, dict) and set(m) == {"role", "content"}
                        and m["role"] in ("system", "user", "assistant")
                        and isinstance(m["content"], str) for m in messages)
                and messages[0]["role"] == "system"
                and all(m["role"] != "system" for m in messages[1:]),
                "Count the complete text wire conversation; tool results must already be wrapped as user messages", _CODE)
        # Reuse the historical format checks and finite-JSON checks on a local
        # two-message envelope, then return the untouched actual conversation.
        # The envelope is never rendered or encoded: it only avoids duplicating
        # those unrelated response-format validators.
        envelope = deepcopy(request)
        envelope["messages"] = [deepcopy(messages[0]), {"role": "user", "content": ""}]
        super()._validated(envelope)
        return deepcopy(request)

    def render_request(self, request):
        value = self._validated(request)
        messages = deepcopy(value["messages"])
        for message in messages:
            if message["role"] == "assistant":
                # The upstream template tests m.tool_calls by truthiness. The
                # old counter never rendered an assistant history, so its
                # StrictUndefined environment did not need this default. These
                # are template-only absent-field defaults, not wire changes.
                message["tool_calls"] = []
                message["reasoning_content"] = None
        try:
            return self._compiled_template.render(messages=messages, tools=None,
                add_generation_prompt=True, reasoning_effort=value["reasoning_effort"],
                clear_thinking=False)
        except Exception:
            raise ContractError(_CODE, "The pinned chat template rejected the full conversation") from None

    def request_statistics(self, request):
        """JSON sidecar metadata, including hashes of every unmodified message."""
        value = self._validated(request)
        estimate = self.estimate_request(value)
        rendered = self.render_request(value)
        counts = Counter(m["role"] for m in value["messages"])
        return {**estimate.to_dict(),
            "counter_schema": "ctx-full-wire-glm53-count-v1",
            "classification": "pinned-upstream-local-count" if self._assets_verified else "fixture-encoder-count",
            "count_scope": "all-wire-messages-after-pinned-chat-template",
            "message_count": len(value["messages"]), "role_counts": dict(sorted(counts.items())),
            "wire_message_sha256s": [digest(m) for m in value["messages"]],
            "wire_messages_sha256": digest(value["messages"]), "wire_request_sha256": digest(value),
            "rendered_prompt_sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
            "rendered_prompt_bytes": len(rendered.encode("utf-8")),
            "message_content_bytes": sum(len(m["content"].encode("utf-8")) for m in value["messages"]),
            "input_messages_dropped": 0, "input_messages_truncated": 0,
            "local_assets_verified": self._assets_verified,
            "server_wrapping_verified": False, "suitable_for_live_admission": False,
            "provider_usage_observed": False,
        }

    def make_fixture_bound_counter(self, *, extra_prompt_tokens=0):
        """Adapter-compatible admission for fake HTTP, never deployment proof.

        Optional padding is explicit fixture policy, not a measured server
        surcharge. The resulting callable exposes ``request_statistics`` so the
        adapter can persist this provenance alongside its PreparedRequest.
        """
        require(type(extra_prompt_tokens) is int and extra_prompt_tokens >= 0,
                "Fixture padding must be a nonnegative integer", _CODE)
        reference = "fixture:ctx-full-wire-glm53-local:" + digest({
            "template_sha256": self._template_sha256,
            "tokenizer_sha256": self._tokenizer_sha256,
            "extra_prompt_tokens": extra_prompt_tokens})

        def statistics(request):
            result = self.request_statistics(request)
            result.update(fixture_only=True, admission_padding_tokens=extra_prompt_tokens,
                          admission_bound_tokens=result["prompt_tokens"] + extra_prompt_tokens,
                          admission_evidence=reference)
            return result

        def bound(request):
            return self.estimate_request(request).prompt_tokens + extra_prompt_tokens

        bound.request_statistics = statistics
        bound.fixture_only = True
        bound.source_counter = self
        return BoundTokenCounter(reference, bound)
