"""Pinned configuration for the explicitly offline S6 gateway.

Money uses integer nano-USD, so neither reservations nor charges round through
floating point. These prices describe simulated standard-token accounting;
this module contains no provider transport or credentials.
"""

from dataclasses import asdict, dataclass, fields

from .contracts import exact_fields, require


@dataclass(frozen=True)
class ModelConfig:
    config_ref: str = "s6-offline-v1"
    model: str = "gpt-4.1-mini-2025-04-14"
    transport: str = "offline_fake"
    max_input_tokens: int = 4000
    max_output_tokens: int = 768
    timeout_s: int = 120
    input_nano_usd_per_token: int = 400
    output_nano_usd_per_token: int = 1600
    max_cost_nano_usd: int = 10_000_000_000

    def __post_init__(self):
        require(isinstance(self.config_ref, str) and bool(self.config_ref), "Missing model config reference")
        require(self.model == "gpt-4.1-mini-2025-04-14", "Offline model snapshot is not the pinned model", "MODEL_CONFIG_ERROR")
        require(self.transport == "offline_fake", "S6 offline integration has no live transport", "OFFLINE_ONLY")
        for name in ("max_input_tokens", "max_output_tokens", "timeout_s",
                     "input_nano_usd_per_token", "output_nano_usd_per_token", "max_cost_nano_usd"):
            require(type(getattr(self, name)) is int and getattr(self, name) > 0,
                    f"Invalid model configuration: {name}", "MODEL_CONFIG_ERROR")
        require(self.max_input_tokens <= 4000 and self.max_output_tokens <= 768
                and self.timeout_s <= 120, "Offline request caps exceed the approved configuration", "MODEL_CONFIG_ERROR")
        require(self.input_nano_usd_per_token == 400 and self.output_nano_usd_per_token == 1600,
                "Token prices differ from the pinned standard-token rates", "MODEL_CONFIG_ERROR")
        require(self.max_cost_nano_usd <= 10_000_000_000,
                "Per-run cost cap exceeds the offline planning limit", "MODEL_CONFIG_ERROR")

    @property
    def worst_case_cost_nano_usd(self):
        return (self.max_input_tokens * self.input_nano_usd_per_token
                + self.max_output_tokens * self.output_nano_usd_per_token)

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, value):
        exact_fields(value, {field.name for field in fields(cls)}, "ModelConfig")
        return cls(**value)
