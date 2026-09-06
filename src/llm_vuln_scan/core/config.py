"""Configuration loading and layering.

Precedence: package defaults -> lvscan.yaml -> --config overlays -> CLI flags
-> environment. Secrets are referenced as ``${env.NAME}`` and never stored.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from .models import Severity, Tier

_ENV_RE = re.compile(r"\$\{env\.([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


class ConfigError(ValueError):
    pass


def _substitute(value: Any) -> Any:
    if isinstance(value, str):

        def repl(m: re.Match[str]) -> str:
            name, default = m.group(1), m.group(2)
            env = os.environ.get(name)
            if env is None:
                if default is None:
                    raise ConfigError(
                        f"environment variable {name} is referenced in config but not set"
                    )
                return default
            return env

        return _ENV_RE.sub(repl, value)
    if isinstance(value, dict):
        return {k: _substitute(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(v) for v in value]
    return value


def deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out


class RateLimitConfig(BaseModel):
    rps: float = 0.0
    burst: int = 1


class TargetCapabilitiesConfig(BaseModel):
    multi_turn: bool = True
    editable_history: bool = True
    system_prompt: bool = True
    tools: bool = False
    streaming: bool = False


class TargetConfig(BaseModel):
    type: str = "callable"
    name: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    capabilities: TargetCapabilitiesConfig = Field(default_factory=TargetCapabilitiesConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    max_retries: int = 3
    timeout: float = 60.0

    model_config = {"extra": "allow"}

    def build_params(self) -> dict[str, Any]:
        """Everything except the framework-level keys is passed to the target."""
        reserved = {"type", "name", "params", "capabilities", "rate_limit", "max_retries", "timeout"}
        extras = {k: v for k, v in (self.__pydantic_extra__ or {}).items() if k not in reserved}
        return {**extras, **self.params}


class AppConfig(BaseModel):
    purpose: str = ""
    entities: list[str] = Field(default_factory=list)
    exposure: str = "medium"
    canaries: list[str] = Field(default_factory=list)
    allowed_topics: list[str] = Field(default_factory=list)
    forbidden_topics: list[str] = Field(default_factory=list)
    languages: list[str] = Field(default_factory=lambda: ["en"])


class VulnerabilityConfig(BaseModel):
    name: str | None = None
    preset: str | None = None
    custom: str | None = None
    criteria: str | None = None
    types: list[str] | None = None
    num_seeds: int | None = None
    severity: Severity | None = None
    params: dict[str, Any] = Field(default_factory=dict)


class AttackConfig(BaseModel):
    static: list[str] = Field(default_factory=lambda: ["direct"])
    dynamic: list[str] = Field(default_factory=list)
    weights: dict[str, float] = Field(default_factory=dict)
    params: dict[str, dict[str, Any]] = Field(default_factory=dict)
    sample: int | None = None
    """If set, sample this many attacks per seed by weight instead of running all."""


class JudgeConfig(BaseModel):
    provider: str = "openai_compat"
    model: str = ""
    base_url: str | None = None
    api_key_env: str = "LVSCAN_JUDGE_API_KEY"
    temperature: float = 0.0
    max_tokens: int = 512
    params: dict[str, Any] = Field(default_factory=dict)

    @property
    def enabled(self) -> bool:
        return bool(self.model)


class ScoringConfig(BaseModel):
    judge: JudgeConfig = Field(default_factory=JudgeConfig)
    cascade: bool = True
    min_confidence: float = 0.6
    extra_scorers: list[str] = Field(default_factory=list)


class BudgetConfig(BaseModel):
    max_attempts: int = 0
    max_tokens: int = 0


class RunConfig(BaseModel):
    tier: Tier = Tier.STATIC
    seed: int = 42
    generations: int = 1
    concurrency: int = 8
    cache: str = ".lvscan/cache"
    output_dir: str = "lvscan_runs"
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    labels: dict[str, str] = Field(default_factory=dict)


class GateConfig(BaseModel):
    fail_on_severity: Severity | None = None
    fail_on_new: bool = False
    pass_rate: float | None = None
    baseline: str | None = None
    flake_retries: int = 0


class ScanConfig(BaseModel):
    target: TargetConfig = Field(default_factory=TargetConfig)
    app: AppConfig = Field(default_factory=AppConfig)
    vulnerabilities: list[VulnerabilityConfig] = Field(
        default_factory=lambda: [VulnerabilityConfig(preset="default")]
    )
    attacks: AttackConfig = Field(default_factory=AttackConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    run: RunConfig = Field(default_factory=RunConfig)
    gates: GateConfig = Field(default_factory=GateConfig)

    @classmethod
    def load(
        cls,
        path: str | Path | None = None,
        overlays: list[str | Path] | None = None,
        overrides: dict[str, Any] | None = None,
    ) -> ScanConfig:
        data: dict[str, Any] = {}
        for candidate in [path, *(overlays or [])]:
            if candidate is None:
                continue
            p = Path(candidate)
            if not p.exists():
                raise ConfigError(f"config file not found: {p}")
            loaded = yaml.safe_load(p.read_text()) or {}
            if not isinstance(loaded, dict):
                raise ConfigError(f"config file {p} must contain a mapping at the top level")
            data = deep_merge(data, loaded)
        if overrides:
            data = deep_merge(data, overrides)
        return cls.model_validate(_substitute(data))

    def dump(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)
