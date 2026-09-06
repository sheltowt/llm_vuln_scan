"""Assemble live objects from a config: target, judge, attacker, context.

Kept separate from the runner so tests can wire a fake target directly and the
CLI has one place that owns credential resolution.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..scorers.llm import JudgeClient
from .cache import ResponseCache
from .config import ScanConfig
from .context import AppContext
from .plugin import build
from .ratelimit import TokenBucket


def build_target(config: ScanConfig) -> Any:
    from ..targets.base import TargetCapabilities

    tc = config.target
    params = tc.build_params()
    # A stateful target keeps its own server-side transcript, so we cannot delete
    # a turn from it. Backtracking attacks must know this, or they corrupt the
    # conversation. Stateful forces editable_history off unless explicitly kept on.
    editable = tc.capabilities.editable_history
    if params.get("stateful") and "editable_history" not in (tc.capabilities.model_fields_set):
        editable = False
    caps = TargetCapabilities(
        multi_turn=tc.capabilities.multi_turn,
        editable_history=editable,
        system_prompt=tc.capabilities.system_prompt,
        tools=tc.capabilities.tools,
        streaming=tc.capabilities.streaming,
    )
    bucket = TokenBucket(rps=tc.rate_limit.rps, burst=tc.rate_limit.burst)
    params.setdefault("max_retries", tc.max_retries)
    params.setdefault("timeout", tc.timeout)
    return build("target", tc.type, capabilities=caps, rate_limit=bucket, **params)


def build_judge(config: ScanConfig, cache: ResponseCache | None = None) -> JudgeClient | None:
    jc = config.scoring.judge
    if not jc.enabled:
        return None
    key = os.environ.get(jc.api_key_env, "")
    target = build(
        "target",
        "openai_compat",
        model=jc.model,
        base_url=jc.base_url or "https://api.openai.com/v1",
        api_key=key or None,
        api_key_env=jc.api_key_env,
        temperature=jc.temperature,
        max_tokens=jc.max_tokens,
        rate_limit=TokenBucket(rps=0),
        **jc.params,
    )
    return JudgeClient(target, cache=cache, model=jc.model)


def build_context(config: ScanConfig, judge: JudgeClient | None = None) -> AppContext:
    app = config.app
    return AppContext(
        purpose=app.purpose,
        entities=app.entities,
        exposure=app.exposure,
        canaries=app.canaries,
        allowed_topics=app.allowed_topics,
        forbidden_topics=app.forbidden_topics,
        languages=app.languages,
        judge=judge,
        attacker=judge.target if judge else None,
        cache_dir=Path(config.run.cache),
        seed=config.run.seed,
    )


def assemble(config: ScanConfig) -> tuple[Any, AppContext]:
    """Return a ready target and context. The judge (if any) is attached to ctx."""

    cache = ResponseCache(config.run.cache, enabled=bool(config.run.cache))
    judge = build_judge(config, cache=cache)
    ctx = build_context(config, judge=judge)
    target = build_target(config)
    return target, ctx
