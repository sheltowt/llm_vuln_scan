"""Agent target: a tool-using system whose actions we can inspect.

Agentic vulnerabilities (BOLA, tool misuse, excessive agency) are about what the
agent *did*, not what it said. This adapter surfaces the tool-call trace so
scorers can judge actions directly.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

from ..core.models import Conversation, Message, ToolCall
from ..core.plugin import register
from .base import Target, TargetCapabilities, TargetError
from .callable_target import _load_dotted


@register("target", "agent")
class AgentTarget(Target):
    """``fn(conversation) -> (text, [ToolCall|dict])`` or a Message with tool_calls."""

    DEFAULT_PARAMS = {**Target.DEFAULT_PARAMS, "fn": None, "import_path": None}

    def __init__(self, fn: Callable[..., Any] | None = None, **params: Any) -> None:
        params.setdefault("capabilities", TargetCapabilities(tools=True))
        caps = params.pop("capabilities")
        super().__init__(capabilities=caps, **params)
        target_fn = fn or self.params.get("fn") or self.params.get("import_path")
        if isinstance(target_fn, str):
            target_fn = _load_dotted(target_fn)
        if target_fn is None:
            raise TargetError("agent target needs fn= or import_path=")
        self.fn = target_fn

    async def _send(self, conversation: Conversation) -> Message:
        result = self.fn(conversation)
        if inspect.isawaitable(result):
            result = await result
        if isinstance(result, Message):
            return result
        text: str = ""
        calls: list[ToolCall] = []
        if isinstance(result, tuple) and len(result) == 2:
            text, raw_calls = result
            for c in raw_calls or []:
                calls.append(c if isinstance(c, ToolCall) else ToolCall(**c))
        elif isinstance(result, dict):
            text = str(result.get("content", ""))
            for c in result.get("tool_calls") or []:
                calls.append(c if isinstance(c, ToolCall) else ToolCall(**c))
        else:
            text = str(result)
        return Message.assistant(str(text), tool_calls=calls)

    @property
    def description(self) -> str:
        return f"agent:{getattr(self.fn, '__qualname__', self.fn)}"
