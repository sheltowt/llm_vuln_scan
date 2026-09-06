"""Wrap any Python callable as a target. The zero-friction path for testing your own app."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable
from typing import Any

from ..core.models import Conversation, Message
from ..core.plugin import register
from .base import Target, TargetError


def _load_dotted(path: str) -> Callable[..., Any]:
    """Resolve ``module:function``, ``module.function`` or ``path/to/file.py:function``.

    The file-path form means a user can point at their own app without putting it
    on PYTHONPATH, which is the common case for testing a local application.
    """
    import importlib.util
    from pathlib import Path

    module_ref, _, attr = path.rpartition(":")
    if module_ref and (module_ref.endswith(".py") or "/" in module_ref):
        file_path = Path(module_ref)
        if not file_path.exists():
            raise TargetError(f"callable file not found: {file_path}")
        spec = importlib.util.spec_from_file_location(f"lvscan_target_{file_path.stem}", file_path)
        if spec is None or spec.loader is None:
            raise TargetError(f"cannot load {file_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        fn = getattr(module, attr, None)
        if fn is None:
            raise TargetError(f"{file_path} has no attribute {attr!r}")
        return fn
    module_name = module_ref
    if not module_name:
        module_name, _, attr = path.rpartition(".")
    if not module_name:
        raise TargetError(f"cannot resolve callable {path!r}; use 'module:function' or 'file.py:function'")
    module = importlib.import_module(module_name)
    fn = getattr(module, attr, None)
    if fn is None:
        raise TargetError(f"{module_name} has no attribute {attr!r}")
    return fn


@register("target", "callable")
class CallableTarget(Target):
    """``fn`` may take a str or a Conversation, and may be sync or async.

    Returning a ``Message`` lets an agent hand back its tool-call trace.
    """

    DEFAULT_PARAMS = {**Target.DEFAULT_PARAMS, "fn": None, "import_path": None}

    def __init__(self, fn: Callable[..., Any] | None = None, **params: Any) -> None:
        super().__init__(**params)
        target_fn = fn or self.params.get("fn")
        if isinstance(target_fn, str):
            target_fn = _load_dotted(target_fn)
        if target_fn is None and self.params.get("import_path"):
            target_fn = _load_dotted(str(self.params["import_path"]))
        if target_fn is None:
            raise TargetError("callable target needs fn= or import_path=")
        self.fn = target_fn
        self._wants_conversation = self._detect_signature()

    def _detect_signature(self) -> bool:
        try:
            sig = inspect.signature(self.fn)
        except (TypeError, ValueError):  # pragma: no cover - builtins
            return False
        first = next(iter(sig.parameters.values()), None)
        if first is None:
            return False
        annotation = first.annotation
        return annotation is Conversation or (
            isinstance(annotation, str) and "Conversation" in annotation
        )

    async def _send(self, conversation: Conversation) -> Message:
        arg: Any = conversation if self._wants_conversation else _last_user_text(conversation)
        result = self.fn(arg)
        if inspect.isawaitable(result):
            result = await result
        elif asyncio.iscoroutinefunction(self.fn):  # pragma: no cover - defensive
            result = await result
        if isinstance(result, Message):
            return result
        if isinstance(result, dict):
            return Message.assistant(str(result.get("content", "")), metadata=result)
        return Message.assistant("" if result is None else str(result))

    @property
    def description(self) -> str:
        return f"callable:{getattr(self.fn, '__qualname__', self.fn)}"


def _last_user_text(conversation: Conversation) -> str:
    for m in reversed(conversation.messages):
        if m.role.value == "user":
            return m.content
    return ""
