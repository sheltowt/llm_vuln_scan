"""Target abstraction: the system under test."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from ..core.models import Conversation, Message
from ..core.plugin import Plugin
from ..core.ratelimit import TokenBucket


@dataclass
class TargetCapabilities:
    """What the target supports.

    Attacks consult this instead of assuming. Crescendo needs editable history;
    a stateful chat endpoint that keeps its own history cannot be backtracked,
    so the attack degrades to non-backtracking rather than producing nonsense.
    """

    multi_turn: bool = True
    editable_history: bool = True
    system_prompt: bool = True
    tools: bool = False
    streaming: bool = False


class TargetError(RuntimeError):
    pass


class Target(Plugin):
    """Base target.

    Subclasses implement ``_send``. The base class owns retries, rate limiting
    and usage accounting so every adapter behaves the same under load.
    """

    kind = "target"
    DEFAULT_PARAMS: dict[str, Any] = {
        "max_retries": 3,
        "timeout": 60.0,
        "retry_backoff": 1.5,
        "stateful": False,
    }

    def __init__(self, capabilities: TargetCapabilities | None = None,
                 rate_limit: TokenBucket | None = None, **params: Any) -> None:
        super().__init__(**params)
        self.capabilities = capabilities or TargetCapabilities()
        self.bucket = rate_limit or TokenBucket()
        self.total_tokens = 0
        self.total_calls = 0

    async def _send(self, conversation: Conversation) -> Message:  # pragma: no cover - abstract
        raise NotImplementedError

    async def send(self, conversation: Conversation) -> Message:
        """Send with rate limiting and bounded retries."""

        last_error: Exception | None = None
        for attempt_no in range(int(self.params["max_retries"]) + 1):
            await self.bucket.acquire()
            try:
                message = await asyncio.wait_for(
                    self._send(conversation), timeout=float(self.params["timeout"])
                )
                self.total_calls += 1
                self.total_tokens += int(message.metadata.get("tokens", 0) or 0)
                return message
            except TimeoutError as exc:
                last_error = TargetError(f"timeout after {self.params['timeout']}s")
                last_error.__cause__ = exc
            except TargetError as exc:
                last_error = exc
                if not getattr(exc, "retryable", True):
                    break
            except Exception as exc:  # noqa: BLE001 - adapters raise anything
                last_error = exc
            if attempt_no < int(self.params["max_retries"]):
                # Honour a server-provided Retry-After over the exponential
                # backoff when it is present and longer.
                backoff = float(self.params["retry_backoff"]) ** attempt_no
                retry_after = getattr(last_error, "retry_after", None)
                await asyncio.sleep(max(backoff, retry_after) if retry_after else backoff)
        raise TargetError(str(last_error) or "target call failed") from last_error

    async def aclose(self) -> None:
        return None

    @property
    def description(self) -> str:
        return f"{self.name}"
