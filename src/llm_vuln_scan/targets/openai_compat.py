"""OpenAI-compatible chat target.

One adapter covers OpenAI, Ollama, vLLM, LiteLLM, Together and any gateway that
speaks /chat/completions, so we never bake in a vendor.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from ..core.models import Conversation, Message, Role
from ..core.plugin import register
from .base import Target, TargetError


@register("target", "openai_compat")
class OpenAICompatTarget(Target):
    DEFAULT_PARAMS = {
        **Target.DEFAULT_PARAMS,
        "base_url": "https://api.openai.com/v1",
        "model": "",
        "api_key": None,
        "api_key_env": "OPENAI_API_KEY",
        "temperature": 0.0,
        "max_tokens": 1024,
        "system_prompt": None,
        "extra_body": {},
        "headers": {},
    }

    def __init__(self, **params: Any) -> None:
        super().__init__(**params)
        if not self.params.get("model"):
            raise TargetError("openai_compat target requires model")
        self._client = httpx.AsyncClient(timeout=float(self.params["timeout"]))

    def _auth_headers(self) -> dict[str, str]:
        key = self.params.get("api_key") or os.environ.get(str(self.params["api_key_env"]), "")
        headers = {"Content-Type": "application/json"}
        headers.update({str(k): str(v) for k, v in (self.params.get("headers") or {}).items()})
        if key:
            headers["Authorization"] = f"Bearer {key}"
        return headers

    async def _send(self, conversation: Conversation) -> Message:
        messages = [
            {"role": m.role.value, "content": m.content}
            for m in conversation.messages
            if m.role is not Role.TOOL
        ]
        if self.params.get("system_prompt") and not any(
            m["role"] == "system" for m in messages
        ):
            messages.insert(0, {"role": "system", "content": str(self.params["system_prompt"])})

        payload: dict[str, Any] = {
            "model": self.params["model"],
            "messages": messages,
            "temperature": self.params["temperature"],
            "max_tokens": self.params["max_tokens"],
            **(self.params.get("extra_body") or {}),
        }
        url = str(self.params["base_url"]).rstrip("/") + "/chat/completions"
        response = await self._client.post(url, json=payload, headers=self._auth_headers())
        if response.status_code == 429:
            raise TargetError("rate limited: HTTP 429")
        if response.status_code >= 400:
            err = TargetError(f"HTTP {response.status_code}: {response.text[:300]}")
            err.retryable = response.status_code >= 500  # type: ignore[attr-defined]
            raise err
        data = response.json()
        choices = data.get("choices") or []
        if not choices:
            raise TargetError(f"no choices in response: {str(data)[:200]}")
        content = (choices[0].get("message") or {}).get("content") or ""
        usage = data.get("usage") or {}
        return Message.assistant(
            content,
            metadata={
                "tokens": usage.get("total_tokens", 0),
                "finish_reason": choices[0].get("finish_reason"),
            },
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    @property
    def description(self) -> str:
        return f"openai_compat:{self.params['model']}"
