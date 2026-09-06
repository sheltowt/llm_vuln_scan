"""Generic HTTP target.

Covers the case garak's REST generator and promptfoo's HTTP provider both aim
at: an internal app behind a bespoke JSON API, with session handling, so
multi-turn attacks work against real chat backends.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from ..core.models import Conversation, Message, Role
from ..core.plugin import register
from .base import Target, TargetError

_VAR_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_.]+)\s*\}\}")


def render(template: Any, variables: dict[str, Any]) -> Any:
    """Substitute ``{{var}}`` throughout a nested structure.

    A template that is exactly one placeholder yields the raw value, so
    ``{"messages": "{{history}}"}`` produces a list rather than its repr.
    """

    if isinstance(template, str):
        whole = _VAR_RE.fullmatch(template.strip())
        if whole:
            return variables.get(whole.group(1), "")
        return _VAR_RE.sub(lambda m: _stringify(variables.get(m.group(1), "")), template)
    if isinstance(template, dict):
        return {k: render(v, variables) for k, v in template.items()}
    if isinstance(template, list):
        return [render(v, variables) for v in template]
    return template


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, default=str)


def json_path(data: Any, path: str) -> Any:
    """Minimal JSONPath: ``$.a.b[0].c``. Enough for response extraction."""

    if not path:
        return data
    cursor = data
    for token in path.lstrip("$").lstrip(".").split("."):
        if not token:
            continue
        name, *indexes = re.split(r"\[(\d+)\]", token)
        if name:
            if not isinstance(cursor, dict):
                return None
            cursor = cursor.get(name)
        for idx in [i for i in indexes if i.isdigit()]:
            if not isinstance(cursor, list) or int(idx) >= len(cursor):
                return None
            cursor = cursor[int(idx)]
        if cursor is None:
            return None
    return cursor


@register("target", "http")
class HttpTarget(Target):
    DEFAULT_PARAMS = {
        **Target.DEFAULT_PARAMS,
        "url": "",
        "method": "POST",
        "headers": {},
        "body": {"prompt": "{{prompt}}"},
        "query": {},
        "response": "$.output",
        "session_parser": None,
        "session_header": None,
        "stateful": False,
        "conversation_ended": None,
        "rate_limit_codes": [429, 503],
        "verify": True,
        "client_cert": None,
        "client_key": None,
        "proxy": None,
    }

    def __init__(self, **params: Any) -> None:
        super().__init__(**params)
        if not self.params.get("url"):
            raise TargetError("http target requires url")
        cert: Any = None
        if self.params.get("client_cert"):
            cert = (
                (self.params["client_cert"], self.params["client_key"])
                if self.params.get("client_key")
                else self.params["client_cert"]
            )
        self._client = httpx.AsyncClient(
            verify=bool(self.params.get("verify", True)),
            cert=cert,
            proxy=self.params.get("proxy"),
            timeout=float(self.params["timeout"]),
        )

    def _variables(self, conversation: Conversation) -> dict[str, Any]:
        history = [
            {"role": m.role.value, "content": m.content}
            for m in conversation.messages
            if m.role is not Role.TOOL
        ]
        last_user = next(
            (m.content for m in reversed(conversation.messages) if m.role is Role.USER), ""
        )
        # A stateful target keeps its own history, so it only gets the new turn.
        sent_history = history[-1:] if self.params.get("stateful") else history
        return {
            "prompt": last_user,
            "history": sent_history,
            "history_text": conversation.render(),
            "session_id": conversation.session_id or "",
            "system": next(
                (m.content for m in conversation.messages if m.role is Role.SYSTEM), ""
            ),
        }

    async def _send(self, conversation: Conversation) -> Message:
        variables = self._variables(conversation)
        headers = {str(k): str(v) for k, v in render(self.params["headers"], variables).items()}
        if self.params.get("session_header") and conversation.session_id:
            headers[str(self.params["session_header"])] = conversation.session_id
        method = str(self.params["method"]).upper()
        body = render(self.params["body"], variables)
        query = render(self.params.get("query") or {}, variables)
        request_kw: dict[str, Any] = {"headers": headers, "params": query or None}
        if method in ("POST", "PUT", "PATCH"):
            request_kw["json"] = body

        response = await self._client.request(method, str(self.params["url"]), **request_kw)
        if response.status_code in set(self.params.get("rate_limit_codes") or []):
            raise TargetError(f"rate limited: HTTP {response.status_code}")
        if response.status_code >= 400:
            err = TargetError(f"HTTP {response.status_code}: {response.text[:300]}")
            err.retryable = response.status_code >= 500  # type: ignore[attr-defined]
            raise err

        try:
            payload = response.json()
        except ValueError:
            payload = response.text

        content = payload
        if isinstance(payload, (dict, list)) and self.params.get("response"):
            content = json_path(payload, str(self.params["response"]))
        if content is None:
            raise TargetError(
                f"response path {self.params['response']!r} not found in {str(payload)[:200]}"
            )

        session_id = conversation.session_id
        if self.params.get("session_parser") and isinstance(payload, (dict, list)):
            parsed = json_path(payload, str(self.params["session_parser"]))
            if parsed:
                session_id = str(parsed)
        elif self.params.get("session_header"):
            session_id = response.headers.get(str(self.params["session_header"]), session_id)
        if session_id:
            conversation.session_id = session_id

        ended = False
        if self.params.get("conversation_ended") and isinstance(payload, (dict, list)):
            ended = bool(json_path(payload, str(self.params["conversation_ended"])))

        return Message.assistant(
            content if isinstance(content, str) else json.dumps(content, default=str),
            metadata={
                "status": response.status_code,
                "session_id": session_id,
                "conversation_ended": ended,
                "raw": payload if isinstance(payload, dict) else None,
            },
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    @property
    def description(self) -> str:
        return f"http:{self.params['url']}"
