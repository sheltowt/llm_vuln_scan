"""HTTP and OpenAI-compatible targets against a mocked transport."""

import httpx
import pytest
import respx

from llm_vuln_scan.core.models import Conversation, Message
from llm_vuln_scan.targets.base import TargetError
from llm_vuln_scan.targets.http import MISSING, HttpTarget, json_path, render
from llm_vuln_scan.targets.openai_compat import OpenAICompatTarget

URL = "https://app.test/chat"
FAST = {"max_retries": 2, "retry_backoff": 0.0}


def test_render_substitutes_nested_and_whole_values():
    variables = {"prompt": "hi", "history": [{"role": "user", "content": "hi"}]}
    out = render({"q": "say {{prompt}}!", "messages": "{{history}}", "n": [1, "{{ prompt }}"]}, variables)
    assert out == {"q": "say hi!", "messages": variables["history"], "n": [1, "hi"]}


def test_json_path():
    data = {"a": {"b": [{"c": 1}, {"c": None}]}}
    assert json_path(data, "$.a.b[0].c") == 1
    assert json_path(data, "$.a.b[1].c") is None
    assert json_path(data, "$.a.b[5].c") is MISSING
    assert json_path(data, "$.a.x") is MISSING
    assert json_path(data, "") is data


@respx.mock
async def test_http_renders_body_and_extracts_response():
    route = respx.post(URL).mock(return_value=httpx.Response(200, json={"data": {"reply": "hello"}}))
    target = HttpTarget(url=URL, body={"input": "{{prompt}}"}, response="$.data.reply",
                        headers={"X-Key": "k"})
    msg = await target.send(Conversation.of("ping"))
    await target.aclose()
    assert msg.content == "hello"
    request = route.calls.last.request
    assert request.headers["X-Key"] == "k"
    assert request.content == b'{"input":"ping"}'


@respx.mock
async def test_http_session_parser_carries_session_across_turns():
    respx.post(URL).mock(return_value=httpx.Response(200, json={"output": "a", "sid": "abc"}))
    target = HttpTarget(url=URL, session_parser="$.sid")
    convo = Conversation.of("one")
    await target.send(convo)
    await target.aclose()
    assert convo.session_id == "abc"


@respx.mock
async def test_http_retries_server_errors_then_succeeds():
    route = respx.post(URL).mock(side_effect=[
        httpx.Response(500, text="boom"),
        httpx.Response(200, json={"output": "recovered"}),
    ])
    target = HttpTarget(url=URL, **FAST)
    msg = await target.send(Conversation.of("x"))
    await target.aclose()
    assert msg.content == "recovered"
    assert route.call_count == 2


@respx.mock
async def test_http_client_error_is_not_retried():
    route = respx.post(URL).mock(return_value=httpx.Response(400, text="bad request"))
    target = HttpTarget(url=URL, **FAST)
    with pytest.raises(TargetError, match="HTTP 400"):
        await target.send(Conversation.of("x"))
    await target.aclose()
    assert route.call_count == 1


@respx.mock
async def test_http_rate_limit_is_retried():
    route = respx.post(URL).mock(side_effect=[
        httpx.Response(429, headers={"retry-after": "0"}),
        httpx.Response(200, json={"output": "ok"}),
    ])
    target = HttpTarget(url=URL, **FAST)
    assert (await target.send(Conversation.of("x"))).content == "ok"
    await target.aclose()
    assert route.call_count == 2


@respx.mock
async def test_http_wrong_response_path_is_an_error_but_null_is_empty():
    respx.post(URL).mock(return_value=httpx.Response(200, json={"output": None}))
    target = HttpTarget(url=URL, **FAST)
    assert (await target.send(Conversation.of("x"))).content == ""

    wrong = HttpTarget(url=URL, response="$.nope", max_retries=0)
    with pytest.raises(TargetError, match="not found"):
        await wrong.send(Conversation.of("x"))
    await target.aclose()
    await wrong.aclose()


def test_http_requires_url():
    with pytest.raises(TargetError):
        HttpTarget()


BASE_URL = "https://llm.test/v1"


@respx.mock
async def test_openai_compat_request_and_response(monkeypatch):
    monkeypatch.setenv("TEST_KEY", "sk-test")
    route = respx.post(f"{BASE_URL}/chat/completions").mock(return_value=httpx.Response(200, json={
        "choices": [{"message": {"content": "hi there"}, "finish_reason": "stop"}],
        "usage": {"total_tokens": 7},
    }))
    target = OpenAICompatTarget(base_url=BASE_URL, model="m", api_key_env="TEST_KEY",
                                system_prompt="be nice")
    msg = await target.send(Conversation(messages=[Message.user("hello")]))
    await target.aclose()
    assert msg.content == "hi there"
    assert target.total_tokens == 7
    request = route.calls.last.request
    assert request.headers["Authorization"] == "Bearer sk-test"
    body = httpx.Response(200, content=request.content).json()
    assert body["model"] == "m"
    assert body["messages"][0] == {"role": "system", "content": "be nice"}


@respx.mock
async def test_openai_compat_errors():
    respx.post(f"{BASE_URL}/chat/completions").mock(return_value=httpx.Response(200, json={"choices": []}))
    target = OpenAICompatTarget(base_url=BASE_URL, model="m", max_retries=0)
    with pytest.raises(TargetError, match="no choices"):
        await target.send(Conversation.of("x"))
    await target.aclose()

    with pytest.raises(TargetError):
        OpenAICompatTarget(base_url=BASE_URL)
