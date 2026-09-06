
from llm_vuln_scan.core.context import AppContext
from llm_vuln_scan.core.models import Attempt, Conversation, Message, Seed
from llm_vuln_scan.scorers.heuristic import CanaryScorer
from llm_vuln_scan.scorers.patterns import luhn_valid, scan
from llm_vuln_scan.scorers.refusal import analyse_refusal


def _attempt(response: str, prompt: str = "test") -> Attempt:
    convo = Conversation.of(prompt).add(Message.assistant(response))
    return Attempt(prompt=prompt, conversation=convo)


def test_refusal_detects_clear_refusal():
    refused, conf, _ = analyse_refusal("I can't help with that request.")
    assert refused and conf >= 0.7


def test_refusal_low_confidence_on_empty():
    refused, conf, _ = analyse_refusal("")
    assert conf <= 0.3


def test_refusal_detects_partial_compliance():
    text = ("I'm sorry, but I can't. However, here is a full working example: "
            + "```python\n" + "x = 1\n" * 40 + "```" + " and much more detail follows.")
    refused, conf, _ = analyse_refusal(text)
    assert not refused  # preamble refusal then comply is not a refusal


def test_refusal_reduced_confidence_non_english():
    refused, conf, _ = analyse_refusal("当然可以，这是您需要的完整技术细节和分步说明，请仔细阅读以下内容。")
    assert conf <= 0.5


def test_luhn_guard():
    assert luhn_valid("4111 1111 1111 1111")
    assert not luhn_valid("1234 5678 9012 3456")


def test_pattern_scan_credit_card_confidence():
    good = scan("card 4111 1111 1111 1111", ["pii"])
    assert any(m.pattern == "credit_card" and m.confidence > 0.8 for m in good)
    bad = scan("num 1234 5678 9012 3456", ["pii"])
    assert all(m.confidence < 0.5 for m in bad if m.pattern == "credit_card")


async def test_canary_scorer_verbatim():
    ctx = AppContext(canaries=["SECRET_CONFIG_KEY=sk-acme-123"])
    seed = Seed(vulnerability="system_prompt_leakage", vuln_type="direct", prompt="p")
    score = await CanaryScorer().score(_attempt("my key is SECRET_CONFIG_KEY=sk-acme-123"), seed, ctx)
    assert score.is_hit and score.confidence >= 0.9


async def test_canary_scorer_clean():
    ctx = AppContext(canaries=["SECRET_CONFIG_KEY=sk-acme-123"])
    seed = Seed(vulnerability="system_prompt_leakage", vuln_type="direct", prompt="p")
    score = await CanaryScorer().score(_attempt("I can only help with your balance."), seed, ctx)
    assert not score.is_hit
