from llm_vuln_scan.core.models import (
    Attempt,
    Conversation,
    Message,
    Outcome,
    Score,
    Severity,
    content_hash,
)


def test_severity_ordering():
    assert Severity.CRITICAL.at_least(Severity.HIGH)
    assert not Severity.LOW.at_least(Severity.HIGH)
    assert Severity.parse("HIGH") is Severity.HIGH


def test_content_hash_is_stable_and_order_independent():
    assert content_hash({"a": 1, "b": 2}) == content_hash({"b": 2, "a": 1})
    assert content_hash([1, 2]) != content_hash([2, 1])


def test_conversation_helpers():
    c = Conversation.of("hello", system="be nice")
    assert c.turns == 1
    c.add(Message.assistant("hi there"))
    assert c.assistant_text == "hi there"
    assert c.drop_last().messages[-1].role.value == "user"


def test_finalize_respects_confidence_floor():
    # A weak hit that clears the "evaluated" floor but not the gate floor, with
    # no clean signal, is INCONCLUSIVE: the check ran but proved nothing. It must
    # never be reported as a clean PASS.
    a = Attempt(scores=[Score(scorer="x", value=1.0, passed=False, confidence=0.3)])
    a.finalize(min_confidence=0.6)
    assert a.outcome is Outcome.INCONCLUSIVE

    # A confident hit fails.
    b = Attempt(scores=[Score(scorer="x", value=1.0, passed=False, confidence=0.9)])
    b.finalize(min_confidence=0.6)
    assert b.outcome is Outcome.FAIL

    # A non-evaluation (0.0 confidence sentinel) alone is INCONCLUSIVE, not PASS.
    c = Attempt(scores=[Score(scorer="judge", value=0.0, passed=True, confidence=0.0)])
    c.finalize(min_confidence=0.6)
    assert c.outcome is Outcome.INCONCLUSIVE

    # A real clean signal is a PASS.
    d = Attempt(scores=[Score(scorer="substring", value=0.0, passed=True, confidence=0.85)])
    d.finalize(min_confidence=0.6)
    assert d.outcome is Outcome.PASS


def test_attempt_key_is_stable():
    a = Attempt(vulnerability="v", vuln_type="t", attack="direct", seed_id="s1")
    assert a.key() == "v/t/direct/s1"
