"""Milestone D: new attacks, converters, and the optional classifier."""



from llm_vuln_scan.converters.encodings import AsciiSmugglingConverter
from llm_vuln_scan.core.context import AppContext
from llm_vuln_scan.core.models import Attempt, Conversation, Message, Seed
from llm_vuln_scan.core.plugin import build
from llm_vuln_scan.scorers.classifier import HFClassifierScorer


def test_ascii_smuggling_is_invisible_and_reversible():
    c = AsciiSmugglingConverter()
    enc = c.transform("LEAK_TOKEN_42")
    # every payload char maps into the invisible tag block
    assert all(ord(ch) >= 0xE0000 for ch in enc)
    # and a model echoing it back decodes for scoring
    assert "LEAK_TOKEN_42" in c.untransform("here you go: " + enc)


def test_ascii_smuggling_cover_is_visible():
    c = AsciiSmugglingConverter(cover="Hello there.")
    out = c.transform("SECRET")
    assert out.startswith("Hello there.")
    assert "SECRET" not in out  # the payload itself is invisible


def test_adaptive_attacks_require_attacker():
    from llm_vuln_scan.targets.base import Target, TargetCapabilities

    class _T(Target):
        capabilities = TargetCapabilities(multi_turn=True)
        async def _send(self, conv):  # pragma: no cover - never called
            return Message.assistant("x")

    target = _T()
    target.capabilities = TargetCapabilities(multi_turn=True)
    ctx = AppContext()  # no attacker
    for name in ("goat", "translate"):
        ok, reason = build("attack", name).supports(target, ctx)
        assert not ok and "attacker" in reason


async def test_hf_classifier_degrades_without_extra():
    a = Attempt(conversation=Conversation.of("x").add(Message.assistant("text")))
    s = await HFClassifierScorer().score(a, Seed(vulnerability="t", vuln_type="hate", prompt="x"), AppContext())
    # transformers not installed -> non-evaluation, cascade falls through
    assert s.confidence == 0.0 and not s.is_hit


def test_ascii_smuggling_attack_registered_static():
    from llm_vuln_scan.core.models import Tier

    cls = build("attack", "ascii_smuggling")
    assert cls.tier is Tier.STATIC  # deterministic, safe for CI
