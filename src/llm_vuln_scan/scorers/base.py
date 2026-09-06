"""Scorer base.

A scorer answers one question about one attempt and reports how sure it is.
Confidence is not decoration: the evaluator drops low-confidence scores out of
CI gates, which is how we keep string matching useful without letting it fail
builds on a short or non-English reply.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..core.models import Attempt, Score, ScorerCost, Seed
from ..core.plugin import Plugin

if TYPE_CHECKING:  # pragma: no cover
    from ..core.context import AppContext


class Scorer(Plugin):
    kind = "scorer"
    cost: ScorerCost = ScorerCost.HEURISTIC
    category: str | None = None

    async def score(self, attempt: Attempt, seed: Seed, ctx: AppContext) -> Score:  # pragma: no cover
        raise NotImplementedError

    def result(
        self,
        value: float,
        *,
        confidence: float = 1.0,
        rationale: str = "",
        category: str | None = None,
        threshold: float = 0.5,
        cost: ScorerCost | None = None,
    ) -> Score:
        value = max(0.0, min(1.0, float(value)))
        return Score(
            scorer=self.name,
            value=value,
            passed=value < threshold,
            confidence=max(0.0, min(1.0, float(confidence))),
            rationale=rationale,
            category=category or self.category,
            cost=cost or self.cost,
            identifier=self.identifier,
        )


def text_of(attempt: Attempt) -> str:
    """The response text a scorer should look at, after response decoding."""
    return attempt.conversation.assistant_text


def is_probably_english(text: str) -> bool:
    if not text:
        return True
    ascii_letters = sum(1 for c in text if c.isascii() and c.isalpha())
    letters = sum(1 for c in text if c.isalpha())
    return letters == 0 or (ascii_letters / letters) > 0.75


def length_confidence(text: str, base: float = 1.0) -> float:
    """Short answers carry little evidence either way. Say so instead of guessing."""
    stripped = text.strip()
    if not stripped:
        return min(base, 0.25)
    if len(stripped) < 20:
        return min(base, 0.5)
    if len(stripped) < 60:
        return min(base, 0.8)
    return base


def build_scorer(name: str, **params: Any) -> Scorer:
    from ..core.plugin import build

    return build("scorer", name, **params)
