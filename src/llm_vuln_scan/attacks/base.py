"""Attack base classes.

An attack owns the *plan*; converters own the *encoding*. Multi-turn attacks
branch only on scorer output, never on raw response text, which is the rule that
keeps adaptive loops from chasing polite refusals forever.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..converters.base import ConverterChain
from ..core.models import Attempt, Conversation, Message, Score, Seed, Tier
from ..core.plugin import Plugin

if TYPE_CHECKING:  # pragma: no cover
    from ..core.context import AppContext
    from ..scorers.base import Scorer
    from ..targets.base import Target


@dataclass
class AttackResult:
    """What an attack hands back to the runner."""

    conversation: Conversation
    prompt: str
    turns: int = 1
    converters: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    in_loop_scores: list[Score] = field(default_factory=list)


class Attack(Plugin):
    kind = "attack"
    tier: Tier = Tier.STATIC
    multi_turn: bool = False
    DEFAULT_PARAMS: dict[str, Any] = {"weight": 1.0}

    @property
    def weight(self) -> float:
        return float(self.params.get("weight", 1.0))

    def supports(self, target: Target) -> bool:
        """Attacks that need capabilities the target lacks are skipped, not faked."""
        if self.multi_turn and not target.capabilities.multi_turn:
            return False
        return True

    async def probe_score(
        self,
        scorer: Scorer | None,
        conversation: Conversation,
        seed: Seed,
        ctx: AppContext,
        prompt: str,
    ) -> Score | None:
        """Score an in-progress conversation so the loop has something to climb."""
        if scorer is None:
            return None
        probe = Attempt(
            vulnerability=seed.vulnerability,
            vuln_type=seed.vuln_type,
            seed_id=seed.id,
            prompt=prompt,
            seed_prompt=seed.prompt,
            goal=seed.goal,
            conversation=conversation,
        )
        return await scorer.score(probe, seed, ctx)


class SingleTurnAttack(Attack):
    """Deliver one prompt, optionally re-encoded.

    ``converter_names`` is the whole implementation for most static attacks,
    which is why adding an encoding costs one line rather than a new class.
    """

    converter_names: list[str] = []
    DEFAULT_PARAMS = {**Attack.DEFAULT_PARAMS, "converters": None, "converter_params": {}}

    def chain(self) -> ConverterChain:
        names = self.params.get("converters") or self.converter_names
        return ConverterChain.build(list(names), self.params.get("converter_params") or {})

    async def build_prompt(self, seed: Seed, ctx: AppContext) -> tuple[str, list[str]]:
        chain = self.chain()
        return chain.transform(seed.prompt), chain.names

    def decode_output(self, text: str) -> str:
        """Undo the attack's encoding on the response before scoring."""
        return self.chain().untransform(text)

    async def run(
        self, seed: Seed, target: Target, scorer: Scorer | None, ctx: AppContext
    ) -> AttackResult:
        prompt, converters = await self.build_prompt(seed, ctx)
        conversation = Conversation.of(prompt)
        message = await target.send(conversation)
        conversation.add(_decoded(message, self.decode_output(message.content)))
        return AttackResult(
            conversation=conversation, prompt=prompt, turns=1, converters=converters
        )


class MultiTurnAttack(Attack):
    """Adaptive loop: attacker proposes, target answers, scorer decides."""

    multi_turn = True
    tier = Tier.DYNAMIC
    DEFAULT_PARAMS = {**Attack.DEFAULT_PARAMS, "max_turns": 5}

    async def run(
        self, seed: Seed, target: Target, scorer: Scorer | None, ctx: AppContext
    ) -> AttackResult:  # pragma: no cover - abstract
        raise NotImplementedError

def _decoded(message: Message, decoded_text: str) -> Message:
    """Attach the decoded response, keeping the original for the report."""
    if decoded_text == message.content:
        return message
    return Message(
        role=message.role,
        content=decoded_text,
        tool_calls=message.tool_calls,
        metadata={**message.metadata, "raw_content": message.content},
    )
