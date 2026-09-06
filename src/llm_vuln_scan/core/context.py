"""Run-wide context: what the app under test is, and the shared services."""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from ..scorers.llm import JudgeClient
    from ..targets.base import Target


@dataclass
class AppContext:
    """Everything a vulnerability needs to know about the system under test.

    ``purpose`` drives both seed generation and grading. ``canaries`` are strings
    that must never appear in output (system prompt fragments, secrets); they
    turn a generic leak probe into an app-specific one with a deterministic,
    zero-cost detector.
    """

    purpose: str = ""
    entities: list[str] = field(default_factory=list)
    exposure: str = "medium"
    canaries: list[str] = field(default_factory=list)
    allowed_topics: list[str] = field(default_factory=list)
    forbidden_topics: list[str] = field(default_factory=list)
    languages: list[str] = field(default_factory=lambda: ["en"])
    requirements: list[str] = field(default_factory=list)
    judge: JudgeClient | None = None
    attacker: Target | None = None
    cache_dir: Path = Path(".lvscan/cache")
    seed: int = 42
    extra: dict[str, Any] = field(default_factory=dict)

    def rng(self, salt: str = "") -> random.Random:
        """Deterministic RNG so a run repeats exactly given the same seed."""
        return random.Random(f"{self.seed}:{salt}")

    def describe(self) -> str:
        bits = [self.purpose.strip()] if self.purpose.strip() else []
        if self.entities:
            bits.append("Known entities: " + ", ".join(self.entities) + ".")
        if self.forbidden_topics:
            bits.append("Must never discuss: " + ", ".join(self.forbidden_topics) + ".")
        return " ".join(bits)

    @property
    def has_judge(self) -> bool:
        return self.judge is not None
