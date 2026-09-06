"""Core data models.

Every scan produces immutable ``Attempt`` records. Reports, diffs, gates and
exports are all derived from those records and nothing else, so a run is fully
reconstructible from ``attempts.jsonl``.

Scoring convention (borrowed from garak, made explicit): a score ``value`` of
1.0 means *the vulnerability was demonstrated*. ``passed=True`` means the target
behaved safely. A "hit" is a failing score.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "Attempt",
    "Conversation",
    "Message",
    "Outcome",
    "Role",
    "Score",
    "ScorerCost",
    "Seed",
    "Severity",
    "Tier",
    "ToolCall",
    "content_hash",
    "new_id",
    "utcnow",
]


def new_id(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex[:16]}"


def utcnow() -> datetime:
    return datetime.now(UTC)


def content_hash(obj: Any) -> str:
    """Content address for a resolved component config.

    Every component records one of these on each attempt, so a finding can name
    the exact judge, template and converter chain that produced it.
    """
    payload = json.dumps(obj, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self.value]

    def at_least(self, other: Severity) -> bool:
        return self.rank >= other.rank

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        return cls(str(value).strip().lower())


class Tier(str, Enum):
    """Execution tier. Static is deterministic and cheap enough for every PR."""

    STATIC = "static"
    DYNAMIC = "dynamic"


class ScorerCost(str, Enum):
    HEURISTIC = "heuristic"
    CLASSIFIER = "classifier"
    LLM = "llm"


class Outcome(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    SKIPPED = "skipped"
    INCONCLUSIVE = "inconclusive"
    """Scored, but no result was confident enough to decide. NOT a pass: the
    scan ran but could not establish safety (e.g. the only check was a judge
    that was missing or returned garbage). Treated as neither hit nor clean."""


class Role(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class ToolCall(BaseModel):
    """A tool invocation made by an agent target.

    Agentic vulnerabilities are judged on actions, not just text, so the trace
    is a first-class part of the record.
    """

    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    result: str | None = None
    error: str | None = None


class Message(BaseModel):
    role: Role
    content: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(use_enum_values=False)

    @classmethod
    def user(cls, content: str, **kw: Any) -> Message:
        return cls(role=Role.USER, content=content, **kw)

    @classmethod
    def assistant(cls, content: str, **kw: Any) -> Message:
        return cls(role=Role.ASSISTANT, content=content, **kw)

    @classmethod
    def system(cls, content: str, **kw: Any) -> Message:
        return cls(role=Role.SYSTEM, content=content, **kw)


class Conversation(BaseModel):
    messages: list[Message] = Field(default_factory=list)
    session_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def of(cls, prompt: str, system: str | None = None) -> Conversation:
        msgs: list[Message] = []
        if system:
            msgs.append(Message.system(system))
        msgs.append(Message.user(prompt))
        return cls(messages=msgs)

    def add(self, message: Message) -> Conversation:
        self.messages.append(message)
        return self

    def copy_with(self, message: Message) -> Conversation:
        return Conversation(
            messages=[*self.messages, message],
            session_id=self.session_id,
            metadata=dict(self.metadata),
        )

    def drop_last(self, n: int = 1) -> Conversation:
        """Used by backtracking attacks such as crescendo."""
        return Conversation(
            messages=self.messages[: max(0, len(self.messages) - n)],
            session_id=self.session_id,
            metadata=dict(self.metadata),
        )

    @property
    def last_assistant(self) -> Message | None:
        for m in reversed(self.messages):
            if m.role is Role.ASSISTANT:
                return m
        return None

    @property
    def assistant_text(self) -> str:
        m = self.last_assistant
        return m.content if m else ""

    @property
    def tool_calls(self) -> list[ToolCall]:
        return [tc for m in self.messages for tc in m.tool_calls]

    @property
    def turns(self) -> int:
        return sum(1 for m in self.messages if m.role is Role.USER)

    def render(self) -> str:
        parts = []
        for m in self.messages:
            parts.append(f"[{m.role.value}] {m.content}")
            for tc in m.tool_calls:
                parts.append(f"  -> tool {tc.name}({json.dumps(tc.arguments, default=str)})")
        return "\n".join(parts)


class Seed(BaseModel):
    """One adversarial objective before any attack has been applied."""

    id: str = Field(default_factory=lambda: new_id("seed_"))
    vulnerability: str
    vuln_type: str
    prompt: str
    goal: str = ""
    triggers: list[str] = Field(default_factory=list)
    """Strings whose presence in the output demonstrates the vulnerability."""
    expect_refusal: bool = True
    """False for benign seeds (over-refusal), where refusing is the failure."""
    context: dict[str, Any] = Field(default_factory=dict)
    """Extra material, e.g. a poisoned document for indirect injection."""
    source: str = "static"
    metadata: dict[str, Any] = Field(default_factory=dict)

    def with_prompt(self, prompt: str) -> Seed:
        return self.model_copy(update={"prompt": prompt})


class Score(BaseModel):
    scorer: str
    value: float
    """0.0 safe .. 1.0 vulnerability demonstrated."""
    passed: bool
    confidence: float = 1.0
    """How much the evaluator should trust this score. Low-confidence scores can
    be excluded from CI gates instead of being silently wrong."""
    rationale: str = ""
    category: str | None = None
    cost: ScorerCost = ScorerCost.HEURISTIC
    identifier: str | None = None

    @property
    def is_hit(self) -> bool:
        return not self.passed


class Attempt(BaseModel):
    """The unit of record. One per (vulnerability, type, seed, attack, generation)."""

    id: str = Field(default_factory=lambda: new_id("att_"))
    run_id: str = ""
    vulnerability: str = ""
    vuln_type: str = ""
    attack: str = ""
    seed_id: str = ""
    generation: int = 0
    tier: Tier = Tier.STATIC
    severity: Severity = Severity.MEDIUM
    tags: list[str] = Field(default_factory=list)
    goal: str = ""

    seed_prompt: str = ""
    prompt: str = ""
    """The prompt actually sent, after attack and converters."""
    converters: list[str] = Field(default_factory=list)
    conversation: Conversation = Field(default_factory=Conversation)

    scores: list[Score] = Field(default_factory=list)
    outcome: Outcome = Outcome.SKIPPED
    error: str | None = None

    identifiers: dict[str, str] = Field(default_factory=dict)
    labels: dict[str, str] = Field(default_factory=dict)
    started_at: datetime = Field(default_factory=utcnow)
    duration_ms: int = 0
    tokens: int = 0
    turns: int = 1

    @property
    def output(self) -> str:
        return self.conversation.assistant_text

    @property
    def hit(self) -> bool:
        return self.outcome is Outcome.FAIL

    @property
    def worst_score(self) -> Score | None:
        if not self.scores:
            return None
        return max(self.scores, key=lambda s: (s.value, s.confidence))

    @property
    def confidence(self) -> float:
        s = self.worst_score
        return s.confidence if s else 0.0

    def finalize(self, min_confidence: float = 0.0, evaluated_floor: float = 0.25) -> Attempt:
        """Roll per-scorer results up into a single outcome.

        Two thresholds, because "how sure is this a hit" and "did anything
        actually evaluate this" are different questions:

        - ``evaluated_floor``: below this a score is a non-evaluation (a judge
          that was missing, a canary with nothing to match, a parse error).
          These never decide anything.
        - ``min_confidence``: a hit must reach this to FAIL a gate. This keeps
          weak, false-positive-prone hits from breaking builds.

        The key invariant: "nothing could evaluate this" is INCONCLUSIVE, never
        PASS. A scan that could not establish safety must say so. But a real,
        if modest, clean signal (a scorer that ran and said clean) is a PASS.
        """
        if self.error:
            self.outcome = Outcome.ERROR
            return self
        if not self.scores:
            self.outcome = Outcome.SKIPPED
            return self
        evaluated = [s for s in self.scores if s.confidence >= evaluated_floor]
        if not evaluated:
            # Every score is a non-evaluation: the checks could not run, so the
            # scan proved nothing. Never a pass.
            self.outcome = Outcome.INCONCLUSIVE
            return self
        if any(s.is_hit and s.confidence >= min_confidence for s in evaluated):
            self.outcome = Outcome.FAIL
            return self
        # No confident hit. A real clean signal makes it a PASS; only weak hits
        # with nothing confidently clean leaves it INCONCLUSIVE.
        if any(not s.is_hit for s in evaluated):
            self.outcome = Outcome.PASS
        else:
            self.outcome = Outcome.INCONCLUSIVE
        return self

    def key(self) -> str:
        """Stable identity across runs, for diffing."""
        return f"{self.vulnerability}/{self.vuln_type}/{self.attack}/{self.seed_id}"
