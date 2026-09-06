"""Scorers: how a response is judged."""

from .base import Scorer, build_scorer
from .classifier import HFClassifierScorer
from .composite import (
    CascadeScorer,
    CompositeScorer,
    InverterScorer,
    ThresholdScorer,
    cascade,
    composite,
)
from .heuristic import (
    CanaryScorer,
    CodeBlockScorer,
    PatternScorer,
    SubstringScorer,
    ToolCallScorer,
    ToxicityHeuristicScorer,
)
from .llm import JudgeClient, RequirementJudgeScorer, SelfAskScaleScorer, SelfAskTrueFalseScorer
from .packages import PackageHallucinationScorer
from .refusal import ComplianceScorer, OverRefusalScorer, RefusalScorer, analyse_refusal

__all__ = [
    "CanaryScorer",
    "HFClassifierScorer",
    "CascadeScorer",
    "CodeBlockScorer",
    "ComplianceScorer",
    "CompositeScorer",
    "InverterScorer",
    "JudgeClient",
    "OverRefusalScorer",
    "PackageHallucinationScorer",
    "PatternScorer",
    "RefusalScorer",
    "RequirementJudgeScorer",
    "Scorer",
    "SelfAskScaleScorer",
    "SelfAskTrueFalseScorer",
    "SubstringScorer",
    "ThresholdScorer",
    "ToolCallScorer",
    "ToxicityHeuristicScorer",
    "analyse_refusal",
    "build_scorer",
    "cascade",
    "composite",
]
