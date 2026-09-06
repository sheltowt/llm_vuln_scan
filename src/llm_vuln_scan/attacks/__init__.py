"""Attacks: how a seed is delivered."""

from .base import Attack, AttackResult, MultiTurnAttack, SingleTurnAttack
from .multi_turn import (
    CrescendoAttack,
    LinearJailbreakAttack,
    PairAttack,
    ScriptedCrescendoAttack,
    TreeOfAttacksAttack,
)
from .single_turn import (
    BestOfNAttack,
    CitationAttack,
    ContextStuffingAttack,
    DirectAttack,
    EncodedInstructionAttack,
    GrayBoxAttack,
    IndirectInjectionAttack,
    JailbreakTemplateAttack,
    ManyShotAttack,
    MathProblemAttack,
    PrefillAttack,
    RoleplayAttack,
    SystemOverrideAttack,
    load_templates,
)

__all__ = [
    "Attack",
    "AttackResult",
    "BestOfNAttack",
    "CitationAttack",
    "ContextStuffingAttack",
    "CrescendoAttack",
    "DirectAttack",
    "EncodedInstructionAttack",
    "GrayBoxAttack",
    "IndirectInjectionAttack",
    "JailbreakTemplateAttack",
    "LinearJailbreakAttack",
    "ManyShotAttack",
    "MathProblemAttack",
    "MultiTurnAttack",
    "PairAttack",
    "PrefillAttack",
    "RoleplayAttack",
    "ScriptedCrescendoAttack",
    "SingleTurnAttack",
    "SystemOverrideAttack",
    "TreeOfAttacksAttack",
    "load_templates",
]
