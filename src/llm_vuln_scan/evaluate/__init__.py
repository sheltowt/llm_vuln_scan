"""Evaluation: aggregation, z-scores, and CI gates."""

from .aggregate import Summary, VulnResult, save_summary, summarise
from .gates import EXIT_GATE_FAILED, EXIT_PASS, GateResult, evaluate_gates

__all__ = [
    "EXIT_GATE_FAILED",
    "EXIT_PASS",
    "GateResult",
    "Summary",
    "VulnResult",
    "evaluate_gates",
    "save_summary",
    "summarise",
]
