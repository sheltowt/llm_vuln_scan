"""llm_vuln_scan: an LLM vulnerability scanner.

Turnkey static tier for CI, composable dynamic tier for deep red teaming. Five
plugin kinds and nothing more: vulnerability, attack, converter, target, scorer.
"""

__version__ = "0.1.0"

from .core.config import ScanConfig
from .core.context import AppContext
from .core.models import Attempt, Outcome, Score, Seed, Severity, Tier

__all__ = [
    "AppContext",
    "Attempt",
    "Outcome",
    "ScanConfig",
    "Score",
    "Seed",
    "Severity",
    "Tier",
    "__version__",
]
