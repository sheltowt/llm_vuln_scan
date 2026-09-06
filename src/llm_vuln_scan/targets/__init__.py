"""Target adapters."""

from .agent import AgentTarget
from .base import Target, TargetCapabilities, TargetError
from .callable_target import CallableTarget
from .http import HttpTarget
from .openai_compat import OpenAICompatTarget

__all__ = [
    "AgentTarget",
    "CallableTarget",
    "HttpTarget",
    "OpenAICompatTarget",
    "Target",
    "TargetCapabilities",
    "TargetError",
]
