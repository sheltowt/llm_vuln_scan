"""Converters: cheap, chainable, deterministic text transforms.

A converter changes the *encoding* of a payload. An attack changes the *plan*.
Keeping them separate is why a single crescendo attack can run over base64
without either knowing about the other.

Converters may also ``untransform`` an output, so a base64 reply is decoded
before scoring instead of silently passing every detector.
"""

from __future__ import annotations

import re
from typing import Any

from ..core.plugin import Plugin

SPAN_RE = re.compile(r"⟪(.+?)⟫", re.DOTALL)


class Converter(Plugin):
    kind = "converter"
    reversible: bool = False

    def transform(self, text: str) -> str:  # pragma: no cover - abstract
        raise NotImplementedError

    def untransform(self, text: str) -> str:
        """Best-effort decode of a response. Default: unchanged."""
        return text

    def apply(self, text: str) -> str:
        """Convert only ``⟪marked⟫`` spans when any are present."""
        if "⟪" in text:
            return SPAN_RE.sub(lambda m: self.transform(m.group(1)), text)
        return self.transform(text)


class ConverterChain:
    """Applies converters in order; reverses them for response decoding."""

    def __init__(self, converters: list[Converter] | None = None) -> None:
        self.converters = list(converters or [])

    def transform(self, text: str) -> str:
        for c in self.converters:
            text = c.apply(text)
        return text

    def untransform(self, text: str) -> str:
        for c in reversed(self.converters):
            text = c.untransform(text)
        return text

    @property
    def names(self) -> list[str]:
        return [c.name for c in self.converters]

    def identifiers(self) -> dict[str, str]:
        return {c.name: c.identifier for c in self.converters}

    def __bool__(self) -> bool:
        return bool(self.converters)

    @classmethod
    def build(cls, names: list[str], params: dict[str, dict[str, Any]] | None = None) -> ConverterChain:
        from ..core.plugin import build as build_plugin

        params = params or {}
        return cls([build_plugin("converter", n, **params.get(n, {})) for n in names])
