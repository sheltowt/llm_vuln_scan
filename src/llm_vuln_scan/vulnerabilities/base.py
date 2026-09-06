"""Vulnerability base and the declarative loader.

A vulnerability owns three things: the seeds that probe it, the scorer that
judges the result, and the framework tags that place it in a compliance map.
Most are pure data, so adding one is a YAML file rather than a class.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

import yaml

from ..core.models import Seed, Severity, content_hash
from ..core.plugin import Plugin, register
from ..scorers.base import Scorer
from ..scorers.composite import _as_scorer

SEED_DIR = Path(__file__).resolve().parent.parent / "data" / "seeds"


class Vulnerability(Plugin):
    kind = "vulnerability"
    severity: ClassVar[Severity] = Severity.MEDIUM
    tags: ClassVar[list[str]] = []
    tier: ClassVar[int] = 1
    description: ClassVar[str] = ""
    types: ClassVar[list[str]] = []
    DEFAULT_PARAMS: ClassVar[dict[str, Any]] = {"num_seeds": 0, "severity": None, "types": None}

    def selected_types(self) -> list[str]:
        wanted = self.params.get("types")
        if not wanted:
            return list(self.types)
        unknown = [t for t in wanted if t not in self.types]
        if unknown:
            raise ValueError(
                f"vulnerability {self.name!r} has no type(s) {unknown}; known types: {self.types}"
            )
        return list(wanted)

    def effective_severity(self) -> Severity:
        override = self.params.get("severity")
        return Severity.parse(override) if override else self.severity

    def seeds(self, ctx: Any) -> list[Seed]:  # pragma: no cover - abstract
        raise NotImplementedError

    def scorer_for(self, vuln_type: str, ctx: Any) -> Scorer:  # pragma: no cover - abstract
        raise NotImplementedError


class DeclarativeVulnerability(Vulnerability):
    """A vulnerability defined entirely by a YAML spec."""

    SPEC: ClassVar[dict[str, Any]] = {}

    def _type_spec(self, vuln_type: str) -> dict[str, Any]:
        return (self.SPEC.get("types") or {}).get(vuln_type, {})

    def seeds(self, ctx: Any) -> list[Seed]:
        limit = int(self.params.get("num_seeds") or 0)
        out: list[Seed] = []
        for vuln_type in self.selected_types():
            spec = self._type_spec(vuln_type)
            goal = str(spec.get("goal", ""))
            raw_seeds = list(spec.get("seeds") or [])
            if limit:
                raw_seeds = raw_seeds[:limit]
            for raw in raw_seeds:
                entry: dict[str, Any] = {"prompt": raw} if isinstance(raw, str) else dict(raw)
                prompt = str(entry.pop("prompt", ""))
                if not prompt:
                    continue
                seed_id = "seed_" + content_hash(
                    {"v": self.name, "t": vuln_type, "p": prompt}
                )[:12]
                out.append(
                    Seed(
                        id=seed_id,
                        vulnerability=self.name,
                        vuln_type=vuln_type,
                        prompt=prompt,
                        goal=str(entry.pop("goal", goal)),
                        triggers=list(entry.pop("triggers", []) or []),
                        expect_refusal=bool(entry.pop("expect_refusal", True)),
                        context=dict(entry.pop("context", {}) or {}),
                        source="static",
                        metadata=entry,
                    )
                )
        return out

    def scorer_for(self, vuln_type: str, ctx: Any) -> Scorer:
        spec = self._type_spec(vuln_type).get("scorer") or self.SPEC.get("scorer")
        if not spec:
            spec = {"name": "cascade", "scorers": ["compliance", "self_ask"]}
        return _as_scorer(_resolve_scorer_spec(spec, ctx))


def _resolve_scorer_spec(spec: Any, ctx: Any) -> Any:
    """Drop judge-backed scorers when no judge is configured.

    A cascade whose expensive stage is unavailable should fall back to its cheap
    stage and say so, not emit a zero-confidence score that looks like a pass.
    """

    has_judge = getattr(ctx, "judge", None) is not None
    if has_judge:
        return spec
    llm_scorers = {"self_ask", "self_ask_scale", "requirement_judge"}
    if isinstance(spec, str):
        return "compliance" if spec in llm_scorers else spec
    if isinstance(spec, dict):
        out = dict(spec)
        if out.get("name") in llm_scorers:
            return "compliance"
        if "scorers" in out:
            children = [
                _resolve_scorer_spec(child, ctx)
                for child in out["scorers"]
                if not _is_llm_spec(child)
            ]
            if not children:
                return "compliance"
            if len(children) == 1 and out.get("name") in ("cascade", "composite"):
                return children[0]
            out["scorers"] = children
        return out
    return spec


def _is_llm_spec(spec: Any) -> bool:
    llm_scorers = {"self_ask", "self_ask_scale", "requirement_judge"}
    if isinstance(spec, str):
        return spec in llm_scorers
    if isinstance(spec, dict):
        return spec.get("name") in llm_scorers
    return False


def load_specs(directory: Path = SEED_DIR) -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    if not directory.is_dir():  # pragma: no cover
        return specs
    for path in sorted(directory.glob("*.yaml")):
        data = yaml.safe_load(path.read_text()) or {}
        if isinstance(data, dict) and data.get("name"):
            data["_source"] = str(path)
            specs.append(data)
    return specs


def build_declarative(spec: dict[str, Any]) -> type[DeclarativeVulnerability]:
    """Turn a YAML spec into a registered vulnerability class."""

    name = str(spec["name"])
    namespace = {
        "SPEC": spec,
        "severity": Severity.parse(spec.get("severity", "medium")),
        "tags": list(spec.get("tags") or []),
        "tier": int(spec.get("tier", 1)),
        "description": str(spec.get("description", "")).strip(),
        "types": list((spec.get("types") or {}).keys()),
        "__doc__": str(spec.get("description", "")).strip() or name,
    }
    cls = type(f"{name.title().replace('_', '')}Vulnerability", (DeclarativeVulnerability,), namespace)
    return register("vulnerability", name)(cls)


def load_all(directory: Path = SEED_DIR) -> list[type[DeclarativeVulnerability]]:
    return [build_declarative(spec) for spec in load_specs(directory)]
