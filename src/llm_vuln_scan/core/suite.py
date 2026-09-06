"""Committed suites: generation is expensive and nondeterministic, so do it once.

``lvscan generate`` freezes a plan (seeds + attacks) to ``lvscan.suite.yaml``,
which is committed to the repo. ``lvscan run`` replays that frozen plan, so a
scan in CI is deterministic and does not re-invoke the generator. This is the
"prompts and agents as code" mechanism.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .config import ScanConfig
from .context import AppContext
from .models import Seed, Severity, Tier
from .planner import Plan, PlanItem, build_plan


def plan_to_suite(plan: Plan, config: ScanConfig) -> dict[str, Any]:
    seeds = []
    for seed in plan.seeds.values():
        seeds.append(
            {
                "id": seed.id,
                "vulnerability": seed.vulnerability,
                "type": seed.vuln_type,
                "prompt": seed.prompt,
                "goal": seed.goal,
                "triggers": seed.triggers,
                "expect_refusal": seed.expect_refusal,
                "context": seed.context,
                "source": seed.source,
            }
        )
    items = [
        {
            "seed": item.seed.id,
            "attack": item.attack,
            "attack_params": item.attack_params or {},
            "severity": item.severity.value,
            "tags": item.tags,
            "tier": item.tier.value,
        }
        for item in plan.items
    ]
    return {
        "version": 1,
        "generations": plan.generations,
        "seeds": seeds,
        "items": items,
    }


def save_suite(plan: Plan, config: ScanConfig, path: str | Path) -> Path:
    path = Path(path)
    path.write_text(yaml.safe_dump(plan_to_suite(plan, config), sort_keys=False, allow_unicode=True))
    return path


def load_suite(path: str | Path) -> Plan:
    data = yaml.safe_load(Path(path).read_text()) or {}
    seeds: dict[str, Seed] = {}
    for raw in data.get("seeds", []):
        seed = Seed(
            id=raw["id"],
            vulnerability=raw["vulnerability"],
            vuln_type=raw["type"],
            prompt=raw["prompt"],
            goal=raw.get("goal", ""),
            triggers=raw.get("triggers", []),
            expect_refusal=raw.get("expect_refusal", True),
            context=raw.get("context", {}),
            source=raw.get("source", "static"),
        )
        seeds[seed.id] = seed
    items = []
    for raw in data.get("items", []):
        seed = seeds.get(raw["seed"])
        if seed is None:
            continue
        items.append(
            PlanItem(
                seed=seed,
                attack=raw["attack"],
                attack_params=raw.get("attack_params", {}),
                severity=Severity.parse(raw.get("severity", "medium")),
                tags=raw.get("tags", []),
                tier=Tier(raw.get("tier", "static")),
            )
        )
    return Plan(items=items, seeds=seeds, generations=int(data.get("generations", 1)))


def generate_suite(config: ScanConfig, ctx: AppContext) -> Plan:
    return build_plan(config, ctx)


def append_regressions(hits: list[Any], path: str | Path) -> int:
    """Append confirmed hit keys to a regressions file that runs first next time."""

    path = Path(path)
    existing: dict[str, Any] = {"regressions": []}
    if path.exists():
        existing = yaml.safe_load(path.read_text()) or {"regressions": []}
    known = {r["key"] for r in existing.get("regressions", [])}
    added = 0
    for hit in hits:
        key = hit.key() if hasattr(hit, "key") else str(hit)
        if key in known:
            continue
        existing.setdefault("regressions", []).append(
            {
                "key": key,
                "vulnerability": getattr(hit, "vulnerability", ""),
                "attack": getattr(hit, "attack", ""),
                "seed_id": getattr(hit, "seed_id", ""),
                "prompt": getattr(hit, "prompt", "")[:500],
            }
        )
        known.add(key)
        added += 1
    path.write_text(yaml.safe_dump(existing, sort_keys=False, allow_unicode=True))
    return added
