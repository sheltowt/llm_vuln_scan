"""Turn a config into a concrete, ordered list of work items.

A plan is deterministic given the config and seed, and it is exactly what
``lvscan generate`` serialises to a committed suite. Running a committed suite
replays this plan instead of rebuilding it, which is what makes CI runs stable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..frameworks.presets import expand
from .config import ScanConfig
from .context import AppContext
from .models import Seed, Severity, Tier, content_hash
from .plugin import build, get


@dataclass
class PlanItem:
    seed: Seed
    attack: str
    attack_params: dict[str, Any]
    severity: Severity
    tags: list[str]
    tier: Tier


@dataclass
class Plan:
    items: list[PlanItem] = field(default_factory=list)
    seeds: dict[str, Seed] = field(default_factory=dict)
    generations: int = 1

    def __len__(self) -> int:
        return len(self.items)


def _resolve_vulnerabilities(config: ScanConfig) -> list[tuple[str, dict[str, Any]]]:
    """Expand presets and explicit entries into (name, params) pairs, de-duped."""

    resolved: dict[str, dict[str, Any]] = {}
    for entry in config.vulnerabilities:
        if entry.preset:
            for name in expand(entry.preset):
                resolved.setdefault(name, {})
        elif entry.custom:
            resolved[entry.custom] = {
                "_custom": True,
                "criteria": entry.criteria or "",
                "severity": entry.severity,
                **entry.params,
            }
        elif entry.name:
            params: dict[str, Any] = dict(entry.params)
            if entry.types is not None:
                params["types"] = entry.types
            if entry.num_seeds is not None:
                params["num_seeds"] = entry.num_seeds
            if entry.severity is not None:
                params["severity"] = entry.severity
            resolved[entry.name] = {**resolved.get(entry.name, {}), **params}
    return list(resolved.items())


def _build_vulnerability(name: str, params: dict[str, Any]):
    if params.get("_custom"):
        from ..vulnerabilities.programmatic import CustomVulnerability

        return CustomVulnerability(
            name=name,
            criteria=str(params.get("criteria", "")),
            severity=params.get("severity") or Severity.MEDIUM,
            seeds_text=params.get("seeds"),
        )
    clean = {k: v for k, v in params.items() if not k.startswith("_")}
    return build("vulnerability", name, **clean)


def _attacks_for_tier(config: ScanConfig) -> list[tuple[str, dict[str, Any]]]:
    names = list(config.attacks.static)
    if config.run.tier is Tier.DYNAMIC:
        names += list(config.attacks.dynamic)
    seen: dict[str, dict[str, Any]] = {}
    for name in names:
        seen[name] = config.attacks.params.get(name, {})
    return list(seen.items())


def _sample_attacks(
    attacks: list[tuple[str, dict[str, Any]]],
    weights: dict[str, float],
    sample: int | None,
    seed: Seed,
    ctx: AppContext,
) -> list[tuple[str, dict[str, Any]]]:
    if not sample or sample >= len(attacks):
        return attacks
    rng = ctx.rng(f"attack_sample:{seed.id}")
    pool = list(attacks)
    chosen: list[tuple[str, dict[str, Any]]] = []
    while pool and len(chosen) < sample:
        ws = [max(0.0, weights.get(name, 1.0)) for name, _ in pool]
        total = sum(ws) or 1.0
        pick = rng.random() * total
        acc = 0.0
        for index, weight in enumerate(ws):
            acc += weight
            if pick <= acc:
                chosen.append(pool.pop(index))
                break
    return chosen


def build_plan(config: ScanConfig, ctx: AppContext) -> Plan:
    plan = Plan(generations=config.run.generations)
    tier = config.run.tier
    attacks = _attacks_for_tier(config)
    weights = config.attacks.weights

    for name, vparams in _resolve_vulnerabilities(config):
        vuln = _build_vulnerability(name, vparams)
        severity = vuln.effective_severity()
        tags = list(getattr(vuln, "tags", []))
        for seed in vuln.seeds(ctx):
            plan.seeds[seed.id] = seed
            seed_attacks = _sample_attacks(attacks, weights, config.attacks.sample, seed, ctx)
            for attack_name, aparams in seed_attacks:
                attack_cls = get("attack", attack_name)
                attack_tier = getattr(attack_cls, "tier", Tier.STATIC)
                if tier is Tier.STATIC and attack_tier is Tier.DYNAMIC:
                    continue
                plan.items.append(
                    PlanItem(
                        seed=seed,
                        attack=attack_name,
                        attack_params=aparams,
                        severity=severity,
                        tags=tags,
                        tier=attack_tier,
                    )
                )
    # Deterministic ordering: regressions (if injected) first, then by identity.
    plan.items.sort(key=lambda i: (i.seed.vulnerability, i.seed.vuln_type, i.seed.id, i.attack))
    return plan


def plan_fingerprint(plan: Plan) -> str:
    return content_hash(
        [f"{i.seed.id}:{i.attack}" for i in plan.items] + [str(plan.generations)]
    )
