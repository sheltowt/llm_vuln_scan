"""Compare two runs: new failures, fixed, and flaky.

Attempts are matched by their stable key (vulnerability/type/attack/seed). A
generated suite replayed against an unchanged target produces identical keys, so
the diff is meaningful rather than noise.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.models import Attempt, Outcome


@dataclass
class Diff:
    new_failures: list[str] = field(default_factory=list)
    fixed: list[str] = field(default_factory=list)
    still_failing: list[str] = field(default_factory=list)
    flaky: list[str] = field(default_factory=list)
    baseline_hits: int = 0
    current_hits: int = 0

    @property
    def has_regressions(self) -> bool:
        return bool(self.new_failures)


def _index(attempts: list[Attempt]) -> dict[str, list[Attempt]]:
    out: dict[str, list[Attempt]] = {}
    for a in attempts:
        out.setdefault(a.key(), []).append(a)
    return out


def _is_hit(group: list[Attempt]) -> bool:
    return any(a.outcome is Outcome.FAIL for a in group)


def _is_flaky(group: list[Attempt]) -> bool:
    outcomes = {a.outcome for a in group}
    return Outcome.FAIL in outcomes and Outcome.PASS in outcomes


def compare(baseline: list[Attempt], current: list[Attempt]) -> Diff:
    base = _index(baseline)
    curr = _index(current)
    diff = Diff()
    diff.baseline_hits = sum(1 for g in base.values() if _is_hit(g))
    diff.current_hits = sum(1 for g in curr.values() if _is_hit(g))

    for key, group in sorted(curr.items()):
        current_hit = _is_hit(group)
        if _is_flaky(group):
            diff.flaky.append(key)
        base_group = base.get(key)
        base_hit = _is_hit(base_group) if base_group else False
        if current_hit and not base_hit:
            diff.new_failures.append(key)
        elif current_hit and base_hit:
            diff.still_failing.append(key)
    for key, group in sorted(base.items()):
        if _is_hit(group) and not _is_hit(curr.get(key, [])):
            if key in curr:  # only "fixed" if we actually retested it
                diff.fixed.append(key)
    return diff


def render_diff_text(diff: Diff) -> str:
    lines = [
        f"baseline hits: {diff.baseline_hits}   current hits: {diff.current_hits}",
        f"  new failures : {len(diff.new_failures)}",
        f"  fixed        : {len(diff.fixed)}",
        f"  still failing: {len(diff.still_failing)}",
        f"  flaky        : {len(diff.flaky)}",
    ]
    if diff.new_failures:
        lines.append("\nNEW FAILURES (regressions):")
        lines += [f"  + {k}" for k in diff.new_failures[:50]]
    if diff.fixed:
        lines.append("\nFIXED:")
        lines += [f"  - {k}" for k in diff.fixed[:50]]
    if diff.flaky:
        lines.append("\nFLAKY (both pass and fail across generations):")
        lines += [f"  ~ {k}" for k in diff.flaky[:50]]
    return "\n".join(lines)
