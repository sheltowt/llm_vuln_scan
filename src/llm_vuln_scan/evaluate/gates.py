"""CI gates: turn a summary (and optionally a baseline) into an exit code."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.models import Attempt, Outcome, Severity
from .aggregate import Summary

EXIT_PASS = 0
EXIT_ERROR = 1
EXIT_GATE_FAILED = 100


@dataclass
class GateResult:
    passed: bool
    exit_code: int
    reasons: list[str] = field(default_factory=list)
    new_failures: list[str] = field(default_factory=list)
    fixed: list[str] = field(default_factory=list)


def _attempt_keys(attempts: list[Attempt], outcome: Outcome) -> set[str]:
    return {a.key() for a in attempts if a.outcome is outcome}


def evaluate_gates(
    summary: Summary,
    attempts: list[Attempt],
    *,
    fail_on_severity: Severity | None = None,
    pass_rate: float | None = None,
    fail_on_new: bool = False,
    baseline_attempts: list[Attempt] | None = None,
) -> GateResult:
    reasons: list[str] = []
    passed = True

    if fail_on_severity is not None:
        offenders = [
            v for v in summary.vulnerabilities
            if v.hits and Severity.parse(v.severity).at_least(fail_on_severity)
        ]
        if offenders:
            passed = False
            names = ", ".join(f"{v.vulnerability}({v.hits})" for v in offenders)
            reasons.append(f"severity gate: {len(offenders)} vulnerability(ies) >= {fail_on_severity.value}: {names}")

    if pass_rate is not None and summary.pass_rate < pass_rate:
        passed = False
        reasons.append(f"pass-rate gate: {summary.pass_rate:.1%} < required {pass_rate:.1%}")

    new_failures: list[str] = []
    fixed: list[str] = []
    if baseline_attempts is not None:
        baseline_hits = _attempt_keys(baseline_attempts, Outcome.FAIL)
        current_hits = _attempt_keys(attempts, Outcome.FAIL)
        new_failures = sorted(current_hits - baseline_hits)
        fixed = sorted(baseline_hits - current_hits)
        if fail_on_new and new_failures:
            passed = False
            reasons.append(f"regression gate: {len(new_failures)} new failure(s) not in baseline")

    return GateResult(
        passed=passed,
        exit_code=EXIT_PASS if passed else EXIT_GATE_FAILED,
        reasons=reasons,
        new_failures=new_failures,
        fixed=fixed,
    )
