"""JUnit XML for CI systems. One testcase per attempt; a hit is a failure."""

from __future__ import annotations

from xml.sax.saxutils import escape, quoteattr

from ..core.models import Attempt, Outcome


def render_junit(attempts: list[Attempt], name: str = "lvscan") -> str:
    total = len(attempts)
    failures = sum(1 for a in attempts if a.outcome is Outcome.FAIL)
    errors = sum(1 for a in attempts if a.outcome is Outcome.ERROR)
    skipped = sum(1 for a in attempts if a.outcome is Outcome.SKIPPED)
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuites name={quoteattr(name)} tests="{total}" failures="{failures}" '
        f'errors="{errors}" skipped="{skipped}">',
    ]
    by_vuln: dict[str, list[Attempt]] = {}
    for a in attempts:
        by_vuln.setdefault(a.vulnerability, []).append(a)
    for vuln, group in sorted(by_vuln.items()):
        gf = sum(1 for a in group if a.outcome is Outcome.FAIL)
        ge = sum(1 for a in group if a.outcome is Outcome.ERROR)
        gs = sum(1 for a in group if a.outcome is Outcome.SKIPPED)
        lines.append(
            f'  <testsuite name={quoteattr(vuln)} tests="{len(group)}" '
            f'failures="{gf}" errors="{ge}" skipped="{gs}">'
        )
        for a in group:
            case_name = f"{a.vuln_type}/{a.attack}/{a.seed_id}"
            lines.append(
                f'    <testcase classname={quoteattr(vuln)} name={quoteattr(case_name)} '
                f'time="{a.duration_ms / 1000:.3f}">'
            )
            if a.outcome is Outcome.FAIL:
                score = a.worst_score
                msg = score.rationale if score else "vulnerability demonstrated"
                lines.append(f'      <failure message={quoteattr(msg[:200])} type={quoteattr(a.severity.value)}>')
                lines.append(escape(f"prompt:\n{a.prompt[:1000]}\n\nresponse:\n{a.output[:1000]}"))
                lines.append("      </failure>")
            elif a.outcome is Outcome.ERROR:
                lines.append(f'      <error message={quoteattr((a.error or "")[:200])}></error>')
            elif a.outcome is Outcome.SKIPPED:
                lines.append(f'      <skipped message={quoteattr((a.error or "")[:200])}></skipped>')
            lines.append("    </testcase>")
        lines.append("  </testsuite>")
    lines.append("</testsuites>")
    return "\n".join(lines)
