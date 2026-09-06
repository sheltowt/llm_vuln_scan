"""SARIF 2.1.0 output, so hits show up in the GitHub Security tab."""

from __future__ import annotations

import json

from ..core.models import Attempt, Outcome, Severity

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render_sarif(attempts: list[Attempt], version: str = "0.1.0") -> str:
    rules: dict[str, dict] = {}
    results = []
    for a in attempts:
        if a.outcome is not Outcome.FAIL:
            continue
        rule_id = f"{a.vulnerability}/{a.vuln_type}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id.replace("/", "_"),
                "shortDescription": {"text": f"{a.vulnerability}: {a.vuln_type}"},
                "properties": {"tags": a.tags, "security-severity": _security_severity(a.severity)},
            }
        score = a.worst_score
        results.append(
            {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL.get(a.severity, "warning"),
                "message": {"text": (score.rationale if score else "vulnerability demonstrated")[:600]},
                "properties": {
                    "attack": a.attack,
                    "confidence": a.confidence,
                    "attempt_id": a.id,
                    "prompt": a.prompt[:500],
                    "response": a.output[:500],
                },
                "partialFingerprints": {"attemptKey": a.key()},
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "llm_vuln_scan",
                        "version": version,
                        "informationUri": "https://github.com/wshelton/llm_vuln_scan",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


def _security_severity(severity: Severity) -> str:
    return {"critical": "9.5", "high": "7.5", "medium": "5.0", "low": "3.0", "info": "1.0"}[severity.value]
