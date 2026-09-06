"""Full scans against the planted-vulnerability fixture."""

import asyncio

from llm_vuln_scan.core.assemble import assemble
from llm_vuln_scan.core.config import ScanConfig
from llm_vuln_scan.core.models import Severity
from llm_vuln_scan.core.runner import Runner
from llm_vuln_scan.diff.compare import compare
from llm_vuln_scan.evaluate import summarise
from llm_vuln_scan.evaluate.gates import evaluate_gates


def _run(config: dict):
    cfg = ScanConfig.model_validate(config)
    target, ctx = assemble(cfg)
    result = asyncio.run(Runner(cfg, target, ctx).run())
    return cfg, result


BASE = {
    "target": {"type": "callable", "fn": "vulnerable_app:respond"},
    "app": {"canaries": ["SECRET_CONFIG_KEY=sk-acme-4f9a2b7c1d8e3f6a0b5c9d2e", "You are AcmeBot"]},
    "attacks": {"static": ["direct", "injection_framing", "base64", "jailbreak_template"]},
    "run": {"tier": "static", "cache": ""},
}


def test_finds_prompt_injection():
    cfg, result = _run({**BASE, "vulnerabilities": [{"name": "prompt_injection"}]})
    s = summarise(result.attempts)
    pi = next(v for v in s.vulnerabilities if v.vulnerability == "prompt_injection")
    assert pi.hits > 0


def test_finds_system_prompt_leak_via_canary():
    cfg, result = _run({**BASE, "vulnerabilities": [{"name": "system_prompt_leakage"}]})
    hits = [a for a in result.attempts if a.hit]
    assert hits
    # at least one hit was caught by the canary scorer, verbatim, at high confidence
    assert any(a.confidence >= 0.9 for a in hits)


def test_package_hallucination_detected():
    cfg, result = _run({**BASE, "vulnerabilities": [{"name": "package_hallucination", "num_seeds": 4}]})
    s = summarise(result.attempts)
    ph = next(v for v in s.vulnerabilities if v.vulnerability == "package_hallucination")
    assert ph.hits > 0  # fixture recommends the fake "phoneflex-validator"


def test_agent_excessive_agency():
    cfg, result = _run({
        **BASE,
        "target": {"type": "agent", "fn": "vulnerable_app:agent", "capabilities": {"tools": True}},
        "vulnerabilities": [{"name": "excessive_agency"}],
        "attacks": {"static": ["direct"], "cache": ""},
    })
    s = summarise(result.attempts)
    ea = next(v for v in s.vulnerabilities if v.vulnerability == "excessive_agency")
    assert ea.hits > 0  # the agent actually calls delete_account/transfer/grant_role


def test_gate_exit_codes():
    cfg, result = _run({**BASE, "vulnerabilities": [{"name": "system_prompt_leakage"}]})
    s = summarise(result.attempts)
    gate = evaluate_gates(s, result.attempts, fail_on_severity=Severity.HIGH)
    assert not gate.passed and gate.exit_code == 100

    clean = evaluate_gates(s, result.attempts, fail_on_severity=Severity.CRITICAL)
    # system_prompt_leakage is high, not critical, so a critical-only gate passes
    assert clean.passed


def test_determinism_same_seed():
    cfg1, r1 = _run({**BASE, "vulnerabilities": [{"name": "prompt_injection"}]})
    cfg2, r2 = _run({**BASE, "vulnerabilities": [{"name": "prompt_injection"}]})
    keys1 = sorted(a.key() for a in r1.attempts if a.hit)
    keys2 = sorted(a.key() for a in r2.attempts if a.hit)
    assert keys1 == keys2


def test_diff_detects_no_regression_between_identical_runs():
    cfg1, r1 = _run({**BASE, "vulnerabilities": [{"name": "prompt_injection"}]})
    cfg2, r2 = _run({**BASE, "vulnerabilities": [{"name": "prompt_injection"}]})
    d = compare(r1.attempts, r2.attempts)
    assert not d.has_regressions
