"""A committed suite must replay to an identical plan."""

import asyncio
from pathlib import Path

from llm_vuln_scan.core.assemble import assemble, build_context
from llm_vuln_scan.core.config import ScanConfig
from llm_vuln_scan.core.planner import build_plan, plan_fingerprint
from llm_vuln_scan.core.runner import Runner
from llm_vuln_scan.core.suite import load_suite, save_suite

BASE = {
    "target": {"type": "callable", "fn": "vulnerable_app:respond"},
    "app": {"canaries": ["SECRET_CONFIG_KEY=sk-acme-4f9a2b7c1d8e3f6a0b5c9d2e"]},
    "vulnerabilities": [{"name": "prompt_injection"}, {"name": "system_prompt_leakage"}],
    "attacks": {"static": ["direct", "base64", "jailbreak_template"]},
    "run": {"tier": "static", "cache": ""},
}


def test_suite_roundtrip_preserves_plan(tmp_path: Path):
    cfg = ScanConfig.model_validate(BASE)
    ctx = build_context(cfg)
    original = build_plan(cfg, ctx)
    suite_path = tmp_path / "suite.yaml"
    save_suite(original, cfg, suite_path)
    reloaded = load_suite(suite_path)
    assert plan_fingerprint(original) == plan_fingerprint(reloaded)
    assert len(reloaded.items) == len(original.items)


def test_replayed_suite_produces_same_hits(tmp_path: Path):
    cfg = ScanConfig.model_validate(BASE)
    ctx = build_context(cfg)
    plan = build_plan(cfg, ctx)
    suite_path = tmp_path / "suite.yaml"
    save_suite(plan, cfg, suite_path)

    target, ctx2 = assemble(cfg)
    live = asyncio.run(Runner(cfg, target, ctx2).run())

    target2, ctx3 = assemble(cfg)
    replay = asyncio.run(Runner(cfg, target2, ctx3, plan=load_suite(suite_path)).run())

    assert sorted(a.key() for a in live.attempts if a.hit) == \
           sorted(a.key() for a in replay.attempts if a.hit)
