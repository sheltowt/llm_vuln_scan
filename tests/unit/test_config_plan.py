import os

from llm_vuln_scan.core.assemble import build_context
from llm_vuln_scan.core.config import ScanConfig
from llm_vuln_scan.core.planner import build_plan, plan_fingerprint


def _config(**over):
    base = {
        "target": {"type": "callable", "fn": "vulnerable_app:respond_str"},
        "vulnerabilities": [{"name": "prompt_injection"}],
        "attacks": {"static": ["direct", "base64"]},
        "run": {"cache": ""},
    }
    base.update(over)
    return ScanConfig.model_validate(base)


def test_env_substitution():
    os.environ["LVSCAN_TEST_TOKEN"] = "sekret"
    cfg = ScanConfig.load(overrides={
        "target": {"type": "http", "url": "http://x", "headers": {"A": "${env.LVSCAN_TEST_TOKEN}"}},
    })
    assert cfg.target.build_params()["headers"]["A"] == "sekret"


def test_env_default_used_when_missing():
    cfg = ScanConfig.load(overrides={
        "target": {"type": "callable", "params": {"x": "${env.LVSCAN_NOPE:-fallback}"}},
    })
    assert cfg.target.params["x"] == "fallback"


def test_plan_is_deterministic():
    cfg = _config()
    ctx = build_context(cfg)
    p1 = build_plan(cfg, ctx)
    p2 = build_plan(cfg, ctx)
    assert plan_fingerprint(p1) == plan_fingerprint(p2)
    assert len(p1.items) == len(p2.items) > 0


def test_dynamic_attacks_excluded_from_static_tier():
    cfg = _config(attacks={"static": ["direct"], "dynamic": ["crescendo"]}, run={"tier": "static", "cache": ""})
    ctx = build_context(cfg)
    attacks = {i.attack for i in build_plan(cfg, ctx).items}
    assert "crescendo" not in attacks
    assert "direct" in attacks


def test_preset_expansion():
    from llm_vuln_scan.frameworks.presets import expand

    default = expand("default")
    assert "prompt_injection" in default
    assert "harmful_content" not in default  # tier 2
    owasp1 = expand("owasp:llm:01")
    assert "prompt_injection" in owasp1
