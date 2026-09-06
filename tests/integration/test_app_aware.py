"""Milestone C: the purpose -> requirements -> seeds -> judge pipeline."""

import asyncio

from stub_generator import StubGenerator

from llm_vuln_scan.core.context import AppContext
from llm_vuln_scan.core.generate import needs_preparation, prepare
from llm_vuln_scan.core.plugin import build
from llm_vuln_scan.scorers.llm import JudgeClient


def _ctx(tmp_path, **kw):
    stub = StubGenerator(**kw)
    judge = JudgeClient(stub, model="stub")
    ctx = AppContext(
        purpose="Support bot for Acme Bank. Must not reveal config or give investment advice.",
        judge=judge, attacker=stub, cache_dir=str(tmp_path),
    )
    return ctx, stub


class _Entry:
    def __init__(self, name=None, preset=None, custom=None, criteria=None):
        self.name, self.preset, self.custom, self.criteria = name, preset, custom, criteria


class _Cfg:
    def __init__(self, vulns):
        self.vulnerabilities = vulns


def test_needs_preparation_detects_consumers():
    wants, crits = needs_preparation(_Cfg([_Entry(name="app_requirements")]))
    assert wants and not crits
    wants, crits = needs_preparation(_Cfg([_Entry(custom="x", criteria="no competitors")]))
    assert not wants and crits == ["no competitors"]
    wants, crits = needs_preparation(_Cfg([_Entry(name="prompt_injection")]))
    assert not wants and not crits


def test_pipeline_generates_requirements_and_seeds(tmp_path):
    ctx, stub = _ctx(tmp_path)
    asyncio.run(prepare(ctx, _Cfg([_Entry(name="app_requirements")])))
    assert len(ctx.requirements) == 2
    req_seeds = ctx.extra["req_seeds"]
    assert sum(len(v) for v in req_seeds.values()) == 8

    seeds = build("vulnerability", "app_requirements").seeds(ctx)
    assert len(seeds) == 8
    assert all("requirement" in s.context for s in seeds)


def test_generation_is_cached(tmp_path):
    ctx, stub = _ctx(tmp_path)
    cfg = _Cfg([_Entry(name="app_requirements")])
    asyncio.run(prepare(ctx, cfg))
    first = stub.total_calls
    assert first > 0
    # A fresh context sharing the same cache dir must not call the generator again.
    ctx2, stub2 = _ctx(tmp_path)
    asyncio.run(prepare(ctx2, cfg))
    assert stub2.total_calls == 0
    assert ctx2.requirements == ctx.requirements


def test_no_purpose_generates_nothing(tmp_path):
    stub = StubGenerator()
    judge = JudgeClient(stub, model="stub")
    ctx = AppContext(purpose="", judge=judge, attacker=stub, cache_dir=str(tmp_path))
    asyncio.run(prepare(ctx, _Cfg([_Entry(name="app_requirements")])))
    assert ctx.requirements == []
    assert build("vulnerability", "app_requirements").seeds(ctx) == []


def test_custom_vuln_uses_generated_seeds(tmp_path):
    ctx, stub = _ctx(tmp_path)
    asyncio.run(prepare(ctx, _Cfg([_Entry(custom="c", criteria="Must not mention competitors.")])))
    from llm_vuln_scan.vulnerabilities.programmatic import CustomVulnerability

    vuln = CustomVulnerability(name="c", criteria="Must not mention competitors.")
    seeds = vuln.seeds(ctx)
    # 4 generated probes, not the 3 templated fallbacks
    assert len(seeds) == 4
