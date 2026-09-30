"""The lvscan CLI end to end: run, gates, reports, and the stored-run commands."""

import json
from pathlib import Path
from xml.etree import ElementTree

import pytest
import yaml
from typer.testing import CliRunner

from llm_vuln_scan.cli.main import app
from llm_vuln_scan.core.store import find_runs, load_attempts

CONFIG = {
    "target": {"type": "callable", "fn": "vulnerable_app:respond"},
    "app": {"canaries": ["SECRET_CONFIG_KEY=sk-acme-4f9a2b7c1d8e3f6a0b5c9d2e", "You are AcmeBot"]},
    "vulnerabilities": [{"name": "system_prompt_leakage"}, {"name": "prompt_injection"}],
    "attacks": {"static": ["direct", "injection_framing"]},
    "run": {"tier": "static", "cache": ""},
}

runner = CliRunner()


def invoke(*args: str):
    return runner.invoke(app, [str(a) for a in args])


@pytest.fixture(scope="module")
def workspace(tmp_path_factory) -> Path:
    """One real scan, shared by the tests that only read stored runs."""
    ws = tmp_path_factory.mktemp("cli")
    (ws / "lvscan.yaml").write_text(yaml.safe_dump(CONFIG))
    result = invoke(
        "run", "-c", ws / "lvscan.yaml", "--output-dir", ws / "runs", "-q",
        "--junit", ws / "out.xml", "--sarif", ws / "out.sarif", "--html", ws / "out.html",
    )
    assert result.exit_code == 0, result.output
    return ws


def test_run_writes_run_dir_and_reports(workspace: Path):
    runs = find_runs(workspace / "runs")
    assert len(runs) == 1
    run_dir = runs[0]
    for name in ("run.sqlite", "attempts.jsonl", "hits.jsonl", "summary.json"):
        assert (run_dir / name).exists(), name
    summary = json.loads((run_dir / "summary.json").read_text())
    assert summary["hits"] > 0

    attempts = load_attempts(run_dir)
    hits = sum(1 for a in attempts if a.hit)
    junit = ElementTree.parse(workspace / "out.xml").getroot()
    assert int(junit.get("tests")) == len(attempts)
    assert int(junit.get("failures")) == hits

    sarif = json.loads((workspace / "out.sarif").read_text())
    assert len(sarif["runs"][0]["results"]) == hits
    assert (workspace / "out.html").read_text().lstrip().lower().startswith("<!doctype html")


def test_run_severity_gate_exits_100(workspace: Path):
    result = invoke(
        "run", "-c", workspace / "lvscan.yaml", "--output-dir", workspace / "gated_runs", "-q",
        "--fail-on-severity", "high",
    )
    assert result.exit_code == 100
    assert "gate failed" in result.output


def test_run_bad_config_exits_1(tmp_path: Path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump({"run": {"tier": "not-a-tier"}}))
    result = invoke("run", "-c", bad, "--output-dir", tmp_path / "runs")
    assert result.exit_code == 1
    assert "config error" in result.output


def test_diff_identical_runs_has_no_regressions(workspace: Path):
    run = find_runs(workspace / "runs")[0]
    result = invoke("diff", run, run, "--output-dir", workspace / "runs")
    assert result.exit_code == 0, result.output


def test_report_regenerates_html(workspace: Path):
    out = workspace / "regen.html"
    result = invoke("report", "latest", "--out", out, "--output-dir", workspace / "runs")
    assert result.exit_code == 0, result.output
    assert "system_prompt_leakage" in out.read_text()


def test_repro_shows_attempt_and_rejects_unknown(workspace: Path):
    runs = workspace / "runs"
    hit = next(a for a in load_attempts(find_runs(runs)[0]) if a.hit)
    result = invoke("repro", "latest", hit.id, "--output-dir", runs)
    assert result.exit_code == 0, result.output
    assert hit.vulnerability in result.output

    missing = invoke("repro", "latest", "att_does_not_exist", "--output-dir", runs)
    assert missing.exit_code == 1


def test_export_regressions_is_idempotent(workspace: Path):
    out = workspace / "regressions.yaml"
    runs = workspace / "runs"
    first = invoke("export-regressions", "latest", "--out", out, "--output-dir", runs)
    assert first.exit_code == 0, first.output
    assert out.exists()
    before = out.read_text()
    second = invoke("export-regressions", "latest", "--out", out, "--output-dir", runs)
    assert second.exit_code == 0
    assert "added 0" in second.output
    assert out.read_text() == before


def test_calibrate_builds_bag(workspace: Path):
    out = workspace / "bag.json"
    run = find_runs(workspace / "runs")[0]
    result = invoke("calibrate", run, "--out", out, "--output-dir", workspace / "runs")
    assert result.exit_code == 0, result.output
    bag = json.loads(out.read_text())
    assert bag["models"] == [run.name]
    assert "system_prompt_leakage" in bag["vulnerabilities"]


def test_plan_and_generate(tmp_path: Path, workspace: Path):
    config = workspace / "lvscan.yaml"
    result = invoke("plan", "-c", config)
    assert result.exit_code == 0, result.output
    assert "system_prompt_leakage" in result.output

    suite = tmp_path / "suite.yaml"
    result = invoke("generate", "-c", config, "--out", suite)
    assert result.exit_code == 0, result.output
    assert suite.exists()


def test_version_and_list():
    assert invoke("version").exit_code == 0
    result = invoke("list", "target")
    assert result.exit_code == 0
    assert "http" in result.output
    assert invoke("list", "nonsense").exit_code == 1
