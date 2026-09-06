"""lvscan command line.

Subcommands map to the workflow in the plan: generate a suite once, run it on
every change, diff runs, export regressions, and produce reports.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .. import __version__
from ..core.assemble import assemble
from ..core.config import ScanConfig
from ..core.models import Outcome, Severity
from ..core.planner import build_plan
from ..core.runner import Runner
from ..core.store import RunStore, load_attempts, resolve_run
from ..core.suite import append_regressions, generate_suite, load_suite, save_suite
from ..diff.compare import compare, render_diff_text
from ..evaluate.aggregate import summarise
from ..evaluate.calibrate import fail_rates, load_bag
from ..evaluate.gates import EXIT_ERROR, EXIT_GATE_FAILED, EXIT_PASS, evaluate_gates
from ..report.html import render_html
from ..report.junit import render_junit
from ..report.sarif import render_sarif

app = typer.Typer(
    add_completion=False,
    help="llm_vuln_scan: an LLM vulnerability scanner.",
    no_args_is_help=True,
)
console = Console()
err = Console(stderr=True)


def _git_labels() -> dict[str, str]:
    labels: dict[str, str] = {}
    for key, cmd in (("git.sha", ["git", "rev-parse", "--short", "HEAD"]),
                     ("git.branch", ["git", "rev-parse", "--abbrev-ref", "HEAD"])):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if out.returncode == 0 and out.stdout.strip():
                labels[key] = out.stdout.strip()
        except Exception:
            pass
    return labels


def _load_config(config: Path | None, overrides: dict) -> ScanConfig:
    try:
        return ScanConfig.load(path=config, overrides=overrides)
    except Exception as exc:
        err.print(f"[red]config error:[/red] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc


def _severity(value: str | None) -> Severity | None:
    return Severity.parse(value) if value else None


@app.command()
def version() -> None:
    """Print the version."""
    console.print(f"llm_vuln_scan {__version__}")


@app.command(name="list")
def list_plugins(kind: str | None = typer.Argument(None, help="vulnerability|attack|converter|target|scorer")) -> None:
    """List available plugins."""
    from ..core.plugin import registry_snapshot

    snap = registry_snapshot()
    kinds = [kind] if kind else list(snap)
    for k in kinds:
        if k not in snap:
            err.print(f"[red]unknown kind {k!r}[/red]")
            raise typer.Exit(EXIT_ERROR)
        table = Table(title=k, show_header=False, title_style="bold cyan")
        for name in snap[k]:
            table.add_row(name)
        console.print(table)


@app.command()
def generate(
    config: Path = typer.Option("lvscan.yaml", "--config", "-c", help="Scan config."),
    out: Path = typer.Option("lvscan.suite.yaml", "--out", "-o", help="Suite output path."),
    tier: str | None = typer.Option(None, help="Override tier: static|dynamic."),
) -> None:
    """Freeze seeds and attacks into a committed suite. Do this once, then commit it."""
    overrides = {"run": {"tier": tier}} if tier else {}
    cfg = _load_config(config, overrides)
    _, ctx = assemble(cfg)
    asyncio.run(_prepare(ctx, cfg))
    plan = generate_suite(cfg, ctx)
    save_suite(plan, cfg, out)
    console.print(
        f"[green]wrote[/green] {out}: {len(plan.items)} items across {len(plan.seeds)} seeds "
        f"(tier={cfg.run.tier.value}). Commit it so scans are reproducible."
    )


@app.command()
def run(
    config: Path = typer.Option("lvscan.yaml", "--config", "-c"),
    suite: Path | None = typer.Option(None, "--suite", "-s", help="Replay a committed suite instead of regenerating."),
    regenerate: bool = typer.Option(False, "--regenerate", help="Rebuild the plan even if a suite exists."),
    tier: str | None = typer.Option(None, help="Override tier: static|dynamic."),
    output_dir: Path | None = typer.Option(None, "--output-dir", help="Where runs are stored."),
    fail_on_severity: str | None = typer.Option(None, help="Gate: fail if any hit at/above this severity."),
    pass_rate: float | None = typer.Option(None, help="Gate: fail if pass rate below this (0-1)."),
    fail_on_new: bool = typer.Option(False, help="Gate: fail only on failures not in the baseline."),
    baseline: str | None = typer.Option(None, help="Baseline run ref for diff gates (id|latest|tag:k=v|path)."),
    html_out: Path | None = typer.Option(None, "--html", help="Write an HTML report."),
    junit_out: Path | None = typer.Option(None, "--junit", help="Write JUnit XML."),
    sarif_out: Path | None = typer.Option(None, "--sarif", help="Write SARIF."),
    show_z: bool = typer.Option(False, "--show-z", help="Show calibrated z-scores."),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Run a scan and apply CI gates. Exit 100 on a gate failure, 1 on error."""
    overrides: dict = {"run": {}}
    if tier:
        overrides["run"]["tier"] = tier
    if output_dir:
        overrides["run"]["output_dir"] = str(output_dir)
    for key, value in (("fail_on_severity", fail_on_severity), ("pass_rate", pass_rate),
                       ("fail_on_new", fail_on_new), ("baseline", baseline)):
        if value not in (None, False):
            overrides.setdefault("gates", {})[key] = value
    cfg = _load_config(config, overrides)

    plan = None
    default_suite = Path("lvscan.suite.yaml")
    suite_path = suite or (default_suite if default_suite.exists() and not regenerate else None)
    if suite_path:
        plan = load_suite(suite_path)
        if not quiet:
            console.print(f"[dim]replaying suite {suite_path} ({len(plan.items)} items)[/dim]")

    target, ctx = assemble(cfg)
    run_id = _new_run_id()
    store = RunStore(run_id, cfg.run.output_dir)
    store.start_run(
        tier=cfg.run.tier.value,
        target=getattr(target, "description", cfg.target.type),
        config=cfg.dump(),
        labels={**_git_labels(), **cfg.run.labels},
        tool_version=__version__,
    )
    cfg.run.labels = {**_git_labels(), **cfg.run.labels}

    runner = Runner(cfg, target, ctx, store=store, plan=plan)

    def progress(attempt, done, total):
        if quiet:
            return
        if attempt.outcome is Outcome.FAIL:
            console.print(f"[red]HIT[/red] [{done}/{total}] {attempt.vulnerability}/{attempt.vuln_type} "
                          f"via {attempt.attack}")

    try:
        result = asyncio.run(runner.run(progress=progress))
    finally:
        asyncio.run(_aclose(target))
        store.finish_run()

    bag = load_bag() if show_z else None
    summary = summarise(result.attempts, run_id, calibration=bag)
    store.write_json("summary.json", _summary_dict(summary))

    meta = {
        "target": getattr(target, "description", cfg.target.type),
        "tier": cfg.run.tier.value,
        "labels": " ".join(f"{k}={v}" for k, v in cfg.run.labels.items()),
    }
    if html_out:
        Path(html_out).write_text(render_html(summary, result.attempts, meta=meta))
        console.print(f"[green]html report:[/green] {html_out}")
    else:
        store.write_text("report.html", render_html(summary, result.attempts, meta=meta))
    if junit_out:
        Path(junit_out).write_text(render_junit(result.attempts))
    if sarif_out:
        Path(sarif_out).write_text(render_sarif(result.attempts))

    baseline_attempts = None
    gates = cfg.gates
    if gates.baseline:
        try:
            baseline_attempts = load_attempts(resolve_run(gates.baseline, cfg.run.output_dir))
        except FileNotFoundError as exc:
            err.print(f"[yellow]baseline not found ({exc}); regression gate skipped[/yellow]")

    if not quiet:
        _print_summary(summary, result, show_z)

    gate = evaluate_gates(
        summary,
        result.attempts,
        fail_on_severity=_severity(gates.fail_on_severity.value if gates.fail_on_severity else None),
        pass_rate=gates.pass_rate,
        fail_on_new=gates.fail_on_new,
        baseline_attempts=baseline_attempts,
    )
    console.print(f"\n[bold]run {run_id}[/bold] -> {store.dir}")
    if gate.passed:
        console.print("[green]gates passed[/green]")
        raise typer.Exit(EXIT_PASS)
    for reason in gate.reasons:
        err.print(f"[red]gate failed:[/red] {reason}")
    raise typer.Exit(EXIT_GATE_FAILED)


@app.command()
def diff(
    baseline: str = typer.Argument(..., help="Baseline run ref."),
    current: str = typer.Argument("latest", help="Current run ref."),
    output_dir: Path = typer.Option("lvscan_runs", "--output-dir"),
) -> None:
    """Compare two runs: new failures, fixed, flaky."""
    base = load_attempts(resolve_run(baseline, output_dir))
    curr = load_attempts(resolve_run(current, output_dir))
    result = compare(base, curr)
    console.print(render_diff_text(result))
    raise typer.Exit(EXIT_GATE_FAILED if result.has_regressions else EXIT_PASS)


@app.command(name="export-regressions")
def export_regressions(
    run: str = typer.Argument("latest"),
    out: Path = typer.Option("lvscan.regressions.yaml", "--out", "-o"),
    output_dir: Path = typer.Option("lvscan_runs", "--output-dir"),
) -> None:
    """Append confirmed hits to a regressions file that runs first next time."""
    attempts = load_attempts(resolve_run(run, output_dir))
    hits = [a for a in attempts if a.outcome is Outcome.FAIL]
    added = append_regressions(hits, out)
    console.print(f"[green]added {added}[/green] regression(s) to {out} ({len(hits)} hits total)")


@app.command()
def report(
    run: str = typer.Argument("latest"),
    out: Path = typer.Option("report.html", "--out", "-o"),
    output_dir: Path = typer.Option("lvscan_runs", "--output-dir"),
    show_z: bool = typer.Option(False, "--show-z"),
) -> None:
    """Regenerate an HTML report from a stored run."""
    run_dir = resolve_run(run, output_dir)
    attempts = load_attempts(run_dir)
    bag = load_bag() if show_z else None
    summary = summarise(attempts, run_dir.name, calibration=bag)
    Path(out).write_text(render_html(summary, attempts))
    console.print(f"[green]wrote[/green] {out}")


@app.command()
def repro(
    run: str = typer.Argument(...),
    attempt_id: str = typer.Argument(...),
    output_dir: Path = typer.Option("lvscan_runs", "--output-dir"),
) -> None:
    """Show the full conversation and config for one attempt."""
    attempts = load_attempts(resolve_run(run, output_dir))
    match = next((a for a in attempts if a.id == attempt_id), None)
    if match is None:
        err.print(f"[red]attempt {attempt_id} not found in run {run}[/red]")
        raise typer.Exit(EXIT_ERROR)
    console.print(f"[bold]{match.vulnerability}/{match.vuln_type}[/bold] via [cyan]{match.attack}[/cyan]")
    console.print(f"outcome: {match.outcome.value}  severity: {match.severity.value}  "
                  f"confidence: {match.confidence:.0%}")
    console.print(f"\n[dim]identifiers:[/dim] {json.dumps(match.identifiers, indent=2)}")
    console.print("\n[bold]conversation[/bold]")
    console.print(match.conversation.render())
    for score in match.scores:
        console.print(f"\n[bold]{score.scorer}[/bold]: value={score.value} "
                      f"confidence={score.confidence:.0%}\n  {score.rationale}")


@app.command()
def plan(
    config: Path = typer.Option("lvscan.yaml", "--config", "-c"),
    tier: str | None = typer.Option(None),
) -> None:
    """Show what a scan would run, without calling the target."""
    overrides = {"run": {"tier": tier}} if tier else {}
    cfg = _load_config(config, overrides)
    _, ctx = assemble(cfg)
    asyncio.run(_prepare(ctx, cfg))
    p = build_plan(cfg, ctx)
    table = Table(title=f"plan: {len(p.items)} items, {len(p.seeds)} seeds, tier={cfg.run.tier.value}")
    table.add_column("vulnerability")
    table.add_column("types")
    table.add_column("seeds", justify="right")
    table.add_column("attacks", justify="right")
    by_vuln: dict[str, dict] = {}
    for item in p.items:
        v = by_vuln.setdefault(item.seed.vulnerability, {"types": set(), "seeds": set(), "attacks": set()})
        v["types"].add(item.seed.vuln_type)
        v["seeds"].add(item.seed.id)
        v["attacks"].add(item.attack)
    for name, info in sorted(by_vuln.items()):
        table.add_row(name, str(len(info["types"])), str(len(info["seeds"])), str(len(info["attacks"])))
    console.print(table)


@app.command()
def calibrate(
    runs: list[str] = typer.Argument(..., help="Run refs, one per reference model."),
    out: Path = typer.Option("bag.json", "--out", "-o"),
    output_dir: Path = typer.Option("lvscan_runs", "--output-dir"),
) -> None:
    """Build a calibration bag from several reference-model runs."""
    from ..evaluate.calibrate import build_bag_from_runs

    model_summaries = {}
    for ref in runs:
        run_dir = resolve_run(ref, output_dir)
        attempts = load_attempts(run_dir)
        model_summaries[run_dir.name] = fail_rates(attempts)
    bag = build_bag_from_runs(model_summaries)
    Path(out).write_text(json.dumps(bag, indent=2))
    console.print(f"[green]wrote[/green] {out}: {len(bag['vulnerabilities'])} vulnerabilities "
                  f"across {len(runs)} models")


def _new_run_id() -> str:
    from datetime import datetime

    from ..core.models import new_id

    return datetime.now().strftime("%Y%m%d-%H%M%S-") + new_id()[:6]


async def _prepare(ctx, cfg) -> None:
    from ..core.generate import prepare

    await prepare(ctx, cfg)


async def _aclose(target) -> None:
    if hasattr(target, "aclose"):
        await target.aclose()


def _summary_dict(summary) -> dict:
    from dataclasses import asdict

    return asdict(summary)


def _print_summary(summary, result, show_z: bool) -> None:
    table = Table(title="scan summary", title_style="bold")
    table.add_column("vulnerability")
    table.add_column("sev")
    table.add_column("hits", justify="right")
    table.add_column("fail%", justify="right")
    table.add_column("issue")
    if show_z:
        table.add_column("z")
    for v in sorted(summary.vulnerabilities, key=lambda x: (-x.hits, x.vulnerability)):
        row = [
            v.vulnerability,
            v.severity,
            f"{v.hits}/{v.total}",
            f"{v.fail_rate:.0%}",
            v.issue_level if v.hits else "-",
        ]
        if show_z:
            row.append(f"{v.z_score:+.2f} {v.z_rating}" if v.z_score is not None else "-")
        style = "red" if v.hits and v.severity in ("critical", "high") else (
            "yellow" if v.hits else "green"
        )
        table.add_row(*row, style=style)
    console.print(table)
    inconclusive_note = (
        f"  ·  [yellow]{summary.inconclusive} inconclusive[/yellow]"
        if summary.inconclusive else ""
    )
    console.print(
        f"pass rate [bold]{summary.pass_rate:.1%}[/bold]  ·  {summary.hits} hits  ·  "
        f"{result.errors} errors  ·  {result.skipped} skipped{inconclusive_note}  ·  "
        f"target calls {result.target_calls}  ·  judge calls {result.judge_calls}"
        + (f"  ·  exposure {summary.cvss}/10" if summary.cvss is not None else "")
    )
    if summary.inconclusive:
        console.print(
            "[yellow]note:[/yellow] inconclusive attempts were scored but no result "
            "was confident enough to decide; they are NOT counted as passes."
        )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
