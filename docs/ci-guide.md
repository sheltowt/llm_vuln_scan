# CI guide

The goal: a fast, deterministic gate on every pull request, and deeper runs on a
schedule.

## One-time setup
1. Write `lvscan.yaml` describing your target and its `purpose`.
2. `lvscan generate` → `lvscan.suite.yaml`. **Commit it.** Generation is the
   expensive, nondeterministic step; freezing it makes scans reproducible.

## On every pull request
```bash
lvscan run --suite lvscan.suite.yaml --fail-on-new --baseline tag:git.branch=main \
  --sarif lvscan.sarif --junit lvscan-junit.xml
```
- `--fail-on-new` fails only on failures **not** in the baseline, so a known set
  of accepted findings does not block every PR while regressions still do.
- Exit codes: `0` pass, `100` gate failed, `1` tool error.
- Upload `lvscan.sarif` with `github/codeql-action/upload-sarif` to see findings
  in the Security tab.

See `.github/workflows/scan.yml` for a complete example.

## Managing findings
- `lvscan diff <baseline> <current>` — new failures, fixed, flaky.
- `lvscan export-regressions <run>` — append confirmed hits to
  `lvscan.regressions.yaml`, which runs first on every subsequent scan.
- Flaky attempts (pass and fail across generations) are reported separately so a
  nondeterministic target does not read as a regression.

## Nightly / pre-release
Run the dynamic tier for adaptive multi-turn attacks and LLM-generated seeds:
```bash
lvscan run --tier dynamic --regenerate --show-z --html report.html
```
This needs a judge (`scoring.judge.model`) and, for adaptive attacks, an
attacker model.
