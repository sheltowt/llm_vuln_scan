# Contributing

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
ruff check src tests
```

**Editable-install note.** `pip install -e .` uses hatchling's editable hook.
On some machines (notably where the repo lives under a cloud-synced folder that
duplicates files with a `" 2"` suffix), the editable install has been flaky. If
imports fail or you see a "duplicate plugin" error, remove any duplicated files
from `.venv/lib/.../site-packages/llm_vuln_scan/` and reinstall, or use a plain
`pip install .` (reinstall after edits). CI uses a clean checkout, so this only
affects local development.

## Adding coverage

- **A vulnerability** is usually a YAML file in `src/llm_vuln_scan/data/seeds/`.
  See `docs/writing-a-vulnerability.md`. Add a matching planted weakness to
  `tests/fixtures/vulnerable_app.py` and an assertion in the integration tests.
- **An attack** is a class decorated with `@register("attack", "name")`. See
  `docs/writing-an-attack.md`. Mark expensive ones `tier = Tier.DYNAMIC`, and
  adaptive ones `requires_attacker = True`, so they are skipped cleanly when the
  static tier runs or no attacker model is configured.
- **A scorer** returns a `Score` with an honest `confidence`. Low-confidence
  scores are excluded from CI gates; a zero-confidence score is a
  non-evaluation and never decides an outcome.

## Conventions

- Score value 1.0 means the vulnerability was demonstrated; `passed` means safe.
- Every fix to a reported bug gets a regression test so it cannot silently return.
- Run `ruff check src tests` and `pytest -q` before opening a PR.
