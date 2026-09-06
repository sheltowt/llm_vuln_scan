# llm_vuln_scan — notes for future work

An LLM vulnerability scanner with a static tier (deterministic, CI-safe) and a
dynamic tier (adaptive, LLM-driven). See `PLAN.md` for the full design rationale
and `docs/` for concepts and how-to guides.

## Architecture in one breath
Five plugin kinds: **vulnerability** (what to test), **attack** (how to deliver),
**converter** (how to encode), **target** (what to test), **scorer** (how to
judge). Everything else is internal. A scan produces immutable `Attempt` records
(`core/models.py`); reports, diffs, gates and exports derive from those.

## Layout
- `core/` — models, plugin registry, config, planner, runner, store, suite, cache.
- `targets/`, `converters/`, `scorers/`, `attacks/`, `vulnerabilities/` — the plugins.
- `data/seeds/*.yaml` — declarative vulnerabilities (add a file to add coverage).
- `evaluate/` — aggregation, z-scores, CI gates. `report/` — html, junit, sarif.
- `frameworks/` — preset expansion from tags (owasp:llm, mitre:atlas, ...).

## Conventions
- Score value: 1.0 means the vulnerability was demonstrated; `passed` means safe.
- Every score carries `confidence`; low-confidence scores are excluded from gates
  (`run.min_confidence`). This is the main defence against judge false positives.
- Attacks branch only on scorer output, never on raw response text.
- Add a vulnerability = a YAML file in `data/seeds/` + a planted bug in
  `tests/fixtures/vulnerable_app.py` + an assertion in the integration tests.

## Development
- `pip install -e ".[dev]"` then `pytest -q` and `ruff check src tests`.
- The bundled `tests/fixtures/vulnerable_app.py` is a deterministic, no-LLM app
  with planted weaknesses; the integration tests assert each is found. Run the
  quickstart with `lvscan run -c examples/quickstart/lvscan.yaml`.
- Local editable installs via hatchling have been flaky in this environment; a
  plain `pip install .` (reinstall after edits) is reliable.

## Not built yet (see PLAN.md milestones)
- Multimodal converters/targets, RAG component attribution (RAGET-style).
- HF classifier scorers (the `[classifiers]` extra is declared, not wired).
- The calibration bag ships seed values; `lvscan calibrate` builds a real one
  from reference-model runs but no CI job refreshes it yet.
