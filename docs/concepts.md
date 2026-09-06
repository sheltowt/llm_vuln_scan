# Concepts

Five plugin kinds, and nothing else, carry the whole design.

## Vulnerability — what you test for
Owns its seeds, its default scorer, its severity, and its framework tags. Most
are declarative YAML under `data/seeds/`; adding one is a file, not a class.
Two seed sources exist for every vulnerability: **static** curated payloads
(free, deterministic) and **generated** payloads synthesised from the app's
`purpose` (Giskard-style). `CustomVulnerability(criteria=...)` builds both its
seeds and its judge from one plain-language rule.

## Attack — how the test is delivered
An attack owns the *plan*. Single-turn attacks transform a seed; multi-turn
attacks run an adaptive loop. Attacks carry a `weight` for sampling and a `cost`
(`static` or `llm`) so the static tier can exclude the expensive ones.
Multi-turn attacks branch **only on scorer output**, never on raw text.

## Converter — how the payload is encoded
An attack owns the plan; a converter owns the encoding. Converters are pure,
chainable, and can `untransform` a response (decode a base64 reply before
scoring) so an encoded answer cannot evade detection.

## Target — the system under test
`callable` (a Python function or `file.py:func`), `openai_compat` (any
OpenAI-style endpoint), `http` (a bespoke JSON API with sessions), or `agent`
(a tool-using system whose call trace is captured). The base class owns retries,
rate limiting and usage accounting.

## Scorer — how the target is judged
Heuristic, classifier, or LLM. Every score carries a **confidence**, and the
evaluator excludes low-confidence scores from CI gates. `cascade` runs the cheap
scorer first and only pays for a judge on ambiguous cases; `composite` combines
scorers with AND/OR/MAJORITY.

## The record
Every scan produces immutable **Attempt** records with content-addressed
identifiers of every component config. Reports, diffs, gates and exports read
those records and nothing else, so a run is fully reconstructible.
