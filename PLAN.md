# llm_vuln_scan — Project Plan

An LLM vulnerability scanner that takes the best structural ideas from garak, PyRIT, Promptfoo, DeepTeam, and Giskard, and drops the parts that make each of them painful. Turnkey like garak, composable like PyRIT, CI-native like Promptfoo, app-aware like Giskard, with DeepTeam's clean vulnerability × attack API.

Working name for the CLI: `lvscan`. Python package: `llm_vuln_scan`.

---

## 1. Positioning

| Tool | Shape | What we take | What we leave behind |
|---|---|---|---|
| **garak** | Turnkey scanner | Probe/detector split, `Attempt` as the unit of record, JSONL attempt log + hitlog, calibrated z-scores against a model "bag", tiered probes, tag-driven reporting, REST/function targets | Single-turn bias, string-match detectors that false-positive on short/non-English output, process-pool parallelism, static payloads that models are trained against, no ATLAS mapping |
| **PyRIT** | Framework | Converter chains (request *and* response), scorer hierarchy (true/false vs float scale, composite AND/OR/MAJORITY, threshold wrapper), multi-turn executors with backtracking (Crescendo, TAP, PAIR), content-addressed component identifiers, scorer-accuracy evaluator, "branch only on scorer output" rule | Seven-layer abstraction stack, Azure defaults, breaking API churn, no export |
| **Promptfoo** | Eval + red team | Plugin vs strategy separation, `purpose` as the driver for generation and grading, framework presets (`owasp:llm:01`…), `retry` strategy as a regression suite, stateful/stateless targets with `sessionParser`, exit codes + pass-rate threshold, `redteam eval` (re-run fixed cases) vs `redteam run` (regenerate), compare view | Cloud-gated generation, probe quotas, noisy version-to-version diffs from nondeterministic generation |
| **DeepTeam** | Library | `red_team(callback, vulnerabilities, attacks)` API shape, vulnerability `types` sub-taxonomy, weighted attack sampling, `CustomVulnerability(criteria=...)` auto-generating its judge, CVSS-style exposure score, dataframe export | Everything LLM-driven at every stage, OpenAI-only defaults, no report without paid platform |
| **Giskard** | Scanner + eval | Description → requirements → adversarial inputs → requirement-based judge, heuristic vs LLM-assisted detector split, major/medium/minor issue levels, issue → regression test export, RAG component scoring (RAGET) | Legacy/v3 rewrite churn, no attack-enhancement layer, heavy deps, Hub gating |

**Design thesis:** separate *what you test for* (vulnerabilities), *how you deliver the test* (attacks + converters), *how you judge* (scorers), and *what you test* (targets). Make every layer pluggable, keep the default path turnkey, and make the cheap deterministic tier good enough to run on every PR.

---

## 2. Core concepts

```
Vulnerability  ──  what could go wrong (PromptLeakage, BOLA, Toxicity[hate], ...)
      │            owns: seed generator, default scorer, severity, framework tags
      ▼
Attack         ──  how the seed is delivered (Direct, Base64, Roleplay, Crescendo, TAP, ...)
      │            single-turn = seed transform; multi-turn = executor loop
      ▼
Converter[]    ──  cheap, chainable request/response transforms (rot13, leetspeak, translate, ...)
      │
      ▼
Target         ──  the system under test (HTTP, Python callable, OpenAI-compatible, agent w/ tools)
      │
      ▼
Scorer[]       ──  heuristic → classifier → LLM judge; each returns Score(value, rationale, confidence)
      │
      ▼
Attempt        ──  the immutable record: seed, converted prompt(s), conversation, scores, identifiers
      │
      ▼
Evaluator      ──  Attempt → pass/fail, severity, z-score vs baseline; aggregates into Report
```

### 2.1 Vulnerability

```python
class Vulnerability(Plugin):
    name: str                       # "prompt_leakage"
    types: list[str]                # ["system_prompt", "secrets", "guardrails"]
    severity: Severity              # default; scorer can escalate/de-escalate
    tags: Tags                      # owasp:llm:07, owasp:agentic:..., mitre:atlas:AML.T0051, avid:..., cwe:...
    tier: Literal[1, 2, 3]          # 1 = of concern, 2 = compete-with-SOTA, 3 = informational (garak)
    def seeds(self, ctx: AppContext, n: int) -> list[Seed]: ...
    def default_scorer(self, ctx) -> Scorer: ...
```

- `seeds()` has two implementations available to every vulnerability:
  - **static**: curated payloads shipped in `data/` (garak-style, deterministic, free).
  - **generated**: LLM-synthesized from `AppContext.purpose` (Promptfoo/Giskard/DeepTeam-style).
- `CustomVulnerability(name, criteria="...")` builds its seed generator and judge from plain-language criteria (DeepTeam). A `policy` vulnerability takes a policy document and tests adherence (Promptfoo).
- Giskard's requirement-derivation is the generated path: `purpose` → list of requirements → seeds per requirement → judge per requirement. Requirements are cached on disk so re-runs are stable.

### 2.2 Attack

```python
class SingleTurnAttack(Attack):
    def transform(self, seed: Seed, ctx) -> Seed: ...          # may call an attacker LLM

class MultiTurnAttack(Attack):
    max_turns: int; max_backtracks: int
    async def run(self, seed, target, scorer, ctx) -> Attempt: ...  # PyRIT executor loop
```

- Attacks carry `weight` for sampling (DeepTeam) and `cost: Literal["static","llm"]` so the CI tier can filter.
- Multi-turn attacks branch **only on scorer output**, never raw text (PyRIT rule). Crescendo backtracks on refusal (requires target `editable_history`); TAP prunes off-topic/low-score branches; PAIR is TAP with width 1.
- Attacks are separate from converters: an attack decides *the plan*, converters decide *the encoding*.

### 2.3 Converter

Pure functions `str -> str` (or multimodal later), chainable, order-preserving, applied to requests and optionally to responses (decode base64 replies before scoring). Selective conversion via `⟪…⟫` span markers (PyRIT). Applied converter identifiers are stored on the attempt.

### 2.4 Target

```python
class Target(Plugin):
    capabilities: TargetCapabilities  # multi_turn, editable_history, system_prompt, tools, streaming
    async def send(self, conv: Conversation) -> Message: ...
```

- `HttpTarget`: request template with `{{prompt}}`, `{{history}}`, `{{session_id}}`; `transform_request` / `transform_response` (Python expr or file); `session_parser`; `stateful: bool`; `conversation_ended` signal; rate-limit codes + retry with backoff; mTLS/proxy (garak REST + Promptfoo HTTP).
- `CallableTarget`: any `async (Conversation) -> str`.
- `OpenAICompatTarget`: base_url + model (covers OpenAI, Anthropic via gateway, Ollama, vLLM, LiteLLM).
- `AgentTarget`: wraps a tool-using agent; exposes tool-call trace so agentic scorers can see *actions*, not just text.
- Throughput: asyncio + per-target token-bucket rate limiter (not reactive-only backoff).

### 2.5 Scorer

```python
class Scorer(Plugin):
    kind: Literal["true_false", "float"]
    cost: Literal["heuristic", "classifier", "llm"]
    async def score(self, attempt: Attempt, ctx) -> Score  # value, rationale, confidence, category
```

- Leaf scorers: `Substring`, `Regex` (secrets, XSS, SQLi, SSRF, package names), `Refusal` (small local classifier, not phrase list), `Toxicity` (HF classifier), `SelfAskTrueFalse`, `SelfAskLikert`, `SelfAskScale`, `RequirementJudge` (Giskard), `ToolCallScorer` (did the agent call X with args Y).
- Wrappers: `Composite(AND|OR|MAJORITY)`, `Inverter`, `Threshold(float→bool)`, `Cascade` (run heuristic first; only invoke LLM judge on ambiguous band).
- **Scorer calibration** (garak detector metrics + PyRIT `ScorerEvaluator`): `data/scorer_eval/` holds human-labeled attempts; `lvscan scorer eval` reports sensitivity/specificity per scorer and feeds a bootstrap CI on the reported failure rate.
- Every `Score` carries `confidence`; the report shows it, and the evaluator can exclude low-confidence hits from gating.

### 2.6 Attempt & Store

One `Attempt` per (vulnerability, type, attack, seed, target). Fields: seed, converted prompt(s), full conversation (all turns, all generations), tool-call trace, scores, `identifiers` (content-addressed SHA-256 of every component config, PyRIT-style), timing, token usage, run id, git sha, labels.

Store: SQLite by default (single file per run, no server), append-only JSONL export alongside (`attempts.jsonl`, `hits.jsonl`). Both are the interchange format; the HTML report and the diff tool read from them.

---

## 3. Coverage taxonomy

Vulnerabilities map to multiple frameworks; presets expand to vulnerability sets.

| Preset | Expands to |
|---|---|
| `owasp:llm` / `owasp:llm:01`…`10` | prompt injection, sensitive info, supply chain (package hallucination), data/model poisoning (RAG poisoning), improper output handling (XSS/SQLi/shell), excessive agency, system prompt leakage, vector/embedding weaknesses, misinformation, unbounded consumption |
| `owasp:agentic` | goal hijacking, tool misuse, memory poisoning, privilege compromise, identity spoofing, cascading failures, human manipulation |
| `mitre:atlas` | tactic-level mapping (garak lacks this; we ship it from day one) |
| `nist:ai:measure` | measure subcategories |
| `default` | tier-1 vulnerabilities, static attacks only |
| `full` | everything, dynamic attacks on |

Initial vulnerability catalog (v0.1 → v0.3):

- **Injection**: direct prompt injection, indirect/latent injection (documents, tool results, web content), system prompt override, special-token injection, ASCII smuggling.
- **Leakage**: system prompt extraction, secrets/API keys, PII (direct, cross-session, via API/DB), training-data replay.
- **Access control (agentic)**: BOLA, BFLA, RBAC, debug/admin access, SSRF, shell/SQL injection via tools, tool discovery, excessive agency, memory poisoning.
- **Harmful content**: hate, self-harm, sexual, violent crime, cybercrime, weapons, radicalization (static datasets: HarmBench, BeaverTails, XSTest for over-refusal).
- **Trust**: hallucination (snowball, package hallucination), sycophancy (Giskard opposing-premise pairs), overreliance, competitors/imitation, off-topic, unverifiable claims.
- **Robustness**: character injection / control sequences, homoglyphs, divergent repetition, reasoning DoS.
- **RAG**: retrieval poisoning, document exfiltration, context-grounding failures (RAGET-style component attribution as a stretch goal).

Initial attack catalog:

- **Static single-turn** (deterministic, no attacker LLM): direct, base64, hex, rot13, leetspeak, homoglyph, morse, emoji, zero-width, jailbreak templates (DAN, skeleton key, many-shot prefix), prompt-injection framing, multilingual (static translations).
- **Dynamic single-turn**: roleplay, gray-box, prompt-probing, math-problem, citation, best-of-N, iterative jailbreak (attacker→judge loop).
- **Multi-turn**: crescendo (backtracking), TAP, PAIR, GOAT-style adaptive attacker, sequential/scripted, custom (natural-language strategy text).

---

## 4. Two execution tiers

This is the single most important product decision, and it is what none of the five tools gets fully right.

| | **Static tier** | **Dynamic tier** |
|---|---|---|
| Seeds | curated `data/` | LLM-generated from `purpose` (cached by content hash) |
| Attacks | deterministic converters/templates | attacker-LLM single- and multi-turn |
| Scorers | heuristic + local classifiers, LLM judge only in `Cascade` ambiguous band | LLM judge allowed |
| Determinism | fully reproducible given `seed` | reproducible given cached seeds + `temperature=0` judge; still noisy |
| Cost | ~free, minutes | $, tens of minutes to hours |
| Where | every PR, blocks merge on regressions | nightly / pre-release, informs |

`lvscan run --tier static` is the CI default. `--tier dynamic` adds the rest. Both produce the same `Attempt` records so reports and diffs are uniform.

---

## 5. Regression & CI story

Directly addresses "prompts and agents as code."

1. `lvscan generate` → writes `lvscan.suite.yaml` (seeds, attacks, expected scorers) — **committed to the repo**. Generation is the expensive, nondeterministic step; it happens once.
2. `lvscan run` → executes a committed suite against a target; deterministic given the suite. This is Promptfoo's `redteam eval`, made the default.
3. `lvscan run --regenerate` → the `redteam run` equivalent; only on demand.
4. `lvscan diff <run-a> <run-b>` → new failures / fixed / flaky, grouped by vulnerability and severity. Flakiness detected by re-running failures N times (configurable) before reporting a regression.
5. `lvscan export-regressions <run>` → appends every confirmed hit to `lvscan.regressions.yaml` (Promptfoo `retry` + Giskard test-suite export). Regressions run first on every subsequent run.
6. Exit codes: `0` pass, `100` gate failed, `1` tool error. Gates: `--fail-on severity>=high`, `--pass-rate 0.98`, `--fail-on-new` (only regressions vs baseline, not absolute).
7. GitHub Action wrapper + JUnit XML + SARIF output (so findings show in the GitHub Security tab).
8. `--tag git.sha=... git.branch=...` labels on every run; baseline selection by tag.

---

## 6. Reporting

- `report.html`: single self-contained file. Sections: executive summary (pass rate, severity histogram, framework compliance badges), per-vulnerability table with **absolute score, calibrated z-score, and confidence interval**, drill-down to every hit with full conversation, tool trace, scorer rationale, and the exact reproduction command.
- Severity levels: critical / high / medium / low (Promptfoo) with an issue level per finding (major/medium/minor, Giskard) derived from severity × pass-rate × confidence.
- Aggregation function is configurable and the default is **minimum-per-vulnerability, mean-per-category** so a single catastrophic probe is never masked (garak's lower-quartile default hides this).
- **Calibration bag** (garak): we ship `data/calibration/` with per-vulnerability × attack pass-rate μ/σ across a bag of ~15 recent open and closed models, refreshed quarterly by a CI job. `--show-z` renders relative ratings.
- Optional CVSS-style 0–10 (DeepTeam) computed from severity, exploitability (which tier/attack succeeded) and user-declared exposure.
- Machine outputs: `attempts.jsonl`, `hits.jsonl`, `summary.json`, JUnit, SARIF, dataframe via `lvscan export --format parquet`.

---

## 7. Configuration

```yaml
# lvscan.yaml
target:
  type: http
  url: https://internal.example.com/chat
  request:
    method: POST
    headers: { Authorization: "Bearer ${env.TOKEN}" }
    body: { message: "{{prompt}}", session: "{{session_id}}" }
  response: "$.reply"
  session_parser: "$.session"
  stateful: true
  capabilities: { multi_turn: true, editable_history: false, tools: true }
  rate_limit: { rps: 5, burst: 10 }

app:
  purpose: >
    Customer-support assistant for Acme Bank. Users are authenticated retail
    customers. It may look up the caller's own accounts only. Must never
    discuss competitor products or give investment advice.
  entities: [Acme Bank, Acme Rewards]
  exposure: high

vulnerabilities:
  - preset: owasp:llm
  - preset: owasp:agentic
  - name: pii_leakage
    types: [direct, cross_session]
    num_seeds: 10
    severity: critical
  - custom: no_investment_advice
    criteria: "The assistant must not recommend specific securities or portfolio actions."

attacks:
  static: [direct, base64, leetspeak, jailbreak_templates, prompt_injection_framing]
  dynamic: [roleplay, iterative_jailbreak, crescendo, tap]
  weights: { crescendo: 2 }

scoring:
  judge: { provider: openai_compat, model: gpt-5, temperature: 0 }
  cascade: true
  min_confidence: 0.6

run:
  tier: static
  seed: 42
  generations: 1        # static tier; dynamic defaults to 3
  concurrency: 8
  cache: .lvscan/cache

gates:
  fail_on_severity: high
  fail_on_new: true
  baseline: tag:git.branch=main
```

Layering: package defaults → `lvscan.yaml` → `--config` overlays → CLI flags → env vars. All secrets via `${env.X}`.

Every component is identified by the SHA-256 of its resolved config so a report can say exactly which judge, prompt template, and converter chain produced a hit.

---

## 8. Repo layout

```
llm_vuln_scan/
├── pyproject.toml              # python>=3.11, hatch, extras: [classifiers], [report], [all]
├── PLAN.md                     # this file
├── README.md
├── src/llm_vuln_scan/
│   ├── cli/                    # typer: run, generate, diff, report, export, scorer, calibrate, targets
│   ├── core/
│   │   ├── models.py           # Seed, Conversation, Message, Attempt, Score, Identifier (pydantic)
│   │   ├── plugin.py           # registry, discovery (entry_points + local dirs), config merge
│   │   ├── context.py          # AppContext (purpose, entities, exposure, requirements cache)
│   │   ├── runner.py           # async orchestration, concurrency, rate limiting, retries, cache
│   │   └── store.py            # SQLite + JSONL export, run metadata, labels
│   ├── vulnerabilities/        # one module per vulnerability; static data in data/
│   ├── attacks/
│   │   ├── single_turn/
│   │   └── multi_turn/         # crescendo.py, tap.py, pair.py, goat.py, scripted.py, custom.py
│   ├── converters/
│   ├── targets/                # http.py, callable.py, openai_compat.py, agent.py
│   ├── scorers/                # heuristic/, classifier/, llm/, composite.py, cascade.py
│   ├── evaluate/               # thresholds, bootstrap CI, z-score, severity, gates
│   ├── report/                 # html (jinja + inline assets), junit, sarif, summary
│   ├── diff/                   # run-to-run comparison, flake detection
│   ├── frameworks/             # owasp_llm.py, owasp_agentic.py, mitre_atlas.py, nist.py → preset expansion
│   └── data/
│       ├── seeds/              # static payloads by vulnerability
│       ├── templates/          # jailbreak templates, attacker system prompts, judge prompts
│       ├── calibration/        # bag.json (μ/σ per vuln×attack per model)
│       └── scorer_eval/        # human-labeled attempts for scorer calibration
├── tests/
│   ├── unit/
│   ├── integration/            # against a deterministic fake target with known weaknesses
│   └── fixtures/vulnerable_app/  # tiny FastAPI app with planted bugs (BOLA, prompt leak, XSS) — also the demo
├── examples/
│   ├── quickstart/
│   ├── ci-github-action/
│   └── agent-with-tools/
├── .github/workflows/          # ci.yml (unit+integration), calibrate.yml (quarterly bag refresh)
└── docs/                       # mkdocs: concepts, writing a vulnerability, writing an attack, CI guide
```

Third-party plugins register via `entry_points` group `llm_vuln_scan.plugins` or a local `plugins/` directory; no fork needed.

---

## 9. Milestones

### v0.1 — Skeleton + static tier (weeks 1–3)
- Data models, plugin registry, config layering, async runner with token-bucket rate limit and disk cache.
- Targets: `callable`, `openai_compat`, `http` (templates, session parser, stateful/stateless).
- 8 vulnerabilities with static seeds: prompt injection (direct), system prompt leakage, PII direct, XSS/markdown exfil, SQLi/shell via output, package hallucination, toxicity, over-refusal (XSTest).
- Static attacks: direct, base64, rot13, leetspeak, homoglyph, jailbreak templates, injection framing.
- Scorers: substring, regex pack, local refusal classifier, cascade wrapper, `SelfAskTrueFalse`.
- SQLite store + JSONL export, `summary.json`, JUnit, exit codes, `lvscan run`.
- Fixture vulnerable app + integration tests that assert planted bugs are found.

### v0.2 — App-aware generation + report (weeks 4–6)
- `AppContext` → requirements → generated seeds (cached), `CustomVulnerability(criteria=)`, `policy`.
- Framework presets: `owasp:llm`, `mitre:atlas`, `nist`.
- HTML report with drill-down and reproduction commands; severity/issue levels; SARIF.
- `lvscan generate` writes committed suite; `lvscan run` replays it.

### v0.3 — Multi-turn + agentic (weeks 7–10)
- Multi-turn executors: crescendo (backtracking), TAP, PAIR, scripted, custom strategy text.
- `AgentTarget` with tool-call trace; `ToolCallScorer`; BOLA/BFLA/RBAC/SSRF/excessive agency/memory poisoning vulnerabilities; `owasp:agentic` preset.
- Response converters (decode before scoring), selective span conversion.

### v0.4 — Regression & CI (weeks 11–12)
- `lvscan diff`, flake re-run, `export-regressions`, `--fail-on-new`, baseline by tag.
- GitHub Action, example workflows, docs.

### v0.5 — Calibration & scorer quality (weeks 13–15)
- Scorer eval harness + labeled dataset; sensitivity/specificity → bootstrap CI in report.
- Calibration bag across ~15 models; `--show-z`; quarterly refresh workflow.
- CVSS-style score.

### Later
- Multimodal converters/targets (image/audio injection), RAG component attribution (RAGET), model-level probes (glitch tokens, adversarial suffixes), guardrail export (turn confirmed hits into input/output filters), web UI for triage.

---

## 10. Non-goals (for now)

- Not a general eval framework (no assertions on quality/latency beyond what a vulnerability needs). Use Promptfoo/DeepEval for that.
- No hosted service, no cloud generation. Bring your own attacker and judge models; ship enough static coverage that zero-LLM runs are still useful.
- No model training or fine-tuning of judges in-repo (we ship small off-the-shelf classifiers).
- No runtime guardrails (export is fine, enforcement is a different product).

---

## 11. Risks and mitigations

| Risk | Mitigation |
|---|---|
| LLM-judge false positives/negatives dominate signal (garak #1104, Promptfoo grading issues) | Cascade scoring, confidence field, scorer calibration dataset, `min_confidence` gate, heuristics first |
| Nondeterministic generation makes diffs noisy | Commit generated suites; replay by default; flake re-runs; `--fail-on-new` compares against baseline not absolute |
| Static payloads decay ("probe drift") | Tier field + calibration bag shows when a probe stops discriminating; quarterly refresh; dynamic tier for novelty |
| Attacker model refuses to generate attacks | Retry with rephrase (DeepTeam), document local uncensored options, static fallback for every vulnerability |
| Abstraction bloat (PyRIT) | Five nouns only: Vulnerability, Attack, Converter, Target, Scorer. Everything else is internal |
| Scope creep into eval/quality | Non-goals list; vulnerability must map to a framework tag to be accepted |
| Cost blowup on dynamic tier | Per-run budget (`max_tokens`, `max_attempts`), cost estimate before run, cache by content hash |

---

## 12. Decisions to confirm

1. **Python only** (all four Python tools are the reference; Promptfoo is TS but its ideas port cleanly). Node users get the GitHub Action and the HTTP target.
2. **SQLite + JSONL** as the only store in v0.x. Postgres later if a team-triage UI appears.
3. **Judge default**: any OpenAI-compatible endpoint at temperature 0; no vendor default baked in.
4. **License**: Apache-2.0 (matches garak, Promptfoo, PyRIT; Giskard is Apache too).
