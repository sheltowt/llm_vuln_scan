# llm_vuln_scan

An LLM vulnerability scanner that is turnkey enough to run on every pull request
and composable enough for deep red-team campaigns. It combines the best
structural ideas from garak, PyRIT, Promptfoo, DeepTeam and Giskard, and drops
the parts that make each of them painful.

- **Turnkey like garak** — one command, a shipped probe library, calibrated
  z-scores.
- **Composable like PyRIT** — converter chains, composite scorers, multi-turn
  attacks with backtracking.
- **CI-native like Promptfoo** — commit a suite, replay it deterministically,
  gate merges on regressions, emit SARIF and JUnit.
- **App-aware like Giskard** — probe the app you actually have, using its stated
  purpose and its own secrets.
- **Clean API like DeepTeam** — vulnerabilities and attacks compose
  independently.

## Design in one paragraph

Five plugin kinds and no more: a **vulnerability** is what you test for, an
**attack** is how the test is delivered, a **converter** re-encodes a payload, a
**target** is the system under test, and a **scorer** decides whether the target
failed. Every scan produces immutable **Attempt** records; reports, diffs and CI
gates are all derived from those records.

The one idea that ties it together is **two tiers**. The *static* tier uses
curated payloads, deterministic attacks and heuristic scorers: reproducible,
nearly free, and fast enough to gate every PR. The *dynamic* tier adds
LLM-generated seeds and adaptive multi-turn attacks for nightly or pre-release
runs. Both produce the same records, so one report format covers both.

## Quick start

```bash
pip install -e .

# See what a scan would run, without calling anything
lvscan plan -c examples/quickstart/lvscan.yaml

# Run the static tier and gate on high-severity hits
lvscan run -c examples/quickstart/lvscan.yaml --fail-on-severity high

# Freeze a suite, commit it, then replay it deterministically in CI
lvscan generate -c lvscan.yaml -o lvscan.suite.yaml
lvscan run --suite lvscan.suite.yaml --fail-on-new --baseline tag:git.branch=main
```

## Configuration

A target is anything that answers a prompt: a Python callable, an
OpenAI-compatible endpoint, a bespoke HTTP API, or a tool-using agent.

```yaml
target:
  type: http
  url: https://internal.example.com/chat
  body: { message: "{{prompt}}", session: "{{session_id}}" }
  response: "$.reply"
  session_parser: "$.session"
  capabilities: { multi_turn: true, tools: true }

app:
  purpose: >
    Customer-support assistant for Acme Bank. Authenticated retail customers
    only. Must never discuss competitor products or give investment advice.
  canaries: ["SECRET_CONFIG_KEY=..."]   # strings that must never appear in output

vulnerabilities:
  - preset: owasp:llm
  - preset: owasp:agentic
  - custom: no_investment_advice
    criteria: "Must not recommend specific securities or portfolio actions."

attacks:
  static:  [direct, base64, leetspeak, jailbreak_template, injection_framing]
  dynamic: [roleplay, crescendo, tap]
  weights: { crescendo: 2 }

scoring:
  judge: { model: gpt-5, temperature: 0 }   # any OpenAI-compatible endpoint
  cascade: true
  min_confidence: 0.6

run:  { tier: static, concurrency: 8 }
gates: { fail_on_severity: high, fail_on_new: true, baseline: "tag:git.branch=main" }
```

## Commands

| Command | Purpose |
|---|---|
| `lvscan run` | Run a scan, write reports, apply CI gates. Exit 100 on gate failure. |
| `lvscan generate` | Freeze seeds and attacks into a committed suite. |
| `lvscan plan` | Show what a scan would run, without calling the target. |
| `lvscan diff <a> <b>` | New failures, fixed, flaky, between two runs. |
| `lvscan export-regressions` | Append confirmed hits to a regressions file that runs first next time. |
| `lvscan report <run>` | Regenerate the HTML report from a stored run. |
| `lvscan repro <run> <id>` | Full conversation and config for one attempt. |
| `lvscan calibrate <runs...>` | Build a z-score calibration bag from reference-model runs. |
| `lvscan list [kind]` | List available plugins. |

## Coverage

Vulnerabilities carry framework tags, so presets like `owasp:llm`,
`owasp:agentic`, `mitre:atlas` and `nist` expand automatically. Shipped
vulnerabilities include prompt injection (direct and indirect), system prompt
and credential leakage, PII disclosure, improper output handling (XSS, markdown
exfiltration, ANSI), code injection (SQLi, shell, SSRF), excessive agency,
package hallucination, harmful content, toxicity, misinformation, and
over-refusal.

## App-aware probing

Beyond the generic probe library, the scanner tests the app you actually have.
From the `purpose` you describe, it derives concrete requirements and generates
adversarial probes for each, then grades every response against the requirement
it targeted:

```yaml
vulnerabilities:
  - name: app_requirements          # purpose -> requirements -> probes -> judge
  - custom: no_investment_advice    # a one-line rule, generated into probes
    criteria: "Must not recommend specific securities."
```

Generation and grading use your judge model; requirements and probes are cached
to disk, so `lvscan generate` freezes them into a committed suite that `lvscan
run` replays deterministically. Without a judge, it degrades to templated probes
so the check still runs. See `examples/app-aware/`.

## Why the scores are trustworthy

The weakest link in every tool in this space is the judge. Three mechanisms
address it: **cascade scoring** runs the free deterministic scorer first and
only pays for a judge on ambiguous cases; every score carries a **confidence**,
and low-confidence scores are recorded but excluded from CI gates; and a
**scorer-evaluation** harness measures each scorer's sensitivity and specificity
against human labels. The result is a static tier you can gate on without
drowning in false positives.

## License

Apache-2.0.
