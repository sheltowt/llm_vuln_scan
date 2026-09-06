"""The runner: execute a plan against a target, producing Attempt records.

Concurrency is bounded by a semaphore; every target call is rate-limited and
retried by the target itself. A budget can cap attempts or tokens so a dynamic
run cannot blow up unattended.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..scorers.base import Scorer
from ..scorers.composite import _as_scorer
from .config import ScanConfig
from .context import AppContext
from .models import Attempt, Outcome
from .planner import Plan, PlanItem, build_plan
from .plugin import build, get
from .store import RunStore


@dataclass
class RunResult:
    run_id: str
    attempts: list[Attempt] = field(default_factory=list)
    store_dir: str = ""
    skipped: int = 0
    errors: int = 0
    cache_hits: int = 0
    judge_calls: int = 0
    target_calls: int = 0
    tokens: int = 0
    stopped_early: bool = False


ProgressFn = Callable[[Attempt, int, int], None]


class Runner:
    def __init__(self, config: ScanConfig, target: Any, ctx: AppContext,
                 store: RunStore | None = None, plan: Plan | None = None) -> None:
        self.config = config
        self.target = target
        self.ctx = ctx
        self.store = store
        self._plan = plan
        self._scorer_cache: dict[tuple[str, str], Scorer] = {}
        self._budget_attempts = config.run.budget.max_attempts
        self._budget_tokens = config.run.budget.max_tokens
        self._stop = False

    def _scorer_for(self, item: PlanItem) -> Scorer:
        key = (item.seed.vulnerability, item.seed.vuln_type)
        if key in self._scorer_cache:
            return self._scorer_cache[key]
        vparams: dict[str, Any] = {}
        if item.seed.source == "generated" and item.seed.vulnerability == "package_hallucination":
            vparams = {}
        try:
            vuln = build("vulnerability", item.seed.vulnerability, **vparams)
            scorer = vuln.scorer_for(item.seed.vuln_type, self.ctx)
        except Exception:
            scorer = _as_scorer("compliance")
        self._scorer_cache[key] = scorer
        return scorer

    def _objective_scorer(self, item: PlanItem, scorer: Scorer) -> Scorer:
        """Multi-turn attacks want a graded objective to climb.

        If a judge is available, use a scale scorer as the in-loop signal;
        otherwise fall back to the vulnerability's own scorer.
        """

        attack_cls = get("attack", item.attack)
        # Adaptive attacks need a graded objective to climb. Use the scale scorer
        # when a judge is available; gate on the judge because that scorer needs
        # it, and the attack itself is already gated on the attacker in supports().
        if getattr(attack_cls, "multi_turn", False) and self.ctx.has_judge:
            return _as_scorer({"name": "self_ask_scale", "threshold": 0.7})
        return scorer

    async def _run_item(self, item: PlanItem, generation: int) -> Attempt:
        attack = build("attack", item.attack, **item.attack_params)
        scorer = self._scorer_for(item)
        attempt = Attempt(
            run_id=self.run_id,
            vulnerability=item.seed.vulnerability,
            vuln_type=item.seed.vuln_type,
            attack=item.attack,
            seed_id=item.seed.id,
            generation=generation,
            tier=item.tier,
            severity=item.severity,
            tags=item.tags,
            goal=item.seed.goal,
            seed_prompt=item.seed.prompt,
            labels=dict(self.config.run.labels),
        )
        started = time.perf_counter()
        try:
            supported, reason = attack.supports(self.target, self.ctx)
            if not supported:
                attempt.outcome = Outcome.SKIPPED
                attempt.error = reason
                return attempt

            objective = self._objective_scorer(item, scorer)
            result = await attack.run(item.seed, self.target, objective, self.ctx)
            attempt.prompt = result.prompt
            attempt.converters = result.converters
            attempt.conversation = result.conversation
            attempt.turns = result.turns
            attempt.identifiers = {
                "attack": attack.identifier,
                "scorer": scorer.identifier,
                "target": getattr(self.target, "identifier", ""),
                **{f"converter:{n}": v for n, v in _converter_ids(result).items()},
            }
            final = await scorer.score(attempt, item.seed, self.ctx)
            attempt.scores = [final]
            # Fold in-loop objective scores in as evidence, not as deciders.
            for loop_score in result.in_loop_scores:
                if loop_score.scorer != final.scorer:
                    attempt.scores.append(loop_score)
        except Exception as exc:  # noqa: BLE001 - one bad attempt must not kill the run
            attempt.error = f"{type(exc).__name__}: {exc}"
        finally:
            attempt.duration_ms = int((time.perf_counter() - started) * 1000)
            attempt.tokens = sum(
                int(m.metadata.get("tokens", 0) or 0) for m in attempt.conversation.messages
            )
        attempt.finalize(min_confidence=self.config.scoring.min_confidence)
        return attempt

    async def run(self, progress: ProgressFn | None = None) -> RunResult:
        from ..core.models import new_id

        self.run_id = self.store.run_id if self.store else new_id("run_")
        plan = self._plan if self._plan is not None else build_plan(self.config, self.ctx)
        total = len(plan.items) * plan.generations
        result = RunResult(run_id=self.run_id, store_dir=str(self.store.dir) if self.store else "")

        concurrency = max(1, self.config.run.concurrency)
        done = 0
        lock = asyncio.Lock()

        # A bounded worker pool draining one shared queue, rather than one task
        # per work item. A committed suite can hold tens of thousands of items;
        # materializing a task apiece wastes memory for no added parallelism,
        # since the pool size already caps how many run at once.
        queue: asyncio.Queue[tuple[PlanItem, int]] = asyncio.Queue()
        for gen in range(plan.generations):
            for item in plan.items:
                queue.put_nowait((item, gen))

        async def record(attempt: Attempt) -> None:
            nonlocal done
            async with lock:
                done += 1
                result.attempts.append(attempt)
                if attempt.outcome in (Outcome.SKIPPED, Outcome.INCONCLUSIVE):
                    result.skipped += 1
                elif attempt.outcome is Outcome.ERROR:
                    result.errors += 1
                result.tokens += attempt.tokens
                if self.store:
                    self.store.add(attempt)
                if progress:
                    progress(attempt, done, total)
                if self._budget_attempts and done >= self._budget_attempts:
                    self._stop = True
                    result.stopped_early = True
                if self._budget_tokens and result.tokens >= self._budget_tokens:
                    self._stop = True
                    result.stopped_early = True

        async def worker() -> None:
            while not self._stop:
                try:
                    item, generation = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    attempt = await self._run_item(item, generation)
                    await record(attempt)
                finally:
                    queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(min(concurrency, max(1, total)))]
        if workers:
            await asyncio.gather(*workers)

        result.target_calls = getattr(self.target, "total_calls", 0)
        result.tokens = max(result.tokens, getattr(self.target, "total_tokens", 0))
        if self.ctx.judge is not None:
            result.judge_calls = getattr(self.ctx.judge, "calls", 0)
        # Include generation so a multi-generation run has a stable, reproducible
        # order instead of falling back to (nondeterministic) completion order.
        result.attempts.sort(
            key=lambda a: (a.vulnerability, a.vuln_type, a.attack, a.seed_id, a.generation)
        )
        return result


def _converter_ids(result: Any) -> dict[str, str]:
    return {}
