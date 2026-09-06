"""Calibration bag and scorer evaluation.

A raw fail rate says how a target did. A z-score against a bag of reference
models says how *unusual* that is, which is what tells you whether a probe still
discriminates or has decayed into something every model passes. The bag is data,
refreshed on a schedule; this module only reads and applies it.
"""

from __future__ import annotations

import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any

from ..core.models import Attempt, Outcome

DEFAULT_BAG = Path(__file__).resolve().parent.parent / "data" / "calibration" / "bag.json"


def load_bag(path: str | Path = DEFAULT_BAG) -> dict[str, Any] | None:
    p = Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text())


def build_bag_from_runs(model_summaries: dict[str, dict[str, float]]) -> dict[str, Any]:
    """Turn per-model fail rates into per-vulnerability mean/std.

    ``model_summaries`` maps model name -> {vulnerability: fail_rate}. Kept
    simple on purpose: the quarterly CI job produces these and calls this.
    """

    by_vuln: dict[str, list[float]] = defaultdict(list)
    for _model, rates in model_summaries.items():
        for vuln, rate in rates.items():
            by_vuln[vuln].append(rate)
    vulnerabilities = {}
    for vuln, rates in by_vuln.items():
        mean = statistics.fmean(rates) if rates else 0.0
        std = statistics.pstdev(rates) if len(rates) > 1 else 0.0
        vulnerabilities[vuln] = {
            "mean_fail_rate": round(mean, 4),
            "std_fail_rate": round(std, 4),
            "n_models": len(rates),
        }
    return {"models": sorted(model_summaries), "vulnerabilities": vulnerabilities}


def fail_rates(attempts: list[Attempt]) -> dict[str, float]:
    by_vuln: dict[str, list[Attempt]] = defaultdict(list)
    for a in attempts:
        by_vuln[a.vulnerability].append(a)
    out = {}
    for vuln, group in by_vuln.items():
        scored = [a for a in group if a.outcome in (Outcome.PASS, Outcome.FAIL)]
        hits = sum(1 for a in scored if a.outcome is Outcome.FAIL)
        out[vuln] = hits / len(scored) if scored else 0.0
    return out


def evaluate_scorer(labeled: list[dict[str, Any]], predicted: list[bool]) -> dict[str, float]:
    """Sensitivity/specificity of a scorer against human labels.

    ``labeled`` items carry a boolean ``is_hit``; ``predicted`` is the scorer's
    call for each. Feeds the confidence interval the report shows on fail rates.
    """

    tp = fp = tn = fn = 0
    for item, pred in zip(labeled, predicted, strict=False):
        actual = bool(item.get("is_hit"))
        if pred and actual:
            tp += 1
        elif pred and not actual:
            fp += 1
        elif not pred and actual:
            fn += 1
        else:
            tn += 1
    sensitivity = tp / (tp + fn) if (tp + fn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    return {
        "sensitivity": round(sensitivity, 3),
        "specificity": round(specificity, 3),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "n": len(labeled),
    }
