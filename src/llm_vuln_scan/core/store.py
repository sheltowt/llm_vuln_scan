"""Run storage: SQLite for querying, JSONL for interchange.

One SQLite file per run, no server. ``attempts.jsonl`` and ``hits.jsonl`` are
written alongside and are the format the report, diff and export tools read.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import Attempt, Outcome, utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    tier TEXT,
    target TEXT,
    config TEXT,
    labels TEXT,
    tool_version TEXT
);
CREATE TABLE IF NOT EXISTS attempts (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    vulnerability TEXT,
    vuln_type TEXT,
    attack TEXT,
    seed_id TEXT,
    generation INTEGER,
    tier TEXT,
    severity TEXT,
    outcome TEXT,
    confidence REAL,
    prompt TEXT,
    output TEXT,
    duration_ms INTEGER,
    tokens INTEGER,
    turns INTEGER,
    error TEXT,
    json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_run ON attempts(run_id);
CREATE INDEX IF NOT EXISTS idx_attempts_vuln ON attempts(run_id, vulnerability);
CREATE INDEX IF NOT EXISTS idx_attempts_outcome ON attempts(run_id, outcome);
CREATE TABLE IF NOT EXISTS scores (
    attempt_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    scorer TEXT,
    value REAL,
    passed INTEGER,
    confidence REAL,
    category TEXT,
    cost TEXT,
    rationale TEXT
);
CREATE INDEX IF NOT EXISTS idx_scores_attempt ON scores(attempt_id);
"""


class RunStore:
    """Writes one run to ``<output_dir>/<run_id>/``."""

    def __init__(self, run_id: str, output_dir: str | Path = "lvscan_runs") -> None:
        self.run_id = run_id
        self.dir = Path(output_dir) / run_id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.dir / "run.sqlite"
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self._attempts_fh = (self.dir / "attempts.jsonl").open("a", encoding="utf-8")
        self._hits_fh = (self.dir / "hits.jsonl").open("a", encoding="utf-8")

    # -- lifecycle ---------------------------------------------------------
    def start_run(self, *, tier: str, target: str, config: dict[str, Any], labels: dict[str, str],
                  tool_version: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO runs (run_id, started_at, tier, target, config, labels, tool_version)"
            " VALUES (?,?,?,?,?,?,?)",
            (
                self.run_id,
                utcnow().isoformat(),
                tier,
                target,
                json.dumps(config, default=str),
                json.dumps(labels),
                tool_version,
            ),
        )
        self.conn.commit()

    def finish_run(self) -> None:
        self.conn.execute(
            "UPDATE runs SET finished_at=? WHERE run_id=?", (utcnow().isoformat(), self.run_id)
        )
        self.conn.commit()

    def close(self) -> None:
        for fh in (self._attempts_fh, self._hits_fh):
            try:
                fh.close()
            except Exception:  # pragma: no cover
                pass
        self.conn.close()

    def __enter__(self) -> RunStore:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- writes ------------------------------------------------------------
    def add(self, attempt: Attempt) -> None:
        payload = attempt.model_dump(mode="json")
        line = json.dumps(payload, default=str)
        self._attempts_fh.write(line + "\n")
        self._attempts_fh.flush()
        if attempt.outcome is Outcome.FAIL:
            self._hits_fh.write(line + "\n")
            self._hits_fh.flush()
        self.conn.execute(
            "INSERT OR REPLACE INTO attempts (id, run_id, vulnerability, vuln_type, attack, seed_id,"
            " generation, tier, severity, outcome, confidence, prompt, output, duration_ms, tokens,"
            " turns, error, json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                attempt.id,
                attempt.run_id,
                attempt.vulnerability,
                attempt.vuln_type,
                attempt.attack,
                attempt.seed_id,
                attempt.generation,
                attempt.tier.value,
                attempt.severity.value,
                attempt.outcome.value,
                attempt.confidence,
                attempt.prompt,
                attempt.output,
                attempt.duration_ms,
                attempt.tokens,
                attempt.turns,
                attempt.error,
                line,
            ),
        )
        self.conn.executemany(
            "INSERT INTO scores (attempt_id, run_id, scorer, value, passed, confidence, category,"
            " cost, rationale) VALUES (?,?,?,?,?,?,?,?,?)",
            [
                (
                    attempt.id,
                    attempt.run_id,
                    s.scorer,
                    s.value,
                    int(s.passed),
                    s.confidence,
                    s.category,
                    s.cost.value,
                    s.rationale,
                )
                for s in attempt.scores
            ],
        )
        self.conn.commit()

    def write_json(self, name: str, payload: Any) -> Path:
        path = self.dir / name
        path.write_text(json.dumps(payload, indent=2, default=_json_default))
        return path

    def write_text(self, name: str, text: str) -> Path:
        path = self.dir / name
        path.write_text(text, encoding="utf-8")
        return path

    # -- reads -------------------------------------------------------------
    def attempts(self) -> Iterator[Attempt]:
        for row in self.conn.execute(
            "SELECT json FROM attempts WHERE run_id=? ORDER BY rowid", (self.run_id,)
        ):
            yield Attempt.model_validate_json(row["json"])


def _json_default(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


def load_attempts(path: str | Path) -> list[Attempt]:
    """Load attempts from a run directory, an attempts.jsonl, or a sqlite file."""

    p = Path(path)
    if p.is_dir():
        jsonl = p / "attempts.jsonl"
        if jsonl.exists():
            return load_attempts(jsonl)
        db = p / "run.sqlite"
        if db.exists():
            return load_attempts(db)
        raise FileNotFoundError(f"no attempts.jsonl or run.sqlite under {p}")
    if p.suffix == ".sqlite":
        conn = sqlite3.connect(p)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute("SELECT json FROM attempts ORDER BY rowid").fetchall()
        finally:
            conn.close()
        return [Attempt.model_validate_json(r["json"]) for r in rows]
    out: list[Attempt] = []
    with p.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(Attempt.model_validate_json(line))
    return out


def find_runs(output_dir: str | Path = "lvscan_runs") -> list[Path]:
    base = Path(output_dir)
    if not base.is_dir():
        return []
    return sorted((d for d in base.iterdir() if d.is_dir()), key=lambda d: d.name)


def resolve_run(ref: str, output_dir: str | Path = "lvscan_runs") -> Path:
    """Resolve a run reference: a path, a run id, ``latest``, or ``tag:k=v``."""

    p = Path(ref)
    if p.exists():
        return p
    runs = find_runs(output_dir)
    if not runs:
        raise FileNotFoundError(f"no runs found under {output_dir}")
    if ref in ("latest", "-"):
        return runs[-1]
    if ref.startswith("tag:"):
        key, _, value = ref[4:].partition("=")
        for candidate in reversed(runs):
            db = candidate / "run.sqlite"
            if not db.exists():
                continue
            conn = sqlite3.connect(db)
            try:
                row = conn.execute("SELECT labels FROM runs LIMIT 1").fetchone()
            finally:
                conn.close()
            if row and json.loads(row[0] or "{}").get(key) == value:
                return candidate
        raise FileNotFoundError(f"no run matching {ref}")
    for candidate in runs:
        if candidate.name == ref:
            return candidate
    raise FileNotFoundError(f"no run matching {ref!r}")


def iter_hits(attempts: Iterable[Attempt]) -> Iterator[Attempt]:
    for a in attempts:
        if a.outcome is Outcome.FAIL:
            yield a
