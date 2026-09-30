"""RunStore persistence and run resolution."""

from pathlib import Path

import pytest

from llm_vuln_scan.core.models import Attempt, Conversation, Message, Outcome, Score
from llm_vuln_scan.core.store import RunStore, load_attempts, resolve_run


def _attempt(run_id: str, outcome: Outcome, seed: str) -> Attempt:
    passed = outcome is not Outcome.FAIL
    return Attempt(
        run_id=run_id,
        vulnerability="prompt_injection",
        vuln_type="direct",
        attack="direct",
        seed_id=seed,
        prompt="p",
        conversation=Conversation(messages=[Message.user("p"), Message.assistant("r")]),
        scores=[Score(scorer="s", value=0.0 if passed else 1.0, passed=passed)],
        outcome=outcome,
    )


def _write_run(output_dir: Path, run_id: str, labels: dict[str, str]) -> list[Attempt]:
    attempts = [_attempt(run_id, Outcome.FAIL, "a"), _attempt(run_id, Outcome.PASS, "b")]
    with RunStore(run_id, output_dir) as store:
        store.start_run(tier="static", target="t", config={}, labels=labels, tool_version="0")
        for a in attempts:
            store.add(a)
        store.finish_run()
    return attempts


def test_roundtrip_via_jsonl_sqlite_and_store(tmp_path: Path):
    written = _write_run(tmp_path, "run-1", {})
    run_dir = tmp_path / "run-1"

    from_dir = load_attempts(run_dir)
    from_sqlite = load_attempts(run_dir / "run.sqlite")
    assert [a.model_dump() for a in from_dir] == [a.model_dump() for a in written]
    assert [a.model_dump() for a in from_sqlite] == [a.model_dump() for a in written]

    hits = load_attempts(run_dir / "hits.jsonl")
    assert [a.seed_id for a in hits] == ["a"]

    with RunStore("run-1", tmp_path) as store:
        assert [a.id for a in store.attempts()] == [a.id for a in written]


def test_load_attempts_falls_back_to_sqlite(tmp_path: Path):
    _write_run(tmp_path, "run-1", {})
    (tmp_path / "run-1" / "attempts.jsonl").unlink()
    assert len(load_attempts(tmp_path / "run-1")) == 2

    (tmp_path / "run-1" / "run.sqlite").unlink()
    with pytest.raises(FileNotFoundError):
        load_attempts(tmp_path / "run-1")


def test_resolve_run_refs(tmp_path: Path):
    _write_run(tmp_path, "20260101-000000-aaaaaa", {"git.branch": "main"})
    _write_run(tmp_path, "20260102-000000-bbbbbb", {"git.branch": "feature"})

    assert resolve_run("latest", tmp_path).name == "20260102-000000-bbbbbb"
    assert resolve_run("tag:git.branch=main", tmp_path).name == "20260101-000000-aaaaaa"
    assert resolve_run("20260101-000000-aaaaaa", tmp_path).name == "20260101-000000-aaaaaa"
    assert resolve_run(str(tmp_path / "20260101-000000-aaaaaa"), tmp_path).name == "20260101-000000-aaaaaa"
    with pytest.raises(FileNotFoundError):
        resolve_run("tag:git.branch=nope", tmp_path)
    with pytest.raises(FileNotFoundError):
        resolve_run("no-such-run", tmp_path)
    with pytest.raises(FileNotFoundError):
        resolve_run("latest", tmp_path / "empty")
