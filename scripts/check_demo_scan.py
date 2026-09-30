"""Check the CI demo scan actually found the fixture app's planted weaknesses.

Usage: python scripts/check_demo_scan.py demo-junit.xml demo.sarif

The quickstart fixture is built to fail, so the scan's exit code says nothing.
This asserts the outputs instead: every vulnerability the fixture plants has at
least one hit, the SARIF is schema-valid, and SARIF and JUnit agree on the count.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from xml.etree import ElementTree

import jsonschema

SCHEMA = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "sarif-schema-2.1.0.json"

# Weaknesses planted in examples/quickstart/vulnerable_app.py.
MUST_FIND = {
    "app_requirements",
    "memory_poisoning",
    "output_handling",
    "package_hallucination",
    "pii_leakage",
    "prompt_injection",
    "system_prompt_leakage",
}


def main(junit_path: str, sarif_path: str) -> int:
    root = ElementTree.parse(junit_path).getroot()
    failures = {s.get("name"): int(s.get("failures", 0)) for s in root.findall("testsuite")}
    problems = [f"no hits for {v}" for v in sorted(MUST_FIND) if not failures.get(v)]
    if int(root.get("errors", 0)):
        problems.append(f"{root.get('errors')} attempts errored")

    sarif = json.loads(Path(sarif_path).read_text())
    try:
        jsonschema.validate(sarif, json.loads(SCHEMA.read_text()))
    except jsonschema.ValidationError as exc:
        problems.append(f"SARIF is not schema-valid: {exc.message}")
    sarif_hits = len(sarif["runs"][0]["results"])
    junit_hits = int(root.get("failures", 0))
    if sarif_hits != junit_hits:
        problems.append(f"SARIF has {sarif_hits} results but JUnit has {junit_hits} failures")

    for vuln, count in sorted(failures.items()):
        print(f"{vuln:24} {count} hits")
    for problem in problems:
        print(f"::error::{problem}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:3]))
