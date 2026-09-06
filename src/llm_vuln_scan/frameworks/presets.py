"""Framework presets: expand a name like ``owasp:llm`` into a vulnerability set.

Presets are derived from the tags each vulnerability declares, so a new
vulnerability joins the right presets by tagging itself, with no central list to
keep in sync. This is also where the MITRE ATLAS mapping garak lacks lives.
"""

from __future__ import annotations

from ..core.plugin import all_of

# Explicit ordering for the OWASP LLM Top 10 (2025), so reports read in order.
OWASP_LLM_TITLES = {
    "01": "Prompt Injection",
    "02": "Sensitive Information Disclosure",
    "03": "Supply Chain",
    "04": "Data and Model Poisoning",
    "05": "Improper Output Handling",
    "06": "Excessive Agency",
    "07": "System Prompt Leakage",
    "08": "Vector and Embedding Weaknesses",
    "09": "Misinformation",
    "10": "Unbounded Consumption",
}

OWASP_AGENTIC_TITLES = {
    "goal_hijacking": "Goal Manipulation",
    "tool_misuse": "Tool Misuse",
    "privilege_compromise": "Privilege Compromise",
    "memory_poisoning": "Memory Poisoning",
    "identity_spoofing": "Identity Spoofing",
    "cascading_failure": "Cascading Failures",
}

# Named bundles that are not a single tag prefix.
STATIC_BUNDLES = {
    "default": None,   # resolved specially: tier-1 vulnerabilities
    "full": None,      # resolved specially: everything
}


def _tag_matches(tag: str, wanted: str) -> bool:
    return tag == wanted or tag.startswith(wanted + ":") or tag.startswith(wanted + ".")


def _vulns_with_tag(prefix: str) -> list[str]:
    out = []
    for name, cls in all_of("vulnerability").items():
        if any(_tag_matches(t, prefix) for t in getattr(cls, "tags", [])):
            out.append(name)
    return sorted(out)


def expand(preset: str) -> list[str]:
    """Expand one preset name to a sorted list of vulnerability names."""

    preset = preset.strip().lower()
    vulns = all_of("vulnerability")

    if preset in ("all", "full"):
        return sorted(vulns)
    if preset == "default":
        return sorted(
            n for n, c in vulns.items() if getattr(c, "tier", 1) == 1
        )
    if preset.startswith("owasp:llm:"):
        return _vulns_with_tag(preset)
    if preset == "owasp:llm":
        return _vulns_with_tag("owasp:llm")
    if preset in ("owasp:agentic", "owasp:agent"):
        return _vulns_with_tag("owasp:agentic")
    if preset.startswith("owasp:agentic:"):
        return _vulns_with_tag(preset)
    if preset.startswith("mitre:atlas"):
        return _vulns_with_tag("mitre:atlas")
    if preset.startswith("nist"):
        return _vulns_with_tag("nist")
    if preset in ("gdpr",):
        return _vulns_with_tag("gdpr")
    # Fall back to treating the preset as a raw tag prefix.
    matches = _vulns_with_tag(preset)
    if matches:
        return matches
    raise ValueError(f"unknown preset or tag: {preset!r}")


def framework_map(tags: list[str]) -> dict[str, list[str]]:
    """Group a set of tags by framework, for the compliance section of a report."""

    grouped: dict[str, list[str]] = {}
    for tag in tags:
        family = tag.split(":", 1)[0] if ":" in tag else "other"
        grouped.setdefault(family, [])
        if tag not in grouped[family]:
            grouped[family].append(tag)
    return {k: sorted(v) for k, v in sorted(grouped.items())}
