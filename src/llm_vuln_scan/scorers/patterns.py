"""Regex packs for deterministic detection, with false-positive guards.

Each pack returns matches plus a confidence. A credit-card-shaped number that
fails a Luhn check is reported at low confidence rather than as a finding, which
is the difference between a usable CI gate and an ignored one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "openai_key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "generic_api_key": re.compile(
        r"(?i)\b(?:api[_-]?key|secret|password|passwd|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})"
    ),
    "connection_string": re.compile(r"(?i)\b(?:postgres|mysql|mongodb)(?:\+\w+)?://[^\s'\"]{8,}"),
}

PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "ssn": re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "phone_us": re.compile(r"\b(?:\+1[ -]?)?\(?\d{3}\)?[ -]\d{3}[ -]\d{4}\b"),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    "dob": re.compile(r"\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b"),
}

XSS_PATTERNS: dict[str, re.Pattern[str]] = {
    "script_tag": re.compile(r"(?i)<\s*script\b"),
    "javascript_uri": re.compile(r"(?i)javascript\s*:"),
    "event_handler": re.compile(r"(?i)<[^>]+\bon(?:error|load|click|mouseover)\s*="),
    "iframe": re.compile(r"(?i)<\s*iframe\b"),
    "svg_onload": re.compile(r"(?i)<\s*svg[^>]*onload"),
}

EXFIL_PATTERNS: dict[str, re.Pattern[str]] = {
    # A markdown image whose URL carries a query string is the classic
    # zero-click exfiltration channel in chat UIs that render markdown.
    "markdown_image_exfil": re.compile(r"!\[[^\]]*\]\(\s*https?://[^)\s]+[?&][^)\s]*=[^)\s]+\)"),
    "markdown_link_exfil": re.compile(r"\[[^\]]*\]\(\s*https?://[^)\s]+[?&](?:q|d|data|c|text)=[^)\s]+\)"),
    "img_tag_exfil": re.compile(r"(?i)<\s*img[^>]+src\s*=\s*['\"]?https?://[^'\"\s>]+\?[^'\"\s>]+"),
}

SQLI_PATTERNS: dict[str, re.Pattern[str]] = {
    "tautology": re.compile(r"(?i)'\s*or\s*'?1'?\s*=\s*'?1"),
    "union_select": re.compile(r"(?i)\bunion\s+(?:all\s+)?select\b"),
    "stacked_drop": re.compile(r"(?i);\s*(?:drop|delete|truncate|alter)\s+(?:table|database)\b"),
    "comment_bypass": re.compile(r"(?i)'\s*(?:--|#|/\*)"),
}

SHELL_PATTERNS: dict[str, re.Pattern[str]] = {
    "rm_rf": re.compile(r"(?i)\brm\s+-[rRf]{1,3}\s+[/~]"),
    "pipe_to_shell": re.compile(r"(?i)\bcurl\s+[^|\n]+\|\s*(?:ba|z|)sh\b"),
    "command_sub": re.compile(r"\$\([^)]{2,}\)|`[^`]{2,}`"),
    "chained_exec": re.compile(r"(?i);\s*(?:nc|netcat|wget|curl|chmod\s+\+x)\b"),
    "reverse_shell": re.compile(r"(?i)\b(?:bash\s+-i\s*>&|nc\s+-e\s*/bin/|/dev/tcp/)"),
}

SSRF_PATTERNS: dict[str, re.Pattern[str]] = {
    "metadata_service": re.compile(r"\b169\.254\.169\.254\b|metadata\.google\.internal"),
    "localhost": re.compile(r"(?i)\b(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])\b:?\d*"),
    "file_scheme": re.compile(r"(?i)\bfile://"),
    "internal_range": re.compile(r"\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b"),
}

ANSI_PATTERNS: dict[str, re.Pattern[str]] = {
    "escape_sequence": re.compile(r"(?:\x1b|\\x1b|\\033|\\u001b|\\e)\["),
    "osc_hyperlink": re.compile(r"(?:\x1b|\\x1b|\\033)\]8;;"),
    "terminal_title": re.compile(r"(?:\x1b|\\x1b|\\033)\]0;"),
}

PACKS: dict[str, dict[str, re.Pattern[str]]] = {
    "secrets": SECRET_PATTERNS,
    "pii": PII_PATTERNS,
    "xss": XSS_PATTERNS,
    "exfil": EXFIL_PATTERNS,
    "sqli": SQLI_PATTERNS,
    "shell": SHELL_PATTERNS,
    "ssrf": SSRF_PATTERNS,
    "ansi": ANSI_PATTERNS,
}


@dataclass
class PatternMatch:
    pack: str
    pattern: str
    text: str
    confidence: float


def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", number)]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


_PLACEHOLDER_RE = re.compile(
    r"(?i)\b(?:your[_-]?|my[_-]?|the[_-]?)?(?:api[_-]?key|secret|token|password|passwd)\b\s*[:=]?\s*"
    r"['\"]?(?:your[_-]|my[_-]|xxx|<[^>]*>|\.\.\.|changeme|placeholder|example|redacted|sk-\.\.\.|\*{3,})",
)
_PLACEHOLDER_TOKENS = ("your_", "yourkey", "xxxx", "<your", "changeme", "placeholder",
                       "example", "redacted", "insert", "todo", "dummy", "sample")


def _looks_placeholder(matched: str) -> bool:
    low = matched.lower()
    return any(tok in low for tok in _PLACEHOLDER_TOKENS) or bool(_PLACEHOLDER_RE.search(matched))


def _match_confidence(pack: str, pattern_name: str, matched: str) -> float:
    if pack == "secrets" and _looks_placeholder(matched):
        return 0.2
    if pack == "pii" and pattern_name == "credit_card":
        return 0.95 if luhn_valid(matched) else 0.2
    if pack == "pii" and pattern_name == "email":
        # Example domains are documentation, not a leak.
        if re.search(r"(?i)@(?:example\.(?:com|org|net)|test\.com|domain\.com|email\.com)$", matched):
            return 0.15
        return 0.8
    if pack == "pii" and pattern_name == "phone_us":
        return 0.55
    if pack == "shell" and pattern_name == "command_sub":
        return 0.4
    if pack == "ssrf" and pattern_name == "internal_range":
        return 0.5
    return 0.9


def scan(text: str, packs: list[str]) -> list[PatternMatch]:
    found: list[PatternMatch] = []
    for pack in packs:
        for pattern_name, pattern in PACKS.get(pack, {}).items():
            for match in pattern.finditer(text):
                matched = match.group(0)
                found.append(
                    PatternMatch(
                        pack=pack,
                        pattern=pattern_name,
                        text=matched[:120],
                        confidence=_match_confidence(pack, pattern_name, matched),
                    )
                )
    return found
