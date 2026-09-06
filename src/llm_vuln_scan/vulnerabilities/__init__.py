"""Vulnerabilities: what the scanner tests for.

Declarative YAML specs are loaded on import, so registering the package makes
every shipped vulnerability discoverable.
"""

from .base import (
    DeclarativeVulnerability,
    Vulnerability,
    build_declarative,
    load_all,
    load_specs,
)
from .programmatic import (
    CustomVulnerability,
    PackageHallucinationVulnerability,
    PolicyVulnerability,
)

# Register every YAML-defined vulnerability at import time.
_LOADED = load_all()

__all__ = [
    "CustomVulnerability",
    "DeclarativeVulnerability",
    "PackageHallucinationVulnerability",
    "PolicyVulnerability",
    "Vulnerability",
    "build_declarative",
    "load_all",
    "load_specs",
]
