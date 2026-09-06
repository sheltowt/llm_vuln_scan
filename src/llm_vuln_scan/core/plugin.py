"""Plugin registry and discovery.

Five plugin kinds and no more: vulnerability, attack, converter, target, scorer.
Anything else is internal machinery. Third parties register through the
``llm_vuln_scan.plugins`` entry-point group or a local ``plugins/`` directory,
so nobody has to fork the package to add a probe.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import importlib.util
import pkgutil
from pathlib import Path
from typing import Any, ClassVar, TypeVar

from .models import content_hash

KINDS = ("vulnerability", "attack", "converter", "target", "scorer")

_REGISTRY: dict[str, dict[str, type]] = {k: {} for k in KINDS}
_DISCOVERED = False


class PluginError(RuntimeError):
    pass


class Plugin:
    """Base for every plugin.

    ``DEFAULT_PARAMS`` is merged with user config at construction, and the
    resolved result is content-addressed so reports can name exact configs.
    """

    kind: ClassVar[str] = ""
    name: ClassVar[str] = ""
    DEFAULT_PARAMS: ClassVar[dict[str, Any]] = {}

    def __init__(self, **params: Any) -> None:
        merged = {**self.DEFAULT_PARAMS, **{k: v for k, v in params.items() if v is not None}}
        self.params = merged
        for key, value in merged.items():
            class_attr = getattr(type(self), key, None)
            if isinstance(class_attr, property) or hasattr(class_attr, "__get__") and hasattr(class_attr, "__set__"):
                # never try to overwrite a property/descriptor (e.g. weight)
                continue
            if callable(getattr(self, key, None)):
                # never shadow a method with a param
                continue
            if value is None and hasattr(type(self), key):
                # a None default must not clobber a real class attribute
                continue
            setattr(self, key, value)

    @property
    def identifier(self) -> str:
        return content_hash({"kind": self.kind, "name": self.name, "params": self.params})

    def __repr__(self) -> str:
        return f"<{self.kind}:{self.name}>"


T = TypeVar("T", bound=type)


def register(kind: str, name: str):
    """Class decorator that adds a plugin to the registry."""

    if kind not in KINDS:
        raise PluginError(f"unknown plugin kind {kind!r}; expected one of {KINDS}")

    def wrap(cls: T) -> T:
        cls.kind = kind  # type: ignore[attr-defined]
        cls.name = name  # type: ignore[attr-defined]
        existing = _REGISTRY[kind].get(name)
        if existing is not None and existing is not cls:
            raise PluginError(f"duplicate {kind} plugin {name!r}")
        _REGISTRY[kind][name] = cls
        return cls

    return wrap


def _import_submodules(package: str) -> None:
    try:
        mod = importlib.import_module(package)
    except ModuleNotFoundError:
        return
    for _finder, sub, _ispkg in pkgutil.walk_packages(mod.__path__, prefix=f"{package}."):
        importlib.import_module(sub)


def discover(extra_dirs: list[str | Path] | None = None, force: bool = False) -> None:
    """Import every builtin plugin module, then entry points, then local dirs."""

    global _DISCOVERED
    if _DISCOVERED and not force and not extra_dirs:
        return
    for pkg in (
        "llm_vuln_scan.targets",
        "llm_vuln_scan.converters",
        "llm_vuln_scan.scorers",
        "llm_vuln_scan.attacks",
        "llm_vuln_scan.vulnerabilities",
    ):
        _import_submodules(pkg)

    try:
        eps = importlib.metadata.entry_points(group="llm_vuln_scan.plugins")
    except Exception:  # pragma: no cover - metadata backends vary
        eps = []
    for ep in eps:
        try:
            ep.load()
        except Exception as exc:  # pragma: no cover
            raise PluginError(f"failed loading plugin entry point {ep.name!r}: {exc}") from exc

    for d in list(extra_dirs or []) + [Path("plugins")]:
        path = Path(d)
        if not path.is_dir():
            continue
        for py in sorted(path.rglob("*.py")):
            if py.name.startswith("_"):
                continue
            spec = importlib.util.spec_from_file_location(f"lvscan_local_{py.stem}", py)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
    _DISCOVERED = True


def get(kind: str, name: str) -> type:
    discover()
    try:
        return _REGISTRY[kind][name]
    except KeyError:
        known = ", ".join(sorted(_REGISTRY.get(kind, {}))) or "none"
        raise PluginError(f"no {kind} named {name!r}. Available: {known}") from None


def build(kind: str, name: str, **params: Any) -> Any:
    return get(kind, name)(**params)


def all_of(kind: str) -> dict[str, type]:
    discover()
    return dict(_REGISTRY[kind])


def registry_snapshot() -> dict[str, list[str]]:
    discover()
    return {k: sorted(v) for k, v in _REGISTRY.items()}
