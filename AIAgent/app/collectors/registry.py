"""
Collector Plugin Registry
Auto-discovers and registers collector functions via a decorator pattern.
Drop a new collector file with @register_collector and it's automatically picked up.
"""

from __future__ import annotations
import importlib, pathlib, pkgutil
from typing import Any, Callable, Literal
from app.logger import log


# ── Global registry ──────────────────────────────────────────────────────

_REGISTRY: dict[str, dict[str, Any]] = {}


def register_collector(
    name: str,
    plane: Literal["control", "data"] = "control",
    source: Literal["azure", "entra"] = "azure",
    priority: int = 100,
):
    """Decorator that registers a collector function in the global registry.

    Usage::

        @register_collector(name="cosmos_db", plane="control", source="azure")
        async def collect_azure_cosmos(creds, subscriptions):
            ...

    Args:
        name:     Human-readable collector name (used for logging & checkpoint).
        plane:    'control' (ARM/management) or 'data' (per-resource data plane).
        source:   'azure' or 'entra'.
        priority: Lower = runs earlier.  Default 100.
    """

    def _decorator(fn: Callable) -> Callable:
        _REGISTRY[fn.__name__] = {
            "fn": fn,
            "name": name,
            "plane": plane,
            "source": source,
            "priority": priority,
        }
        return fn

    return _decorator


# ── Discovery helpers ────────────────────────────────────────────────────

def discover_collectors(package_path: str | pathlib.Path | None = None) -> None:
    """Import all modules under ``app.collectors.azure`` and ``app.collectors.entra``
    so that decorated collectors are registered.

    This is idempotent — safe to call multiple times.
    """
    base = pathlib.Path(__file__).parent
    for sub in ("azure", "entra"):
        pkg_dir = base / sub
        if not pkg_dir.is_dir():
            continue
        pkg_name = f"app.collectors.{sub}"
        for _importer, mod_name, _ispkg in pkgutil.iter_modules([str(pkg_dir)]):
            full = f"{pkg_name}.{mod_name}"
            try:
                importlib.import_module(full)
            except Exception as exc:  # pragma: no cover
                log.warning("Failed to import collector module %s: %s", full, exc)


def get_collectors(
    source: str | None = None,
    plane: str | None = None,
) -> list[dict[str, Any]]:
    """Return registered collectors, optionally filtered by source and/or plane.

    Each entry is ``{"fn": <callable>, "name": ..., "plane": ..., "source": ..., "priority": ...}``.
    Results are sorted by priority (ascending).
    """
    out = list(_REGISTRY.values())
    if source:
        out = [c for c in out if c["source"] == source]
    if plane:
        out = [c for c in out if c["plane"] == plane]
    return sorted(out, key=lambda c: c["priority"])


def get_collector_functions(source: str | None = None, plane: str | None = None) -> list[Callable]:
    """Convenience: return just the callable functions (sorted by priority)."""
    return [c["fn"] for c in get_collectors(source=source, plane=plane)]


def registered_names() -> list[str]:
    """Return the list of all registered collector function names."""
    return list(_REGISTRY.keys())
