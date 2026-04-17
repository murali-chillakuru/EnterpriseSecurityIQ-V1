"""
Custom Controls / Plugin Loader
Loads user-defined evaluator plugins from a configurable directory.
Each plugin is a Python file exposing an `evaluate(control, evidence_index)` function
that returns a (status, findings) tuple.
"""

from __future__ import annotations
import importlib.util
import pathlib
from typing import Any, Callable
from app.logger import log


# Plugin signature: (control: dict, evidence_index: dict) -> (str, list[dict])
PluginFn = Callable[[dict, dict[str, list]], tuple[str, list[dict]]]


def load_plugins(plugin_dir: str = "plugins") -> dict[str, PluginFn]:
    """Scan *plugin_dir* for .py files and load their ``evaluate`` functions.

    Returns a dict keyed by plugin filename (stem) to the evaluate callable.
    Files without an ``evaluate`` function are silently skipped.
    """
    plugins: dict[str, PluginFn] = {}
    root = pathlib.Path(plugin_dir)
    if not root.is_dir():
        return plugins

    for py_file in sorted(root.glob("*.py")):
        name = py_file.stem
        if name.startswith("_"):
            continue
        try:
            spec = importlib.util.spec_from_file_location(f"plugin_{name}", py_file)
            if spec is None or spec.loader is None:
                continue
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
            fn = getattr(mod, "evaluate", None)
            if callable(fn):
                plugins[name] = fn
                log.info("Loaded custom evaluator plugin: %s", name)
            else:
                log.debug("Plugin %s has no evaluate() — skipped", name)
        except Exception as exc:
            log.warning("Failed to load plugin %s: %s", name, exc)

    return plugins


def run_plugins(
    plugins: dict[str, PluginFn],
    controls: list[dict],
    evidence_index: dict[str, list],
) -> list[dict[str, Any]]:
    """Execute each plugin against every control tagged with ``custom_evaluator``
    matching the plugin name.  Returns a flat list of result dicts.
    """
    results: list[dict[str, Any]] = []
    for ctrl in controls:
        evaluator_name = ctrl.get("custom_evaluator", "")
        if evaluator_name not in plugins:
            continue
        fn = plugins[evaluator_name]
        try:
            status, findings = fn(ctrl, evidence_index)
            results.append({
                "control_id": ctrl.get("control_id", ""),
                "status": status,
                "findings": findings,
                "evaluator": evaluator_name,
            })
        except Exception as exc:
            log.error("Plugin %s error on %s: %s",
                      evaluator_name, ctrl.get("control_id"), exc)
            results.append({
                "control_id": ctrl.get("control_id", ""),
                "status": "ERROR",
                "findings": [{"detail": str(exc)}],
                "evaluator": evaluator_name,
            })
    return results
