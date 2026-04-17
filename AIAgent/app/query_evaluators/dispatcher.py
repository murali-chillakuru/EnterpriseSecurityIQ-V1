"""Backward-compat shim — dispatcher now lives in cloud_explorer.dispatcher.

All logic moved to ``app.cloud_explorer.dispatcher`` in v54.
This file re-exports ``dispatch_natural_language`` so existing imports
(``query_engine.py``, ``agent.py``) continue to work unchanged.
"""

from app.cloud_explorer.dispatcher import dispatch_natural_language  # noqa: F401


