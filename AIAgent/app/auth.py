"""Backward-compatibility shim — real implementation in app.core.auth."""
from app.core.auth import *  # noqa: F401,F403
from app.core.auth import _request_creds  # noqa: F401  (private but used by api/agent)
