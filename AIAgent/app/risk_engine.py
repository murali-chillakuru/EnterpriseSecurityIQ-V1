"""
Risk Analysis Engine — backward-compatibility shim.

All evaluator logic has moved to `risk_evaluators/` and the orchestrator
to `risk_orchestrator.py`.  This module re-exports the public API so
existing imports (agent.py, CLI runners) continue to work.
"""
from app.risk_orchestrator import run_risk_analysis  # noqa: F401
from app.risk_evaluators.scoring import compute_risk_scores  # noqa: F401
from app.risk_evaluators.identity import analyze_identity_risk  # noqa: F401
from app.risk_evaluators.network import analyze_network_risk  # noqa: F401
from app.risk_evaluators.defender import analyze_defender_posture  # noqa: F401
from app.risk_evaluators.config_drift import analyze_config_drift  # noqa: F401
from app.risk_evaluators.insider_risk import analyze_insider_risk  # noqa: F401