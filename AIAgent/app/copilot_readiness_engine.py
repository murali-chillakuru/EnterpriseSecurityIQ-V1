"""Backward-compatibility shim — re-exports from modular copilot_evaluators / copilot_orchestrator.

All logic has moved to:
  app.copilot_evaluators.finding           — _cr_finding, _CR_FINDING_NS, _SEVERITY_WEIGHTS
  app.copilot_evaluators.oversharing       — analyze_oversharing_risk
  app.copilot_evaluators.labels            — analyze_label_coverage
  app.copilot_evaluators.dlp               — analyze_dlp_readiness
  app.copilot_evaluators.restricted_search — analyze_restricted_search
  app.copilot_evaluators.access_governance — analyze_access_governance
  app.copilot_evaluators.content_lifecycle — analyze_content_lifecycle
  app.copilot_evaluators.audit_monitoring  — analyze_audit_monitoring
  app.copilot_evaluators.copilot_security  — analyze_copilot_security
  app.copilot_evaluators.zero_trust        — analyze_zero_trust
  app.copilot_evaluators.shadow_ai         — analyze_shadow_ai
  app.copilot_evaluators.scoring           — compute_copilot_readiness_scores
  app.copilot_evaluators.controls_matrix   — build_security_controls_matrix
  app.copilot_evaluators.inventory         — _build_*_inventory
  app.copilot_evaluators.collector         — _cr_collect
  app.copilot_orchestrator                 — run_copilot_readiness_assessment
"""

from app.copilot_orchestrator import run_copilot_readiness_assessment  # noqa: F401
from app.copilot_evaluators.scoring import compute_copilot_readiness_scores  # noqa: F401
from app.copilot_evaluators.controls_matrix import build_security_controls_matrix  # noqa: F401