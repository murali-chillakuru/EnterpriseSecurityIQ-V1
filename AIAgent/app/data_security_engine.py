"""
EnterpriseSecurityIQ — Data Security Assessment Engine  (v46 — modular).

Backward-compatible facade.  All real logic now lives in:
  - datasec_evaluators/   (domain evaluators)
  - datasec_frameworks/   (compliance framework JSON mappings)
  - datasec_reports/      (report generators)
  - datasec_orchestrator.py  (assessment orchestrator)

This file re-exports every public and private symbol so that existing
callers (agent.py, run_data_security.py, tests) continue to work
without any import changes.
"""
from __future__ import annotations

# ── Re-export finding helper & constants (private names preserved) ──────
from app.datasec_evaluators.finding import (
    ds_finding as _ds_finding,
    SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS,
    DS_FINDING_NS as _DS_FINDING_NS,
)

# ── Re-export evaluators ────────────────────────────────────────────────
from app.datasec_evaluators.storage import *  # noqa: F401,F403
from app.datasec_evaluators.database import *  # noqa: F401,F403
from app.datasec_evaluators.cosmosdb import *  # noqa: F401,F403
from app.datasec_evaluators.postgres_mysql import *  # noqa: F401,F403
from app.datasec_evaluators.keyvault import *  # noqa: F401,F403
from app.datasec_evaluators.encryption import *  # noqa: F401,F403
from app.datasec_evaluators.data_classification_tags import *  # noqa: F401,F403
from app.datasec_evaluators.data_access import *  # noqa: F401,F403
from app.datasec_evaluators.private_endpoints import *  # noqa: F401,F403
from app.datasec_evaluators.purview import *  # noqa: F401,F403
from app.datasec_evaluators.file_sync import *  # noqa: F401,F403
from app.datasec_evaluators.m365_dlp import *  # noqa: F401,F403
from app.datasec_evaluators.data_classification import *  # noqa: F401,F403
from app.datasec_evaluators.backup_dr import *  # noqa: F401,F403
from app.datasec_evaluators.containers import *  # noqa: F401,F403
from app.datasec_evaluators.network_segmentation import *  # noqa: F401,F403
from app.datasec_evaluators.data_residency import *  # noqa: F401,F403
from app.datasec_evaluators.threat_detection import *  # noqa: F401,F403
from app.datasec_evaluators.sharepoint import *  # noqa: F401,F403
from app.datasec_evaluators.m365_lifecycle import *  # noqa: F401,F403
from app.datasec_evaluators.dlp_alerts import *  # noqa: F401,F403
from app.datasec_evaluators.redis import *  # noqa: F401,F403
from app.datasec_evaluators.messaging import *  # noqa: F401,F403
from app.datasec_evaluators.ai_services import *  # noqa: F401,F403
from app.datasec_evaluators.data_factory import *  # noqa: F401,F403
from app.datasec_evaluators.managed_identity import *  # noqa: F401,F403
from app.datasec_evaluators.platform_services import *  # noqa: F401,F403
from app.datasec_evaluators.identity_access import *  # noqa: F401,F403
from app.datasec_evaluators.advanced_analytics import *  # noqa: F401,F403

# ── Re-export scoring & enrichment ──────────────────────────────────────
from app.datasec_evaluators.scoring import *  # noqa: F401,F403
from app.datasec_evaluators.enrichment import *  # noqa: F401,F403

# ── Re-export orchestrator ──────────────────────────────────────────────
from app.datasec_orchestrator import run_data_security_assessment  # noqa: F401
