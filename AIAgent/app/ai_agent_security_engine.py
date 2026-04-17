"""Backward-compat shim — delegates to modular aiagentsec_evaluators + orchestrator."""

# Orchestrator
from app.aiagentsec_orchestrator import run_ai_agent_security_assessment  # noqa: F401

# Scoring
from app.aiagentsec_evaluators.scoring import compute_agent_security_scores  # noqa: F401

# A. Copilot Studio
from app.aiagentsec_evaluators.copilot_studio import (  # noqa: F401
    analyze_cs_authentication, analyze_cs_data_connectors,
    analyze_cs_logging, analyze_cs_channels,
)
# A-ext. Copilot Studio Extended
from app.aiagentsec_evaluators.copilot_studio_ext import (  # noqa: F401
    analyze_cs_knowledge_sources, analyze_cs_generative_ai,
    analyze_cs_governance, analyze_cs_connector_security,
)
# A-ext. Copilot Studio DLP Deep Dive
from app.aiagentsec_evaluators.copilot_studio_dlp import (  # noqa: F401
    analyze_cs_dlp_depth, analyze_cs_environment_governance,
    analyze_cs_agent_security_advanced, analyze_cs_audit_compliance,
    analyze_cs_dataverse_security, analyze_cs_readiness_crosscheck,
)
# B. Microsoft Foundry Infrastructure
from app.aiagentsec_evaluators.foundry_infra import (  # noqa: F401
    analyze_foundry_network, analyze_foundry_identity,
    analyze_foundry_content_safety, analyze_foundry_deployments,
    analyze_foundry_governance,
)
# B-ext. Microsoft Foundry Extended
from app.aiagentsec_evaluators.foundry_ext import (  # noqa: F401
    analyze_foundry_compute, analyze_foundry_datastores,
    analyze_foundry_endpoints, analyze_foundry_registry,
    analyze_foundry_connections, analyze_foundry_serverless,
    analyze_foundry_ws_diagnostics,
)
# B-new. Microsoft Foundry New Categories
from app.aiagentsec_evaluators.foundry_new import (  # noqa: F401
    analyze_foundry_prompt_shields, analyze_foundry_model_catalog,
    analyze_foundry_data_exfiltration, analyze_foundry_agent_identity,
    analyze_foundry_agent_application, analyze_foundry_mcp_tools,
    analyze_foundry_tool_security, analyze_foundry_guardrails,
    analyze_foundry_hosted_agents, analyze_foundry_data_resources,
    analyze_foundry_observability, analyze_foundry_lifecycle,
)
# C. Custom Agent Security
from app.aiagentsec_evaluators.custom_ai import (  # noqa: F401
    analyze_custom_api_security, analyze_custom_data_residency,
    analyze_custom_content_leakage,
)
# D. Entra AI Identity
from app.aiagentsec_evaluators.entra_ai import (  # noqa: F401
    analyze_entra_ai_service_principals, analyze_entra_ai_conditional_access,
    analyze_entra_ai_consent, analyze_entra_ai_workload_identity,
    analyze_entra_ai_cross_tenant, analyze_entra_ai_privileged_access,
)
# E. AI Infrastructure Security
from app.aiagentsec_evaluators.ai_infra import (  # noqa: F401
    analyze_ai_diagnostics, analyze_ai_model_governance,
    analyze_ai_threat_protection, analyze_ai_data_governance,
)
# F. Agent Orchestration & Platform Security
from app.aiagentsec_evaluators.ai_defense import (  # noqa: F401
    analyze_ai_defender_coverage, analyze_ai_policy_compliance,
    analyze_agent_communication, analyze_agent_governance,
)
