"""AI Agent Security orchestrator — runs all evaluators and builds the final assessment result."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from app.auth import ComplianceCredentials
# A. Copilot Studio
from app.aiagentsec_evaluators.copilot_studio import (
    analyze_cs_authentication, analyze_cs_data_connectors,
    analyze_cs_logging, analyze_cs_channels,
)
# A-ext. Copilot Studio Extended
from app.aiagentsec_evaluators.copilot_studio_ext import (
    analyze_cs_knowledge_sources, analyze_cs_generative_ai,
    analyze_cs_governance, analyze_cs_connector_security,
)
# A-ext. Copilot Studio DLP Deep Dive
from app.aiagentsec_evaluators.copilot_studio_dlp import (
    analyze_cs_dlp_depth, analyze_cs_environment_governance,
    analyze_cs_agent_security_advanced, analyze_cs_audit_compliance,
    analyze_cs_dataverse_security, analyze_cs_readiness_crosscheck,
)
# B. Microsoft Foundry Infrastructure
from app.aiagentsec_evaluators.foundry_infra import (
    analyze_foundry_network, analyze_foundry_identity,
    analyze_foundry_content_safety, analyze_foundry_deployments,
    analyze_foundry_governance,
)
# B-ext. Microsoft Foundry Extended
from app.aiagentsec_evaluators.foundry_ext import (
    analyze_foundry_compute, analyze_foundry_datastores,
    analyze_foundry_endpoints, analyze_foundry_registry,
    analyze_foundry_connections, analyze_foundry_serverless,
    analyze_foundry_ws_diagnostics,
)
# B-new. Microsoft Foundry New Categories
from app.aiagentsec_evaluators.foundry_new import (
    analyze_foundry_prompt_shields, analyze_foundry_model_catalog,
    analyze_foundry_data_exfiltration, analyze_foundry_agent_identity,
    analyze_foundry_agent_application, analyze_foundry_mcp_tools,
    analyze_foundry_tool_security, analyze_foundry_guardrails,
    analyze_foundry_hosted_agents, analyze_foundry_data_resources,
    analyze_foundry_observability, analyze_foundry_lifecycle,
)
# C. Custom Agent Security
from app.aiagentsec_evaluators.custom_ai import (
    analyze_custom_api_security, analyze_custom_data_residency,
    analyze_custom_content_leakage,
)
# D. Entra AI Identity
from app.aiagentsec_evaluators.entra_ai import (
    analyze_entra_ai_service_principals, analyze_entra_ai_conditional_access,
    analyze_entra_ai_consent, analyze_entra_ai_workload_identity,
    analyze_entra_ai_cross_tenant, analyze_entra_ai_privileged_access,
)
# E. AI Infrastructure Security
from app.aiagentsec_evaluators.ai_infra import (
    analyze_ai_diagnostics, analyze_ai_model_governance,
    analyze_ai_threat_protection, analyze_ai_data_governance,
)
# F. Agent Orchestration & Platform Security
from app.aiagentsec_evaluators.ai_defense import (
    analyze_ai_defender_coverage, analyze_ai_policy_compliance,
    analyze_agent_communication, analyze_agent_governance,
)
from app.aiagentsec_evaluators.scoring import compute_agent_security_scores
from app.aiagentsec_evaluators.enrichment import enrich_compliance_mapping
from app.aiagentsec_evaluators.collector import _as_collect

log = logging.getLogger(__name__)


async def run_ai_agent_security_assessment(
    creds: ComplianceCredentials,
    evidence: list[dict] | None = None,
    subscriptions: list[dict] | None = None,
) -> dict:
    """Run complete AI agent security assessment."""
    if subscriptions is None:
        subscriptions = await creds.list_subscriptions()

    evidence_index: dict[str, list[dict]] = {}
    if evidence:
        for ev in evidence:
            etype = ev.get("EvidenceType", ev.get("evidence_type", ""))
            if etype:
                evidence_index.setdefault(etype, []).append(ev)

    has_evidence = bool(evidence_index)
    if not has_evidence:
        log.info("No existing evidence — running targeted collection for AI agent security")
        evidence_index = await _as_collect(creds, subscriptions)

    # A. Copilot Studio Agents
    log.info("Running Copilot Studio authentication analysis …")
    cs_auth_findings = analyze_cs_authentication(evidence_index)
    log.info("Running Copilot Studio data connector analysis …")
    cs_connector_findings = analyze_cs_data_connectors(evidence_index)
    log.info("Running Copilot Studio logging analysis …")
    cs_logging_findings = analyze_cs_logging(evidence_index)
    log.info("Running Copilot Studio channel analysis …")
    cs_channel_findings = analyze_cs_channels(evidence_index)
    log.info("Running Copilot Studio knowledge source analysis …")
    cs_knowledge_findings = analyze_cs_knowledge_sources(evidence_index)
    log.info("Running Copilot Studio generative AI analysis …")
    cs_gen_ai_findings = analyze_cs_generative_ai(evidence_index)
    log.info("Running Copilot Studio governance analysis …")
    cs_gov_findings = analyze_cs_governance(evidence_index)
    log.info("Running Copilot Studio connector security analysis …")
    cs_connector_sec_findings = analyze_cs_connector_security(evidence_index)

    # A-ext. Copilot Studio Deep Dive
    log.info("Running Copilot Studio DLP depth analysis …")
    cs_dlp_depth_findings = analyze_cs_dlp_depth(evidence_index)
    log.info("Running Copilot Studio environment governance analysis …")
    cs_env_gov_findings = analyze_cs_environment_governance(evidence_index)
    log.info("Running Copilot Studio agent advanced security analysis …")
    cs_agent_adv_findings = analyze_cs_agent_security_advanced(evidence_index)
    log.info("Running Copilot Studio audit & compliance analysis …")
    cs_audit_comp_findings = analyze_cs_audit_compliance(evidence_index)
    log.info("Running Copilot Studio Dataverse security analysis …")
    cs_dv_sec_findings = analyze_cs_dataverse_security(evidence_index)
    log.info("Running Copilot Studio readiness cross-check analysis …")
    cs_readiness_xcheck_findings = analyze_cs_readiness_crosscheck(evidence_index)

    # B. Microsoft Foundry / AI Services
    log.info("Running Foundry network isolation analysis …")
    foundry_network_findings = analyze_foundry_network(evidence_index)
    log.info("Running Foundry identity analysis …")
    foundry_identity_findings = analyze_foundry_identity(evidence_index)
    log.info("Running Foundry content safety analysis …")
    foundry_safety_findings = analyze_foundry_content_safety(evidence_index)
    log.info("Running Foundry deployment security analysis …")
    foundry_deploy_findings = analyze_foundry_deployments(evidence_index)
    log.info("Running Foundry governance analysis …")
    foundry_gov_findings = analyze_foundry_governance(evidence_index)
    log.info("Running Foundry compute security analysis …")
    foundry_compute_findings = analyze_foundry_compute(evidence_index)
    log.info("Running Foundry datastore security analysis …")
    foundry_datastore_findings = analyze_foundry_datastores(evidence_index)
    log.info("Running Foundry endpoint security analysis …")
    foundry_endpoint_findings = analyze_foundry_endpoints(evidence_index)
    log.info("Running Foundry registry security analysis …")
    foundry_registry_findings = analyze_foundry_registry(evidence_index)
    log.info("Running Foundry connection security analysis …")
    foundry_connection_findings = analyze_foundry_connections(evidence_index)
    log.info("Running Foundry serverless endpoint analysis …")
    foundry_serverless_findings = analyze_foundry_serverless(evidence_index)
    log.info("Running Foundry workspace diagnostics analysis …")
    foundry_ws_diag_findings = analyze_foundry_ws_diagnostics(evidence_index)
    log.info("Running Foundry prompt shield analysis …")
    foundry_prompt_shield_findings = analyze_foundry_prompt_shields(evidence_index)
    log.info("Running Foundry model catalog analysis …")
    foundry_model_catalog_findings = analyze_foundry_model_catalog(evidence_index)
    log.info("Running Foundry data exfiltration analysis …")
    foundry_data_exfil_findings = analyze_foundry_data_exfiltration(evidence_index)
    log.info("Running Foundry agent identity analysis …")
    foundry_agent_identity_findings = analyze_foundry_agent_identity(evidence_index)
    log.info("Running Foundry agent application analysis …")
    foundry_agent_app_findings = analyze_foundry_agent_application(evidence_index)
    log.info("Running Foundry MCP tool security analysis …")
    foundry_mcp_findings = analyze_foundry_mcp_tools(evidence_index)
    log.info("Running Foundry tool connection security analysis …")
    foundry_tool_findings = analyze_foundry_tool_security(evidence_index)
    log.info("Running Foundry guardrails analysis …")
    foundry_guardrail_findings = analyze_foundry_guardrails(evidence_index)
    log.info("Running Foundry hosted agent security analysis …")
    foundry_hosted_findings = analyze_foundry_hosted_agents(evidence_index)
    log.info("Running Foundry data resources analysis …")
    foundry_data_findings = analyze_foundry_data_resources(evidence_index)
    log.info("Running Foundry observability analysis …")
    foundry_obs_findings = analyze_foundry_observability(evidence_index)
    log.info("Running Foundry lifecycle governance analysis …")
    foundry_lifecycle_findings = analyze_foundry_lifecycle(evidence_index)

    # C. Custom Agent Security
    log.info("Running custom agent API security analysis …")
    custom_api_findings = analyze_custom_api_security(evidence_index)
    log.info("Running custom agent data residency analysis …")
    custom_residency_findings = analyze_custom_data_residency(evidence_index)
    log.info("Running custom agent content leakage analysis …")
    custom_leakage_findings = analyze_custom_content_leakage(evidence_index)

    # D. Entra Identity Security for AI
    log.info("Running Entra AI service principal analysis …")
    entra_sp_findings = analyze_entra_ai_service_principals(evidence_index)
    log.info("Running Entra AI Conditional Access analysis …")
    entra_ca_findings = analyze_entra_ai_conditional_access(evidence_index)
    log.info("Running Entra AI consent grants analysis …")
    entra_consent_findings = analyze_entra_ai_consent(evidence_index)
    log.info("Running Entra AI workload identity analysis …")
    entra_wif_findings = analyze_entra_ai_workload_identity(evidence_index)
    log.info("Running Entra AI cross-tenant access analysis …")
    entra_ct_findings = analyze_entra_ai_cross_tenant(evidence_index)
    log.info("Running Entra AI privileged access analysis …")
    entra_pa_findings = analyze_entra_ai_privileged_access(evidence_index)

    # E. AI Infrastructure Security
    log.info("Running AI diagnostics analysis …")
    ai_diag_findings = analyze_ai_diagnostics(evidence_index)
    log.info("Running AI model governance analysis …")
    ai_model_gov_findings = analyze_ai_model_governance(evidence_index)
    log.info("Running AI threat protection analysis …")
    ai_threat_findings = analyze_ai_threat_protection(evidence_index)
    log.info("Running AI data governance analysis …")
    ai_data_gov_findings = analyze_ai_data_governance(evidence_index)

    # F. Agent Orchestration & Platform Security
    log.info("Running Defender for AI analysis …")
    ai_defender_findings = analyze_ai_defender_coverage(evidence_index)
    log.info("Running Azure Policy for AI analysis …")
    ai_policy_findings = analyze_ai_policy_compliance(evidence_index)
    log.info("Running agent communication security analysis …")
    agent_comm_findings = analyze_agent_communication(evidence_index)
    log.info("Running agent governance analysis …")
    agent_gov_findings = analyze_agent_governance(evidence_index)

    all_findings = (
        cs_auth_findings + cs_connector_findings + cs_logging_findings
        + cs_channel_findings + cs_knowledge_findings + cs_gen_ai_findings
        + cs_gov_findings + cs_connector_sec_findings
        + cs_dlp_depth_findings + cs_env_gov_findings + cs_agent_adv_findings
        + cs_audit_comp_findings + cs_dv_sec_findings + cs_readiness_xcheck_findings
        + foundry_network_findings + foundry_identity_findings
        + foundry_safety_findings + foundry_deploy_findings + foundry_gov_findings
        + foundry_compute_findings + foundry_datastore_findings
        + foundry_endpoint_findings + foundry_registry_findings
        + foundry_connection_findings + foundry_serverless_findings
        + foundry_ws_diag_findings
        + foundry_prompt_shield_findings + foundry_model_catalog_findings
        + foundry_data_exfil_findings
        + foundry_agent_identity_findings + foundry_agent_app_findings
        + foundry_mcp_findings + foundry_tool_findings
        + foundry_guardrail_findings + foundry_hosted_findings
        + foundry_data_findings + foundry_obs_findings
        + foundry_lifecycle_findings
        + custom_api_findings + custom_residency_findings + custom_leakage_findings
        + entra_sp_findings + entra_ca_findings + entra_consent_findings
        + entra_wif_findings + entra_ct_findings + entra_pa_findings
        + ai_diag_findings + ai_model_gov_findings + ai_threat_findings
        + ai_data_gov_findings
        + ai_defender_findings + ai_policy_findings
        + agent_comm_findings + agent_gov_findings
    )

    enrich_compliance_mapping(all_findings)
    log.info("Computing AI agent security scores (%d findings) …", len(all_findings))
    scores = compute_agent_security_scores(all_findings)

    # Build per-platform evidence summary for report transparency
    evidence_summary: dict[str, dict] = {}
    foundry_summaries = evidence_index.get("foundry-config-summary", [])
    if foundry_summaries:
        fs = (foundry_summaries[0].get("Data") or foundry_summaries[0].get("data", {}))
        evidence_summary["foundry"] = {
            "AIServices": fs.get("TotalAIServices", 0),
            "OpenAIAccounts": fs.get("OpenAIAccounts", 0),
            "Workspaces": fs.get("AIWorkspaces", 0),
            "Deployments": fs.get("OpenAIDeployments", 0),
            "ContentFilters": fs.get("ContentFilterPolicies", 0),
            "Compute": fs.get("ComputeInstances", 0),
            "Datastores": fs.get("Datastores", 0),
            "Endpoints": fs.get("Endpoints", 0),
            "Registries": fs.get("Registries", 0),
            "Connections": fs.get("Connections", 0),
            "Serverless": fs.get("ServerlessEndpoints", 0),
            "FoundryProjects_New": fs.get("FoundryProjectsNew", 0),
            "AgentApplications": fs.get("AgentApplications", 0),
            "AgentDeployments": fs.get("AgentDeployments", 0),
            "CapabilityHosts": fs.get("CapabilityHosts", 0),
            "AccessDeniedErrors": fs.get("AccessDeniedErrors", 0),
        }

    return {
        "AssessmentId": str(uuid.uuid4()),
        "AssessmentType": "AIAgentSecurity",
        "AssessedAt": datetime.now(timezone.utc).isoformat(),
        "SubscriptionCount": len(subscriptions),
        "EvidenceSource": "existing_assessment" if has_evidence else "targeted_collection",
        "EvidenceSummary": evidence_summary,
        "AgentSecurityScores": scores,
        "Findings": all_findings,
        "FindingCount": len(all_findings),
        "Categories": {
            "cs_authentication": cs_auth_findings,
            "cs_data_connectors": cs_connector_findings,
            "cs_logging": cs_logging_findings,
            "cs_channels": cs_channel_findings,
            "cs_knowledge_sources": cs_knowledge_findings,
            "cs_generative_ai": cs_gen_ai_findings,
            "cs_governance": cs_gov_findings,
            "cs_connector_security": cs_connector_sec_findings,
            "cs_dlp_depth": cs_dlp_depth_findings,
            "cs_environment_governance": cs_env_gov_findings,
            "cs_agent_security_advanced": cs_agent_adv_findings,
            "cs_audit_compliance": cs_audit_comp_findings,
            "cs_dataverse_security": cs_dv_sec_findings,
            "cs_readiness_crosscheck": cs_readiness_xcheck_findings,
            "foundry_network": foundry_network_findings,
            "foundry_identity": foundry_identity_findings,
            "foundry_content_safety": foundry_safety_findings,
            "foundry_deployments": foundry_deploy_findings,
            "foundry_governance": foundry_gov_findings,
            "foundry_compute": foundry_compute_findings,
            "foundry_datastores": foundry_datastore_findings,
            "foundry_endpoints": foundry_endpoint_findings,
            "foundry_registry": foundry_registry_findings,
            "foundry_connections": foundry_connection_findings,
            "foundry_serverless": foundry_serverless_findings,
            "foundry_ws_diagnostics": foundry_ws_diag_findings,
            "foundry_prompt_shields": foundry_prompt_shield_findings,
            "foundry_model_catalog": foundry_model_catalog_findings,
            "foundry_data_exfiltration": foundry_data_exfil_findings,
            "foundry_agent_identity": foundry_agent_identity_findings,
            "foundry_agent_application": foundry_agent_app_findings,
            "foundry_mcp_tools": foundry_mcp_findings,
            "foundry_tool_security": foundry_tool_findings,
            "foundry_guardrails": foundry_guardrail_findings,
            "foundry_hosted_agents": foundry_hosted_findings,
            "foundry_data_resources": foundry_data_findings,
            "foundry_observability": foundry_obs_findings,
            "foundry_lifecycle": foundry_lifecycle_findings,
            "custom_api_security": custom_api_findings,
            "custom_data_residency": custom_residency_findings,
            "custom_content_leakage": custom_leakage_findings,
            "entra_ai_service_principals": entra_sp_findings,
            "entra_ai_conditional_access": entra_ca_findings,
            "entra_ai_consent": entra_consent_findings,
            "entra_ai_workload_identity": entra_wif_findings,
            "entra_ai_cross_tenant": entra_ct_findings,
            "entra_ai_privileged_access": entra_pa_findings,
            "ai_diagnostics": ai_diag_findings,
            "ai_model_governance": ai_model_gov_findings,
            "ai_threat_protection": ai_threat_findings,
            "ai_data_governance": ai_data_gov_findings,
            "ai_defender_coverage": ai_defender_findings,
            "ai_policy_compliance": ai_policy_findings,
            "agent_communication": agent_comm_findings,
            "agent_governance": agent_gov_findings,
        },
        "CategoryCounts": {
            "cs_authentication": len(cs_auth_findings),
            "cs_data_connectors": len(cs_connector_findings),
            "cs_logging": len(cs_logging_findings),
            "cs_channels": len(cs_channel_findings),
            "cs_knowledge_sources": len(cs_knowledge_findings),
            "cs_generative_ai": len(cs_gen_ai_findings),
            "cs_governance": len(cs_gov_findings),
            "cs_connector_security": len(cs_connector_sec_findings),
            "cs_dlp_depth": len(cs_dlp_depth_findings),
            "cs_environment_governance": len(cs_env_gov_findings),
            "cs_agent_security_advanced": len(cs_agent_adv_findings),
            "cs_audit_compliance": len(cs_audit_comp_findings),
            "cs_dataverse_security": len(cs_dv_sec_findings),
            "cs_readiness_crosscheck": len(cs_readiness_xcheck_findings),
            "foundry_network": len(foundry_network_findings),
            "foundry_identity": len(foundry_identity_findings),
            "foundry_content_safety": len(foundry_safety_findings),
            "foundry_deployments": len(foundry_deploy_findings),
            "foundry_governance": len(foundry_gov_findings),
            "foundry_compute": len(foundry_compute_findings),
            "foundry_datastores": len(foundry_datastore_findings),
            "foundry_endpoints": len(foundry_endpoint_findings),
            "foundry_registry": len(foundry_registry_findings),
            "foundry_connections": len(foundry_connection_findings),
            "foundry_serverless": len(foundry_serverless_findings),
            "foundry_ws_diagnostics": len(foundry_ws_diag_findings),
            "foundry_prompt_shields": len(foundry_prompt_shield_findings),
            "foundry_model_catalog": len(foundry_model_catalog_findings),
            "foundry_data_exfiltration": len(foundry_data_exfil_findings),
            "foundry_agent_identity": len(foundry_agent_identity_findings),
            "foundry_agent_application": len(foundry_agent_app_findings),
            "foundry_mcp_tools": len(foundry_mcp_findings),
            "foundry_tool_security": len(foundry_tool_findings),
            "foundry_guardrails": len(foundry_guardrail_findings),
            "foundry_hosted_agents": len(foundry_hosted_findings),
            "foundry_data_resources": len(foundry_data_findings),
            "foundry_observability": len(foundry_obs_findings),
            "foundry_lifecycle": len(foundry_lifecycle_findings),
            "custom_api_security": len(custom_api_findings),
            "custom_data_residency": len(custom_residency_findings),
            "custom_content_leakage": len(custom_leakage_findings),
            "entra_ai_service_principals": len(entra_sp_findings),
            "entra_ai_conditional_access": len(entra_ca_findings),
            "entra_ai_consent": len(entra_consent_findings),
            "entra_ai_workload_identity": len(entra_wif_findings),
            "entra_ai_cross_tenant": len(entra_ct_findings),
            "entra_ai_privileged_access": len(entra_pa_findings),
            "ai_diagnostics": len(ai_diag_findings),
            "ai_model_governance": len(ai_model_gov_findings),
            "ai_threat_protection": len(ai_threat_findings),
            "ai_data_governance": len(ai_data_gov_findings),
            "ai_defender_coverage": len(ai_defender_findings),
            "ai_policy_compliance": len(ai_policy_findings),
            "agent_communication": len(agent_comm_findings),
            "agent_governance": len(agent_gov_findings),
        },
    }
