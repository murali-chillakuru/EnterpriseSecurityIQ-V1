"""
Tests for AI Agent Security Assessment Engine.

Covers:
  A. Copilot Studio Agents:
    - Authentication & Authorization (3 sub-checks)
    - Data Connector Security (2 sub-checks)
    - Conversation Logging (2 sub-checks)
    - Channel Security (2 sub-checks)
    - Knowledge Source Security (3 sub-checks)
    - Generative AI Controls (2 sub-checks)
    - Governance Controls (3 sub-checks)
    - Connector Security (3 sub-checks)
  B. Microsoft Foundry:
    - Network Isolation (3 sub-checks)
    - Managed Identity (2 sub-checks)
    - Content Safety Filters (2 sub-checks)
    - Deployment Security (3 sub-checks)
    - Workspace Governance (3 sub-checks)
    - Compute Security (4 sub-checks)
    - Datastore Security (2 sub-checks)
    - Endpoint Security (4 sub-checks)
    - Registry Security (2 sub-checks)
    - Connection Security (4 sub-checks)
    - Serverless Endpoints (3 sub-checks)
    - Workspace Diagnostics (2 sub-checks)
    - Prompt Shield Security (3 sub-checks)
    - Model Catalog Governance (2 sub-checks)
    - Data Exfiltration Prevention (3 sub-checks)
  C. Custom Agent Security:
    - API Key Management (1 sub-check)
    - Data Residency (1 sub-check)
    - Content Leakage (2 sub-checks)
  D. Entra Identity Security for AI:
    - AI Service Principals (4 sub-checks)
    - AI Conditional Access (2 sub-checks)
    - AI Consent Grants (2 sub-checks)
  E. AI Infrastructure Security:
    - AI Diagnostics (2 sub-checks)
    - AI Model Governance (3 sub-checks)
    - AI Threat Protection (4 sub-checks)
    - AI Data Governance (2 sub-checks)
  F. Agent Orchestration Security:
    - Defender for AI (2 sub-checks)
    - Azure Policy for AI (2 sub-checks)
    - Agent Communication (3 sub-checks)
    - Agent Governance (3 sub-checks)
  - Scoring algorithm
  - Finding structure
  - Agent tool registration
  - CLI parsability
  - Module imports
"""

from __future__ import annotations

import os
import sys
import unittest
from app.ai_agent_security_engine import (
    analyze_cs_dlp_depth, analyze_cs_environment_governance,
    analyze_cs_agent_security_advanced, analyze_cs_audit_compliance,
    analyze_cs_dataverse_security, analyze_cs_readiness_crosscheck,
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ====================================================================
# Helpers — build evidence records matching collector shapes
# ====================================================================

def _cs_bot_ev(data: dict) -> dict:
    return {"EvidenceType": "copilot-studio-bot", "Data": data, "ResourceId": data.get("BotId", "")}

def _cs_summary_ev(data: dict) -> dict:
    return {"EvidenceType": "copilot-studio-summary", "Data": data, "ResourceId": "tenant"}

def _pp_env_ev(data: dict) -> dict:
    return {"EvidenceType": "pp-environment", "Data": data, "ResourceId": data.get("EnvironmentId", "")}

def _pp_dlp_ev(data: dict) -> dict:
    return {"EvidenceType": "pp-dlp-policy", "Data": data, "ResourceId": data.get("id", "")}

def _audit_ev(data: dict) -> dict:
    return {"EvidenceType": "m365-audit-config", "Data": data, "ResourceId": "tenant"}

def _ai_service_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-ai-service", "Data": data, "ResourceId": data.get("AccountId", "")}

def _ai_workspace_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-ai-workspace", "Data": data, "ResourceId": data.get("WorkspaceId", "")}

def _ai_deployment_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-openai-deployment", "Data": data, "ResourceId": data.get("DeploymentId", "")}

def _ai_filter_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-openai-content-filter", "Data": data, "ResourceId": data.get("PolicyId", "")}

def _foundry_summary_ev(data: dict) -> dict:
    return {"EvidenceType": "foundry-config-summary", "Data": data, "ResourceId": "tenant"}

def _ai_compute_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-ai-compute", "Data": data, "ResourceId": data.get("ComputeId", "")}

def _ai_datastore_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-ai-datastore", "Data": data, "ResourceId": data.get("DatastoreId", "")}

def _ai_endpoint_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-ai-endpoint", "Data": data, "ResourceId": data.get("EndpointId", "")}

def _ai_registry_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-ai-registry", "Data": data, "ResourceId": data.get("RegistryId", "")}

def _ai_connection_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-ai-connection", "Data": data, "ResourceId": data.get("ConnectionId", "")}

def _ai_serverless_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-ai-serverless-endpoint", "Data": data, "ResourceId": data.get("EndpointId", "")}

def _ai_ws_diag_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-ai-workspace-diagnostics", "Data": data, "ResourceId": data.get("WorkspaceId", "")}

def _foundry_project_ev(data: dict) -> dict:
    return {"EvidenceType": "foundry-project", "Data": data, "ResourceId": data.get("ProjectId", "")}

def _foundry_agent_app_ev(data: dict) -> dict:
    return {"EvidenceType": "foundry-agent-application", "Data": data, "ResourceId": data.get("ApplicationId", "")}

def _foundry_capability_host_ev(data: dict) -> dict:
    return {"EvidenceType": "foundry-capability-host", "Data": data, "ResourceId": data.get("CapabilityHostId", "")}

def _foundry_agent_deploy_ev(data: dict) -> dict:
    return {"EvidenceType": "foundry-agent-deployment", "Data": data, "ResourceId": data.get("DeploymentId", "")}

def _entra_sp_ev(data: dict) -> dict:
    return {"EvidenceType": "entra-ai-service-principal", "Data": data, "ResourceId": data.get("AppId", "")}

def _entra_consent_ev(data: dict) -> dict:
    return {"EvidenceType": "entra-ai-consent-grant", "Data": data, "ResourceId": data.get("AppId", "")}

def _entra_ct_policy_ev(data: dict) -> dict:
    return {"EvidenceType": "entra-cross-tenant-policy", "Data": data, "ResourceId": "ct-policy"}

def _pp_custom_connector_ev(data: dict) -> dict:
    return {"EvidenceType": "pp-custom-connector", "Data": data, "ResourceId": data.get("ConnectorId", "")}

def _agent_config_ev(data: dict) -> dict:
    return {"EvidenceType": "agent-orchestration-config", "Data": data, "ResourceId": data.get("AgentId", "")}

def _defender_plan_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-defender-plan", "Data": data, "ResourceId": data.get("SubscriptionId", "")}

def _policy_assignment_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-policy-assignment", "Data": data, "ResourceId": data.get("PolicyAssignmentId", "")}

def _policy_compliance_ev(data: dict) -> dict:
    return {"EvidenceType": "azure-policy-compliance", "Data": data, "ResourceId": data.get("ResourceId", "")}

def _build_index(records: list[dict]) -> dict[str, list[dict]]:
    idx: dict[str, list[dict]] = {}
    for r in records:
        etype = r.get("EvidenceType", "")
        idx.setdefault(etype, []).append(r)
    return idx


# ====================================================================
# A1. Copilot Studio — Authentication
# ====================================================================

class TestCSAuthentication(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_cs_authentication
        self.analyze = analyze_cs_authentication

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_no_auth_detected(self):
        """RequiresAuthentication == False triggers no_auth_required."""
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-1", "DisplayName": "NoAuth Bot",
            "RequiresAuthentication": False,
            "EnvironmentName": "Default",
            "AuthMode": "None",
        })])
        findings = self.analyze(idx)
        no_auth = [f for f in findings if f["Subcategory"] == "no_auth_required"]
        self.assertGreater(len(no_auth), 0)
        self.assertEqual(no_auth[0]["Severity"], "critical")

    def test_non_aad_provider_detected(self):
        """AllowedAuthProviders with non-Azure/Microsoft entries triggers non_aad_auth."""
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-2", "DisplayName": "Google Bot",
            "RequiresAuthentication": True,
            "AllowedAuthProviders": ["google"],
            "EnvironmentName": "Dev",
        })])
        findings = self.analyze(idx)
        provider = [f for f in findings if f["Subcategory"] == "non_aad_auth"]
        self.assertGreater(len(provider), 0)

    def test_aad_auth_no_finding(self):
        """Azure AD auth provider should produce no auth findings."""
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-3", "DisplayName": "Secure Bot",
            "RequiresAuthentication": True,
            "AllowedAuthProviders": ["azureActiveDirectory"],
            "EnvironmentName": "Prod",
        })])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)

    def test_stale_auth_config_detected(self):
        """Bot with auth unchanged for >180 days triggers stale_auth_config."""
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-stale", "DisplayName": "Stale Bot",
            "RequiresAuthentication": True,
            "AllowedAuthProviders": ["azureActiveDirectory"],
            "ModifiedTime": "2025-01-01T00:00:00Z",
        })])
        findings = self.analyze(idx)
        stale = [f for f in findings if f["Subcategory"] == "stale_auth_config"]
        self.assertGreater(len(stale), 0)
        self.assertEqual(stale[0]["Severity"], "low")

    def test_recent_auth_config_no_stale_finding(self):
        """Bot modified recently should not trigger stale_auth_config."""
        from datetime import datetime, timezone
        recent = datetime.now(timezone.utc).isoformat()
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-fresh", "DisplayName": "Fresh Bot",
            "RequiresAuthentication": True,
            "AllowedAuthProviders": ["azureActiveDirectory"],
            "ModifiedTime": recent,
        })])
        findings = self.analyze(idx)
        stale = [f for f in findings if f["Subcategory"] == "stale_auth_config"]
        self.assertEqual(len(stale), 0)


# ====================================================================
# A2. Copilot Studio — Data Connectors
# ====================================================================

class TestCSDataConnectors(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_cs_data_connectors
        self.analyze = analyze_cs_data_connectors

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_no_dlp_policies_detected(self):
        """DLPPolicies == 0 in copilot-studio-summary triggers no_pp_dlp_policies."""
        idx = _build_index([_cs_summary_ev({
            "TotalBots": 5, "TotalEnvironments": 2, "DLPPolicies": 0,
        })])
        findings = self.analyze(idx)
        no_dlp = [f for f in findings if f["Subcategory"] == "no_pp_dlp_policies"]
        self.assertGreater(len(no_dlp), 0)

    def test_unmanaged_environments_detected(self):
        """IsManagedEnvironment == False triggers unmanaged_environments."""
        idx = _build_index([_pp_env_ev({
            "EnvironmentId": "env-1", "DisplayName": "Default",
            "IsManagedEnvironment": False,
            "HasSecurityGroup": True,
        })])
        findings = self.analyze(idx)
        env = [f for f in findings if f["Subcategory"] == "unmanaged_environments"]
        self.assertGreater(len(env), 0)

    def test_no_security_group_detected(self):
        """HasSecurityGroup == False triggers no_security_group."""
        idx = _build_index([_pp_env_ev({
            "EnvironmentId": "env-2", "DisplayName": "Open Env",
            "IsManagedEnvironment": True,
            "HasSecurityGroup": False,
        })])
        findings = self.analyze(idx)
        sg = [f for f in findings if f["Subcategory"] == "no_security_group"]
        self.assertGreater(len(sg), 0)

    def test_managed_env_with_sg_no_finding(self):
        idx = _build_index([_pp_env_ev({
            "EnvironmentId": "env-3", "DisplayName": "Production",
            "IsManagedEnvironment": True,
            "HasSecurityGroup": True,
        })])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)


# ====================================================================
# A3. Copilot Studio — Logging
# ====================================================================

class TestCSLogging(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_cs_logging
        self.analyze = analyze_cs_logging

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_logging_disabled_detected(self):
        """HasConversationLogging == False on bot triggers no_conversation_logging."""
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-nolog", "DisplayName": "Silent Bot",
            "HasConversationLogging": False,
            "EnvironmentName": "Default",
        })])
        findings = self.analyze(idx)
        logging_f = [f for f in findings if f["Subcategory"] == "no_conversation_logging"]
        self.assertGreater(len(logging_f), 0)

    def test_logging_enabled_no_finding(self):
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-log", "DisplayName": "Logged Bot",
            "HasConversationLogging": True,
            "EnvironmentName": "Prod",
        })])
        findings = self.analyze(idx)
        logging_f = [f for f in findings if f["Subcategory"] == "no_conversation_logging"]
        self.assertEqual(len(logging_f), 0)

    def test_environment_audit_disabled_detected(self):
        """Audit log not enabled triggers environment_audit_disabled."""
        idx = _build_index([_audit_ev({"UnifiedAuditLogEnabled": False})])
        findings = self.analyze(idx)
        audit = [f for f in findings if f["Subcategory"] == "environment_audit_disabled"]
        self.assertGreater(len(audit), 0)
        self.assertEqual(audit[0]["Severity"], "high")

    def test_environment_audit_unknown_detected(self):
        """Audit log status 'unknown' triggers environment_audit_disabled."""
        idx = _build_index([_audit_ev({"UnifiedAuditLogEnabled": "unknown"})])
        findings = self.analyze(idx)
        audit = [f for f in findings if f["Subcategory"] == "environment_audit_disabled"]
        self.assertGreater(len(audit), 0)

    def test_environment_audit_enabled_no_finding(self):
        """Audit log enabled produces no finding."""
        idx = _build_index([_audit_ev({"UnifiedAuditLogEnabled": True})])
        findings = self.analyze(idx)
        audit = [f for f in findings if f["Subcategory"] == "environment_audit_disabled"]
        self.assertEqual(len(audit), 0)


# ====================================================================
# A4. Copilot Studio — Channel Security
# ====================================================================

class TestCSChannels(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_cs_channels
        self.analyze = analyze_cs_channels

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_unauthenticated_web_channel_detected(self):
        """WebChannel == True and RequiresAuthentication == False triggers finding."""
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-web", "DisplayName": "Web Bot",
            "WebChannel": True,
            "RequiresAuthentication": False,
            "EnvironmentName": "Default",
        })])
        findings = self.analyze(idx)
        web = [f for f in findings if f["Subcategory"] == "unauthenticated_web_channel"]
        self.assertGreater(len(web), 0)
        self.assertEqual(web[0]["Severity"], "critical")

    def test_authenticated_web_channel_no_finding(self):
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-secure-web", "DisplayName": "Secure Web Bot",
            "WebChannel": True,
            "RequiresAuthentication": True,
            "EnvironmentName": "Prod",
        })])
        findings = self.analyze(idx)
        web = [f for f in findings if f["Subcategory"] == "unauthenticated_web_channel"]
        self.assertEqual(len(web), 0)

    def test_teams_channel_no_sso_detected(self):
        """Teams channel without SSO triggers teams_channel_no_sso."""
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-teams", "DisplayName": "Teams Bot",
            "TeamsChannel": True,
            "TeamsSSOEnabled": False,
        })])
        findings = self.analyze(idx)
        sso = [f for f in findings if f["Subcategory"] == "teams_channel_no_sso"]
        self.assertGreater(len(sso), 0)
        self.assertEqual(sso[0]["Severity"], "medium")

    def test_teams_channel_with_sso_no_finding(self):
        """Teams channel with SSO yields no finding."""
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-teams-sso", "DisplayName": "SSO Bot",
            "TeamsChannel": True,
            "TeamsSSOEnabled": True,
        })])
        findings = self.analyze(idx)
        sso = [f for f in findings if f["Subcategory"] == "teams_channel_no_sso"]
        self.assertEqual(len(sso), 0)


# ====================================================================
# B1. Foundry — Network Isolation
# ====================================================================

class TestFoundryNetwork(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_network
        self.analyze = analyze_foundry_network

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_public_access_detected(self):
        """PublicNetworkAccess == 'Enabled' triggers public_access_enabled."""
        idx = _build_index([_ai_service_ev({
            "AccountId": "acc-1", "Name": "myai",
            "PublicNetworkAccess": "Enabled",
            "Kind": "OpenAI", "IsOpenAI": True,
        })])
        findings = self.analyze(idx)
        public = [f for f in findings if f["Subcategory"] == "public_access_enabled"]
        self.assertGreater(len(public), 0)

    def test_no_private_endpoints_detected(self):
        """HasPrivateEndpoints == False triggers no_private_endpoints."""
        idx = _build_index([_ai_service_ev({
            "AccountId": "acc-2", "Name": "nope-ai",
            "PublicNetworkAccess": "Disabled",
            "HasPrivateEndpoints": False,
            "Kind": "OpenAI",
        })])
        findings = self.analyze(idx)
        pe = [f for f in findings if f["Subcategory"] == "no_private_endpoints"]
        self.assertGreater(len(pe), 0)

    def test_workspace_not_isolated_detected(self):
        """HasNetworkIsolation == False triggers workspace_no_isolation."""
        idx = _build_index([_ai_workspace_ev({
            "WorkspaceId": "ws-1", "Name": "open-ws",
            "HasNetworkIsolation": False,
            "IsolationMode": "None", "Kind": "Project",
        })])
        findings = self.analyze(idx)
        iso = [f for f in findings if f["Subcategory"] == "workspace_no_isolation"]
        self.assertGreater(len(iso), 0)

    def test_private_access_with_pe_no_finding(self):
        """Disabled public + private endpoints = no network findings."""
        idx = _build_index([_ai_service_ev({
            "AccountId": "acc-3", "Name": "secureai",
            "PublicNetworkAccess": "Disabled",
            "HasPrivateEndpoints": True,
            "Kind": "OpenAI",
        })])
        findings = self.analyze(idx)
        public = [f for f in findings if f["Subcategory"] == "public_access_enabled"]
        pe = [f for f in findings if f["Subcategory"] == "no_private_endpoints"]
        self.assertEqual(len(public), 0)
        self.assertEqual(len(pe), 0)


# ====================================================================
# B2. Foundry — Identity
# ====================================================================

class TestFoundryIdentity(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_identity
        self.analyze = analyze_foundry_identity

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_local_auth_enabled_detected(self):
        """DisableLocalAuth == False triggers local_auth_enabled."""
        idx = _build_index([_ai_service_ev({
            "AccountId": "acc-key", "Name": "keyai",
            "DisableLocalAuth": False,
            "Kind": "OpenAI",
        })])
        findings = self.analyze(idx)
        local = [f for f in findings if f["Subcategory"] == "local_auth_enabled"]
        self.assertGreater(len(local), 0)

    def test_no_managed_identity_detected(self):
        """HasManagedIdentity == False triggers workspace_no_managed_identity."""
        idx = _build_index([_ai_workspace_ev({
            "WorkspaceId": "ws-nomi", "Name": "nomi-ws",
            "HasManagedIdentity": False,
            "IdentityType": "None",
        })])
        findings = self.analyze(idx)
        mi = [f for f in findings if f["Subcategory"] == "workspace_no_managed_identity"]
        self.assertGreater(len(mi), 0)

    def test_local_auth_disabled_no_finding(self):
        idx = _build_index([_ai_service_ev({
            "AccountId": "acc-secure", "Name": "secureai",
            "DisableLocalAuth": True,
            "Kind": "OpenAI",
        })])
        findings = self.analyze(idx)
        local = [f for f in findings if f["Subcategory"] == "local_auth_enabled"]
        self.assertEqual(len(local), 0)


# ====================================================================
# B3. Foundry — Content Safety
# ====================================================================

class TestFoundryContentSafety(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_content_safety
        self.analyze = analyze_foundry_content_safety

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_no_content_filter_detected(self):
        """HasContentFilter == False triggers no_content_filter."""
        idx = _build_index([_ai_deployment_ev({
            "DeploymentId": "dep-1", "DeploymentName": "gpt4",
            "AccountName": "myai", "ModelName": "gpt-4",
            "HasContentFilter": False,
        })])
        findings = self.analyze(idx)
        no_filter = [f for f in findings if f["Subcategory"] == "no_content_filter"]
        self.assertGreater(len(no_filter), 0)
        self.assertEqual(no_filter[0]["Severity"], "critical")

    def test_weak_content_filter_detected(self):
        """AllFiltersBlocking == False with TotalFilters > 0 triggers weak_content_filters."""
        idx = _build_index([_ai_filter_ev({
            "PolicyId": "filter-1", "PolicyName": "lenient-policy",
            "AccountId": "acc-1",
            "AllFiltersBlocking": False,
            "TotalFilters": 4,
            "BlockingFilters": 1,
        })])
        findings = self.analyze(idx)
        weak = [f for f in findings if f["Subcategory"] == "weak_content_filters"]
        self.assertGreater(len(weak), 0)

    def test_deployment_with_filter_no_finding(self):
        idx = _build_index([_ai_deployment_ev({
            "DeploymentId": "dep-2", "DeploymentName": "gpt4",
            "AccountName": "myai", "ModelName": "gpt-4",
            "HasContentFilter": True,
        })])
        findings = self.analyze(idx)
        no_filter = [f for f in findings if f["Subcategory"] == "no_content_filter"]
        self.assertEqual(len(no_filter), 0)

    def test_all_filters_blocking_no_finding(self):
        idx = _build_index([_ai_filter_ev({
            "PolicyId": "filter-2", "PolicyName": "strict-policy",
            "AccountId": "acc-1",
            "AllFiltersBlocking": True,
            "TotalFilters": 4,
            "BlockingFilters": 4,
        })])
        findings = self.analyze(idx)
        weak = [f for f in findings if f["Subcategory"] == "weak_content_filters"]
        self.assertEqual(len(weak), 0)


# ====================================================================
# B4. Foundry — Deployment Security
# ====================================================================

class TestFoundryDeployments(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_deployments
        self.analyze = analyze_foundry_deployments

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_high_capacity_detected(self):
        """SkuCapacity > 100 triggers high_capacity_allocation."""
        idx = _build_index([_ai_deployment_ev({
            "DeploymentId": "dep-big", "DeploymentName": "gpt4-prod",
            "ModelName": "gpt-4", "SkuCapacity": 200,
        })])
        findings = self.analyze(idx)
        cap = [f for f in findings if f["Subcategory"] == "high_capacity_allocation"]
        self.assertGreater(len(cap), 0)

    def test_normal_capacity_no_finding(self):
        idx = _build_index([_ai_deployment_ev({
            "DeploymentId": "dep-norm", "DeploymentName": "gpt4-dev",
            "ModelName": "gpt-4", "SkuCapacity": 50,
        })])
        findings = self.analyze(idx)
        cap = [f for f in findings if f["Subcategory"] == "high_capacity_allocation"]
        self.assertEqual(len(cap), 0)


# ====================================================================
# B5. Foundry — Workspace Governance
# ====================================================================

class TestFoundryGovernance(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_governance
        self.analyze = analyze_foundry_governance

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_no_hub_detected(self):
        """Projects without hubs triggers no_hub_structure."""
        idx = _build_index([_ai_workspace_ev({
            "WorkspaceId": "ws-proj", "Name": "my-project",
            "IsProject": True, "IsHub": False,
        })])
        findings = self.analyze(idx)
        hub = [f for f in findings if f["Subcategory"] == "no_hub_structure"]
        self.assertGreater(len(hub), 0)

    def test_hub_with_projects_no_finding(self):
        idx = _build_index([
            _ai_workspace_ev({
                "WorkspaceId": "ws-hub", "Name": "my-hub",
                "IsHub": True, "IsProject": False,
            }),
            _ai_workspace_ev({
                "WorkspaceId": "ws-proj", "Name": "my-project",
                "IsProject": True, "IsHub": False,
            }),
        ])
        findings = self.analyze(idx)
        hub = [f for f in findings if f["Subcategory"] == "no_hub_structure"]
        self.assertEqual(len(hub), 0)


# ====================================================================
# C1. Custom Agent — API Key Security
# ====================================================================

class TestCustomAPISecurity(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_custom_api_security
        self.analyze = analyze_custom_api_security

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_api_key_exposed_detected(self):
        """DisableLocalAuth == False AND HasPrivateEndpoints == False triggers finding."""
        idx = _build_index([_ai_service_ev({
            "AccountId": "acc-exposed", "Name": "exposed",
            "DisableLocalAuth": False,
            "HasPrivateEndpoints": False,
            "PublicNetworkAccess": "Enabled",
            "Kind": "OpenAI",
        })])
        findings = self.analyze(idx)
        key_exp = [f for f in findings if f["Subcategory"] == "key_without_network_restriction"]
        self.assertGreater(len(key_exp), 0)

    def test_local_auth_disabled_no_finding(self):
        idx = _build_index([_ai_service_ev({
            "AccountId": "acc-safe", "Name": "safe-ai",
            "DisableLocalAuth": True,
            "HasPrivateEndpoints": False,
            "Kind": "OpenAI",
        })])
        findings = self.analyze(idx)
        key_exp = [f for f in findings if f["Subcategory"] == "key_without_network_restriction"]
        self.assertEqual(len(key_exp), 0)


# ====================================================================
# C2. Custom Agent — Data Residency
# ====================================================================

class TestCustomDataResidency(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_custom_data_residency
        self.analyze = analyze_custom_data_residency

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_many_regions_detected(self):
        """More than 3 unique regions triggers multi_region_sprawl."""
        services = [_ai_service_ev({
            "AccountId": f"acc-{i}", "Name": f"ai-{i}",
            "Location": region,
        }) for i, region in enumerate(["eastus", "westeurope", "japaneast", "australiaeast"])]
        idx = _build_index(services)
        findings = self.analyze(idx)
        residency = [f for f in findings if f["Subcategory"] == "multi_region_sprawl"]
        self.assertGreater(len(residency), 0)

    def test_single_region_no_finding(self):
        idx = _build_index([_ai_service_ev({
            "AccountId": "acc-1", "Name": "ai1",
            "Location": "eastus",
        })])
        findings = self.analyze(idx)
        residency = [f for f in findings if f["Subcategory"] == "multi_region_sprawl"]
        self.assertEqual(len(residency), 0)


# ====================================================================
# C3. Custom Agent — Content Leakage
# ====================================================================

class TestCustomContentLeakage(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_custom_content_leakage
        self.analyze = analyze_custom_content_leakage

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_content_filter_gaps_detected(self):
        """Mix of filtered and unfiltered deployments triggers content_filter_gaps."""
        idx = _build_index([
            _ai_deployment_ev({
                "DeploymentId": "dep-1", "DeploymentName": "gpt4-filtered",
                "HasContentFilter": True,
            }),
            _ai_deployment_ev({
                "DeploymentId": "dep-2", "DeploymentName": "gpt4-unfiltered",
                "HasContentFilter": False,
            }),
        ])
        findings = self.analyze(idx)
        gaps = [f for f in findings if f["Subcategory"] == "content_filter_gaps"]
        self.assertGreater(len(gaps), 0)

    def test_no_cmk_detected(self):
        """HasCMK == False and IsOpenAI == True triggers no_cmk_encryption."""
        idx = _build_index([_ai_service_ev({
            "AccountId": "acc-nocmk", "Name": "nocmk-ai",
            "HasCMK": False, "IsOpenAI": True,
        })])
        findings = self.analyze(idx)
        cmk = [f for f in findings if f["Subcategory"] == "no_cmk_encryption"]
        self.assertGreater(len(cmk), 0)


# ====================================================================
# A5. Copilot Studio — Knowledge Source Security
# ====================================================================

class TestCSKnowledgeSources(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_cs_knowledge_sources
        self.analyze = analyze_cs_knowledge_sources

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_overshared_knowledge_detected(self):
        """Org-wide SharePoint knowledge sources trigger overshared_knowledge_source."""
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-ks", "DisplayName": "Wiki Bot",
            "KnowledgeSources": [{"Type": "SharePoint", "IsOrgWide": True, "Name": "AllCompanyDocs"}],
        })])
        findings = self.analyze(idx)
        overshared = [f for f in findings if f["Subcategory"] == "overshared_knowledge_source"]
        self.assertGreater(len(overshared), 0)
        self.assertEqual(overshared[0]["Severity"], "high")

    def test_external_knowledge_detected(self):
        """HTTP knowledge sources trigger external_knowledge_source."""
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-ext", "DisplayName": "External Bot",
            "KnowledgeSources": [{"Type": "http", "Name": "ExternalAPI", "Endpoint": "https://ext.com"}],
        })])
        findings = self.analyze(idx)
        external = [f for f in findings if f["Subcategory"] == "external_knowledge_source"]
        self.assertGreater(len(external), 0)

    def test_scoped_sharepoint_no_finding(self):
        """Scoped (non org-wide) SharePoint knowledge produces no overshared finding."""
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-safe", "DisplayName": "Scoped Bot",
            "KnowledgeSources": [{"Type": "SharePoint", "IsOrgWide": False, "Name": "TeamDocs"}],
        })])
        findings = self.analyze(idx)
        overshared = [f for f in findings if f["Subcategory"] == "overshared_knowledge_source"]
        self.assertEqual(len(overshared), 0)

    def test_public_website_source_detected(self):
        """Public website URL knowledge source triggers public_website_source."""
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-pub-ks", "DisplayName": "PubKS Bot",
            "KnowledgeSources": [{"Type": "website", "Name": "Wiki", "Endpoint": "https://wiki.example.com"}],
        })])
        findings = self.analyze(idx)
        pub = [f for f in findings if f["Subcategory"] == "public_website_source"]
        self.assertGreater(len(pub), 0)
        self.assertEqual(pub[0]["Severity"], "medium")

    def test_sharepoint_knowledge_no_public_finding(self):
        """SharePoint knowledge source does not trigger public_website_source."""
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-sp-ks", "DisplayName": "SPKS Bot",
            "KnowledgeSources": [{"Type": "SharePoint", "Name": "TeamSite",
                                  "Endpoint": "https://contoso.sharepoint.com/sites/team",
                                  "IsOrgWide": False}],
        })])
        findings = self.analyze(idx)
        pub = [f for f in findings if f["Subcategory"] == "public_website_source"]
        self.assertEqual(len(pub), 0)


# ====================================================================
# A6. Copilot Studio — Generative AI Controls
# ====================================================================

class TestCSGenerativeAI(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_cs_generative_ai
        self.analyze = analyze_cs_generative_ai

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_no_guardrails_detected(self):
        """GenerativeAnswersEnabled without ContentModerationEnabled triggers finding."""
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-gen", "DisplayName": "Gen Bot",
            "GenerativeAnswersEnabled": True,
            "ContentModerationEnabled": False,
        })])
        findings = self.analyze(idx)
        no_guard = [f for f in findings if f["Subcategory"] == "generative_answers_no_guardrails"]
        self.assertGreater(len(no_guard), 0)
        self.assertEqual(no_guard[0]["Severity"], "high")

    def test_unrestricted_orchestration_detected(self):
        """OrchestratorEnabled without TopicRestrictionEnabled triggers finding."""
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-orch", "DisplayName": "Orch Bot",
            "OrchestratorEnabled": True,
            "TopicRestrictionEnabled": False,
        })])
        findings = self.analyze(idx)
        unrestricted = [f for f in findings if f["Subcategory"] == "generative_orchestration_unrestricted"]
        self.assertGreater(len(unrestricted), 0)

    def test_moderated_generative_no_finding(self):
        """GenerativeAnswers WITH ContentModeration yields no finding."""
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-safe", "DisplayName": "Safe Bot",
            "GenerativeAnswersEnabled": True,
            "ContentModerationEnabled": True,
        })])
        findings = self.analyze(idx)
        no_guard = [f for f in findings if f["Subcategory"] == "generative_answers_no_guardrails"]
        self.assertEqual(len(no_guard), 0)


# ====================================================================
# A7. Copilot Studio — Governance Controls
# ====================================================================

class TestCSGovernance(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_cs_governance
        self.analyze = analyze_cs_governance

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_unpublished_bot_with_secrets(self):
        """Unpublished bot with configured connectors triggers finding."""
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-draft", "DisplayName": "Draft Bot",
            "IsPublished": False, "HasConfiguredConnectors": True,
            "EnvironmentName": "Dev",
        })])
        findings = self.analyze(idx)
        draft = [f for f in findings if f["Subcategory"] == "unpublished_bot_with_secrets"]
        self.assertGreater(len(draft), 0)

    def test_not_solution_aware(self):
        """Published bot not in solution triggers bot_not_solution_aware."""
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-pub", "DisplayName": "Pub Bot",
            "IsPublished": True, "IsSolutionAware": False,
        })])
        findings = self.analyze(idx)
        sol = [f for f in findings if f["Subcategory"] == "bot_not_solution_aware"]
        self.assertGreater(len(sol), 0)

    def test_published_in_solution_no_finding(self):
        """Published bot in solution yields no governance findings."""
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-good", "DisplayName": "Good Bot",
            "IsPublished": True, "IsSolutionAware": True,
        })])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)

    def test_draft_bot_stale_detected(self):
        """Unpublished bot idle >90 days triggers draft_bot_stale."""
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-old-draft", "DisplayName": "Old Draft",
            "IsPublished": False, "ModifiedTime": "2025-01-01T00:00:00Z",
            "EnvironmentName": "Dev",
        })])
        findings = self.analyze(idx)
        stale = [f for f in findings if f["Subcategory"] == "draft_bot_stale"]
        self.assertGreater(len(stale), 0)
        self.assertEqual(stale[0]["Severity"], "low")

    def test_recent_draft_no_stale_finding(self):
        """Recently modified draft bot should not trigger draft_bot_stale."""
        from datetime import datetime, timezone
        recent = datetime.now(timezone.utc).isoformat()
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-new-draft", "DisplayName": "New Draft",
            "IsPublished": False, "ModifiedTime": recent,
            "EnvironmentName": "Dev",
        })])
        findings = self.analyze(idx)
        stale = [f for f in findings if f["Subcategory"] == "draft_bot_stale"]
        self.assertEqual(len(stale), 0)


# ====================================================================
# A8. Copilot Studio — Connector Security
# ====================================================================

class TestCSConnectorSecurity(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_cs_connector_security
        self.analyze = analyze_cs_connector_security

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_custom_connector_no_auth(self):
        """Custom connector without authentication triggers finding."""
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-conn", "DisplayName": "Conn Bot",
            "CustomConnectors": [{"Name": "MyAPI", "HasAuthentication": False}],
        })])
        findings = self.analyze(idx)
        no_auth = [f for f in findings if f["Subcategory"] == "custom_connector_no_auth"]
        self.assertGreater(len(no_auth), 0)
        self.assertEqual(no_auth[0]["Severity"], "high")

    def test_premium_connector_uncontrolled(self):
        """Premium connectors with zero DLP triggers finding."""
        idx = _build_index([
            _cs_bot_ev({
                "BotId": "bot-prem", "DisplayName": "Prem Bot",
                "PremiumConnectors": ["SQL Server", "HTTP"],
            }),
            _cs_summary_ev({"DLPPolicies": 0}),
        ])
        findings = self.analyze(idx)
        prem = [f for f in findings if f["Subcategory"] == "premium_connector_uncontrolled"]
        self.assertGreater(len(prem), 0)

    def test_custom_connector_with_auth_no_finding(self):
        """Custom connector with authentication yields no finding."""
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-safe", "DisplayName": "Safe Bot",
            "CustomConnectors": [{"Name": "MyAPI", "HasAuthentication": True}],
        })])
        findings = self.analyze(idx)
        no_auth = [f for f in findings if f["Subcategory"] == "custom_connector_no_auth"]
        self.assertEqual(len(no_auth), 0)

    def test_env_level_connector_no_auth_detected(self):
        """Environment-level custom connector without auth triggers finding."""
        idx = _build_index([_pp_custom_connector_ev({
            "ConnectorId": "c1", "DisplayName": "NoAuth Connector",
            "HasAuthentication": False, "EnvironmentName": "Dev",
        })])
        findings = self.analyze(idx)
        no_auth = [f for f in findings if f["Subcategory"] == "custom_connector_no_auth"]
        self.assertGreater(len(no_auth), 0)

    def test_connector_no_dlp_coverage_detected(self):
        """Environment with connectors but no DLP triggers finding."""
        idx = _build_index([
            _pp_custom_connector_ev({
                "ConnectorId": "c1", "DisplayName": "MyConn",
                "EnvironmentId": "env-1", "EnvironmentName": "Dev",
                "HasAuthentication": True,
            }),
            _cs_summary_ev({"DLPPolicies": 0}),
        ])
        findings = self.analyze(idx)
        dlp = [f for f in findings if f["Subcategory"] == "connector_no_dlp_coverage"]
        self.assertGreater(len(dlp), 0)
        self.assertEqual(dlp[0]["Severity"], "medium")

    def test_connector_with_dlp_no_coverage_finding(self):
        """Connectors with DLP policies present produce no coverage finding."""
        idx = _build_index([
            _pp_custom_connector_ev({
                "ConnectorId": "c1", "DisplayName": "MyConn",
                "EnvironmentId": "env-1", "EnvironmentName": "Dev",
                "HasAuthentication": True,
            }),
            _cs_summary_ev({"DLPPolicies": 2}),
        ])
        findings = self.analyze(idx)
        dlp = [f for f in findings if f["Subcategory"] == "connector_no_dlp_coverage"]
        self.assertEqual(len(dlp), 0)


# ====================================================================
# B6. Foundry — Compute Security
# ====================================================================

class TestFoundryCompute(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_compute
        self.analyze = analyze_foundry_compute

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_public_ip_detected(self):
        """HasPublicIP == True triggers compute_public_ip."""
        idx = _build_index([_ai_compute_ev({
            "ComputeId": "comp-1", "Name": "dev-vm",
            "HasPublicIP": True, "WorkspaceName": "ws1",
        })])
        findings = self.analyze(idx)
        pub = [f for f in findings if f["Subcategory"] == "compute_public_ip"]
        self.assertGreater(len(pub), 0)
        self.assertEqual(pub[0]["Severity"], "high")

    def test_ssh_enabled_detected(self):
        """SSHEnabled == True triggers compute_ssh_enabled."""
        idx = _build_index([_ai_compute_ev({
            "ComputeId": "comp-2", "Name": "ssh-vm",
            "SSHEnabled": True,
        })])
        findings = self.analyze(idx)
        ssh = [f for f in findings if f["Subcategory"] == "compute_ssh_enabled"]
        self.assertGreater(len(ssh), 0)

    def test_no_idle_shutdown_detected(self):
        """IdleShutdownEnabled == False triggers compute_idle_no_shutdown."""
        idx = _build_index([_ai_compute_ev({
            "ComputeId": "comp-3", "Name": "always-on",
            "IdleShutdownEnabled": False,
        })])
        findings = self.analyze(idx)
        idle = [f for f in findings if f["Subcategory"] == "compute_idle_no_shutdown"]
        self.assertGreater(len(idle), 0)

    def test_secure_compute_no_finding(self):
        """Secure compute with no public IP, no SSH, idle shutdown yields no findings."""
        idx = _build_index([_ai_compute_ev({
            "ComputeId": "comp-ok", "Name": "secure-vm",
            "HasPublicIP": False, "SSHEnabled": False,
            "IdleShutdownEnabled": True,
            "HasManagedIdentity": True,
        })])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)


# ====================================================================
# B7. Foundry — Datastore Security
# ====================================================================

class TestFoundryDatastores(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_datastores
        self.analyze = analyze_foundry_datastores

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_credential_in_config_detected(self):
        """CredentialType == account_key triggers datastore_credential_in_config."""
        idx = _build_index([_ai_datastore_ev({
            "DatastoreId": "ds-1", "Name": "blob-store",
            "CredentialType": "account_key", "WorkspaceName": "ws1",
        })])
        findings = self.analyze(idx)
        cred = [f for f in findings if f["Subcategory"] == "datastore_credential_in_config"]
        self.assertGreater(len(cred), 0)
        self.assertEqual(cred[0]["Severity"], "high")

    def test_no_encryption_detected(self):
        """StorageEncrypted == False triggers datastore_no_encryption."""
        idx = _build_index([_ai_datastore_ev({
            "DatastoreId": "ds-2", "Name": "unenc-store",
            "StorageEncrypted": False,
        })])
        findings = self.analyze(idx)
        enc = [f for f in findings if f["Subcategory"] == "datastore_no_encryption"]
        self.assertGreater(len(enc), 0)

    def test_identity_based_encrypted_no_finding(self):
        """Identity-based access with encryption yields no findings."""
        idx = _build_index([_ai_datastore_ev({
            "DatastoreId": "ds-ok", "Name": "good-store",
            "CredentialType": "identity", "StorageEncrypted": True,
        })])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)


# ====================================================================
# B8. Foundry — Endpoint Security
# ====================================================================

class TestFoundryEndpoints(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_endpoints
        self.analyze = analyze_foundry_endpoints

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_public_endpoint_detected(self):
        """PublicNetworkAccess == Enabled triggers online_endpoint_public."""
        idx = _build_index([_ai_endpoint_ev({
            "EndpointId": "ep-1", "Name": "pub-ep",
            "PublicNetworkAccess": "Enabled", "EndpointType": "online",
        })])
        findings = self.analyze(idx)
        pub = [f for f in findings if f["Subcategory"] == "online_endpoint_public"]
        self.assertGreater(len(pub), 0)

    def test_no_auth_endpoint_detected(self):
        """AuthMode == none triggers endpoint_no_auth."""
        idx = _build_index([_ai_endpoint_ev({
            "EndpointId": "ep-2", "Name": "open-ep",
            "AuthMode": "none",
        })])
        findings = self.analyze(idx)
        no_auth = [f for f in findings if f["Subcategory"] == "endpoint_no_auth"]
        self.assertGreater(len(no_auth), 0)
        self.assertEqual(no_auth[0]["Severity"], "critical")

    def test_key_auth_detected(self):
        """AuthMode == key triggers endpoint_key_auth_only."""
        idx = _build_index([_ai_endpoint_ev({
            "EndpointId": "ep-3", "Name": "key-ep",
            "AuthMode": "key", "PublicNetworkAccess": "Disabled",
        })])
        findings = self.analyze(idx)
        key = [f for f in findings if f["Subcategory"] == "endpoint_key_auth_only"]
        self.assertGreater(len(key), 0)

    def test_aad_private_endpoint_no_finding(self):
        """AAD auth with disabled public access yields no findings."""
        idx = _build_index([_ai_endpoint_ev({
            "EndpointId": "ep-ok", "Name": "secure-ep",
            "AuthMode": "aad_token",
            "PublicNetworkAccess": "Disabled",
        })])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)


# ====================================================================
# B9. Foundry — Registry Security
# ====================================================================

class TestFoundryRegistry(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_registry
        self.analyze = analyze_foundry_registry

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_public_registry_detected(self):
        """PublicNetworkAccess == Enabled triggers registry_public_access."""
        idx = _build_index([_ai_registry_ev({
            "RegistryId": "reg-1", "Name": "pub-reg",
            "PublicNetworkAccess": "Enabled",
        })])
        findings = self.analyze(idx)
        pub = [f for f in findings if f["Subcategory"] == "registry_public_access"]
        self.assertGreater(len(pub), 0)

    def test_no_rbac_detected(self):
        """HasRBACAssignments == False triggers registry_no_rbac."""
        idx = _build_index([_ai_registry_ev({
            "RegistryId": "reg-2", "Name": "open-reg",
            "HasRBACAssignments": False,
            "PublicNetworkAccess": "Disabled",
        })])
        findings = self.analyze(idx)
        rbac = [f for f in findings if f["Subcategory"] == "registry_no_rbac"]
        self.assertGreater(len(rbac), 0)

    def test_private_with_rbac_no_finding(self):
        """Private registry with RBAC yields no findings."""
        idx = _build_index([_ai_registry_ev({
            "RegistryId": "reg-ok", "Name": "good-reg",
            "PublicNetworkAccess": "Disabled",
            "HasRBACAssignments": True,
        })])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)


# ====================================================================
# B-ext2. Foundry — Connection Security
# ====================================================================

class TestFoundryConnections(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_connections
        self.analyze = analyze_foundry_connections

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_static_creds_detected(self):
        """HasCredentials == True triggers connection_static_credentials."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-1", "Name": "key-conn",
            "HasCredentials": True, "AuthType": "ApiKey",
            "WorkspaceName": "ws1", "Category": "AzureOpenAI",
        })])
        findings = self.analyze(idx)
        static = [f for f in findings if f["Subcategory"] == "connection_static_credentials"]
        self.assertGreater(len(static), 0)

    def test_shared_to_all_detected(self):
        """IsSharedToAll + HasCredentials triggers connection_shared_to_all."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-2", "Name": "shared-conn",
            "HasCredentials": True, "IsSharedToAll": True,
            "WorkspaceName": "ws1",
        })])
        findings = self.analyze(idx)
        shared = [f for f in findings if f["Subcategory"] == "connection_shared_to_all"]
        self.assertGreater(len(shared), 0)

    def test_expired_creds_detected(self):
        """Expired ExpiryTime triggers connection_expired_credentials."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-3", "Name": "expired-conn",
            "ExpiryTime": "2023-01-01T00:00:00Z",
        })])
        findings = self.analyze(idx)
        expired = [f for f in findings if f["Subcategory"] == "connection_expired_credentials"]
        self.assertGreater(len(expired), 0)

    def test_identity_conn_no_finding(self):
        """Identity-based connection without sharing yields no findings."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-ok", "Name": "safe-conn",
            "HasCredentials": False, "AuthType": "ManagedIdentity",
            "IsSharedToAll": False,
        })])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)


# ====================================================================
# B-ext3. Foundry — Serverless Endpoints
# ====================================================================

class TestFoundryServerless(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_serverless
        self.analyze = analyze_foundry_serverless

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_key_auth_detected(self):
        """AuthMode == Key triggers serverless_key_auth."""
        idx = _build_index([_ai_serverless_ev({
            "EndpointId": "sep-1", "Name": "key-ep",
            "AuthMode": "Key", "ModelId": "gpt-4o",
            "WorkspaceName": "ws1", "ContentSafetyEnabled": True,
        })])
        findings = self.analyze(idx)
        key = [f for f in findings if f["Subcategory"] == "serverless_key_auth"]
        self.assertGreater(len(key), 0)

    def test_no_content_safety_detected(self):
        """ContentSafetyEnabled == False triggers serverless_no_content_safety."""
        idx = _build_index([_ai_serverless_ev({
            "EndpointId": "sep-2", "Name": "unsafe-ep",
            "AuthMode": "AAD", "ContentSafetyEnabled": False,
            "WorkspaceName": "ws1",
        })])
        findings = self.analyze(idx)
        safety = [f for f in findings if f["Subcategory"] == "serverless_no_content_safety"]
        self.assertGreater(len(safety), 0)

    def test_aad_with_safety_no_finding(self):
        """AAD auth with content safety yields no findings."""
        idx = _build_index([_ai_serverless_ev({
            "EndpointId": "sep-ok", "Name": "good-ep",
            "AuthMode": "AAD", "ContentSafetyEnabled": True,
            "WorkspaceName": "ws1",
        })])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)


# ====================================================================
# B-ext4. Foundry — Workspace Diagnostics
# ====================================================================

class TestFoundryWsDiagnostics(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_ws_diagnostics
        self.analyze = analyze_foundry_ws_diagnostics

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_no_diagnostics_detected(self):
        """HasDiagnostics == False triggers ws_no_diagnostic_settings."""
        idx = _build_index([_ai_ws_diag_ev({
            "WorkspaceId": "ws-1", "WorkspaceName": "no-diag-ws",
            "HasDiagnostics": False,
        })])
        findings = self.analyze(idx)
        no_diag = [f for f in findings if f["Subcategory"] == "ws_no_diagnostic_settings"]
        self.assertGreater(len(no_diag), 0)

    def test_no_log_analytics_detected(self):
        """HasDiagnostics but no HasLogAnalytics triggers ws_no_log_analytics."""
        idx = _build_index([_ai_ws_diag_ev({
            "WorkspaceId": "ws-2", "WorkspaceName": "no-la-ws",
            "HasDiagnostics": True, "HasLogAnalytics": False,
            "HasStorageAccount": True,
        })])
        findings = self.analyze(idx)
        no_la = [f for f in findings if f["Subcategory"] == "ws_no_log_analytics"]
        self.assertGreater(len(no_la), 0)

    def test_full_diagnostics_no_finding(self):
        """Full diagnostics with Log Analytics yields no findings."""
        idx = _build_index([_ai_ws_diag_ev({
            "WorkspaceId": "ws-ok", "WorkspaceName": "good-ws",
            "HasDiagnostics": True, "HasLogAnalytics": True,
        })])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)


# ====================================================================
# B-Phase2. Foundry — New Sub-checks in Existing Categories
# ====================================================================

class TestFoundryDeploymentDeprecatedModel(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_deployments
        self.analyze = analyze_foundry_deployments

    def test_deprecated_model_detected(self):
        """gpt-35-turbo-0301 triggers deployment_deprecated_model."""
        idx = _build_index([_ai_deployment_ev({
            "DeploymentId": "dep-old", "DeploymentName": "gpt35-legacy",
            "ModelName": "gpt-35-turbo", "ModelVersion": "0301",
            "SkuCapacity": 10,
        })])
        findings = self.analyze(idx)
        dep = [f for f in findings if f["Subcategory"] == "deployment_deprecated_model"]
        self.assertGreater(len(dep), 0)

    def test_current_model_no_finding(self):
        idx = _build_index([_ai_deployment_ev({
            "DeploymentId": "dep-new", "DeploymentName": "gpt4o-prod",
            "ModelName": "gpt-4o", "ModelVersion": "2024-05-13",
            "SkuCapacity": 50,
        })])
        findings = self.analyze(idx)
        dep = [f for f in findings if f["Subcategory"] == "deployment_deprecated_model"]
        self.assertEqual(len(dep), 0)


class TestFoundryDeploymentNoRaiPolicy(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_deployments
        self.analyze = analyze_foundry_deployments

    def test_no_rai_policy_detected(self):
        """Empty RAIPolicy triggers deployment_no_rai_policy."""
        idx = _build_index([_ai_deployment_ev({
            "DeploymentId": "dep-norai", "DeploymentName": "unfiltered",
            "ModelName": "gpt-4", "RAIPolicy": "",
            "SkuCapacity": 10,
        })])
        findings = self.analyze(idx)
        rai = [f for f in findings if f["Subcategory"] == "deployment_no_rai_policy"]
        self.assertGreater(len(rai), 0)

    def test_rai_policy_present_no_finding(self):
        idx = _build_index([_ai_deployment_ev({
            "DeploymentId": "dep-ok", "DeploymentName": "filtered",
            "ModelName": "gpt-4", "RAIPolicy": "my-policy",
            "SkuCapacity": 10,
        })])
        findings = self.analyze(idx)
        rai = [f for f in findings if f["Subcategory"] == "deployment_no_rai_policy"]
        self.assertEqual(len(rai), 0)


class TestFoundryWorkspaceNoCMK(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_governance
        self.analyze = analyze_foundry_governance

    def test_no_cmk_detected(self):
        """HasCMK == False triggers workspace_no_cmk."""
        idx = _build_index([_ai_workspace_ev({
            "WorkspaceId": "ws-nocmk", "Name": "nocmk-ws",
            "HasCMK": False, "IsHub": True, "IsProject": False,
        })])
        findings = self.analyze(idx)
        cmk = [f for f in findings if f["Subcategory"] == "workspace_no_cmk"]
        self.assertGreater(len(cmk), 0)

    def test_cmk_enabled_no_finding(self):
        idx = _build_index([_ai_workspace_ev({
            "WorkspaceId": "ws-cmk", "Name": "cmk-ws",
            "HasCMK": True, "IsHub": True, "IsProject": False,
        })])
        findings = self.analyze(idx)
        cmk = [f for f in findings if f["Subcategory"] == "workspace_no_cmk"]
        self.assertEqual(len(cmk), 0)


class TestFoundryHubNoProjectIsolation(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_governance
        self.analyze = analyze_foundry_governance

    def test_project_no_isolation_under_isolated_hub(self):
        """Project without network isolation under an isolated hub triggers hub_no_project_isolation."""
        idx = _build_index([
            _ai_workspace_ev({
                "WorkspaceId": "ws-hub", "Name": "isolated-hub",
                "IsHub": True, "IsProject": False,
                "HasNetworkIsolation": True,
            }),
            _ai_workspace_ev({
                "WorkspaceId": "ws-proj", "Name": "open-project",
                "IsHub": False, "IsProject": True,
                "HasNetworkIsolation": False,
                "HubWorkspaceId": "ws-hub",
            }),
        ])
        findings = self.analyze(idx)
        iso = [f for f in findings if f["Subcategory"] == "hub_no_project_isolation"]
        self.assertGreater(len(iso), 0)

    def test_project_with_isolation_no_finding(self):
        idx = _build_index([
            _ai_workspace_ev({
                "WorkspaceId": "ws-hub", "Name": "isolated-hub",
                "IsHub": True, "IsProject": False,
                "HasNetworkIsolation": True,
            }),
            _ai_workspace_ev({
                "WorkspaceId": "ws-proj", "Name": "isolated-project",
                "IsHub": False, "IsProject": True,
                "HasNetworkIsolation": True,
                "HubWorkspaceId": "ws-hub",
            }),
        ])
        findings = self.analyze(idx)
        iso = [f for f in findings if f["Subcategory"] == "hub_no_project_isolation"]
        self.assertEqual(len(iso), 0)


class TestFoundryComputeNoManagedIdentity(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_compute
        self.analyze = analyze_foundry_compute

    def test_no_managed_identity_detected(self):
        """HasManagedIdentity == False triggers compute_no_managed_identity."""
        idx = _build_index([_ai_compute_ev({
            "ComputeId": "ci-noid", "ComputeName": "my-ci",
            "HasManagedIdentity": False,
            "IdleShutdownEnabled": True,
        })])
        findings = self.analyze(idx)
        mi = [f for f in findings if f["Subcategory"] == "compute_no_managed_identity"]
        self.assertGreater(len(mi), 0)

    def test_managed_identity_present_no_finding(self):
        idx = _build_index([_ai_compute_ev({
            "ComputeId": "ci-ok", "ComputeName": "my-ci",
            "HasManagedIdentity": True,
            "IdleShutdownEnabled": True,
        })])
        findings = self.analyze(idx)
        mi = [f for f in findings if f["Subcategory"] == "compute_no_managed_identity"]
        self.assertEqual(len(mi), 0)


class TestFoundryEndpointNoLogging(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_endpoints
        self.analyze = analyze_foundry_endpoints

    def test_endpoint_no_logging_detected(self):
        """Endpoint in workspace without diagnostics triggers endpoint_no_logging."""
        idx = _build_index([
            _ai_endpoint_ev({
                "EndpointId": "ep-1", "EndpointName": "my-ep",
                "WorkspaceId": "ws-1",
                "AuthMode": "amltoken",
            }),
            _ai_ws_diag_ev({
                "WorkspaceId": "ws-1", "WorkspaceName": "no-diag-ws",
                "HasDiagnostics": False,
            }),
        ])
        findings = self.analyze(idx)
        log_f = [f for f in findings if f["Subcategory"] == "endpoint_no_logging"]
        self.assertGreater(len(log_f), 0)

    def test_endpoint_with_logging_no_finding(self):
        idx = _build_index([
            _ai_endpoint_ev({
                "EndpointId": "ep-2", "EndpointName": "logged-ep",
                "WorkspaceId": "ws-2",
                "AuthMode": "amltoken",
            }),
            _ai_ws_diag_ev({
                "WorkspaceId": "ws-2", "WorkspaceName": "diag-ws",
                "HasDiagnostics": True, "HasLogAnalytics": True,
            }),
        ])
        findings = self.analyze(idx)
        log_f = [f for f in findings if f["Subcategory"] == "endpoint_no_logging"]
        self.assertEqual(len(log_f), 0)


class TestFoundryConnectionNoExpiry(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_connections
        self.analyze = analyze_foundry_connections

    def test_no_expiry_detected(self):
        """Connection with credentials but no expiry triggers connection_no_expiry."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-1", "ConnectionName": "my-conn",
            "HasCredentials": True, "ExpiryTime": "",
            "ConnectionType": "AzureOpenAI",
        })])
        findings = self.analyze(idx)
        exp = [f for f in findings if f["Subcategory"] == "connection_no_expiry"]
        self.assertGreater(len(exp), 0)

    def test_expiry_set_no_finding(self):
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-2", "ConnectionName": "my-conn",
            "HasCredentials": True, "ExpiryTime": "2025-12-31",
            "ConnectionType": "AzureOpenAI",
        })])
        findings = self.analyze(idx)
        exp = [f for f in findings if f["Subcategory"] == "connection_no_expiry"]
        self.assertEqual(len(exp), 0)


class TestFoundryServerlessKeyNotRotated(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_serverless
        self.analyze = analyze_foundry_serverless

    def test_key_auth_triggers_rotation_finding(self):
        """AuthMode == 'key' triggers serverless_key_not_rotated."""
        idx = _build_index([_ai_serverless_ev({
            "EndpointId": "se-1", "EndpointName": "my-maas",
            "AuthMode": "key", "ModelId": "meta-llama",
        })])
        findings = self.analyze(idx)
        rot = [f for f in findings if f["Subcategory"] == "serverless_key_not_rotated"]
        self.assertGreater(len(rot), 0)

    def test_aad_auth_no_finding(self):
        idx = _build_index([_ai_serverless_ev({
            "EndpointId": "se-2", "EndpointName": "my-maas",
            "AuthMode": "aad", "ModelId": "meta-llama",
        })])
        findings = self.analyze(idx)
        rot = [f for f in findings if f["Subcategory"] == "serverless_key_not_rotated"]
        self.assertEqual(len(rot), 0)


# ====================================================================
# B-Phase3. Foundry — New Categories
# ====================================================================

class TestFoundryPromptShields(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_prompt_shields
        self.analyze = analyze_foundry_prompt_shields

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_no_prompt_shield_detected(self):
        """HasPromptShield == False triggers no_prompt_shield."""
        idx = _build_index([_ai_filter_ev({
            "PolicyId": "pol-1", "PolicyName": "default",
            "HasPromptShield": False, "HasJailbreakFilter": True,
            "CustomBlocklistCount": 1, "AccountName": "acct-1",
        })])
        findings = self.analyze(idx)
        ps = [f for f in findings if f["Subcategory"] == "no_prompt_shield"]
        self.assertGreater(len(ps), 0)

    def test_prompt_shield_enabled_no_finding(self):
        idx = _build_index([_ai_filter_ev({
            "PolicyId": "pol-2", "PolicyName": "secure",
            "HasPromptShield": True, "HasJailbreakFilter": True,
            "CustomBlocklistCount": 1, "AccountName": "acct-1",
        })])
        findings = self.analyze(idx)
        ps = [f for f in findings if f["Subcategory"] == "no_prompt_shield"]
        self.assertEqual(len(ps), 0)

    def test_jailbreak_filter_disabled_detected(self):
        """HasJailbreakFilter == False triggers jailbreak_filter_disabled."""
        idx = _build_index([_ai_filter_ev({
            "PolicyId": "pol-3", "PolicyName": "no-jb",
            "HasPromptShield": True, "HasJailbreakFilter": False,
            "CustomBlocklistCount": 1, "AccountName": "acct-1",
        })])
        findings = self.analyze(idx)
        jb = [f for f in findings if f["Subcategory"] == "jailbreak_filter_disabled"]
        self.assertGreater(len(jb), 0)

    def test_jailbreak_filter_enabled_no_finding(self):
        idx = _build_index([_ai_filter_ev({
            "PolicyId": "pol-4", "PolicyName": "good",
            "HasPromptShield": True, "HasJailbreakFilter": True,
            "CustomBlocklistCount": 1, "AccountName": "acct-1",
        })])
        findings = self.analyze(idx)
        jb = [f for f in findings if f["Subcategory"] == "jailbreak_filter_disabled"]
        self.assertEqual(len(jb), 0)

    def test_no_blocklist_detected(self):
        """CustomBlocklistCount == 0 triggers blocklist_not_configured."""
        idx = _build_index([_ai_filter_ev({
            "PolicyId": "pol-5", "PolicyName": "no-bl",
            "HasPromptShield": True, "HasJailbreakFilter": True,
            "CustomBlocklistCount": 0, "AccountName": "acct-1",
        })])
        findings = self.analyze(idx)
        bl = [f for f in findings if f["Subcategory"] == "blocklist_not_configured"]
        self.assertGreater(len(bl), 0)

    def test_blocklist_configured_no_finding(self):
        idx = _build_index([_ai_filter_ev({
            "PolicyId": "pol-6", "PolicyName": "with-bl",
            "HasPromptShield": True, "HasJailbreakFilter": True,
            "CustomBlocklistCount": 3, "AccountName": "acct-1",
        })])
        findings = self.analyze(idx)
        bl = [f for f in findings if f["Subcategory"] == "blocklist_not_configured"]
        self.assertEqual(len(bl), 0)


class TestFoundryModelCatalog(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_model_catalog
        self.analyze = analyze_foundry_model_catalog

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_unapproved_model_detected(self):
        """Unknown model name triggers unapproved_model_deployed."""
        idx = _build_index([_ai_deployment_ev({
            "DeploymentId": "dep-unk", "DeploymentName": "mystery-model",
            "ModelName": "custom-finetune-v99", "ModelVersion": "1",
            "AccountName": "acct-1",
        })])
        findings = self.analyze(idx)
        unapp = [f for f in findings if f["Subcategory"] == "unapproved_model_deployed"]
        self.assertGreater(len(unapp), 0)

    def test_known_model_no_finding(self):
        idx = _build_index([_ai_deployment_ev({
            "DeploymentId": "dep-ok", "DeploymentName": "gpt4o-deploy",
            "ModelName": "gpt-4o", "ModelVersion": "2024-05-13",
        })])
        findings = self.analyze(idx)
        unapp = [f for f in findings if f["Subcategory"] == "unapproved_model_deployed"]
        self.assertEqual(len(unapp), 0)

    def test_outdated_version_detected(self):
        """Old model version triggers model_version_outdated."""
        idx = _build_index([_ai_deployment_ev({
            "DeploymentId": "dep-old", "DeploymentName": "gpt4-legacy",
            "ModelName": "gpt-4", "ModelVersion": "0613",
        })])
        findings = self.analyze(idx)
        old = [f for f in findings if f["Subcategory"] == "model_version_outdated"]
        self.assertGreater(len(old), 0)

    def test_current_version_no_finding(self):
        idx = _build_index([_ai_deployment_ev({
            "DeploymentId": "dep-new", "DeploymentName": "gpt4o-v2",
            "ModelName": "gpt-4o", "ModelVersion": "2024-08-06",
        })])
        findings = self.analyze(idx)
        old = [f for f in findings if f["Subcategory"] == "model_version_outdated"]
        self.assertEqual(len(old), 0)


class TestFoundryDataExfiltration(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_data_exfiltration
        self.analyze = analyze_foundry_data_exfiltration

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_no_managed_network_detected(self):
        """HasNetworkIsolation == False triggers workspace_no_managed_network."""
        idx = _build_index([_ai_workspace_ev({
            "WorkspaceId": "ws-open", "Name": "open-ws",
            "HasNetworkIsolation": False, "Kind": "project",
        })])
        findings = self.analyze(idx)
        no_net = [f for f in findings if f["Subcategory"] == "workspace_no_managed_network"]
        self.assertGreater(len(no_net), 0)

    def test_managed_network_present_no_finding(self):
        idx = _build_index([_ai_workspace_ev({
            "WorkspaceId": "ws-iso", "Name": "isolated-ws",
            "HasNetworkIsolation": True, "OutboundRuleCount": 5,
            "IsolationMode": "AllowOnlyApprovedOutbound",
        })])
        findings = self.analyze(idx)
        no_net = [f for f in findings if f["Subcategory"] == "workspace_no_managed_network"]
        self.assertEqual(len(no_net), 0)

    def test_no_outbound_rules_detected(self):
        """Isolated workspace with 0 outbound rules triggers managed_network_no_outbound_rules."""
        idx = _build_index([_ai_workspace_ev({
            "WorkspaceId": "ws-empty", "Name": "empty-rules-ws",
            "HasNetworkIsolation": True, "OutboundRuleCount": 0,
            "IsolationMode": "AllowOnlyApprovedOutbound",
        })])
        findings = self.analyze(idx)
        no_rules = [f for f in findings if f["Subcategory"] == "managed_network_no_outbound_rules"]
        self.assertGreater(len(no_rules), 0)

    def test_outbound_rules_present_no_finding(self):
        idx = _build_index([_ai_workspace_ev({
            "WorkspaceId": "ws-ok", "Name": "good-ws",
            "HasNetworkIsolation": True, "OutboundRuleCount": 3,
            "IsolationMode": "AllowOnlyApprovedOutbound",
        })])
        findings = self.analyze(idx)
        no_rules = [f for f in findings if f["Subcategory"] == "managed_network_no_outbound_rules"]
        self.assertEqual(len(no_rules), 0)

    def test_unrestricted_outbound_detected(self):
        """AllowInternetOutbound triggers outbound_fqdn_unrestricted."""
        idx = _build_index([_ai_workspace_ev({
            "WorkspaceId": "ws-open", "Name": "open-ws",
            "HasNetworkIsolation": True,
            "IsolationMode": "AllowInternetOutbound",
            "OutboundRuleCount": 2,
        })])
        findings = self.analyze(idx)
        fqdn = [f for f in findings if f["Subcategory"] == "outbound_fqdn_unrestricted"]
        self.assertGreater(len(fqdn), 0)

    def test_approved_only_no_finding(self):
        idx = _build_index([_ai_workspace_ev({
            "WorkspaceId": "ws-locked", "Name": "locked-ws",
            "HasNetworkIsolation": True,
            "IsolationMode": "AllowOnlyApprovedOutbound",
            "OutboundRuleCount": 5,
        })])
        findings = self.analyze(idx)
        fqdn = [f for f in findings if f["Subcategory"] == "outbound_fqdn_unrestricted"]
        self.assertEqual(len(fqdn), 0)


# ====================================================================
# B16. Foundry — Agent Identity Security
# ====================================================================

class TestFoundryAgentIdentity(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_agent_identity
        self.analyze = analyze_foundry_agent_identity

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_project_no_managed_identity_detected(self):
        """Foundry project without MI triggers project_no_managed_identity."""
        idx = _build_index([_foundry_project_ev({
            "ProjectId": "proj-1", "Name": "my-project",
            "AccountName": "my-account",
            "HasManagedIdentity": False,
        })])
        findings = self.analyze(idx)
        mi = [f for f in findings if f["Subcategory"] == "project_no_managed_identity"]
        self.assertGreater(len(mi), 0)

    def test_project_with_mi_no_finding(self):
        """Project with MI does not trigger finding."""
        idx = _build_index([_foundry_project_ev({
            "ProjectId": "proj-2", "Name": "secure-project",
            "AccountName": "my-account",
            "HasManagedIdentity": True,
            "AgentCount": 1,
        })])
        findings = self.analyze(idx)
        mi = [f for f in findings if f["Subcategory"] == "project_no_managed_identity"]
        self.assertEqual(len(mi), 0)

    def test_shared_identity_detected(self):
        """Multiple unpublished agents sharing project identity triggers finding."""
        idx = _build_index([
            _foundry_project_ev({
                "ProjectId": "proj-3", "Name": "busy-project",
                "AccountName": "acct",
                "HasManagedIdentity": True,
                "AgentCount": 5,
            }),
        ])
        findings = self.analyze(idx)
        shared = [f for f in findings if f["Subcategory"] == "shared_project_identity"]
        self.assertGreater(len(shared), 0)

    def test_agent_permission_drift_detected(self):
        """Published app without RBAC triggers agent_permission_drift."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "app-1", "Name": "my-agent-app",
            "ProjectName": "proj",
            "HasRBACAssignments": False,
        })])
        findings = self.analyze(idx)
        drift = [f for f in findings if f["Subcategory"] == "agent_permission_drift"]
        self.assertGreater(len(drift), 0)

    def test_agent_with_rbac_no_drift(self):
        """Published app with RBAC does not trigger drift finding."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "app-2", "Name": "rbac-agent",
            "ProjectName": "proj",
            "HasRBACAssignments": True,
        })])
        findings = self.analyze(idx)
        drift = [f for f in findings if f["Subcategory"] == "agent_permission_drift"]
        self.assertEqual(len(drift), 0)


# ====================================================================
# B17. Foundry — Agent Application Security
# ====================================================================

class TestFoundryAgentApplication(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_agent_application
        self.analyze = analyze_foundry_agent_application

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_public_endpoint_detected(self):
        """Agent app with public endpoint triggers public_endpoint_exposure."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "app-pub", "Name": "public-agent",
            "IsPublicEndpoint": True,
            "Protocol": "ResponsesAPI",
            "AuthenticationType": "RBAC",
        })])
        findings = self.analyze(idx)
        pub = [f for f in findings if f["Subcategory"] == "public_endpoint_exposure"]
        self.assertGreater(len(pub), 0)

    def test_private_endpoint_no_finding(self):
        """Agent app with private endpoint (IsPublicEndpoint=False) is clean."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "app-priv", "Name": "private-agent",
            "IsPublicEndpoint": False,
            "AuthenticationType": "RBAC",
        })])
        findings = self.analyze(idx)
        pub = [f for f in findings if f["Subcategory"] == "public_endpoint_exposure"]
        self.assertEqual(len(pub), 0)

    def test_no_auth_detected(self):
        """Agent app without auth triggers no_auth_policy."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "app-noauth", "Name": "unauth-agent",
            "AuthenticationType": "None",
            "IsPublicEndpoint": True,
        })])
        findings = self.analyze(idx)
        auth = [f for f in findings if f["Subcategory"] == "no_auth_policy"]
        self.assertGreater(len(auth), 0)

    def test_rbac_auth_no_finding(self):
        """Agent app with RBAC auth is clean."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "app-rbac", "Name": "secure-agent",
            "AuthenticationType": "RBAC",
            "IsPublicEndpoint": False,
        })])
        findings = self.analyze(idx)
        auth = [f for f in findings if f["Subcategory"] == "no_auth_policy"]
        self.assertEqual(len(auth), 0)

    def test_unhealthy_deployment_detected(self):
        """Agent deployment not succeeded triggers deployment_unhealthy."""
        idx = _build_index([_foundry_agent_deploy_ev({
            "DeploymentId": "dep-1", "Name": "broken-deploy",
            "ApplicationName": "my-app",
            "ProvisioningState": "Failed",
        })])
        findings = self.analyze(idx)
        bad = [f for f in findings if f["Subcategory"] == "deployment_unhealthy"]
        self.assertGreater(len(bad), 0)

    def test_healthy_deployment_no_finding(self):
        """Succeeded deployment is clean."""
        idx = _build_index([_foundry_agent_deploy_ev({
            "DeploymentId": "dep-2", "Name": "good-deploy",
            "ApplicationName": "my-app",
            "ProvisioningState": "Succeeded",
        })])
        findings = self.analyze(idx)
        bad = [f for f in findings if f["Subcategory"] == "deployment_unhealthy"]
        self.assertEqual(len(bad), 0)



# ====================================================================
# B16. Foundry — Agent Identity Security
# ====================================================================

class TestFoundryAgentIdentity(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_agent_identity
        self.analyze = analyze_foundry_agent_identity

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_project_no_managed_identity_detected(self):
        """Foundry project without MI triggers project_no_managed_identity."""
        idx = _build_index([_foundry_project_ev({
            "ProjectId": "proj-1", "Name": "my-project",
            "AccountName": "my-account",
            "HasManagedIdentity": False,
        })])
        findings = self.analyze(idx)
        mi = [f for f in findings if f["Subcategory"] == "project_no_managed_identity"]
        self.assertGreater(len(mi), 0)

    def test_project_with_mi_no_finding(self):
        """Project with MI does not trigger finding."""
        idx = _build_index([_foundry_project_ev({
            "ProjectId": "proj-2", "Name": "secure-project",
            "AccountName": "my-account",
            "HasManagedIdentity": True,
            "AgentCount": 1,
        })])
        findings = self.analyze(idx)
        mi = [f for f in findings if f["Subcategory"] == "project_no_managed_identity"]
        self.assertEqual(len(mi), 0)

    def test_shared_identity_detected(self):
        """Multiple unpublished agents sharing project identity triggers finding."""
        idx = _build_index([
            _foundry_project_ev({
                "ProjectId": "proj-3", "Name": "busy-project",
                "AccountName": "acct",
                "HasManagedIdentity": True,
                "AgentCount": 5,
            }),
        ])
        findings = self.analyze(idx)
        shared = [f for f in findings if f["Subcategory"] == "shared_project_identity"]
        self.assertGreater(len(shared), 0)

    def test_agent_permission_drift_detected(self):
        """Published app without RBAC triggers agent_permission_drift."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "app-1", "Name": "my-agent-app",
            "ProjectName": "proj",
            "HasRBACAssignments": False,
        })])
        findings = self.analyze(idx)
        drift = [f for f in findings if f["Subcategory"] == "agent_permission_drift"]
        self.assertGreater(len(drift), 0)

    def test_agent_with_rbac_no_drift(self):
        """Published app with RBAC does not trigger drift finding."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "app-2", "Name": "rbac-agent",
            "ProjectName": "proj",
            "HasRBACAssignments": True,
        })])
        findings = self.analyze(idx)
        drift = [f for f in findings if f["Subcategory"] == "agent_permission_drift"]
        self.assertEqual(len(drift), 0)


# ====================================================================
# B17. Foundry — Agent Application Security
# ====================================================================

class TestFoundryAgentApplication(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_agent_application
        self.analyze = analyze_foundry_agent_application

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_public_endpoint_detected(self):
        """Agent app with public endpoint triggers public_endpoint_exposure."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "app-pub", "Name": "public-agent",
            "IsPublicEndpoint": True,
            "Protocol": "ResponsesAPI",
            "AuthenticationType": "RBAC",
        })])
        findings = self.analyze(idx)
        pub = [f for f in findings if f["Subcategory"] == "public_endpoint_exposure"]
        self.assertGreater(len(pub), 0)

    def test_private_endpoint_no_finding(self):
        """Agent app with private endpoint (IsPublicEndpoint=False) is clean."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "app-priv", "Name": "private-agent",
            "IsPublicEndpoint": False,
            "AuthenticationType": "RBAC",
        })])
        findings = self.analyze(idx)
        pub = [f for f in findings if f["Subcategory"] == "public_endpoint_exposure"]
        self.assertEqual(len(pub), 0)

    def test_no_auth_detected(self):
        """Agent app without auth triggers no_auth_policy."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "app-noauth", "Name": "unauth-agent",
            "AuthenticationType": "None",
            "IsPublicEndpoint": True,
        })])
        findings = self.analyze(idx)
        auth = [f for f in findings if f["Subcategory"] == "no_auth_policy"]
        self.assertGreater(len(auth), 0)

    def test_rbac_auth_no_finding(self):
        """Agent app with RBAC auth is clean."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "app-rbac", "Name": "secure-agent",
            "AuthenticationType": "RBAC",
            "IsPublicEndpoint": False,
        })])
        findings = self.analyze(idx)
        auth = [f for f in findings if f["Subcategory"] == "no_auth_policy"]
        self.assertEqual(len(auth), 0)

    def test_unhealthy_deployment_detected(self):
        """Agent deployment not succeeded triggers deployment_unhealthy."""
        idx = _build_index([_foundry_agent_deploy_ev({
            "DeploymentId": "dep-1", "Name": "broken-deploy",
            "ApplicationName": "my-app",
            "ProvisioningState": "Failed",
        })])
        findings = self.analyze(idx)
        bad = [f for f in findings if f["Subcategory"] == "deployment_unhealthy"]
        self.assertGreater(len(bad), 0)

    def test_healthy_deployment_no_finding(self):
        """Succeeded deployment is clean."""
        idx = _build_index([_foundry_agent_deploy_ev({
            "DeploymentId": "dep-2", "Name": "good-deploy",
            "ApplicationName": "my-app",
            "ProvisioningState": "Succeeded",
        })])
        findings = self.analyze(idx)
        bad = [f for f in findings if f["Subcategory"] == "deployment_unhealthy"]
        self.assertEqual(len(bad), 0)


# ====================================================================
# B18. Foundry — MCP Tool Security
# ====================================================================

class TestFoundryMCPTools(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_mcp_tools
        self.analyze = analyze_foundry_mcp_tools

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_mcp_no_auth_detected(self):
        """MCP connection with apikey auth triggers mcp_no_secure_auth."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-mcp-1", "Name": "my-mcp-server",
            "WorkspaceName": "ws1",
            "Category": "MCP",
            "AuthType": "ApiKey",
            "Target": "https://mcp.example.com/sse",
            "IsSharedToAll": False,
        })])
        findings = self.analyze(idx)
        auth = [f for f in findings if f["Subcategory"] == "mcp_no_secure_auth"]
        self.assertGreater(len(auth), 0)

    def test_mcp_entra_auth_no_finding(self):
        """MCP connection with Entra auth is clean."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-mcp-2", "Name": "secure-mcp",
            "WorkspaceName": "ws1",
            "Category": "MCP",
            "AuthType": "AAD",
            "Target": "https://mcp.internal.azure.com/sse",
            "IsSharedToAll": False,
        })])
        findings = self.analyze(idx)
        auth = [f for f in findings if f["Subcategory"] == "mcp_no_secure_auth"]
        self.assertEqual(len(auth), 0)

    def test_mcp_public_endpoint_detected(self):
        """MCP connection on public URL triggers mcp_public_endpoint."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-mcp-3", "Name": "public-mcp",
            "WorkspaceName": "ws1",
            "Category": "MCP",
            "AuthType": "AAD",
            "Target": "https://mcp.example.com/sse",
            "IsSharedToAll": False,
        })])
        findings = self.analyze(idx)
        pub = [f for f in findings if f["Subcategory"] == "mcp_public_endpoint"]
        self.assertGreater(len(pub), 0)

    def test_mcp_private_endpoint_no_finding(self):
        """MCP connection on privatelink URL is clean."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-mcp-4", "Name": "private-mcp",
            "WorkspaceName": "ws1",
            "Category": "MCP",
            "AuthType": "AAD",
            "Target": "https://myserver.privatelink.azure.com/sse",
            "IsSharedToAll": False,
        })])
        findings = self.analyze(idx)
        pub = [f for f in findings if f["Subcategory"] == "mcp_public_endpoint"]
        self.assertEqual(len(pub), 0)

    def test_mcp_shared_to_all_detected(self):
        """MCP connection shared to all triggers mcp_shared_to_all."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-mcp-5", "Name": "shared-mcp",
            "WorkspaceName": "ws1",
            "Category": "MCP",
            "AuthType": "AAD",
            "Target": "https://mcp.internal.azure.com/sse",
            "IsSharedToAll": True,
        })])
        findings = self.analyze(idx)
        shared = [f for f in findings if f["Subcategory"] == "mcp_shared_to_all"]
        self.assertGreater(len(shared), 0)

    def test_non_mcp_connection_no_finding(self):
        """Non-MCP connection should not trigger MCP findings."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-other", "Name": "storage-conn",
            "WorkspaceName": "ws1",
            "Category": "AzureBlob",
            "AuthType": "ApiKey",
            "Target": "https://storage.blob.core.windows.net",
            "IsSharedToAll": True,
        })])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)


# ====================================================================
# B19. Foundry — Tool Connection Security
# ====================================================================

class TestFoundryToolSecurity(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_tool_security
        self.analyze = analyze_foundry_tool_security

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_a2a_no_auth_detected(self):
        """A2A connection without identity auth triggers a2a_no_identity_auth."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-a2a-1", "Name": "agent-link",
            "WorkspaceName": "ws1",
            "Category": "A2A",
            "AuthType": "ApiKey",
            "Target": "https://other-agent.azure.com/api",
        })])
        findings = self.analyze(idx)
        a2a = [f for f in findings if f["Subcategory"] == "a2a_no_identity_auth"]
        self.assertGreater(len(a2a), 0)

    def test_a2a_entra_auth_no_finding(self):
        """A2A connection with Entra ID auth is clean."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-a2a-2", "Name": "secure-agent-link",
            "WorkspaceName": "ws1",
            "Category": "A2A",
            "AuthType": "AAD",
            "Target": "https://agent.azure.com/api",
        })])
        findings = self.analyze(idx)
        a2a = [f for f in findings if f["Subcategory"] == "a2a_no_identity_auth"]
        self.assertEqual(len(a2a), 0)

    def test_non_microsoft_tool_detected(self):
        """MCP to non-MS endpoint triggers non_microsoft_tool_connection."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-ext-1", "Name": "external-tool",
            "WorkspaceName": "ws1",
            "Category": "MCP",
            "AuthType": "AAD",
            "Target": "https://tools.thirdparty.io/api",
        })])
        findings = self.analyze(idx)
        ext = [f for f in findings if f["Subcategory"] == "non_microsoft_tool_connection"]
        self.assertGreater(len(ext), 0)

    def test_microsoft_tool_no_finding(self):
        """MCP to Azure endpoint does not trigger non-MS finding."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-az-1", "Name": "azure-tool",
            "WorkspaceName": "ws1",
            "Category": "MCP",
            "AuthType": "AAD",
            "Target": "https://mymcp.azure.com/sse",
        })])
        findings = self.analyze(idx)
        ext = [f for f in findings if f["Subcategory"] == "non_microsoft_tool_connection"]
        self.assertEqual(len(ext), 0)

    def test_credential_based_tool_detected(self):
        """Tool connection with API key triggers tool_credential_based_auth."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-func-1", "Name": "my-function",
            "WorkspaceName": "ws1",
            "Category": "AzureFunction",
            "AuthType": "ApiKey",
            "Target": "https://func.azurewebsites.net",
        })])
        findings = self.analyze(idx)
        cred = [f for f in findings if f["Subcategory"] == "tool_credential_based_auth"]
        self.assertGreater(len(cred), 0)

    def test_mi_tool_no_credential_finding(self):
        """Tool connection with managed identity has no credential finding."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-func-2", "Name": "mi-function",
            "WorkspaceName": "ws1",
            "Category": "AzureFunction",
            "AuthType": "ManagedIdentity",
            "Target": "https://func.azurewebsites.net",
        })])
        findings = self.analyze(idx)
        cred = [f for f in findings if f["Subcategory"] == "tool_credential_based_auth"]
        self.assertEqual(len(cred), 0)


# ====================================================================
# B20. Foundry — Guardrails Configuration
# ====================================================================

class TestFoundryGuardrails(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_guardrails
        self.analyze = analyze_foundry_guardrails

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_no_custom_guardrail_detected(self):
        """Agent app with no guardrail triggers agent_no_custom_guardrail."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "/sub/app1", "Name": "agent-1",
            "ProjectName": "proj-1", "AccountName": "acct-1",
            "GuardrailCollection": "",
        })])
        findings = self.analyze(idx)
        guard = [f for f in findings if f["Subcategory"] == "agent_no_custom_guardrail"]
        self.assertGreater(len(guard), 0)

    def test_default_guardrail_detected(self):
        """Agent app with Microsoft.DefaultV2 guardrail triggers finding."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "/sub/app2", "Name": "agent-2",
            "ProjectName": "proj-1", "AccountName": "acct-1",
            "GuardrailCollection": "Microsoft.DefaultV2",
        })])
        findings = self.analyze(idx)
        guard = [f for f in findings if f["Subcategory"] == "agent_no_custom_guardrail"]
        self.assertGreater(len(guard), 0)

    def test_custom_guardrail_no_finding(self):
        """Agent app with custom guardrail is clean."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "/sub/app3", "Name": "agent-3",
            "ProjectName": "proj-1", "AccountName": "acct-1",
            "GuardrailCollection": "MyCustomGuardrails",
        })])
        findings = self.analyze(idx)
        guard = [f for f in findings if f["Subcategory"] == "agent_no_custom_guardrail"]
        self.assertEqual(len(guard), 0)

    def test_agent_account_no_content_safety(self):
        """Agent in account with no content filters triggers finding."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "/sub/app4", "Name": "agent-4",
            "ProjectName": "proj-1", "AccountName": "acct-no-filters",
        })])
        findings = self.analyze(idx)
        safety = [f for f in findings if f["Subcategory"] == "agent_account_no_content_safety"]
        self.assertGreater(len(safety), 0)

    def test_agent_account_with_content_safety_no_finding(self):
        """Agent in account that has content filters is clean."""
        idx = _build_index([
            _foundry_agent_app_ev({
                "ApplicationId": "/sub/app5", "Name": "agent-5",
                "ProjectName": "proj-1", "AccountName": "acct-safe",
            }),
            _ai_filter_ev({"AccountName": "acct-safe", "Name": "filter-1"}),
        ])
        findings = self.analyze(idx)
        safety = [f for f in findings if f["Subcategory"] == "agent_account_no_content_safety"]
        self.assertEqual(len(safety), 0)


# ====================================================================
# B21. Foundry — Hosted Agent Security
# ====================================================================

class TestFoundryHostedAgents(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_hosted_agents
        self.analyze = analyze_foundry_hosted_agents

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_hosted_no_vnet_detected(self):
        """Capability host without VNet triggers hosted_no_vnet."""
        idx = _build_index([_foundry_capability_host_ev({
            "CapabilityHostId": "/sub/ch1", "Name": "cap-host-1",
            "AccountName": "acct-1",
            "HasVNetConfig": False,
            "ContainerRegistryId": "/sub/acr1",
            "ProvisioningState": "Succeeded",
        })])
        findings = self.analyze(idx)
        vnet = [f for f in findings if f["Subcategory"] == "hosted_no_vnet"]
        self.assertGreater(len(vnet), 0)

    def test_hosted_with_vnet_no_finding(self):
        """Capability host with VNet is clean."""
        idx = _build_index([_foundry_capability_host_ev({
            "CapabilityHostId": "/sub/ch2", "Name": "cap-host-2",
            "AccountName": "acct-1",
            "HasVNetConfig": True,
            "ContainerRegistryId": "/sub/acr1",
            "ProvisioningState": "Succeeded",
        })])
        findings = self.analyze(idx)
        vnet = [f for f in findings if f["Subcategory"] == "hosted_no_vnet"]
        self.assertEqual(len(vnet), 0)

    def test_hosted_no_acr_detected(self):
        """Capability host without ACR triggers hosted_no_acr."""
        idx = _build_index([_foundry_capability_host_ev({
            "CapabilityHostId": "/sub/ch3", "Name": "cap-host-3",
            "AccountName": "acct-1",
            "HasVNetConfig": True,
            "ContainerRegistryId": "",
            "AcrRegistryName": "",
            "ProvisioningState": "Succeeded",
        })])
        findings = self.analyze(idx)
        acr = [f for f in findings if f["Subcategory"] == "hosted_no_acr"]
        self.assertGreater(len(acr), 0)

    def test_hosted_with_acr_no_finding(self):
        """Capability host with ACR configured is clean."""
        idx = _build_index([_foundry_capability_host_ev({
            "CapabilityHostId": "/sub/ch4", "Name": "cap-host-4",
            "AccountName": "acct-1",
            "HasVNetConfig": True,
            "ContainerRegistryId": "/sub/acr1",
            "ProvisioningState": "Succeeded",
        })])
        findings = self.analyze(idx)
        acr = [f for f in findings if f["Subcategory"] == "hosted_no_acr"]
        self.assertEqual(len(acr), 0)

    def test_hosted_unhealthy_detected(self):
        """Capability host with failed state triggers hosted_unhealthy."""
        idx = _build_index([_foundry_capability_host_ev({
            "CapabilityHostId": "/sub/ch5", "Name": "cap-host-5",
            "AccountName": "acct-1",
            "HasVNetConfig": True,
            "ContainerRegistryId": "/sub/acr1",
            "ProvisioningState": "Failed",
        })])
        findings = self.analyze(idx)
        unhealthy = [f for f in findings if f["Subcategory"] == "hosted_unhealthy"]
        self.assertGreater(len(unhealthy), 0)

    def test_hosted_succeeded_no_unhealthy_finding(self):
        """Capability host with Succeeded state is clean."""
        idx = _build_index([_foundry_capability_host_ev({
            "CapabilityHostId": "/sub/ch6", "Name": "cap-host-6",
            "AccountName": "acct-1",
            "HasVNetConfig": True,
            "ContainerRegistryId": "/sub/acr1",
            "ProvisioningState": "Succeeded",
        })])
        findings = self.analyze(idx)
        unhealthy = [f for f in findings if f["Subcategory"] == "hosted_unhealthy"]
        self.assertEqual(len(unhealthy), 0)


# ====================================================================
# B22. Foundry — Agent Data Resources
# ====================================================================

class TestFoundryDataResources(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_data_resources
        self.analyze = analyze_foundry_data_resources

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_cosmos_no_mi_detected(self):
        """Cosmos DB connection with API key triggers data_connection_no_managed_identity."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-cosmos-1", "Name": "cosmos-state",
            "WorkspaceName": "ws1",
            "Category": "CosmosDB",
            "AuthType": "ApiKey",
            "Target": "https://myagent.documents.azure.com",
            "IsSharedToAll": False,
        })])
        findings = self.analyze(idx)
        mi = [f for f in findings if f["Subcategory"] == "data_connection_no_managed_identity"]
        self.assertGreater(len(mi), 0)

    def test_cosmos_mi_no_finding(self):
        """Cosmos DB connection with managed identity is clean."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-cosmos-2", "Name": "cosmos-mi",
            "WorkspaceName": "ws1",
            "Category": "CosmosDB",
            "AuthType": "ManagedIdentity",
            "Target": "https://myagent.documents.azure.com",
            "IsSharedToAll": False,
        })])
        findings = self.analyze(idx)
        mi = [f for f in findings if f["Subcategory"] == "data_connection_no_managed_identity"]
        self.assertEqual(len(mi), 0)

    def test_aisearch_no_mi_detected(self):
        """AI Search connection with API key triggers finding."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-search-1", "Name": "search-conn",
            "WorkspaceName": "ws1",
            "Category": "CognitiveSearch",
            "AuthType": "ApiKey",
            "Target": "https://mysearch.search.windows.net",
            "IsSharedToAll": False,
        })])
        findings = self.analyze(idx)
        mi = [f for f in findings if f["Subcategory"] == "data_connection_no_managed_identity"]
        self.assertGreater(len(mi), 0)

    def test_no_cmk_detected(self):
        """AI service account without CMK triggers no_customer_managed_key."""
        idx = _build_index([_ai_service_ev({
            "AccountId": "/sub/acct1", "Name": "myai",
            "Kind": "AIServices", "HasCMK": False,
        })])
        findings = self.analyze(idx)
        cmk = [f for f in findings if f["Subcategory"] == "no_customer_managed_key"]
        self.assertGreater(len(cmk), 0)

    def test_cmk_no_finding(self):
        """AI service account with CMK is clean."""
        idx = _build_index([_ai_service_ev({
            "AccountId": "/sub/acct2", "Name": "myai-cmk",
            "Kind": "AIServices", "HasCMK": True,
        })])
        findings = self.analyze(idx)
        cmk = [f for f in findings if f["Subcategory"] == "no_customer_managed_key"]
        self.assertEqual(len(cmk), 0)

    def test_data_shared_to_all_detected(self):
        """Data connection shared to all triggers data_connection_shared_to_all."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-blob-1", "Name": "blob-store",
            "WorkspaceName": "ws1",
            "Category": "AzureBlobStorage",
            "AuthType": "ManagedIdentity",
            "IsSharedToAll": True,
        })])
        findings = self.analyze(idx)
        shared = [f for f in findings if f["Subcategory"] == "data_connection_shared_to_all"]
        self.assertGreater(len(shared), 0)

    def test_non_data_connection_ignored(self):
        """Non-data connections (e.g., Git) should not trigger findings."""
        idx = _build_index([_ai_connection_ev({
            "ConnectionId": "conn-git-1", "Name": "github-repo",
            "WorkspaceName": "ws1",
            "Category": "GitHub",
            "AuthType": "PAT",
            "IsSharedToAll": True,
        })])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)


# ====================================================================
# B23. Foundry — Agent Observability
# ====================================================================

class TestFoundryObservability(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_observability
        self.analyze = analyze_foundry_observability

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_workspace_no_diagnostics_detected(self):
        """Workspace without diagnostics triggers workspace_no_diagnostics."""
        idx = _build_index([_ai_ws_diag_ev({
            "WorkspaceId": "/sub/ws1", "WorkspaceName": "ws1",
            "HasDiagnostics": False,
        })])
        findings = self.analyze(idx)
        diag = [f for f in findings if f["Subcategory"] == "workspace_no_diagnostics"]
        self.assertGreater(len(diag), 0)

    def test_workspace_with_diagnostics_no_finding(self):
        """Workspace with diagnostics is clean for workspace_no_diagnostics."""
        idx = _build_index([_ai_ws_diag_ev({
            "WorkspaceId": "/sub/ws2", "WorkspaceName": "ws2",
            "HasDiagnostics": True,
            "HasLogAnalytics": True,
            "EnabledLogs": ["Audit", "RequestResponse"],
            "EnabledMetrics": ["AllMetrics"],
        })])
        findings = self.analyze(idx)
        diag = [f for f in findings if f["Subcategory"] == "workspace_no_diagnostics"]
        self.assertEqual(len(diag), 0)

    def test_project_no_tracing_detected(self):
        """Foundry project without linked diagnostics triggers project_no_tracing."""
        idx = _build_index([_foundry_project_ev({
            "ProjectId": "/sub/proj1", "Name": "my-project",
            "AccountName": "my-account",
        })])
        findings = self.analyze(idx)
        trace = [f for f in findings if f["Subcategory"] == "project_no_tracing"]
        self.assertGreater(len(trace), 0)

    def test_project_with_tracing_no_finding(self):
        """Foundry project with matching monitored workspace is clean."""
        idx = _build_index([
            _foundry_project_ev({
                "ProjectId": "/sub/proj2", "Name": "my-project",
                "AccountName": "my-account",
            }),
            _ai_ws_diag_ev({
                "WorkspaceId": "/sub/ws-acct", "WorkspaceName": "my-account",
                "HasDiagnostics": True, "HasLogAnalytics": True,
            }),
        ])
        findings = self.analyze(idx)
        trace = [f for f in findings if f["Subcategory"] == "project_no_tracing"]
        self.assertEqual(len(trace), 0)

    def test_workspace_limited_logs_detected(self):
        """Workspace with incomplete log coverage triggers finding."""
        idx = _build_index([_ai_ws_diag_ev({
            "WorkspaceId": "/sub/ws3", "WorkspaceName": "ws3",
            "HasDiagnostics": True,
            "EnabledLogs": ["Audit"],
            "EnabledMetrics": [],
        })])
        findings = self.analyze(idx)
        limited = [f for f in findings if f["Subcategory"] == "workspace_limited_log_coverage"]
        self.assertGreater(len(limited), 0)

    def test_workspace_full_logs_no_finding(self):
        """Workspace with all required log categories is clean."""
        idx = _build_index([_ai_ws_diag_ev({
            "WorkspaceId": "/sub/ws4", "WorkspaceName": "ws4",
            "HasDiagnostics": True,
            "EnabledLogs": ["Audit", "RequestResponse"],
            "EnabledMetrics": ["AllMetrics"],
        })])
        findings = self.analyze(idx)
        limited = [f for f in findings if f["Subcategory"] == "workspace_limited_log_coverage"]
        self.assertEqual(len(limited), 0)


# ====================================================================
# B24. Foundry — Agent Lifecycle Governance
# ====================================================================

class TestFoundryLifecycle(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_foundry_lifecycle
        self.analyze = analyze_foundry_lifecycle

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_shadow_agents_detected(self):
        """Project with agents but no published apps triggers shadow finding."""
        idx = _build_index([_foundry_project_ev({
            "ProjectId": "/sub/proj1", "Name": "dev-project",
            "AccountName": "acct-1", "AgentCount": 5,
        })])
        findings = self.analyze(idx)
        shadow = [f for f in findings if f["Subcategory"] == "shadow_agents_unpublished"]
        self.assertGreater(len(shadow), 0)

    def test_no_shadow_agents_when_published(self):
        """Project with agents and published apps is clean."""
        idx = _build_index([
            _foundry_project_ev({
                "ProjectId": "/sub/proj2", "Name": "prod-project",
                "AccountName": "acct-1", "AgentCount": 3,
            }),
            _foundry_agent_app_ev({
                "ApplicationId": "/sub/app1", "Name": "agent-1",
                "ProjectId": "/sub/proj2", "ProjectName": "prod-project",
            }),
        ])
        findings = self.analyze(idx)
        shadow = [f for f in findings if f["Subcategory"] == "shadow_agents_unpublished"]
        self.assertEqual(len(shadow), 0)

    def test_no_shadow_when_zero_agents(self):
        """Project with zero agents count does not trigger shadow finding."""
        idx = _build_index([_foundry_project_ev({
            "ProjectId": "/sub/proj3", "Name": "empty-project",
            "AccountName": "acct-1", "AgentCount": 0,
        })])
        findings = self.analyze(idx)
        shadow = [f for f in findings if f["Subcategory"] == "shadow_agents_unpublished"]
        self.assertEqual(len(shadow), 0)

    def test_excess_unpublished_detected(self):
        """Project with many more agents than published apps triggers excess finding."""
        idx = _build_index([
            _foundry_project_ev({
                "ProjectId": "/sub/proj4", "Name": "sprawl-project",
                "AccountName": "acct-1", "AgentCount": 20,
            }),
            _foundry_agent_app_ev({
                "ApplicationId": "/sub/app2", "Name": "only-app",
                "ProjectId": "/sub/proj4", "ProjectName": "sprawl-project",
            }),
        ])
        findings = self.analyze(idx)
        excess = [f for f in findings if f["Subcategory"] == "excess_unpublished_agents"]
        self.assertGreater(len(excess), 0)

    def test_balanced_agents_no_excess(self):
        """Project with balanced agent/app ratio is clean."""
        idx = _build_index([
            _foundry_project_ev({
                "ProjectId": "/sub/proj5", "Name": "balanced-project",
                "AccountName": "acct-1", "AgentCount": 3,
            }),
            _foundry_agent_app_ev({
                "ApplicationId": "/sub/app3", "Name": "app-1",
                "ProjectId": "/sub/proj5", "ProjectName": "balanced-project",
            }),
            _foundry_agent_app_ev({
                "ApplicationId": "/sub/app4", "Name": "app-2",
                "ProjectId": "/sub/proj5", "ProjectName": "balanced-project",
            }),
        ])
        findings = self.analyze(idx)
        excess = [f for f in findings if f["Subcategory"] == "excess_unpublished_agents"]
        self.assertEqual(len(excess), 0)

    def test_agent_no_rbac_detected(self):
        """Published agent without RBAC triggers agent_no_rbac."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "/sub/app5", "Name": "no-rbac-agent",
            "ProjectName": "proj-1", "AccountName": "acct-1",
            "HasRBACAssignments": False,
        })])
        findings = self.analyze(idx)
        rbac = [f for f in findings if f["Subcategory"] == "agent_no_rbac"]
        self.assertGreater(len(rbac), 0)

    def test_agent_with_rbac_no_finding(self):
        """Published agent with explicit RBAC is clean."""
        idx = _build_index([_foundry_agent_app_ev({
            "ApplicationId": "/sub/app6", "Name": "rbac-agent",
            "ProjectName": "proj-1", "AccountName": "acct-1",
            "HasRBACAssignments": True,
        })])
        findings = self.analyze(idx)
        rbac = [f for f in findings if f["Subcategory"] == "agent_no_rbac"]
        self.assertEqual(len(rbac), 0)

# ====================================================================
# D1. Entra — AI Service Principals
# ====================================================================

class TestEntraServicePrincipals(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_entra_ai_service_principals
        self.analyze = analyze_entra_ai_service_principals

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_excessive_permissions_detected(self):
        """SP with Directory.ReadWrite.All triggers sp_excessive_permissions."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-1", "DisplayName": "AI App",
            "APIPermissions": ["Directory.ReadWrite.All", "User.Read"],
        })])
        findings = self.analyze(idx)
        excessive = [f for f in findings if f["Subcategory"] == "sp_excessive_permissions"]
        self.assertGreater(len(excessive), 0)
        self.assertEqual(excessive[0]["Severity"], "high")

    def test_credential_expiry_detected(self):
        """Expired credential triggers sp_credential_expiry."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-2", "DisplayName": "Expired App",
            "CredentialStatus": "expired", "CredentialExpiry": "2024-01-01",
        })])
        findings = self.analyze(idx)
        expiry = [f for f in findings if f["Subcategory"] == "sp_credential_expiry"]
        self.assertGreater(len(expiry), 0)

    def test_no_rotation_detected(self):
        """Single credential without managed identity triggers sp_no_credential_rotation."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-3", "DisplayName": "Single Cred App",
            "CredentialCount": 1, "UsesManagedIdentity": False,
        })])
        findings = self.analyze(idx)
        rotation = [f for f in findings if f["Subcategory"] == "sp_no_credential_rotation"]
        self.assertGreater(len(rotation), 0)

    def test_multi_tenant_detected(self):
        """Multi-tenant sign-in audience triggers sp_multi_tenant_exposure."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-4", "DisplayName": "Multi Tenant App",
            "SignInAudience": "AzureADMultipleOrgs",
        })])
        findings = self.analyze(idx)
        mt = [f for f in findings if f["Subcategory"] == "sp_multi_tenant_exposure"]
        self.assertGreater(len(mt), 0)

    def test_healthy_sp_no_finding(self):
        """SP with minimal perms, valid creds, single-tenant, managed identity yields no findings."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-ok", "DisplayName": "Good App",
            "APIPermissions": ["User.Read"],
            "CredentialStatus": "valid",
            "CredentialCount": 2,
            "UsesManagedIdentity": True,
            "SignInAudience": "AzureADMyOrg",
        })])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)


# ====================================================================
# D2. Entra — AI Conditional Access
# ====================================================================

class TestEntraConditionalAccess(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_entra_ai_conditional_access
        self.analyze = analyze_entra_ai_conditional_access

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_no_ca_detected(self):
        """CoveredByCA == False triggers no_ca_for_ai_apps."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-noca", "DisplayName": "No CA App",
            "CoveredByCA": False,
        })])
        findings = self.analyze(idx)
        noca = [f for f in findings if f["Subcategory"] == "no_ca_for_ai_apps"]
        self.assertGreater(len(noca), 0)
        self.assertEqual(noca[0]["Severity"], "high")

    def test_no_token_lifetime_detected(self):
        """HasTokenLifetimePolicy == False triggers no_token_lifetime_restriction."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-notl", "DisplayName": "No TL App",
            "HasTokenLifetimePolicy": False,
        })])
        findings = self.analyze(idx)
        tl = [f for f in findings if f["Subcategory"] == "no_token_lifetime_restriction"]
        self.assertGreater(len(tl), 0)

    def test_ca_covered_no_finding(self):
        """SP covered by CA and with token lifetime policy yields no findings."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-ok", "DisplayName": "Covered App",
            "CoveredByCA": True,
            "HasTokenLifetimePolicy": True,
            "CARequiresMFA": True,
            "CARequiresCompliantDevice": True,
            "CAHasLocationCondition": False,
            "CAEEnabled": True,
            "CASignInFrequency": True,
        })])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)


# ====================================================================
# D3. Entra — AI Consent Grants
# ====================================================================

class TestEntraConsent(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_entra_ai_consent
        self.analyze = analyze_entra_ai_consent

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_broad_user_consent_detected(self):
        """User consent with sensitive scopes triggers broad_user_consent_to_ai_apps."""
        idx = _build_index([_entra_consent_ev({
            "AppId": "app-consent", "AppDisplayName": "AI App",
            "ConsentType": "user",
            "Scopes": ["Mail.Read", "Files.ReadWrite.All"],
            "UserPrincipalName": "user@example.com",
        })])
        findings = self.analyze(idx)
        broad = [f for f in findings if f["Subcategory"] == "broad_user_consent_to_ai_apps"]
        self.assertGreater(len(broad), 0)

    def test_admin_consent_high_privilege_detected(self):
        """Admin consent with high-privilege scopes triggers finding."""
        idx = _build_index([_entra_consent_ev({
            "AppId": "app-admin", "AppDisplayName": "Admin AI",
            "ConsentType": "admin",
            "Scopes": ["Directory.ReadWrite.All"],
        })])
        findings = self.analyze(idx)
        admin = [f for f in findings if f["Subcategory"] == "admin_consent_ai_high_privilege"]
        self.assertGreater(len(admin), 0)

    def test_safe_consent_no_finding(self):
        """User consent with non-sensitive scopes yields no findings."""
        idx = _build_index([_entra_consent_ev({
            "AppId": "app-safe", "AppDisplayName": "Safe AI",
            "ConsentType": "user",
            "Scopes": ["User.Read", "openid", "profile"],
        })])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)


# ====================================================================
# D1b. Entra — New SP Sub-checks (Gaps 1, 2, 6, 7, 9, 11)
# ====================================================================

class TestEntraSPManagedIdentity(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_entra_ai_service_principals
        self.analyze = analyze_entra_ai_service_principals

    def test_no_managed_identity_detected(self):
        """SP with credentials but no managed identity triggers sp_no_managed_identity."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-nomi", "DisplayName": "No MI App",
            "UsesManagedIdentity": False, "CredentialCount": 2,
            "APIPermissions": [], "SignInAudience": "AzureADMyOrg",
            "CredentialStatus": "valid",
        })])
        findings = self.analyze(idx)
        nomi = [f for f in findings if f["Subcategory"] == "sp_no_managed_identity"]
        self.assertGreater(len(nomi), 0)
        self.assertEqual(nomi[0]["Severity"], "high")

    def test_managed_identity_sp_no_finding(self):
        """SP using managed identity does not trigger sp_no_managed_identity."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-mi", "DisplayName": "MI App",
            "UsesManagedIdentity": True, "CredentialCount": 0,
            "APIPermissions": [], "SignInAudience": "AzureADMyOrg",
            "CredentialStatus": "valid",
        })])
        findings = self.analyze(idx)
        nomi = [f for f in findings if f["Subcategory"] == "sp_no_managed_identity"]
        self.assertEqual(len(nomi), 0)


class TestEntraSPAIPermissions(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_entra_ai_service_principals
        self.analyze = analyze_entra_ai_service_principals

    def test_ai_api_over_scoped_detected(self):
        """SP with Cognitive Services Contributor role triggers sp_ai_api_over_scoped."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-aip", "DisplayName": "AI Perm App",
            "AzureRoleAssignments": ["Cognitive Services Contributor"],
            "APIPermissions": [], "SignInAudience": "AzureADMyOrg",
            "CredentialStatus": "valid", "CredentialCount": 2,
            "UsesManagedIdentity": True,
        })])
        findings = self.analyze(idx)
        over = [f for f in findings if f["Subcategory"] == "sp_ai_api_over_scoped"]
        self.assertGreater(len(over), 0)
        self.assertEqual(over[0]["Severity"], "high")

    def test_non_ai_roles_no_finding(self):
        """SP with non-AI roles does not trigger sp_ai_api_over_scoped."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-ok", "DisplayName": "Normal App",
            "AzureRoleAssignments": ["Reader"],
            "APIPermissions": ["User.Read"],
            "SignInAudience": "AzureADMyOrg",
            "CredentialStatus": "valid", "CredentialCount": 2,
            "UsesManagedIdentity": True,
        })])
        findings = self.analyze(idx)
        over = [f for f in findings if f["Subcategory"] == "sp_ai_api_over_scoped"]
        self.assertEqual(len(over), 0)


class TestEntraSPRisky(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_entra_ai_service_principals
        self.analyze = analyze_entra_ai_service_principals

    def test_risky_sp_detected(self):
        """SP with high risk level triggers sp_risky_identity_protection."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-risky", "DisplayName": "Risky AI App",
            "RiskLevel": "high", "RiskState": "atRisk",
            "APIPermissions": [], "SignInAudience": "AzureADMyOrg",
            "CredentialStatus": "valid", "CredentialCount": 2,
            "UsesManagedIdentity": True,
        })])
        findings = self.analyze(idx)
        risky = [f for f in findings if f["Subcategory"] == "sp_risky_identity_protection"]
        self.assertGreater(len(risky), 0)
        self.assertEqual(risky[0]["Severity"], "critical")

    def test_no_risk_no_finding(self):
        """SP with no risk does not trigger sp_risky_identity_protection."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-safe", "DisplayName": "Safe App",
            "RiskLevel": "none", "RiskState": "none",
            "APIPermissions": [], "SignInAudience": "AzureADMyOrg",
            "CredentialStatus": "valid", "CredentialCount": 2,
            "UsesManagedIdentity": True,
        })])
        findings = self.analyze(idx)
        risky = [f for f in findings if f["Subcategory"] == "sp_risky_identity_protection"]
        self.assertEqual(len(risky), 0)


class TestEntraSPPrivilegedRoles(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_entra_ai_service_principals
        self.analyze = analyze_entra_ai_service_principals

    def test_privileged_directory_roles_detected(self):
        """SP with Global Administrator triggers sp_privileged_directory_roles."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-priv", "DisplayName": "Priv AI App",
            "DirectoryRoles": ["Global Administrator"],
            "APIPermissions": [], "SignInAudience": "AzureADMyOrg",
            "CredentialStatus": "valid", "CredentialCount": 2,
            "UsesManagedIdentity": True,
        })])
        findings = self.analyze(idx)
        priv = [f for f in findings if f["Subcategory"] == "sp_privileged_directory_roles"]
        self.assertGreater(len(priv), 0)
        self.assertEqual(priv[0]["Severity"], "critical")

    def test_no_privileged_roles_no_finding(self):
        """SP without privileged roles does not trigger finding."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-ok", "DisplayName": "Normal App",
            "DirectoryRoles": [],
            "APIPermissions": [], "SignInAudience": "AzureADMyOrg",
            "CredentialStatus": "valid", "CredentialCount": 2,
            "UsesManagedIdentity": True,
        })])
        findings = self.analyze(idx)
        priv = [f for f in findings if f["Subcategory"] == "sp_privileged_directory_roles"]
        self.assertEqual(len(priv), 0)


class TestEntraSPOwnerGovernance(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_entra_ai_service_principals
        self.analyze = analyze_entra_ai_service_principals

    def test_single_owner_detected(self):
        """SP with just 1 owner triggers sp_owner_governance_weak."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-1own", "DisplayName": "Single Owner App",
            "Owners": [{"Name": "User1", "Type": "member"}],
            "APIPermissions": [], "SignInAudience": "AzureADMyOrg",
            "CredentialStatus": "valid", "CredentialCount": 2,
            "UsesManagedIdentity": True,
        })])
        findings = self.analyze(idx)
        own = [f for f in findings if f["Subcategory"] == "sp_owner_governance_weak"]
        self.assertGreater(len(own), 0)

    def test_guest_owner_detected(self):
        """SP with a guest owner triggers sp_owner_governance_weak."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-guest", "DisplayName": "Guest Owner App",
            "Owners": [{"Name": "Internal", "Type": "member"}, {"Name": "External", "Type": "guest"}],
            "APIPermissions": [], "SignInAudience": "AzureADMyOrg",
            "CredentialStatus": "valid", "CredentialCount": 2,
            "UsesManagedIdentity": True,
        })])
        findings = self.analyze(idx)
        own = [f for f in findings if f["Subcategory"] == "sp_owner_governance_weak"]
        self.assertGreater(len(own), 0)

    def test_good_ownership_no_finding(self):
        """SP with multiple member owners does not trigger finding."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-ok", "DisplayName": "Well Owned App",
            "Owners": [{"Name": "User1", "Type": "member"}, {"Name": "User2", "Type": "member"}],
            "APIPermissions": [], "SignInAudience": "AzureADMyOrg",
            "CredentialStatus": "valid", "CredentialCount": 2,
            "UsesManagedIdentity": True,
        })])
        findings = self.analyze(idx)
        own = [f for f in findings if f["Subcategory"] == "sp_owner_governance_weak"]
        self.assertEqual(len(own), 0)


class TestEntraSPStaleDisabled(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_entra_ai_service_principals
        self.analyze = analyze_entra_ai_service_principals

    def test_disabled_with_creds_detected(self):
        """Disabled SP with credentials triggers sp_stale_disabled."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-dis", "DisplayName": "Disabled App",
            "AccountEnabled": False, "CredentialCount": 1,
            "DirectoryRoles": [],
            "AzureRoleAssignments": [],
            "APIPermissions": [], "SignInAudience": "AzureADMyOrg",
            "CredentialStatus": "valid", "UsesManagedIdentity": False,
        })])
        findings = self.analyze(idx)
        stale = [f for f in findings if f["Subcategory"] == "sp_stale_disabled"]
        self.assertGreater(len(stale), 0)

    def test_enabled_sp_no_stale_finding(self):
        """Enabled SP does not trigger sp_stale_disabled regardless of credentials."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-en", "DisplayName": "Enabled App",
            "AccountEnabled": True, "CredentialCount": 1,
            "DirectoryRoles": [], "AzureRoleAssignments": [],
            "APIPermissions": [], "SignInAudience": "AzureADMyOrg",
            "CredentialStatus": "valid", "UsesManagedIdentity": False,
        })])
        findings = self.analyze(idx)
        stale = [f for f in findings if f["Subcategory"] == "sp_stale_disabled"]
        self.assertEqual(len(stale), 0)


# ====================================================================
# D2b. Entra — CA Quality & Session Controls (Gaps 4, 10)
# ====================================================================

class TestEntraCAQuality(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_entra_ai_conditional_access
        self.analyze = analyze_entra_ai_conditional_access

    def test_weak_ca_quality_detected(self):
        """CA-covered SP without MFA/compliance/location triggers ca_weak_policy_quality."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-weakca", "DisplayName": "Weak CA App",
            "CoveredByCA": True, "HasTokenLifetimePolicy": True,
            "CARequiresMFA": False, "CARequiresCompliantDevice": False,
            "CAHasLocationCondition": False,
        })])
        findings = self.analyze(idx)
        weak = [f for f in findings if f["Subcategory"] == "ca_weak_policy_quality"]
        self.assertGreater(len(weak), 0)
        self.assertEqual(weak[0]["Severity"], "high")

    def test_strong_ca_no_finding(self):
        """CA-covered SP with MFA does not trigger ca_weak_policy_quality."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-strongca", "DisplayName": "Strong CA App",
            "CoveredByCA": True, "HasTokenLifetimePolicy": True,
            "CARequiresMFA": True, "CARequiresCompliantDevice": False,
            "CAHasLocationCondition": False,
        })])
        findings = self.analyze(idx)
        weak = [f for f in findings if f["Subcategory"] == "ca_weak_policy_quality"]
        self.assertEqual(len(weak), 0)


class TestEntraCASessionControls(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_entra_ai_conditional_access
        self.analyze = analyze_entra_ai_conditional_access

    def test_no_session_controls_detected(self):
        """CA-covered SP without CAE or sign-in frequency triggers ca_no_session_controls."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-nosess", "DisplayName": "No Session App",
            "CoveredByCA": True, "HasTokenLifetimePolicy": True,
            "CARequiresMFA": True,
            "CAEEnabled": False, "CASignInFrequency": False,
        })])
        findings = self.analyze(idx)
        sess = [f for f in findings if f["Subcategory"] == "ca_no_session_controls"]
        self.assertGreater(len(sess), 0)
        self.assertEqual(sess[0]["Severity"], "medium")

    def test_cae_enabled_no_finding(self):
        """CA-covered SP with CAE enabled does not trigger finding."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-cae", "DisplayName": "CAE App",
            "CoveredByCA": True, "HasTokenLifetimePolicy": True,
            "CARequiresMFA": True,
            "CAEEnabled": True, "CASignInFrequency": False,
        })])
        findings = self.analyze(idx)
        sess = [f for f in findings if f["Subcategory"] == "ca_no_session_controls"]
        self.assertEqual(len(sess), 0)


# ====================================================================
# D3b. Entra — AI-Specific Consent Scopes (Gap 8)
# ====================================================================

class TestEntraAIConsentScopes(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_entra_ai_consent
        self.analyze = analyze_entra_ai_consent

    def test_ai_specific_scopes_detected(self):
        """Consent with CognitiveServices scopes triggers ai_specific_consent_scopes."""
        idx = _build_index([_entra_consent_ev({
            "AppId": "app-aiscope", "AppDisplayName": "AI Scope App",
            "ConsentType": "user",
            "Scopes": ["CognitiveServices.ReadWrite"],
        })])
        findings = self.analyze(idx)
        ai = [f for f in findings if f["Subcategory"] == "ai_specific_consent_scopes"]
        self.assertGreater(len(ai), 0)
        self.assertEqual(ai[0]["Severity"], "high")

    def test_third_party_admin_consent_detected(self):
        """Third-party app with admin consent triggers ai_specific_consent_scopes."""
        idx = _build_index([_entra_consent_ev({
            "AppId": "app-3p", "AppDisplayName": "Third Party AI",
            "ConsentType": "admin",
            "Scopes": ["User.Read"],
            "IsThirdParty": True,
        })])
        findings = self.analyze(idx)
        ai = [f for f in findings if f["Subcategory"] == "ai_specific_consent_scopes"]
        self.assertGreater(len(ai), 0)

    def test_normal_scopes_no_finding(self):
        """Non-AI scopes, first-party app does not trigger finding."""
        idx = _build_index([_entra_consent_ev({
            "AppId": "app-normal", "AppDisplayName": "Normal App",
            "ConsentType": "user",
            "Scopes": ["User.Read", "openid"],
            "IsThirdParty": False,
        })])
        findings = self.analyze(idx)
        ai = [f for f in findings if f["Subcategory"] == "ai_specific_consent_scopes"]
        self.assertEqual(len(ai), 0)


# ====================================================================
# D4. Entra — AI Workload Identity (Gap 3)
# ====================================================================

class TestEntraWorkloadIdentity(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_entra_ai_workload_identity
        self.analyze = analyze_entra_ai_workload_identity

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_missing_federation_detected(self):
        """SP with password creds but no federation triggers wif_missing_federation."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-nofed", "DisplayName": "No Fed App",
            "PasswordCredentialCount": 2, "HasFederatedCredential": False,
            "UsesManagedIdentity": False,
        })])
        findings = self.analyze(idx)
        wif = [f for f in findings if f["Subcategory"] == "wif_missing_federation"]
        self.assertGreater(len(wif), 0)
        self.assertEqual(wif[0]["Severity"], "medium")

    def test_federated_sp_no_finding(self):
        """SP with federated credential does not trigger finding."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-fed", "DisplayName": "Fed App",
            "PasswordCredentialCount": 1, "HasFederatedCredential": True,
            "UsesManagedIdentity": False,
        })])
        findings = self.analyze(idx)
        wif = [f for f in findings if f["Subcategory"] == "wif_missing_federation"]
        self.assertEqual(len(wif), 0)

    def test_managed_identity_sp_no_finding(self):
        """SP using managed identity does not trigger finding."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-mi", "DisplayName": "MI App",
            "PasswordCredentialCount": 0, "HasFederatedCredential": False,
            "UsesManagedIdentity": True,
        })])
        findings = self.analyze(idx)
        wif = [f for f in findings if f["Subcategory"] == "wif_missing_federation"]
        self.assertEqual(len(wif), 0)


# ====================================================================
# D5. Entra — AI Cross-Tenant Access (Gap 5)
# ====================================================================

class TestEntraCrossTenant(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_entra_ai_cross_tenant
        self.analyze = analyze_entra_ai_cross_tenant

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_cross_tenant_exposure_detected(self):
        """Multi-tenant SP + permissive cross-tenant policy triggers cross_tenant_ai_exposure."""
        idx = _build_index([
            _entra_sp_ev({
                "AppId": "app-mt", "DisplayName": "Multi Tenant AI",
                "SignInAudience": "AzureADMultipleOrgs",
            }),
            _entra_ct_policy_ev({"HasInboundRestrictions": False}),
        ])
        findings = self.analyze(idx)
        ct = [f for f in findings if f["Subcategory"] == "cross_tenant_ai_exposure"]
        self.assertGreater(len(ct), 0)
        self.assertEqual(ct[0]["Severity"], "high")

    def test_restricted_policy_no_finding(self):
        """Multi-tenant SP + restricted cross-tenant policy yields no finding."""
        idx = _build_index([
            _entra_sp_ev({
                "AppId": "app-mt2", "DisplayName": "Multi Tenant AI 2",
                "SignInAudience": "AzureADMultipleOrgs",
            }),
            _entra_ct_policy_ev({"HasInboundRestrictions": True}),
        ])
        findings = self.analyze(idx)
        ct = [f for f in findings if f["Subcategory"] == "cross_tenant_ai_exposure"]
        self.assertEqual(len(ct), 0)

    def test_single_tenant_no_finding(self):
        """Single-tenant SP + permissive policy yields no finding."""
        idx = _build_index([
            _entra_sp_ev({
                "AppId": "app-st", "DisplayName": "Single Tenant AI",
                "SignInAudience": "AzureADMyOrg",
            }),
            _entra_ct_policy_ev({"HasInboundRestrictions": False}),
        ])
        findings = self.analyze(idx)
        ct = [f for f in findings if f["Subcategory"] == "cross_tenant_ai_exposure"]
        self.assertEqual(len(ct), 0)


# ====================================================================
# D6. Entra — AI Privileged Access (Gap 12)
# ====================================================================

class TestEntraPrivilegedAccess(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_entra_ai_privileged_access
        self.analyze = analyze_entra_ai_privileged_access

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_pim_missing_detected(self):
        """SP with permanent AI role and no PIM triggers pim_missing_for_ai_roles."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-nopim", "DisplayName": "No PIM App",
            "AzureRoleAssignments": ["Cognitive Services Contributor"],
            "UsesPIM": False,
        })])
        findings = self.analyze(idx)
        pim = [f for f in findings if f["Subcategory"] == "pim_missing_for_ai_roles"]
        self.assertGreater(len(pim), 0)
        self.assertEqual(pim[0]["Severity"], "high")

    def test_pim_enabled_no_finding(self):
        """SP with PIM-eligible AI role does not trigger finding."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-pim", "DisplayName": "PIM App",
            "AzureRoleAssignments": ["Cognitive Services Contributor"],
            "UsesPIM": True,
        })])
        findings = self.analyze(idx)
        pim = [f for f in findings if f["Subcategory"] == "pim_missing_for_ai_roles"]
        self.assertEqual(len(pim), 0)

    def test_non_ai_role_no_finding(self):
        """SP with non-AI role without PIM does not trigger finding."""
        idx = _build_index([_entra_sp_ev({
            "AppId": "app-nonai", "DisplayName": "Non AI App",
            "AzureRoleAssignments": ["Reader"],
            "UsesPIM": False,
        })])
        findings = self.analyze(idx)
        pim = [f for f in findings if f["Subcategory"] == "pim_missing_for_ai_roles"]
        self.assertEqual(len(pim), 0)


# ====================================================================
# E1. AI Diagnostics
# ====================================================================

class TestAIDiagnostics(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_ai_diagnostics
        self.analyze = analyze_ai_diagnostics

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_no_diagnostic_settings_detected(self):
        """HasDiagnosticSettings == False triggers no_diagnostic_settings."""
        idx = _build_index([_ai_service_ev({
            "AccountId": "acc-nodiag", "Name": "no-diag-ai",
            "HasDiagnosticSettings": False, "Kind": "OpenAI",
        })])
        findings = self.analyze(idx)
        nodiag = [f for f in findings if f["Subcategory"] == "no_diagnostic_settings"]
        self.assertGreater(len(nodiag), 0)
        self.assertEqual(nodiag[0]["Severity"], "high")

    def test_no_audit_logging_detected(self):
        """Diagnostics enabled but missing audit category triggers no_audit_logging."""
        idx = _build_index([_ai_service_ev({
            "AccountId": "acc-noaud", "Name": "no-audit-ai",
            "HasDiagnosticSettings": True,
            "DiagnosticCategories": ["Metrics"],
        })])
        findings = self.analyze(idx)
        noaudit = [f for f in findings if f["Subcategory"] == "no_audit_logging"]
        self.assertGreater(len(noaudit), 0)

    def test_full_diagnostics_no_finding(self):
        """Diagnostics with Audit category yields no findings."""
        idx = _build_index([_ai_service_ev({
            "AccountId": "acc-ok", "Name": "good-ai",
            "HasDiagnosticSettings": True,
            "DiagnosticCategories": ["Audit", "RequestResponse"],
        })])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)


# ====================================================================
# E2. AI Model Governance
# ====================================================================

class TestAIModelGovernance(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_ai_model_governance
        self.analyze = analyze_ai_model_governance

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_outdated_model_detected(self):
        """IsDeprecated == True triggers outdated_model_version."""
        idx = _build_index([_ai_deployment_ev({
            "DeploymentId": "dep-old", "DeploymentName": "gpt3-dep",
            "ModelName": "gpt-35-turbo", "IsDeprecated": True,
            "DeprecationDate": "2025-01-01",
        })])
        findings = self.analyze(idx)
        outdated = [f for f in findings if f["Subcategory"] == "outdated_model_version"]
        self.assertGreater(len(outdated), 0)

    def test_no_rate_limit_detected(self):
        """RateLimitTPM == 0 triggers no_token_rate_limit."""
        idx = _build_index([_ai_deployment_ev({
            "DeploymentId": "dep-nolim", "DeploymentName": "unlimited",
            "RateLimitTPM": 0,
        })])
        findings = self.analyze(idx)
        nolim = [f for f in findings if f["Subcategory"] == "no_token_rate_limit"]
        self.assertGreater(len(nolim), 0)

    def test_excessive_rate_limit_detected(self):
        """RateLimitTPM > 250000 triggers excessive_rate_limit."""
        idx = _build_index([_ai_deployment_ev({
            "DeploymentId": "dep-high", "DeploymentName": "high-tpm",
            "RateLimitTPM": 500000,
        })])
        findings = self.analyze(idx)
        excess = [f for f in findings if f["Subcategory"] == "excessive_rate_limit"]
        self.assertGreater(len(excess), 0)

    def test_current_model_normal_rates_no_finding(self):
        """Current model with normal rate limits yields no findings."""
        idx = _build_index([_ai_deployment_ev({
            "DeploymentId": "dep-ok", "DeploymentName": "gpt4-prod",
            "ModelName": "gpt-4", "IsDeprecated": False,
            "RateLimitTPM": 80000,
        })])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)


# ====================================================================
# E3. AI Threat Protection
# ====================================================================

class TestAIThreatProtection(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_ai_threat_protection
        self.analyze = analyze_ai_threat_protection

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_no_prompt_injection_detected(self):
        """OpenAI account without Prompt Shields triggers no_prompt_injection_mitigation."""
        idx = _build_index([
            _ai_service_ev({"AccountId": "acc-1", "Name": "myai", "IsOpenAI": True}),
            _ai_filter_ev({"PolicyId": "f-1", "AccountId": "acc-1",
                           "HasPromptShields": False, "TotalFilters": 1}),
        ])
        findings = self.analyze(idx)
        prompt_inj = [f for f in findings if f["Subcategory"] == "no_prompt_injection_mitigation"]
        self.assertGreater(len(prompt_inj), 0)
        self.assertEqual(prompt_inj[0]["Severity"], "critical")

    def test_no_groundedness_detected(self):
        """Filter without groundedness detection triggers finding."""
        idx = _build_index([_ai_filter_ev({
            "PolicyId": "f-2", "PolicyName": "basic",
            "HasGroundednessDetection": False, "TotalFilters": 2,
        })])
        findings = self.analyze(idx)
        ground = [f for f in findings if f["Subcategory"] == "no_groundedness_detection"]
        self.assertGreater(len(ground), 0)

    def test_no_pii_filter_detected(self):
        """Filter without PII detection triggers no_pii_filter."""
        idx = _build_index([_ai_filter_ev({
            "PolicyId": "f-3", "PolicyName": "nopii",
            "HasPIIDetection": False, "TotalFilters": 2,
        })])
        findings = self.analyze(idx)
        pii = [f for f in findings if f["Subcategory"] == "no_pii_filter"]
        self.assertGreater(len(pii), 0)

    def test_jailbreak_disabled_detected(self):
        """JailbreakFilterDisabled == True triggers jailbreak_filter_disabled."""
        idx = _build_index([_ai_filter_ev({
            "PolicyId": "f-4", "PolicyName": "nojb",
            "JailbreakFilterDisabled": True,
        })])
        findings = self.analyze(idx)
        jb = [f for f in findings if f["Subcategory"] == "jailbreak_filter_disabled"]
        self.assertGreater(len(jb), 0)
        self.assertEqual(jb[0]["Severity"], "critical")

    def test_full_protection_no_finding(self):
        """Fully protected account yields no threat protection findings."""
        idx = _build_index([
            _ai_service_ev({"AccountId": "acc-safe", "Name": "safe-ai", "IsOpenAI": True}),
            _ai_filter_ev({
                "PolicyId": "f-ok", "PolicyName": "strict", "AccountId": "acc-safe",
                "HasPromptShields": True, "HasGroundednessDetection": True,
                "HasPIIDetection": True, "JailbreakFilterDisabled": False,
                "TotalFilters": 4,
            }),
        ])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)


# ====================================================================
# E4. AI Data Governance
# ====================================================================

class TestAIDataGovernance(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_ai_data_governance
        self.analyze = analyze_ai_data_governance

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_no_classification_detected(self):
        """HasSensitivityLabel == False triggers training_data_no_classification."""
        idx = _build_index([_ai_datastore_ev({
            "DatastoreId": "ds-uncl", "Name": "uncl-store",
            "HasSensitivityLabel": False,
        })])
        findings = self.analyze(idx)
        uncl = [f for f in findings if f["Subcategory"] == "training_data_no_classification"]
        self.assertGreater(len(uncl), 0)

    def test_no_retention_detected(self):
        """IsOpenAI without HasDataRetentionPolicy triggers output_data_no_retention_policy."""
        idx = _build_index([_ai_service_ev({
            "AccountId": "acc-noret", "Name": "noret-ai",
            "IsOpenAI": True, "HasDataRetentionPolicy": False,
        })])
        findings = self.analyze(idx)
        ret = [f for f in findings if f["Subcategory"] == "output_data_no_retention_policy"]
        self.assertGreater(len(ret), 0)

    def test_classified_with_retention_no_finding(self):
        """Classified data with retention yields no findings."""
        idx = _build_index([
            _ai_datastore_ev({"DatastoreId": "ds-ok", "Name": "good-store", "HasSensitivityLabel": True}),
            _ai_service_ev({"AccountId": "acc-ok", "Name": "good-ai", "IsOpenAI": True, "HasDataRetentionPolicy": True}),
        ])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)


# ====================================================================
# F1. Defender for AI
# ====================================================================

class TestDefenderCoverage(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_ai_defender_coverage
        self.analyze = analyze_ai_defender_coverage

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_no_defender_detected(self):
        """Subscription with AI services but no Defender AI plan triggers finding."""
        idx = _build_index([
            _ai_service_ev({"AccountId": "acc-1", "Name": "ai1", "SubscriptionId": "sub-1"}),
            _defender_plan_ev({"PlanName": "VirtualMachines", "PricingTier": "Standard", "SubscriptionId": "sub-1"}),
        ])
        findings = self.analyze(idx)
        nodef = [f for f in findings if f["Subcategory"] == "no_defender_for_ai"]
        self.assertGreater(len(nodef), 0)

    def test_suppression_detected(self):
        """Defender AI plan with suppression rules triggers finding."""
        idx = _build_index([_defender_plan_ev({
            "PlanName": "AI", "PricingTier": "Standard",
            "HasSuppressionRules": True, "SuppressionRuleCount": 3,
            "SubscriptionId": "sub-1",
        })])
        findings = self.analyze(idx)
        supp = [f for f in findings if f["Subcategory"] == "defender_ai_alerts_suppressed"]
        self.assertGreater(len(supp), 0)

    def test_defender_enabled_no_finding(self):
        """Subscription with Defender for AI enabled and no suppressions yields no findings."""
        idx = _build_index([
            _ai_service_ev({"AccountId": "acc-1", "Name": "ai1", "SubscriptionId": "sub-1"}),
            _defender_plan_ev({
                "PlanName": "AI", "PricingTier": "Standard",
                "HasSuppressionRules": False, "SubscriptionId": "sub-1",
            }),
        ])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)


# ====================================================================
# F2. Azure Policy for AI
# ====================================================================

class TestPolicyCompliance(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_ai_policy_compliance
        self.analyze = analyze_ai_policy_compliance

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_no_ai_policies_detected(self):
        """AI services present but no AI-related policies triggers finding."""
        idx = _build_index([
            _ai_service_ev({"AccountId": "acc-1", "Name": "ai1"}),
            _policy_assignment_ev({
                "PolicyAssignmentId": "pa-1",
                "PolicyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/storage-something",
                "DisplayName": "Enforce Storage Encryption",
            }),
        ])
        findings = self.analyze(idx)
        nopol = [f for f in findings if f["Subcategory"] == "no_ai_azure_policies"]
        self.assertGreater(len(nopol), 0)

    def test_non_compliant_ai_detected(self):
        """Non-compliant Cognitive Services resource triggers finding."""
        idx = _build_index([_policy_compliance_ev({
            "ResourceId": "res-1", "ResourceName": "myai",
            "ResourceType": "Microsoft.CognitiveServices/accounts",
            "ComplianceState": "NonCompliant",
            "PolicyDefinitionName": "Deny-PublicAccess",
        })])
        findings = self.analyze(idx)
        noncomp = [f for f in findings if f["Subcategory"] == "ai_policy_non_compliant"]
        self.assertGreater(len(noncomp), 0)

    def test_ai_policy_assigned_compliant_no_finding(self):
        """AI policy assigned and resources compliant yields no findings."""
        idx = _build_index([
            _ai_service_ev({"AccountId": "acc-1", "Name": "ai1"}),
            _policy_assignment_ev({
                "PolicyAssignmentId": "pa-1",
                "PolicyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/cognitiveservices-deny-public",
                "DisplayName": "Deny Cognitive Services Public Access",
            }),
        ])
        findings = self.analyze(idx)
        nopol = [f for f in findings if f["Subcategory"] == "no_ai_azure_policies"]
        self.assertEqual(len(nopol), 0)


# ====================================================================
# F3. Agent Communication Security
# ====================================================================

class TestAgentCommunication(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_agent_communication
        self.analyze = analyze_agent_communication

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_no_inter_agent_auth_detected(self):
        """Multi-agent without inter-agent auth triggers finding."""
        idx = _build_index([_agent_config_ev({
            "AgentId": "a-1", "AgentName": "Orchestrator",
            "IsMultiAgent": True, "HasInterAgentAuth": False,
            "OrchestrationType": "sequential",
        })])
        findings = self.analyze(idx)
        noauth = [f for f in findings if f["Subcategory"] == "agent_no_auth_between_agents"]
        self.assertGreater(len(noauth), 0)
        self.assertEqual(noauth[0]["Severity"], "critical")

    def test_unrestricted_tool_access_detected(self):
        """HasUnrestrictedToolAccess == True triggers finding."""
        idx = _build_index([_agent_config_ev({
            "AgentId": "a-2", "AgentName": "FullAccess",
            "HasUnrestrictedToolAccess": True, "ToolCount": 25,
        })])
        findings = self.analyze(idx)
        tools = [f for f in findings if f["Subcategory"] == "agent_unrestricted_tool_access"]
        self.assertGreater(len(tools), 0)

    def test_memory_no_encryption_detected(self):
        """HasMemoryStore without MemoryEncrypted triggers finding."""
        idx = _build_index([_agent_config_ev({
            "AgentId": "a-3", "AgentName": "MemAgent",
            "HasMemoryStore": True, "MemoryEncrypted": False,
        })])
        findings = self.analyze(idx)
        mem = [f for f in findings if f["Subcategory"] == "agent_memory_no_encryption"]
        self.assertGreater(len(mem), 0)

    def test_secure_agent_no_finding(self):
        """Single agent with no memory yields no findings."""
        idx = _build_index([_agent_config_ev({
            "AgentId": "a-ok", "AgentName": "Simple",
            "IsMultiAgent": False, "HasUnrestrictedToolAccess": False,
            "HasMemoryStore": False,
        })])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)


# ====================================================================
# F4. Agent Governance
# ====================================================================

class TestAgentGovernance(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import analyze_agent_governance
        self.analyze = analyze_agent_governance

    def test_no_evidence_returns_empty(self):
        self.assertEqual(len(self.analyze({})), 0)

    def test_no_inventory_detected(self):
        """Agents without IsPartOfInventory triggers no_agent_inventory."""
        idx = _build_index([_agent_config_ev({
            "AgentId": "a-1", "AgentName": "Untracked",
            "IsPartOfInventory": False,
        })])
        findings = self.analyze(idx)
        inv = [f for f in findings if f["Subcategory"] == "no_agent_inventory"]
        self.assertGreater(len(inv), 0)

    def test_no_human_in_loop_detected(self):
        """Write operations without human approval triggers finding."""
        idx = _build_index([_agent_config_ev({
            "AgentId": "a-2", "AgentName": "AutoWriter",
            "HasWriteOperations": True, "HasHumanInLoop": False,
            "WriteOperations": ["create_resource", "delete_resource"],
        })])
        findings = self.analyze(idx)
        hitl = [f for f in findings if f["Subcategory"] == "agent_no_human_in_loop"]
        self.assertGreater(len(hitl), 0)
        self.assertEqual(hitl[0]["Severity"], "high")

    def test_shadow_agents_detected(self):
        """IsUngoverned == True triggers shadow_ai_agents."""
        idx = _build_index([_agent_config_ev({
            "AgentId": "a-3", "AgentName": "Shadow Bot",
            "IsUngoverned": True, "DeploymentType": "container",
        })])
        findings = self.analyze(idx)
        shadow = [f for f in findings if f["Subcategory"] == "shadow_ai_agents"]
        self.assertGreater(len(shadow), 0)

    def test_governed_agents_no_finding(self):
        """Governed agent in inventory with HITL yields no findings."""
        idx = _build_index([_agent_config_ev({
            "AgentId": "a-ok", "AgentName": "Good Agent",
            "IsPartOfInventory": True,
            "HasWriteOperations": True, "HasHumanInLoop": True,
            "IsUngoverned": False,
        })])
        findings = self.analyze(idx)
        self.assertEqual(len(findings), 0)


# ====================================================================
# Scoring
# ====================================================================

class TestAgentSecurityScoring(unittest.TestCase):
    def setUp(self):
        from app.ai_agent_security_engine import compute_agent_security_scores
        self.score = compute_agent_security_scores

    def test_no_findings_returns_zero(self):
        scores = self.score([])
        self.assertEqual(scores["OverallScore"], 0)

    def test_findings_produce_nonzero_score(self):
        findings = [{
            "AgentSecurityFindingId": "AS-001",
            "Category": "cs_authentication",
            "Subcategory": "no_auth_required",
            "Platform": "copilot_studio",
            "Title": "No Auth Enforcement",
            "Severity": "critical",
            "ComplianceStatus": "gap",
            "AffectedCount": 3,
        }]
        scores = self.score(findings)
        self.assertGreater(scores["OverallScore"], 0)

    def test_severity_distribution(self):
        findings = [
            {"AgentSecurityFindingId": "1", "Category": "cs_authentication", "Subcategory": "a", "Platform": "copilot_studio", "Severity": "critical", "ComplianceStatus": "gap", "AffectedCount": 1, "Title": "A"},
            {"AgentSecurityFindingId": "2", "Category": "foundry_network", "Subcategory": "b", "Platform": "foundry", "Severity": "high", "ComplianceStatus": "gap", "AffectedCount": 1, "Title": "B"},
            {"AgentSecurityFindingId": "3", "Category": "custom_api_security", "Subcategory": "c", "Platform": "cross-cutting", "Severity": "medium", "ComplianceStatus": "partial", "AffectedCount": 1, "Title": "C"},
            {"AgentSecurityFindingId": "4", "Category": "foundry_identity", "Subcategory": "d", "Platform": "foundry", "Severity": "low", "ComplianceStatus": "compliant", "AffectedCount": 1, "Title": "D"},
        ]
        scores = self.score(findings)
        dist = scores["SeverityDistribution"]
        self.assertEqual(dist["critical"], 1)
        self.assertEqual(dist["high"], 1)
        self.assertEqual(dist["medium"], 1)
        self.assertEqual(dist["low"], 1)

    def test_platform_breakdown(self):
        findings = [
            {"AgentSecurityFindingId": "1", "Category": "cs_authentication", "Subcategory": "a", "Platform": "copilot_studio", "Severity": "high", "ComplianceStatus": "gap", "AffectedCount": 1, "Title": "A"},
            {"AgentSecurityFindingId": "2", "Category": "cs_channels", "Subcategory": "b", "Platform": "copilot_studio", "Severity": "critical", "ComplianceStatus": "gap", "AffectedCount": 1, "Title": "B"},
            {"AgentSecurityFindingId": "3", "Category": "foundry_network", "Subcategory": "c", "Platform": "foundry", "Severity": "high", "ComplianceStatus": "gap", "AffectedCount": 1, "Title": "C"},
        ]
        scores = self.score(findings)
        plat = scores["PlatformBreakdown"]
        self.assertEqual(plat["copilot_studio"], 2)
        self.assertEqual(plat["foundry"], 1)

    def test_category_scores_present(self):
        findings = [
            {"AgentSecurityFindingId": "1", "Category": "cs_authentication", "Subcategory": "a", "Platform": "copilot_studio", "Severity": "high", "ComplianceStatus": "gap", "AffectedCount": 1, "Title": "A"},
            {"AgentSecurityFindingId": "2", "Category": "foundry_network", "Subcategory": "b", "Platform": "foundry", "Severity": "medium", "ComplianceStatus": "gap", "AffectedCount": 1, "Title": "B"},
        ]
        scores = self.score(findings)
        cats = scores["CategoryScores"]
        self.assertIn("cs_authentication", cats)
        self.assertIn("foundry_network", cats)


# ====================================================================
# Finding Structure
# ====================================================================



# ====================================================================
# Phases L–Q: Copilot Studio + Power Platform Deep Dive Tests
# ====================================================================

class TestCSDLPDepth(unittest.TestCase):
    """Phase L: DLP Deep Assessment tests."""

    def _idx(self, **kw):
        idx = {}
        if "dlp" in kw:
            idx["pp-dlp-policy"] = kw["dlp"]
        if "summary" in kw:
            idx["copilot-studio-summary"] = kw["summary"]
        if "bots" in kw:
            idx["copilot-studio-bot"] = kw["bots"]
        return idx

    def _dlp(self, blocked=None):
        return [{"Data": {
            "PolicyId": "pol-1", "DisplayName": "TestPolicy",
            "EnvironmentType": "AllEnvironments",
            "BlockedConnectors": blocked or [],
            "HasBlockedConnectors": bool(blocked),
        }}]

    def _summary(self, dlp=1, bots=2):
        return [{"Data": {"DLPPolicies": dlp, "TotalBots": bots}}]

    def test_no_auth_connector_not_blocked(self):
        idx = self._idx(dlp=self._dlp(blocked=[]), summary=self._summary())
        findings = analyze_cs_dlp_depth(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_dlp_no_auth_connector_allowed", cats)

    def test_auth_connector_blocked(self):
        idx = self._idx(dlp=self._dlp(
            blocked=["Chat without Microsoft Entra ID authentication in Copilot Studio"]))
        findings = analyze_cs_dlp_depth(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertNotIn("cs_dlp_no_auth_connector_allowed", cats)

    def test_knowledge_source_unrestricted(self):
        idx = self._idx(dlp=self._dlp(blocked=[]), summary=self._summary())
        findings = analyze_cs_dlp_depth(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_dlp_knowledge_source_unrestricted", cats)

    def test_channel_unrestricted(self):
        idx = self._idx(dlp=self._dlp(blocked=[]), summary=self._summary())
        findings = analyze_cs_dlp_depth(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_dlp_channel_unrestricted", cats)

    def test_skills_unrestricted(self):
        idx = self._idx(dlp=self._dlp(blocked=[]), summary=self._summary())
        findings = analyze_cs_dlp_depth(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_dlp_skills_unrestricted", cats)

    def test_default_group_not_blocked(self):
        idx = self._idx(dlp=self._dlp(blocked=[]))
        findings = analyze_cs_dlp_depth(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_dlp_default_group_not_blocked", cats)

    def test_no_tenant_policy(self):
        idx = self._idx(dlp=[{"Data": {
            "PolicyId": "p1", "EnvironmentType": "OnlyEnvironments",
            "BlockedConnectors": ["some"], "HasBlockedConnectors": True,
        }}])
        findings = analyze_cs_dlp_depth(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_dlp_no_tenant_policy", cats)

    def test_tenant_policy_exists(self):
        idx = self._idx(dlp=[{"Data": {
            "PolicyId": "p1", "EnvironmentType": "AllEnvironments",
            "BlockedConnectors": ["x"], "HasBlockedConnectors": True,
        }}])
        findings = analyze_cs_dlp_depth(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertNotIn("cs_dlp_no_tenant_policy", cats)

    def test_http_unrestricted(self):
        idx = self._idx(dlp=self._dlp(blocked=[]), summary=self._summary())
        findings = analyze_cs_dlp_depth(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_dlp_http_unrestricted", cats)

    def test_http_blocked(self):
        idx = self._idx(dlp=self._dlp(blocked=["HTTP"]), summary=self._summary())
        findings = analyze_cs_dlp_depth(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertNotIn("cs_dlp_http_unrestricted", cats)

    def test_empty_evidence_no_crash(self):
        findings = analyze_cs_dlp_depth({})
        self.assertIsInstance(findings, list)

    def test_finding_structure(self):
        idx = self._idx(dlp=self._dlp(blocked=[]), summary=self._summary())
        findings = analyze_cs_dlp_depth(idx)
        for f in findings:
            self.assertIn("Category", f)
            self.assertEqual(f["Category"], "cs_dlp_depth")
            self.assertIn("Severity", f)
            self.assertIn("Remediation", f)


class TestCSEnvironmentGovernance(unittest.TestCase):
    """Phase M: Environment Governance & Tenant Security tests."""

    def _env(self, sku="Production", is_default=False, has_sg=True, cross_tenant=False):
        eid = f"env-{sku.lower()}"
        return {"Data": {
            "EnvironmentId": eid, "DisplayName": f"Test {sku}",
            "EnvironmentSku": sku, "IsDefault": is_default,
            "HasSecurityGroup": has_sg, "CrossTenantIsolation": cross_tenant,
            "IsManagedEnvironment": sku == "Production",
            "Region": "unitedstates",
        }}

    def _bot(self, env_id="env-production", published=True, gen_ai=False):
        return {"Data": {
            "BotId": "bot-1", "DisplayName": "TestBot",
            "EnvironmentId": env_id, "EnvironmentName": "Test",
            "IsPublished": published, "GenerativeAnswersEnabled": gen_ai,
            "OrchestratorEnabled": gen_ai,
        }}

    def test_bots_in_default_env(self):
        idx = {
            "pp-environment": [self._env(sku="Default", is_default=True)],
            "copilot-studio-bot": [self._bot(env_id="env-default")],
        }
        findings = analyze_cs_environment_governance(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_env_bots_in_default", cats)

    def test_bots_in_dev_env(self):
        idx = {
            "pp-environment": [self._env(sku="Developer")],
            "copilot-studio-bot": [self._bot(env_id="env-developer")],
        }
        findings = analyze_cs_environment_governance(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_env_bots_in_dev_env", cats)

    def test_sandbox_for_production(self):
        idx = {
            "pp-environment": [self._env(sku="Sandbox")],
            "copilot-studio-bot": [self._bot(env_id="env-sandbox")],
        }
        findings = analyze_cs_environment_governance(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_env_sandbox_for_production", cats)

    def test_no_tenant_isolation(self):
        idx = {"pp-environment": [self._env(cross_tenant=False)]}
        findings = analyze_cs_environment_governance(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_env_no_tenant_isolation", cats)

    def test_tenant_isolation_enabled(self):
        idx = {"pp-environment": [self._env(cross_tenant=True)]}
        findings = analyze_cs_environment_governance(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertNotIn("cs_env_no_tenant_isolation", cats)

    def test_gen_ai_unrestricted(self):
        idx = {
            "pp-environment": [self._env()],
            "copilot-studio-bot": [self._bot(gen_ai=True)],
            "copilot-studio-summary": [{"Data": {"TotalBots": 1}}],
            "pp-dlp-policy": [],
        }
        findings = analyze_cs_environment_governance(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_env_gen_ai_unrestricted", cats)

    def test_production_env_no_finding(self):
        idx = {
            "pp-environment": [self._env(sku="Production", cross_tenant=True)],
            "copilot-studio-bot": [self._bot(env_id="env-production")],
        }
        findings = analyze_cs_environment_governance(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertNotIn("cs_env_bots_in_default", cats)
        self.assertNotIn("cs_env_bots_in_dev_env", cats)

    def test_empty_evidence(self):
        findings = analyze_cs_environment_governance({})
        self.assertIsInstance(findings, list)


class TestCSAgentSecurityAdvanced(unittest.TestCase):
    """Phase N: Agent Advanced Security tests."""

    def _bot(self, auth="manual", requires_auth=False, providers=None,
             published=True, web=False, orchestrator=False):
        return {"Data": {
            "BotId": "bot-1", "DisplayName": "TestBot",
            "AuthMode": auth, "RequiresAuthentication": requires_auth,
            "AllowedAuthProviders": providers or [],
            "IsPublished": published, "WebChannel": web,
            "OrchestratorEnabled": orchestrator,
        }}

    def _dlp(self, blocked=None):
        return [{"Data": {"BlockedConnectors": blocked or [], "HasBlockedConnectors": bool(blocked)}}]

    def test_no_sign_in_required(self):
        idx = {"copilot-studio-bot": [self._bot(auth="manual", requires_auth=False)]}
        findings = analyze_cs_agent_security_advanced(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_auth_no_sign_in_required", cats)

    def test_sign_in_required(self):
        idx = {"copilot-studio-bot": [self._bot(auth="manual", requires_auth=True)]}
        findings = analyze_cs_agent_security_advanced(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertNotIn("cs_auth_no_sign_in_required", cats)

    def test_generic_oauth(self):
        idx = {"copilot-studio-bot": [self._bot(providers=["GenericOAuth2"])]}
        findings = analyze_cs_agent_security_advanced(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_auth_generic_oauth", cats)

    def test_entra_id_provider(self):
        idx = {"copilot-studio-bot": [self._bot(providers=["AzureADv2"])]}
        findings = analyze_cs_agent_security_advanced(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertNotIn("cs_auth_generic_oauth", cats)

    def test_dlp_not_enforcing_auth(self):
        idx = {
            "copilot-studio-bot": [self._bot(requires_auth=False)],
            "pp-dlp-policy": self._dlp(blocked=[]),
        }
        findings = analyze_cs_agent_security_advanced(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_auth_dlp_not_enforcing", cats)

    def test_agent_shared_to_everyone(self):
        idx = {"copilot-studio-bot": [self._bot(published=True, requires_auth=False, web=True)]}
        findings = analyze_cs_agent_security_advanced(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_agent_shared_to_everyone", cats)

    def test_event_triggers_ungoverned(self):
        idx = {
            "copilot-studio-bot": [self._bot(orchestrator=True)],
            "pp-dlp-policy": self._dlp(blocked=[]),
        }
        findings = analyze_cs_agent_security_advanced(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_agent_event_triggers_ungoverned", cats)

    def test_http_unrestricted_published(self):
        idx = {
            "copilot-studio-bot": [self._bot(published=True)],
            "pp-dlp-policy": self._dlp(blocked=[]),
        }
        findings = analyze_cs_agent_security_advanced(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_agent_http_unrestricted", cats)

    def test_http_blocked(self):
        idx = {
            "copilot-studio-bot": [self._bot(published=True)],
            "pp-dlp-policy": self._dlp(blocked=["HTTP"]),
        }
        findings = analyze_cs_agent_security_advanced(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertNotIn("cs_agent_http_unrestricted", cats)

    def test_empty_evidence(self):
        findings = analyze_cs_agent_security_advanced({})
        self.assertIsInstance(findings, list)


class TestCSAuditCompliance(unittest.TestCase):
    """Phase O: Audit, Compliance & Observability tests."""

    def test_audit_disabled(self):
        idx = {
            "m365-audit-config": [{"Data": {"UnifiedAuditLogEnabled": False}}],
            "copilot-studio-summary": [{"Data": {"TotalBots": 1}}],
        }
        findings = analyze_cs_audit_compliance(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_audit_no_purview_integration", cats)

    def test_audit_enabled(self):
        idx = {
            "m365-audit-config": [{"Data": {"UnifiedAuditLogEnabled": True}}],
        }
        findings = analyze_cs_audit_compliance(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertNotIn("cs_audit_no_purview_integration", cats)

    def test_no_dspm(self):
        idx = {"copilot-studio-summary": [{"Data": {"TotalBots": 1}}]}
        findings = analyze_cs_audit_compliance(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_audit_no_dspm_for_ai", cats)

    def test_dspm_configured(self):
        idx = {
            "copilot-studio-summary": [{"Data": {"TotalBots": 1}}],
            "m365-dspm-for-ai": [{"Data": {"Enabled": True}}],
        }
        findings = analyze_cs_audit_compliance(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertNotIn("cs_audit_no_dspm_for_ai", cats)

    def test_cross_geo_risk(self):
        idx = {
            "copilot-studio-bot": [{"Data": {"GenerativeAnswersEnabled": True}}],
            "pp-environment": [
                {"Data": {"Region": "unitedstates", "EnvironmentId": "e1"}},
                {"Data": {"Region": "europe", "EnvironmentId": "e2"}},
            ],
        }
        findings = analyze_cs_audit_compliance(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_compliance_cross_geo_data_movement", cats)

    def test_single_region_no_cross_geo(self):
        idx = {
            "copilot-studio-bot": [{"Data": {"GenerativeAnswersEnabled": True}}],
            "pp-environment": [
                {"Data": {"Region": "unitedstates", "EnvironmentId": "e1"}},
                {"Data": {"Region": "unitedstates", "EnvironmentId": "e2"}},
            ],
        }
        findings = analyze_cs_audit_compliance(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertNotIn("cs_compliance_cross_geo_data_movement", cats)

    def test_region_mismatch(self):
        idx = {
            "pp-environment": [
                {"Data": {"Region": "unitedstates", "DisplayName": "US"}},
                {"Data": {"Region": "europe", "DisplayName": "EU"}},
            ],
        }
        findings = analyze_cs_audit_compliance(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_compliance_env_region_mismatch", cats)

    def test_empty_evidence(self):
        findings = analyze_cs_audit_compliance({})
        self.assertIsInstance(findings, list)


class TestCSDataverseSecurity(unittest.TestCase):
    """Phase P: Dataverse Security & Power Platform Admin tests."""

    def _env(self, sku="Production", has_sg=False, managed=True):
        return {"Data": {
            "EnvironmentId": "env-1", "DisplayName": f"Test {sku}",
            "EnvironmentSku": sku, "HasSecurityGroup": has_sg,
            "IsManagedEnvironment": managed,
        }}

    def test_prod_no_security_group(self):
        idx = {"pp-environment": [self._env(sku="Production", has_sg=False)]}
        findings = analyze_cs_dataverse_security(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_dv_env_maker_in_prod", cats)

    def test_prod_with_security_group(self):
        idx = {"pp-environment": [self._env(sku="Production", has_sg=True)]}
        findings = analyze_cs_dataverse_security(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertNotIn("cs_dv_env_maker_in_prod", cats)

    def test_default_env_no_sg(self):
        idx = {"pp-environment": [self._env(sku="Default", has_sg=False)]}
        findings = analyze_cs_dataverse_security(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_dv_env_maker_in_prod", cats)

    def test_no_lockbox(self):
        idx = {"pp-environment": [self._env(managed=True)]}
        findings = analyze_cs_dataverse_security(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_dv_no_lockbox", cats)

    def test_no_cmk(self):
        idx = {"pp-environment": [self._env(managed=True)]}
        findings = analyze_cs_dataverse_security(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("cs_dv_no_cmk", cats)

    def test_non_managed_skips_lockbox_cmk(self):
        idx = {"pp-environment": [self._env(managed=False)]}
        findings = analyze_cs_dataverse_security(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertNotIn("cs_dv_no_lockbox", cats)
        self.assertNotIn("cs_dv_no_cmk", cats)

    def test_empty_evidence(self):
        findings = analyze_cs_dataverse_security({})
        self.assertIsInstance(findings, list)


class TestCSReadinessCrosscheck(unittest.TestCase):
    """Phase Q: Copilot Readiness Cross-Pollination tests."""

    def test_env_governance_partial_managed(self):
        idx = {"pp-environment": [
            {"Data": {"IsManagedEnvironment": True, "EnvironmentId": "e1"}},
            {"Data": {"IsManagedEnvironment": False, "EnvironmentId": "e2"}},
        ]}
        findings = analyze_cs_readiness_crosscheck(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("pp_env_governance_for_readiness", cats)

    def test_env_governance_all_managed(self):
        idx = {"pp-environment": [
            {"Data": {"IsManagedEnvironment": True, "EnvironmentId": "e1"}},
            {"Data": {"IsManagedEnvironment": True, "EnvironmentId": "e2"}},
        ]}
        findings = analyze_cs_readiness_crosscheck(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertNotIn("pp_env_governance_for_readiness", cats)

    def test_dlp_coverage_no_policies(self):
        idx = {"copilot-studio-summary": [{"Data": {"DLPPolicies": 0, "TotalBots": 3}}]}
        findings = analyze_cs_readiness_crosscheck(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("pp_dlp_coverage_for_copilot", cats)

    def test_dlp_coverage_has_policies(self):
        idx = {"copilot-studio-summary": [{"Data": {"DLPPolicies": 2, "TotalBots": 3}}]}
        findings = analyze_cs_readiness_crosscheck(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertNotIn("pp_dlp_coverage_for_copilot", cats)

    def test_cross_tenant_isolation_missing(self):
        idx = {
            "pp-environment": [{"Data": {"CrossTenantIsolation": False, "EnvironmentId": "e1"}}],
            "copilot-studio-bot": [{"Data": {"BotId": "b1", "DisplayName": "Bot"}}],
        }
        findings = analyze_cs_readiness_crosscheck(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertIn("pp_cross_tenant_for_readiness", cats)

    def test_cross_tenant_isolation_enabled(self):
        idx = {
            "pp-environment": [{"Data": {"CrossTenantIsolation": True, "EnvironmentId": "e1"}}],
            "copilot-studio-bot": [{"Data": {"BotId": "b1"}}],
        }
        findings = analyze_cs_readiness_crosscheck(idx)
        cats = [f["Subcategory"] for f in findings]
        self.assertNotIn("pp_cross_tenant_for_readiness", cats)

    def test_empty_evidence(self):
        findings = analyze_cs_readiness_crosscheck({})
        self.assertIsInstance(findings, list)


class TestASFindingStructure(unittest.TestCase):
    def test_finding_has_required_fields(self):
        from app.ai_agent_security_engine import analyze_cs_authentication
        idx = _build_index([_cs_bot_ev({
            "BotId": "bot-1", "DisplayName": "NoAuth Bot",
            "RequiresAuthentication": False,
            "EnvironmentName": "Default",
        })])
        findings = analyze_cs_authentication(idx)
        self.assertGreater(len(findings), 0)
        f = findings[0]
        for key in ("AgentSecurityFindingId", "Category", "Subcategory", "Platform",
                     "Title", "Description", "Severity", "ComplianceStatus",
                     "AffectedResources", "AffectedCount", "Remediation", "DetectedAt"):
            self.assertIn(key, f, f"Missing key: {key}")
        self.assertIsInstance(f["AffectedResources"], list)
        self.assertIsInstance(f["Remediation"], dict)
        self.assertIn(f["Platform"], ("copilot_studio", "foundry", "cross-cutting",
                                        "entra_identity", "ai_infra", "agent_orchestration"))


# ====================================================================
# Agent Tool Registration
# ====================================================================

class TestAgentAISecurityTool(unittest.TestCase):
    def test_tools_list_has_assess_ai_agent_security(self):
        from app.agent import TOOLS
        names = [t.__name__ for t in TOOLS]
        self.assertIn("assess_ai_agent_security", names)

    def test_tools_list_has_expected_count(self):
        from app.agent import TOOLS
        self.assertEqual(len(TOOLS), 12)


# ====================================================================
# Module Imports
# ====================================================================

class TestAIAgentSecurityImports(unittest.TestCase):
    def test_import_engine(self):
        import app.ai_agent_security_engine
        self.assertTrue(hasattr(app.ai_agent_security_engine, "run_ai_agent_security_assessment"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "compute_agent_security_scores"))
        # A – Copilot Studio
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_cs_authentication"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_cs_data_connectors"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_cs_logging"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_cs_channels"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_cs_knowledge_sources"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_cs_generative_ai"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_cs_governance"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_cs_connector_security"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_cs_dlp_depth"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_cs_environment_governance"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_cs_agent_security_advanced"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_cs_audit_compliance"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_cs_dataverse_security"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_cs_readiness_crosscheck"))
        # B – Foundry
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_network"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_identity"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_content_safety"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_deployments"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_governance"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_compute"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_datastores"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_endpoints"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_registry"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_agent_identity"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_agent_application"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_mcp_tools"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_tool_security"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_guardrails"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_hosted_agents"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_data_resources"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_observability"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_foundry_lifecycle"))
        # C – Cross-cutting
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_custom_api_security"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_custom_data_residency"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_custom_content_leakage"))
        # D – Entra Identity
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_entra_ai_service_principals"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_entra_ai_conditional_access"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_entra_ai_consent"))
        # E – AI Infrastructure
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_ai_diagnostics"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_ai_model_governance"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_ai_threat_protection"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_ai_data_governance"))
        # F – Agent Orchestration
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_ai_defender_coverage"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_ai_policy_compliance"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_agent_communication"))
        self.assertTrue(hasattr(app.ai_agent_security_engine, "analyze_agent_governance"))

    def test_import_report(self):
        import app.reports.ai_agent_security_report
        self.assertTrue(hasattr(app.reports.ai_agent_security_report, "generate_ai_agent_security_report"))

    def test_cli_parseable(self):
        import ast
        cli_path = os.path.join(os.path.dirname(__file__), "..", "run_ai_agent_security.py")
        with open(cli_path, "r", encoding="utf-8") as fh:
            ast.parse(fh.read())


if __name__ == "__main__":
    unittest.main()
