"""
Determinism validation test for the AI Agent Security Assessment Engine.

Verifies that identical evidence inputs produce identical outputs across
multiple runs, excluding only the ``AgentSecurityFindingId`` (uuid4) and
``DetectedAt`` timestamps.

Tests cover all 6 assessment platforms and 46 analyzer functions:
  A. Copilot Studio (14 analyzers)
  B. Microsoft Foundry (24 analyzers)
  C. Custom Agent Security (3 analyzers)
  D. Entra Identity for AI (6 analyzers)
  E. AI Infrastructure (4 analyzers)
  F. Agent Orchestration & Platform (4 analyzers)
  + Scoring algorithm
"""

from __future__ import annotations

import copy
import json
import os
import sys
import unittest
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.ai_agent_security_engine import (
    # A. Copilot Studio
    analyze_cs_authentication,
    analyze_cs_data_connectors,
    analyze_cs_logging,
    analyze_cs_channels,
    analyze_cs_knowledge_sources,
    analyze_cs_generative_ai,
    analyze_cs_governance,
    analyze_cs_connector_security,
    analyze_cs_dlp_depth,
    analyze_cs_environment_governance,
    analyze_cs_agent_security_advanced,
    analyze_cs_audit_compliance,
    analyze_cs_dataverse_security,
    analyze_cs_readiness_crosscheck,
    # B. Microsoft Foundry
    analyze_foundry_network,
    analyze_foundry_identity,
    analyze_foundry_content_safety,
    analyze_foundry_deployments,
    analyze_foundry_governance,
    analyze_foundry_compute,
    analyze_foundry_datastores,
    analyze_foundry_endpoints,
    analyze_foundry_registry,
    analyze_foundry_connections,
    analyze_foundry_serverless,
    analyze_foundry_ws_diagnostics,
    analyze_foundry_prompt_shields,
    analyze_foundry_model_catalog,
    analyze_foundry_data_exfiltration,
    analyze_foundry_agent_identity,
    analyze_foundry_agent_application,
    analyze_foundry_mcp_tools,
    analyze_foundry_tool_security,
    analyze_foundry_guardrails,
    analyze_foundry_hosted_agents,
    analyze_foundry_data_resources,
    analyze_foundry_observability,
    analyze_foundry_lifecycle,
    # C. Custom Agent Security
    analyze_custom_api_security,
    analyze_custom_data_residency,
    analyze_custom_content_leakage,
    # D. Entra Identity for AI
    analyze_entra_ai_service_principals,
    analyze_entra_ai_conditional_access,
    analyze_entra_ai_consent,
    analyze_entra_ai_workload_identity,
    analyze_entra_ai_cross_tenant,
    analyze_entra_ai_privileged_access,
    # E. AI Infrastructure
    analyze_ai_diagnostics,
    analyze_ai_model_governance,
    analyze_ai_threat_protection,
    analyze_ai_data_governance,
    # F. Agent Orchestration
    analyze_ai_defender_coverage,
    analyze_ai_policy_compliance,
    analyze_agent_communication,
    analyze_agent_governance,
    # Scoring
    compute_agent_security_scores,
)


# ── All 46 analyzers in pipeline execution order ─────────────────────

ALL_ANALYZERS = [
    # A. Copilot Studio
    analyze_cs_authentication,
    analyze_cs_data_connectors,
    analyze_cs_logging,
    analyze_cs_channels,
    analyze_cs_knowledge_sources,
    analyze_cs_generative_ai,
    analyze_cs_governance,
    analyze_cs_connector_security,
    analyze_cs_dlp_depth,
    analyze_cs_environment_governance,
    analyze_cs_agent_security_advanced,
    analyze_cs_audit_compliance,
    analyze_cs_dataverse_security,
    analyze_cs_readiness_crosscheck,
    # B. Microsoft Foundry
    analyze_foundry_network,
    analyze_foundry_identity,
    analyze_foundry_content_safety,
    analyze_foundry_deployments,
    analyze_foundry_governance,
    analyze_foundry_compute,
    analyze_foundry_datastores,
    analyze_foundry_endpoints,
    analyze_foundry_registry,
    analyze_foundry_connections,
    analyze_foundry_serverless,
    analyze_foundry_ws_diagnostics,
    analyze_foundry_prompt_shields,
    analyze_foundry_model_catalog,
    analyze_foundry_data_exfiltration,
    analyze_foundry_agent_identity,
    analyze_foundry_agent_application,
    analyze_foundry_mcp_tools,
    analyze_foundry_tool_security,
    analyze_foundry_guardrails,
    analyze_foundry_hosted_agents,
    analyze_foundry_data_resources,
    analyze_foundry_observability,
    analyze_foundry_lifecycle,
    # C. Custom Agent Security
    analyze_custom_api_security,
    analyze_custom_data_residency,
    analyze_custom_content_leakage,
    # D. Entra Identity for AI
    analyze_entra_ai_service_principals,
    analyze_entra_ai_conditional_access,
    analyze_entra_ai_consent,
    analyze_entra_ai_workload_identity,
    analyze_entra_ai_cross_tenant,
    analyze_entra_ai_privileged_access,
    # E. AI Infrastructure
    analyze_ai_diagnostics,
    analyze_ai_model_governance,
    analyze_ai_threat_protection,
    analyze_ai_data_governance,
    # F. Agent Orchestration
    analyze_ai_defender_coverage,
    analyze_ai_policy_compliance,
    analyze_agent_communication,
    analyze_agent_governance,
]


# ── Evidence builder helpers ─────────────────────────────────────────

def _ev(etype: str, data: dict, resource_id: str = "") -> dict:
    return {"EvidenceType": etype, "Data": data, "ResourceId": resource_id or data.get("id", "")}


def _build_index(records: list[dict]) -> dict[str, list[dict]]:
    idx: dict[str, list[dict]] = {}
    for r in records:
        idx.setdefault(r["EvidenceType"], []).append(r)
    return idx


# ── Frozen evidence covering ALL 6 platforms ─────────────────────────

def _build_frozen_evidence() -> dict[str, list[dict]]:
    """Create deterministic evidence that triggers findings in every category."""

    _stale_date = "2025-01-01T00:00:00Z"
    _recent_date = datetime.now(timezone.utc).isoformat()

    records: list[dict] = [
        # ──────────────────────────────────────────────────────────
        # A. COPILOT STUDIO AGENTS
        # ──────────────────────────────────────────────────────────

        # Bots — one insecure, one secure
        _ev("copilot-studio-bot", {
            "BotId": "bot-001", "DisplayName": "No Auth Bot",
            "RequiresAuthentication": False,
            "AuthMode": "None",
            "AllowedAuthProviders": [],
            "WebChannel": True, "TeamsChannel": True,
            "TeamsSSOEnabled": False,
            "HasConversationLogging": False,
            "ModifiedTime": _stale_date,
            "EnvironmentName": "Default",
            "IsPublished": True,
            "HasKnowledgeSources": True,
            "KnowledgeSources": [
                {"Type": "SharePoint", "Url": "https://contoso.sharepoint.com/sites/hr"},
                {"Type": "PublicWebsite", "Url": "https://example.com"},
            ],
            "HasGenerativeAIEnabled": True,
            "GenerativeOrchestration": "unrestricted",
            "HasAnswerGuardrails": False,
            "IsSolutionAware": False,
            "IsDraft": True,
            "HasSecrets": True,
            "Owner": "",
        }, "bot-001"),
        _ev("copilot-studio-bot", {
            "BotId": "bot-002", "DisplayName": "Secure Bot",
            "RequiresAuthentication": True,
            "AuthMode": "azureActiveDirectory",
            "AllowedAuthProviders": ["azureActiveDirectory"],
            "WebChannel": False, "TeamsChannel": True,
            "TeamsSSOEnabled": True,
            "HasConversationLogging": True,
            "ModifiedTime": _recent_date,
            "EnvironmentName": "Production",
            "IsPublished": True,
            "HasKnowledgeSources": True,
            "KnowledgeSources": [
                {"Type": "SharePoint", "Url": "https://contoso.sharepoint.com/sites/kb"},
            ],
            "HasGenerativeAIEnabled": True,
            "GenerativeOrchestration": "restricted",
            "HasAnswerGuardrails": True,
            "IsSolutionAware": True,
            "IsDraft": False,
            "HasSecrets": False,
            "Owner": "user-001",
        }, "bot-002"),

        # Summary
        _ev("copilot-studio-summary", {
            "TotalBots": 2, "TotalEnvironments": 2,
            "DLPPolicies": 0, "ManagedEnvironments": 1,
        }, "tenant"),

        # Power Platform environments
        _ev("pp-environment", {
            "EnvironmentId": "env-001", "DisplayName": "Default",
            "IsManagedEnvironment": False,
            "HasSecurityGroup": False,
            "IsDefault": True,
        }, "env-001"),
        _ev("pp-environment", {
            "EnvironmentId": "env-002", "DisplayName": "Production",
            "IsManagedEnvironment": True,
            "HasSecurityGroup": True,
            "IsDefault": False,
        }, "env-002"),

        # DLP policies — none (triggers no_pp_dlp)
        # (intentionally empty)

        # Audit config
        _ev("m365-audit-config", {"UnifiedAuditLogEnabled": True}, "tenant"),

        # Custom connectors
        _ev("pp-custom-connector", {
            "ConnectorId": "cc-001", "DisplayName": "REST API",
            "AuthType": "apiKey",
            "IsPremium": True,
        }, "cc-001"),
        _ev("pp-custom-connector", {
            "ConnectorId": "cc-002", "DisplayName": "SharePoint Connector",
            "AuthType": "oauth2",
            "IsPremium": False,
        }, "cc-002"),

        # PP DLP policies
        _ev("pp-dlp-policy", {
            "id": "dlp-001", "DisplayName": "Default DLP",
            "Environments": ["env-001"],
            "BlockedConnectors": [],
        }, "dlp-001"),

        # Dataverse security records
        _ev("pp-dataverse-config", {
            "EnvironmentId": "env-001",
            "HasAuditEnabled": False,
            "HasColumnLevelSecurity": False,
            "HasFieldLevelEncryption": False,
            "HasRecordSharing": True,
        }, "env-001"),

        # ──────────────────────────────────────────────────────────
        # B. MICROSOFT FOUNDRY / AI SERVICES
        # ──────────────────────────────────────────────────────────

        # Foundry summary
        _ev("foundry-config-summary", {
            "TotalAIServices": 2, "OpenAIAccounts": 1,
            "AIWorkspaces": 2, "OpenAIDeployments": 3,
            "ContentFilterPolicies": 1,
            "ComputeInstances": 2, "Datastores": 2,
            "Endpoints": 3, "Registries": 1,
            "Connections": 4, "ServerlessEndpoints": 1,
            "FoundryProjectsNew": 1, "AgentApplications": 2,
            "AgentDeployments": 1, "CapabilityHosts": 1,
            "AccessDeniedErrors": 0,
        }, "tenant"),

        # AI services — one public, one private
        _ev("azure-ai-service", {
            "AccountId": "/subscriptions/sub-001/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/oai-public",
            "AccountName": "oai-public",
            "Kind": "OpenAI",
            "PublicNetworkAccess": True,
            "PrivateEndpoints": [],
            "HasManagedIdentity": False,
            "LocalAuthEnabled": True,
            "HasCMK": False,
            "SubscriptionId": "sub-001",
        }, "/subscriptions/sub-001/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/oai-public"),
        _ev("azure-ai-service", {
            "AccountId": "/subscriptions/sub-001/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/oai-private",
            "AccountName": "oai-private",
            "Kind": "OpenAI",
            "PublicNetworkAccess": False,
            "PrivateEndpoints": [{"id": "pe-001"}],
            "HasManagedIdentity": True,
            "LocalAuthEnabled": False,
            "HasCMK": True,
            "SubscriptionId": "sub-001",
        }, "/subscriptions/sub-001/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/oai-private"),

        # AI workspaces
        _ev("azure-ai-workspace", {
            "WorkspaceId": "/subscriptions/sub-001/resourceGroups/rg-ai/providers/Microsoft.MachineLearningServices/workspaces/ws-public",
            "WorkspaceName": "ws-public",
            "PublicNetworkAccess": True,
            "PrivateEndpoints": [],
            "HasManagedIdentity": False,
            "LocalAuthEnabled": True,
            "HasCMK": False,
            "IsHubWorkspace": True,
            "SubscriptionId": "sub-001",
        }, "ws-public"),
        _ev("azure-ai-workspace", {
            "WorkspaceId": "/subscriptions/sub-001/resourceGroups/rg-ai/providers/Microsoft.MachineLearningServices/workspaces/ws-private",
            "WorkspaceName": "ws-private",
            "PublicNetworkAccess": False,
            "PrivateEndpoints": [{"id": "pe-ws-001"}],
            "HasManagedIdentity": True,
            "LocalAuthEnabled": False,
            "HasCMK": True,
            "IsHubWorkspace": False,
            "SubscriptionId": "sub-001",
        }, "ws-private"),

        # OpenAI deployments — one without content filter, one deprecated
        _ev("azure-openai-deployment", {
            "DeploymentId": "deploy-001",
            "DeploymentName": "gpt-4-turbo",
            "ModelName": "gpt-4", "ModelVersion": "turbo-2024-04-09",
            "AccountName": "oai-public",
            "HasContentFilter": False,
            "HasRateLimiting": False,
            "IsDeprecated": False,
            "HasRAIPolicy": True,
            "SubscriptionId": "sub-001",
        }, "deploy-001"),
        _ev("azure-openai-deployment", {
            "DeploymentId": "deploy-002",
            "DeploymentName": "gpt-35-turbo",
            "ModelName": "gpt-35-turbo", "ModelVersion": "0301",
            "AccountName": "oai-public",
            "HasContentFilter": True,
            "HasRateLimiting": True,
            "IsDeprecated": True,
            "HasRAIPolicy": False,
            "SubscriptionId": "sub-001",
        }, "deploy-002"),
        _ev("azure-openai-deployment", {
            "DeploymentId": "deploy-003",
            "DeploymentName": "text-embedding",
            "ModelName": "text-embedding-ada-002", "ModelVersion": "2",
            "AccountName": "oai-private",
            "HasContentFilter": True,
            "HasRateLimiting": True,
            "IsDeprecated": False,
            "HasRAIPolicy": True,
            "SubscriptionId": "sub-001",
        }, "deploy-003"),

        # Content filters
        _ev("azure-openai-content-filter", {
            "PolicyId": "cf-001",
            "PolicyName": "Default",
            "HateBlocking": "medium_and_above",
            "ViolenceBlocking": "medium_and_above",
            "SexualBlocking": "medium_and_above",
            "SelfHarmBlocking": "medium_and_above",
            "JailbreakDetection": False,
            "IndirectAttackDetection": False,
            "SubscriptionId": "sub-001",
        }, "cf-001"),

        # Compute instances — one with SSH, one with public IP
        _ev("azure-ai-compute", {
            "ComputeId": "compute-001",
            "ComputeName": "gpu-dev",
            "ComputeType": "ComputeInstance",
            "HasSSHKeys": True,
            "HasPublicIP": True,
            "IdleTimeout": 0,
            "WorkspaceName": "ws-public",
            "SubscriptionId": "sub-001",
        }, "compute-001"),
        _ev("azure-ai-compute", {
            "ComputeId": "compute-002",
            "ComputeName": "gpu-prod",
            "ComputeType": "ComputeInstance",
            "HasSSHKeys": False,
            "HasPublicIP": False,
            "IdleTimeout": 30,
            "WorkspaceName": "ws-private",
            "SubscriptionId": "sub-001",
        }, "compute-002"),

        # Datastores — one credential-based
        _ev("azure-ai-datastore", {
            "DatastoreId": "ds-001",
            "DatastoreName": "blob-credentials",
            "DatastoreType": "AzureBlob",
            "CredentialType": "account_key",
            "HasEncryption": False,
            "WorkspaceName": "ws-public",
        }, "ds-001"),
        _ev("azure-ai-datastore", {
            "DatastoreId": "ds-002",
            "DatastoreName": "blob-mi",
            "DatastoreType": "AzureBlob",
            "CredentialType": "managed_identity",
            "HasEncryption": True,
            "WorkspaceName": "ws-private",
        }, "ds-002"),

        # Endpoints — public, auth=key, auth=aad
        _ev("azure-ai-endpoint", {
            "EndpointId": "ep-001",
            "EndpointName": "scoring-public",
            "EndpointType": "online",
            "IsPublic": True,
            "AuthMode": "key",
            "HasTrafficLogging": False,
            "WorkspaceName": "ws-public",
        }, "ep-001"),
        _ev("azure-ai-endpoint", {
            "EndpointId": "ep-002",
            "EndpointName": "scoring-private",
            "EndpointType": "online",
            "IsPublic": False,
            "AuthMode": "aad_token",
            "HasTrafficLogging": True,
            "WorkspaceName": "ws-private",
        }, "ep-002"),
        _ev("azure-ai-endpoint", {
            "EndpointId": "ep-003",
            "EndpointName": "batch-endpoint",
            "EndpointType": "batch",
            "IsPublic": True,
            "AuthMode": "key",
            "HasTrafficLogging": False,
            "WorkspaceName": "ws-public",
        }, "ep-003"),

        # Registry — public ACR
        _ev("azure-ai-registry", {
            "RegistryId": "reg-001",
            "RegistryName": "acrpublic",
            "IsPublicAccess": True,
            "HasRBAC": False,
        }, "reg-001"),

        # Connections — various auth types
        _ev("azure-ai-connection", {
            "ConnectionId": "conn-001",
            "ConnectionName": "openai-key",
            "ConnectionType": "AzureOpenAI",
            "AuthType": "api_key",
            "WorkspaceName": "ws-public",
        }, "conn-001"),
        _ev("azure-ai-connection", {
            "ConnectionId": "conn-002",
            "ConnectionName": "openai-mi",
            "ConnectionType": "AzureOpenAI",
            "AuthType": "managed_identity",
            "WorkspaceName": "ws-private",
        }, "conn-002"),
        _ev("azure-ai-connection", {
            "ConnectionId": "conn-003",
            "ConnectionName": "storage-sas",
            "ConnectionType": "AzureBlob",
            "AuthType": "sas_token",
            "WorkspaceName": "ws-public",
        }, "conn-003"),
        _ev("azure-ai-connection", {
            "ConnectionId": "conn-004",
            "ConnectionName": "custom-api",
            "ConnectionType": "Custom",
            "AuthType": "api_key",
            "WorkspaceName": "ws-public",
        }, "conn-004"),

        # Serverless endpoints
        _ev("azure-ai-serverless-endpoint", {
            "EndpointId": "sless-001",
            "EndpointName": "phi-serverless",
            "ModelId": "azureml://registries/azureml/models/Phi-3-mini",
            "IsPublic": True,
            "AuthMode": "key",
            "HasContentFilter": False,
        }, "sless-001"),

        # Workspace diagnostics
        _ev("azure-ai-workspace-diagnostics", {
            "WorkspaceId": "ws-public",
            "HasDiagnosticSettings": False,
            "LogCategories": [],
        }, "ws-public"),
        _ev("azure-ai-workspace-diagnostics", {
            "WorkspaceId": "ws-private",
            "HasDiagnosticSettings": True,
            "LogCategories": ["AmlComputeClusterEvent", "AmlRunStatusChangedEvent"],
        }, "ws-private"),

        # Foundry projects
        _ev("foundry-project", {
            "ProjectId": "proj-001",
            "ProjectName": "contoso-agent-proj",
            "HubId": "hub-001",
            "HasManagedIdentity": True,
        }, "proj-001"),

        # Foundry agent applications
        _ev("foundry-agent-application", {
            "ApplicationId": "app-agent-001",
            "ApplicationName": "HR Agent",
            "HasManagedIdentity": False,
            "HasEntraAuth": False,
            "ToolCount": 5,
            "HasInputValidation": False,
            "ProjectId": "proj-001",
        }, "app-agent-001"),
        _ev("foundry-agent-application", {
            "ApplicationId": "app-agent-002",
            "ApplicationName": "IT Support Agent",
            "HasManagedIdentity": True,
            "HasEntraAuth": True,
            "ToolCount": 3,
            "HasInputValidation": True,
            "ProjectId": "proj-001",
        }, "app-agent-002"),

        # Foundry agent deployments
        _ev("foundry-agent-deployment", {
            "DeploymentId": "agent-deploy-001",
            "AgentName": "HR Agent v1",
            "HasVersioning": False,
            "HasRollback": False,
            "IsProduction": True,
            "LastUpdated": _stale_date,
        }, "agent-deploy-001"),

        # Capability hosts
        _ev("foundry-capability-host", {
            "CapabilityHostId": "caphost-001",
            "HasNetworkIsolation": False,
            "StorageConnections": 2,
        }, "caphost-001"),

        # MCP tool configs
        _ev("foundry-mcp-tool", {
            "ToolId": "mcp-001",
            "ToolName": "sql-query",
            "HasAuthConfig": False,
            "HasRateLimiting": False,
            "IsPublic": True,
        }, "mcp-001"),
        _ev("foundry-mcp-tool", {
            "ToolId": "mcp-002",
            "ToolName": "file-read",
            "HasAuthConfig": True,
            "HasRateLimiting": True,
            "IsPublic": False,
        }, "mcp-002"),

        # ──────────────────────────────────────────────────────────
        # C. CUSTOM AGENT SECURITY
        # ──────────────────────────────────────────────────────────

        _ev("custom-agent-config", {
            "AgentId": "custom-001",
            "DisplayName": "Customer Support Agent",
            "HasAPIKeyExposure": True,
            "HasNetworkRestrictions": False,
            "DataResidencyRegions": ["eastus", "westeurope"],
            "HasContentFilter": False,
            "HasCMK": False,
        }, "custom-001"),

        # ──────────────────────────────────────────────────────────
        # D. ENTRA IDENTITY FOR AI
        # ──────────────────────────────────────────────────────────

        # AI service principals — one over-permissioned
        _ev("entra-ai-service-principal", {
            "AppId": "sp-ai-001",
            "DisplayName": "OpenAI Connector",
            "ApplicationPermissions": 15,
            "DelegatedPermissions": 8,
            "HasHighPrivilegePermissions": True,
            "CredentialCount": 3,
            "HasExpiredCredentials": True,
            "OldestCredentialAge": 400,
            "HasFederatedCredentials": False,
        }, "sp-ai-001"),
        _ev("entra-ai-service-principal", {
            "AppId": "sp-ai-002",
            "DisplayName": "AI Workspace MI",
            "ApplicationPermissions": 2,
            "DelegatedPermissions": 0,
            "HasHighPrivilegePermissions": False,
            "CredentialCount": 0,
            "HasExpiredCredentials": False,
            "OldestCredentialAge": 0,
            "HasFederatedCredentials": True,
        }, "sp-ai-002"),

        # AI consent grants
        _ev("entra-ai-consent-grant", {
            "AppId": "sp-ai-001",
            "DisplayName": "OpenAI Connector",
            "ConsentType": "admin",
            "Scope": "Directory.ReadWrite.All User.ReadWrite.All",
            "IsHighPrivilege": True,
        }, "sp-ai-001"),
        _ev("entra-ai-consent-grant", {
            "AppId": "sp-ai-002",
            "DisplayName": "AI Workspace MI",
            "ConsentType": "principal",
            "Scope": "User.Read",
            "IsHighPrivilege": False,
        }, "sp-ai-002"),

        # Cross-tenant policies
        _ev("entra-cross-tenant-policy", {
            "PolicyType": "default",
            "InboundTrustSettings": {"IsConfigured": False},
            "OutboundSettings": {"IsConfigured": False},
        }, "ct-policy"),

        # Conditional access for AI — gaps
        _ev("entra-conditional-access-policy", {
            "id": "ca-001", "DisplayName": "Require MFA for Admins",
            "State": "enabled",
            "IncludedApplications": ["All"],
            "RequiresMFA": True,
            "TargetsAllUsers": False,
        }, "ca-001"),

        # ──────────────────────────────────────────────────────────
        # E. AI INFRASTRUCTURE
        # ──────────────────────────────────────────────────────────

        # Diagnostic settings for AI
        _ev("azure-diagnostic-setting", {
            "ResourceId": "/subscriptions/sub-001/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/oai-public",
            "HasDiagnosticSettings": False,
        }, "diag-oai-public"),
        _ev("azure-diagnostic-setting", {
            "ResourceId": "/subscriptions/sub-001/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/oai-private",
            "HasDiagnosticSettings": True,
            "LogCategories": ["Audit", "RequestResponse"],
        }, "diag-oai-private"),

        # AI model governance
        _ev("azure-policy-assignment", {
            "PolicyAssignmentId": "pa-001",
            "DisplayName": "Require cognitive services CMK",
            "PolicyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/cognitive-services-cmk",
            "Scope": "/subscriptions/sub-001",
            "ComplianceState": "NonCompliant",
        }, "pa-001"),
        _ev("azure-policy-assignment", {
            "PolicyAssignmentId": "pa-002",
            "DisplayName": "Require AI private endpoints",
            "PolicyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/cognitive-services-pe",
            "Scope": "/subscriptions/sub-001",
            "ComplianceState": "Compliant",
        }, "pa-002"),

        # Policy compliance records
        _ev("azure-policy-compliance", {
            "ResourceId": "/subscriptions/sub-001/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/oai-public",
            "PolicyAssignmentId": "pa-001",
            "ComplianceState": "NonCompliant",
        }, "/subscriptions/sub-001/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/oai-public"),

        # Threat protection / Defender for AI
        _ev("azure-defender-plan", {
            "SubscriptionId": "sub-001",
            "PlanName": "AI",
            "PricingTier": "Free",
            "IsEnabled": False,
        }, "sub-001"),

        # ──────────────────────────────────────────────────────────
        # F. AGENT ORCHESTRATION
        # ──────────────────────────────────────────────────────────

        _ev("agent-orchestration-config", {
            "AgentId": "orch-agent-001",
            "DisplayName": "Multi-Agent Router",
            "HasInterAgentAuth": False,
            "HasToolScoping": False,
            "HasHumanInTheLoop": False,
            "IsInventoried": True,
            "CommunicationProtocol": "http",
        }, "orch-agent-001"),
        _ev("agent-orchestration-config", {
            "AgentId": "orch-agent-002",
            "DisplayName": "Data Processor Agent",
            "HasInterAgentAuth": True,
            "HasToolScoping": True,
            "HasHumanInTheLoop": True,
            "IsInventoried": False,
            "CommunicationProtocol": "grpc",
        }, "orch-agent-002"),
    ]

    return _build_index(records)


# ── Comparison utilities ─────────────────────────────────────────────

_VOLATILE_KEYS = frozenset({"AgentSecurityFindingId", "DetectedAt"})

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def _strip_volatile(obj):
    """Recursively strip volatile fields (IDs and timestamps) for comparison."""
    if isinstance(obj, dict):
        return {k: _strip_volatile(v) for k, v in obj.items() if k not in _VOLATILE_KEYS}
    if isinstance(obj, list):
        return [_strip_volatile(item) for item in obj]
    return obj


def _run_full_pipeline(evidence_index: dict) -> dict:
    """Run all 46 analyzers and compute scores — mirrors the engine orchestrator."""
    all_findings: list[dict] = []
    for fn in ALL_ANALYZERS:
        all_findings.extend(fn(evidence_index))

    # Sort by (Category, Subcategory, Severity) for deterministic comparison
    all_findings.sort(
        key=lambda f: (
            f.get("Category", ""),
            f.get("Subcategory", ""),
            _SEV_ORDER.get(f.get("Severity", "medium").lower(), 9),
        )
    )
    # Sort AffectedResources within each finding
    for f in all_findings:
        f.get("AffectedResources", []).sort(
            key=lambda r: r.get("ResourceId", r.get("Name", ""))
        )

    scores = compute_agent_security_scores(all_findings)

    return {
        "Findings": all_findings,
        "FindingCount": len(all_findings),
        "AgentSecurityScores": scores,
    }


# ====================================================================
# DETERMINISM TESTS
# ====================================================================

class TestAIAgentSecurityDeterminism(unittest.TestCase):
    """Ensure identical evidence → identical output (excluding volatile fields)."""

    def test_two_runs_produce_identical_output(self):
        """Run pipeline twice with same evidence and compare."""
        evidence = _build_frozen_evidence()
        result_a = _run_full_pipeline(copy.deepcopy(evidence))
        result_b = _run_full_pipeline(copy.deepcopy(evidence))

        clean_a = _strip_volatile(result_a)
        clean_b = _strip_volatile(result_b)

        self.assertEqual(
            json.dumps(clean_a, sort_keys=True, default=str),
            json.dumps(clean_b, sort_keys=True, default=str),
            "Two runs with identical evidence produced different output",
        )

    def test_finding_count_is_stable(self):
        """Finding count must be identical across runs."""
        evidence = _build_frozen_evidence()
        result_a = _run_full_pipeline(copy.deepcopy(evidence))
        result_b = _run_full_pipeline(copy.deepcopy(evidence))

        self.assertEqual(
            result_a["FindingCount"],
            result_b["FindingCount"],
            "Finding count differs between runs",
        )

    def test_finding_content_is_identical_across_runs(self):
        """All finding fields except volatile keys should match."""
        evidence = _build_frozen_evidence()
        result_a = _run_full_pipeline(copy.deepcopy(evidence))
        result_b = _run_full_pipeline(copy.deepcopy(evidence))

        for fa, fb in zip(result_a["Findings"], result_b["Findings"]):
            clean_a = {k: v for k, v in fa.items() if k not in _VOLATILE_KEYS}
            clean_b = {k: v for k, v in fb.items() if k not in _VOLATILE_KEYS}
            self.assertEqual(
                json.dumps(clean_a, sort_keys=True, default=str),
                json.dumps(clean_b, sort_keys=True, default=str),
                f"Finding content differs for subcategory={fa.get('Subcategory')}",
            )

    def test_finding_order_is_stable(self):
        """Findings should be in deterministic (Category, Subcategory, Severity) order."""
        evidence = _build_frozen_evidence()
        result = _run_full_pipeline(copy.deepcopy(evidence))

        tuples = [
            (f["Category"], f["Subcategory"], f["Severity"])
            for f in result["Findings"]
        ]
        sorted_tuples = sorted(
            tuples,
            key=lambda t: (t[0], t[1], _SEV_ORDER.get(t[2].lower(), 9)),
        )
        self.assertEqual(
            tuples, sorted_tuples,
            "Findings are not in deterministic (Category, Subcategory, Severity) order",
        )

    def test_scores_are_identical(self):
        """Score values must match exactly across runs."""
        evidence = _build_frozen_evidence()
        scores_a = _run_full_pipeline(copy.deepcopy(evidence))["AgentSecurityScores"]
        scores_b = _run_full_pipeline(copy.deepcopy(evidence))["AgentSecurityScores"]

        self.assertEqual(scores_a["OverallScore"], scores_b["OverallScore"])
        self.assertEqual(scores_a["OverallLevel"], scores_b["OverallLevel"])
        self.assertEqual(scores_a["SeverityDistribution"], scores_b["SeverityDistribution"])
        self.assertEqual(scores_a["ComplianceBreakdown"], scores_b["ComplianceBreakdown"])
        self.assertEqual(
            json.dumps(scores_a["CategoryScores"], sort_keys=True),
            json.dumps(scores_b["CategoryScores"], sort_keys=True),
        )
        self.assertEqual(
            json.dumps(scores_a["PlatformBreakdown"], sort_keys=True),
            json.dumps(scores_b["PlatformBreakdown"], sort_keys=True),
        )

    def test_affected_resources_are_sorted(self):
        """AffectedResources within each finding must be in deterministic order."""
        evidence = _build_frozen_evidence()
        result = _run_full_pipeline(copy.deepcopy(evidence))
        for f in result["Findings"]:
            resources = f.get("AffectedResources", [])
            ids = [r.get("ResourceId", r.get("Name", "")) for r in resources]
            self.assertEqual(
                ids, sorted(ids),
                f"AffectedResources not sorted in: {f.get('Subcategory')}",
            )

    def test_three_runs_all_match(self):
        """Triple-run consistency check (excluding volatile fields)."""
        evidence = _build_frozen_evidence()
        results = [
            _strip_volatile(_run_full_pipeline(copy.deepcopy(evidence)))
            for _ in range(3)
        ]
        baseline = json.dumps(results[0], sort_keys=True, default=str)
        for i, r in enumerate(results[1:], 2):
            self.assertEqual(
                baseline,
                json.dumps(r, sort_keys=True, default=str),
                f"Run {i} differs from run 1",
            )

    def test_severity_distribution_stable(self):
        """Severity distribution must be identical across runs."""
        evidence = _build_frozen_evidence()
        dist_a = _run_full_pipeline(copy.deepcopy(evidence))["AgentSecurityScores"]["SeverityDistribution"]
        dist_b = _run_full_pipeline(copy.deepcopy(evidence))["AgentSecurityScores"]["SeverityDistribution"]
        self.assertEqual(dist_a, dist_b)

    def test_per_category_finding_counts_stable(self):
        """Finding count per category must be identical across runs."""
        evidence = _build_frozen_evidence()
        result_a = _run_full_pipeline(copy.deepcopy(evidence))
        result_b = _run_full_pipeline(copy.deepcopy(evidence))

        counts_a: dict[str, int] = {}
        for f in result_a["Findings"]:
            counts_a[f["Category"]] = counts_a.get(f["Category"], 0) + 1
        counts_b: dict[str, int] = {}
        for f in result_b["Findings"]:
            counts_b[f["Category"]] = counts_b.get(f["Category"], 0) + 1

        self.assertEqual(counts_a, counts_b, "Per-category finding counts differ")

    def test_top_findings_stable(self):
        """TopFindings in scores must be identical across runs."""
        evidence = _build_frozen_evidence()
        top_a = _run_full_pipeline(copy.deepcopy(evidence))["AgentSecurityScores"]["TopFindings"]
        top_b = _run_full_pipeline(copy.deepcopy(evidence))["AgentSecurityScores"]["TopFindings"]

        self.assertEqual(
            json.dumps(top_a, sort_keys=True, default=str),
            json.dumps(top_b, sort_keys=True, default=str),
            "TopFindings differ between runs",
        )

    def test_platform_breakdown_stable(self):
        """Platform breakdown must be identical across runs."""
        evidence = _build_frozen_evidence()
        plat_a = _run_full_pipeline(copy.deepcopy(evidence))["AgentSecurityScores"]["PlatformBreakdown"]
        plat_b = _run_full_pipeline(copy.deepcopy(evidence))["AgentSecurityScores"]["PlatformBreakdown"]
        self.assertEqual(plat_a, plat_b)

    def test_findings_have_required_fields(self):
        """Every finding must have all required fields."""
        evidence = _build_frozen_evidence()
        result = _run_full_pipeline(copy.deepcopy(evidence))

        required = {"AgentSecurityFindingId", "Category", "Subcategory", "Platform",
                     "Title", "Description", "Severity", "ComplianceStatus",
                     "AffectedResources", "AffectedCount", "DetectedAt"}
        for f in result["Findings"]:
            missing = required - set(f.keys())
            self.assertFalse(
                missing,
                f"Finding {f.get('Subcategory')} missing fields: {missing}",
            )

    def test_severity_values_are_valid(self):
        """All severity values must be one of the defined levels."""
        evidence = _build_frozen_evidence()
        result = _run_full_pipeline(copy.deepcopy(evidence))

        valid_severities = {"critical", "high", "medium", "low", "informational"}
        for f in result["Findings"]:
            self.assertIn(
                f["Severity"].lower(), valid_severities,
                f"Invalid severity '{f['Severity']}' in {f.get('Subcategory')}",
            )

    def test_pipeline_produces_findings(self):
        """Pipeline must produce at least 1 finding with frozen evidence."""
        evidence = _build_frozen_evidence()
        result = _run_full_pipeline(copy.deepcopy(evidence))
        self.assertGreater(
            result["FindingCount"], 0,
            "Pipeline produced zero findings — frozen evidence insufficient",
        )


# ====================================================================
# PER-ANALYZER DETERMINISM
# ====================================================================

class TestPerAnalyzerDeterminism(unittest.TestCase):
    """Run each analyzer individually twice and verify determinism."""

    def test_each_analyzer_is_deterministic(self):
        """Every analyzer must produce identical output (after stripping volatile fields)."""
        evidence = _build_frozen_evidence()

        for fn in ALL_ANALYZERS:
            with self.subTest(analyzer=fn.__name__):
                result_a = fn(copy.deepcopy(evidence))
                result_b = fn(copy.deepcopy(evidence))

                clean_a = _strip_volatile(result_a)
                clean_b = _strip_volatile(result_b)

                self.assertEqual(
                    json.dumps(clean_a, sort_keys=True, default=str),
                    json.dumps(clean_b, sort_keys=True, default=str),
                    f"{fn.__name__} produced different output across two runs",
                )


if __name__ == "__main__":
    unittest.main()
