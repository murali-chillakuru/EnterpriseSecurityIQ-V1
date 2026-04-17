"""Microsoft Foundry new category evaluators — prompt shields, model catalog, data exfiltration, agent apps, MCP, guardrails, hosted agents, data resources, observability, lifecycle."""

from __future__ import annotations

from .finding import _as_finding


def analyze_foundry_prompt_shields(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess prompt injection and jailbreak protection for AI deployments."""
    findings: list[dict] = []
    findings.extend(_check_foundry_no_prompt_shield(evidence_index))
    findings.extend(_check_foundry_jailbreak_filter_disabled(evidence_index))
    findings.extend(_check_foundry_blocklist_not_configured(evidence_index))
    return findings


def _check_foundry_no_prompt_shield(idx: dict) -> list[dict]:
    """Flag RAI policies without prompt shield enabled."""
    filters = idx.get("azure-openai-content-filter", [])
    if not filters:
        return []
    no_shield: list[dict] = []
    for ev in filters:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasPromptShield"):
            no_shield.append({
                "Type": "ContentFilter",
                "Name": data.get("PolicyName", "Unknown"),
                "ResourceId": data.get("PolicyId", ""),
                "AccountName": data.get("AccountName", ""),
            })
    if no_shield:
        return [_as_finding(
            "foundry_prompt_shields", "no_prompt_shield",
            f"{len(no_shield)} content filter policies lack prompt shield protection",
            "Prompt shields detect and block prompt injection attacks — the #1 AI "
            "attack vector. Without prompt shields, adversarial inputs can override "
            "system instructions and exfiltrate data.",
            "high", "foundry", no_shield,
            {"Description": "Enable prompt shields on all content filter policies.",
             "PortalSteps": ["Go to Microsoft Foundry > Safety + Security > Content filters",
                             "Edit each content filter policy",
                             "Enable 'Prompt Shields' under input filters",
                             "Apply updated policy to all deployments"]},
        )]
    return []


def _check_foundry_jailbreak_filter_disabled(idx: dict) -> list[dict]:
    """Flag RAI policies without jailbreak detection enabled."""
    filters = idx.get("azure-openai-content-filter", [])
    if not filters:
        return []
    no_jailbreak: list[dict] = []
    for ev in filters:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasJailbreakFilter"):
            no_jailbreak.append({
                "Type": "ContentFilter",
                "Name": data.get("PolicyName", "Unknown"),
                "ResourceId": data.get("PolicyId", ""),
                "AccountName": data.get("AccountName", ""),
            })
    if no_jailbreak:
        return [_as_finding(
            "foundry_prompt_shields", "jailbreak_filter_disabled",
            f"{len(no_jailbreak)} content filter policies lack jailbreak detection",
            "Jailbreak detection identifies attempts to bypass system prompts and "
            "safety guardrails. Without it, attackers can manipulate model behavior.",
            "high", "foundry", no_jailbreak,
            {"Description": "Enable jailbreak detection in content filter policies.",
             "PortalSteps": ["Go to Microsoft Foundry > Safety + Security > Content filters",
                             "Edit each content filter policy",
                             "Enable 'Jailbreak risk detection' under input filters",
                             "Save and apply to all deployments"]},
        )]
    return []


def _check_foundry_blocklist_not_configured(idx: dict) -> list[dict]:
    """Flag RAI policies with no custom blocklists configured."""
    filters = idx.get("azure-openai-content-filter", [])
    if not filters:
        return []
    no_blocklist: list[dict] = []
    for ev in filters:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("CustomBlocklistCount", 0) == 0:
            no_blocklist.append({
                "Type": "ContentFilter",
                "Name": data.get("PolicyName", "Unknown"),
                "ResourceId": data.get("PolicyId", ""),
                "AccountName": data.get("AccountName", ""),
            })
    if no_blocklist:
        return [_as_finding(
            "foundry_prompt_shields", "blocklist_not_configured",
            f"{len(no_blocklist)} content filter policies have no custom blocklists",
            "Custom blocklists allow blocking organization-specific sensitive terms, "
            "competitor names, or regulated content. Without them, only generic "
            "categories are filtered.",
            "medium", "foundry", no_blocklist,
            {"Description": "Configure custom blocklists for organization-specific terms.",
             "PortalSteps": ["Go to Microsoft Foundry > Safety + Security > Blocklists",
                             "Create a blocklist with organization-specific terms",
                             "Attach the blocklist to content filter policies"]},
        )]
    return []


# ── 9j. Model Catalog Governance ────────────────────────────────────

def analyze_foundry_model_catalog(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess model catalog governance and deployment controls."""
    findings: list[dict] = []
    findings.extend(_check_unapproved_model_deployed(evidence_index))
    findings.extend(_check_model_version_outdated(evidence_index))
    return findings


def _check_unapproved_model_deployed(idx: dict) -> list[dict]:
    """Flag deployments using community/third-party models outside standard catalog."""
    deployments = idx.get("azure-openai-deployment", [])
    _KNOWN_MODELS = {
        "gpt-4o", "gpt-4o-mini", "gpt-4", "gpt-4-turbo", "gpt-35-turbo",
        "text-embedding-ada-002", "text-embedding-3-small", "text-embedding-3-large",
        "dall-e-3", "whisper", "tts", "tts-hd",
        "o1", "o1-mini", "o1-preview", "o3-mini",
        "gpt-4.1", "gpt-4.1-mini", "gpt-4.1-nano",
    }
    unknown: list[dict] = []
    for ev in deployments:
        data = ev.get("Data", ev.get("data", {}))
        model_name = data.get("ModelName", "").lower()
        if model_name and model_name not in _KNOWN_MODELS:
            unknown.append({
                "Type": "OpenAIDeployment",
                "Name": data.get("DeploymentName", "Unknown"),
                "ResourceId": data.get("DeploymentId", ""),
                "ModelName": data.get("ModelName", ""),
                "AccountName": data.get("AccountName", ""),
            })
    if unknown:
        return [_as_finding(
            "foundry_model_catalog", "unapproved_model_deployed",
            f"{len(unknown)} deployments use models outside the standard catalog",
            "Deployments using non-standard or unrecognized models may not meet "
            "organizational security and compliance requirements. Review and approve "
            "before production use.",
            "medium", "foundry", unknown,
            {"Description": "Review and approve deployed models against organizational policy.",
             "PortalSteps": ["Go to Microsoft Foundry > Model deployments",
                             "Review each deployment's model name and version",
                             "Verify models are in your organization's approved list",
                             "Remove or replace unapproved model deployments"]},
        )]
    return []


def _check_model_version_outdated(idx: dict) -> list[dict]:
    """Flag deployments using very old model versions."""
    deployments = idx.get("azure-openai-deployment", [])
    _OLD_VERSIONS = {
        "0301", "0314", "0613", "1106-preview",
    }
    outdated: list[dict] = []
    for ev in deployments:
        data = ev.get("Data", ev.get("data", {}))
        version = data.get("ModelVersion", "")
        if version and version in _OLD_VERSIONS:
            outdated.append({
                "Type": "OpenAIDeployment",
                "Name": data.get("DeploymentName", "Unknown"),
                "ResourceId": data.get("DeploymentId", ""),
                "ModelName": data.get("ModelName", ""),
                "ModelVersion": version,
            })
    if outdated:
        return [_as_finding(
            "foundry_model_catalog", "model_version_outdated",
            f"{len(outdated)} deployments use outdated model versions",
            "Older model versions may lack safety improvements, performance fixes, "
            "and security patches available in newer versions.",
            "low", "foundry", outdated,
            {"Description": "Update deployments to use the latest model versions.",
             "PortalSteps": ["Go to Microsoft Foundry > Model deployments",
                             "Select outdated deployments",
                             "Update model version to the latest available",
                             "Test applications with the new version before production rollout"]},
        )]
    return []


# ── 9k. Data Exfiltration Prevention ────────────────────────────────

def analyze_foundry_data_exfiltration(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess data exfiltration prevention controls for AI workspaces."""
    findings: list[dict] = []
    findings.extend(_check_workspace_no_managed_network(evidence_index))
    findings.extend(_check_managed_network_no_outbound_rules(evidence_index))
    findings.extend(_check_outbound_fqdn_unrestricted(evidence_index))
    return findings


def _check_workspace_no_managed_network(idx: dict) -> list[dict]:
    """Flag workspaces without managed network isolation."""
    workspaces = idx.get("azure-ai-workspace", [])
    no_network: list[dict] = []
    for ev in workspaces:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasNetworkIsolation"):
            no_network.append({
                "Type": "AIWorkspace",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("WorkspaceId", ""),
                "Kind": data.get("Kind", ""),
            })
    if no_network:
        return [_as_finding(
            "foundry_data_exfiltration", "workspace_no_managed_network",
            f"{len(no_network)} AI workspaces lack managed network isolation",
            "Workspaces without managed networking allow unrestricted outbound access, "
            "enabling data exfiltration through arbitrary network connections.",
            "medium", "foundry", no_network,
            {"Description": "Enable managed network with approved outbound only.",
             "PortalSteps": ["Go to Azure portal > AI Foundry workspace > Networking",
                             "Enable managed network isolation",
                             "Select 'Allow only approved outbound' mode",
                             "Add required outbound rules for approved destinations"]},
        )]
    return []


def _check_managed_network_no_outbound_rules(idx: dict) -> list[dict]:
    """Flag isolated workspaces with no explicit outbound rules configured."""
    workspaces = idx.get("azure-ai-workspace", [])
    no_rules: list[dict] = []
    for ev in workspaces:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("HasNetworkIsolation") and data.get("OutboundRuleCount", 0) == 0:
            no_rules.append({
                "Type": "AIWorkspace",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("WorkspaceId", ""),
                "IsolationMode": data.get("IsolationMode", ""),
            })
    if no_rules:
        return [_as_finding(
            "foundry_data_exfiltration", "managed_network_no_outbound_rules",
            f"{len(no_rules)} isolated workspaces have no explicit outbound rules",
            "Network-isolated workspaces with zero outbound rules may use default "
            "allow-all behavior, defeating the purpose of isolation.",
            "high", "foundry", no_rules,
            {"Description": "Configure explicit outbound rules on isolated workspaces.",
             "AzureCLI": "az ml workspace update --name <ws> --resource-group <rg> "
                         "--managed-network allow-only-approved-outbound",
             "PortalSteps": ["Go to Azure portal > AI Foundry workspace > Networking",
                             "Add outbound rules for required FQDN destinations",
                             "Add private endpoint rules for Azure services",
                             "Remove any 'allow all' rules"]},
        )]
    return []


def _check_outbound_fqdn_unrestricted(idx: dict) -> list[dict]:
    """Flag workspaces in allow-internet-outbound mode (less restrictive)."""
    workspaces = idx.get("azure-ai-workspace", [])
    unrestricted: list[dict] = []
    for ev in workspaces:
        data = ev.get("Data", ev.get("data", {}))
        isolation = str(data.get("IsolationMode", "")).lower()
        if isolation == "allowinternetoutbound":
            unrestricted.append({
                "Type": "AIWorkspace",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("WorkspaceId", ""),
                "IsolationMode": data.get("IsolationMode", ""),
            })
    if unrestricted:
        return [_as_finding(
            "foundry_data_exfiltration", "outbound_fqdn_unrestricted",
            f"{len(unrestricted)} workspaces allow all internet outbound traffic",
            "The 'AllowInternetOutbound' mode permits traffic to any internet destination. "
            "Use 'AllowOnlyApprovedOutbound' for stricter data exfiltration protection.",
            "medium", "foundry", unrestricted,
            {"Description": "Switch to AllowOnlyApprovedOutbound isolation mode.",
             "PortalSteps": ["Go to Azure portal > AI Foundry workspace > Networking",
                             "Change isolation mode to 'Allow only approved outbound'",
                             "Configure FQDN rules for required external endpoints"]},
        )]
    return []


# ── 9L. Agent Identity Security ──────────────────────────────────────

def analyze_foundry_agent_identity(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess Entra Agent ID and identity posture for Foundry projects."""
    findings: list[dict] = []
    findings.extend(_check_project_no_managed_identity(evidence_index))
    findings.extend(_check_project_shared_identity(evidence_index))
    findings.extend(_check_agent_identity_permission_drift(evidence_index))
    return findings


def _check_project_no_managed_identity(idx: dict) -> list[dict]:
    """Flag Foundry projects without a managed identity configured."""
    projects = idx.get("foundry-project", [])
    no_mi: list[dict] = []
    for ev in projects:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasManagedIdentity"):
            no_mi.append({
                "Type": "FoundryProject",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ProjectId", ""),
                "AccountName": data.get("AccountName", ""),
            })
    if no_mi:
        return [_as_finding(
            "foundry_agent_identity", "project_no_managed_identity",
            f"{len(no_mi)} Foundry projects lack managed identity",
            "Foundry projects require a system-assigned managed identity to issue "
            "federated credentials for Entra Agent ID. Without it, agents cannot "
            "obtain scoped tokens for downstream resources.",
            "high", "foundry", no_mi,
            {"Description": "Enable system-assigned managed identity on Foundry projects.",
             "PortalSteps": ["Go to Azure portal > AI Foundry > Select the project",
                             "Go to Settings > Identity",
                             "Enable system-assigned managed identity",
                             "Grant necessary RBAC roles to the identity"]},
        )]
    return []


def _check_project_shared_identity(idx: dict) -> list[dict]:
    """Flag projects where multiple agents share a single project identity."""
    projects = idx.get("foundry-project", [])
    apps = idx.get("foundry-agent-application", [])
    shared: list[dict] = []
    for ev in projects:
        data = ev.get("Data", ev.get("data", {}))
        project_id = data.get("ProjectId", "")
        published = [
            a for a in apps
            if (a.get("Data", a.get("data", {})).get("ProjectId", "") == project_id)
        ]
        unpublished_count = data.get("AgentCount", 0) - len(published)
        if unpublished_count > 1:
            shared.append({
                "Type": "FoundryProject",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": project_id,
                "UnpublishedAgents": unpublished_count,
                "PublishedAgents": len(published),
            })
    if shared:
        return [_as_finding(
            "foundry_agent_identity", "shared_project_identity",
            f"{len(shared)} projects have multiple agents sharing a single identity",
            "Unpublished agents in a Foundry project share one project-level identity. "
            "This means all agents get the same permissions, preventing least-privilege "
            "isolation. Publishing agents creates distinct Entra Agent IDs.",
            "medium", "foundry", shared,
            {"Description": "Publish agents to create distinct Entra Agent IDs.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Select each agent and click 'Publish'",
                             "Each published agent receives a unique Entra Agent Identity",
                             "Assign RBAC roles per-agent on their Agent Application scope"]},
        )]
    return []


def _check_agent_identity_permission_drift(idx: dict) -> list[dict]:
    """Flag published agent apps without RBAC assignments (permission drift risk)."""
    apps = idx.get("foundry-agent-application", [])
    no_rbac: list[dict] = []
    for ev in apps:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasRBACAssignments"):
            no_rbac.append({
                "Type": "AgentApplication",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ApplicationId", ""),
                "ProjectName": data.get("ProjectName", ""),
            })
    if no_rbac:
        return [_as_finding(
            "foundry_agent_identity", "agent_permission_drift",
            f"{len(no_rbac)} published agent applications lack RBAC assignments",
            "Published agents with distinct Entra Agent IDs but no explicit RBAC "
            "assignments may inherit overly broad permissions from the project identity, "
            "violating least-privilege. Assign scoped roles on the Agent Application resource.",
            "high", "foundry", no_rbac,
            {"Description": "Assign Azure AI User role on each Agent Application scope.",
             "AzureCLI": "az role assignment create --assignee <agent-identity-object-id> "
                         "--role 'Azure AI User' --scope <agent-application-resource-id>",
             "PortalSteps": ["Go to Azure portal > AI Foundry > Projects > Agent Applications",
                             "Select the agent application",
                             "Go to Access Control (IAM)",
                             "Add role assignment with minimum required permissions"]},
        )]
    return []


# ── 9m. Agent Application Security ──────────────────────────────────

def analyze_foundry_agent_application(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess published agent applications and their deployment posture."""
    findings: list[dict] = []
    findings.extend(_check_agent_app_public_endpoint(evidence_index))
    findings.extend(_check_agent_app_no_auth(evidence_index))
    findings.extend(_check_agent_deployment_unhealthy(evidence_index))
    return findings


def _check_agent_app_public_endpoint(idx: dict) -> list[dict]:
    """Flag agent applications with public endpoint exposure."""
    apps = idx.get("foundry-agent-application", [])
    public: list[dict] = []
    for ev in apps:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("IsPublicEndpoint", True):
            public.append({
                "Type": "AgentApplication",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ApplicationId", ""),
                "EndpointUrl": data.get("EndpointUrl", ""),
                "Protocol": data.get("Protocol", ""),
            })
    if public:
        return [_as_finding(
            "foundry_agent_application", "public_endpoint_exposure",
            f"{len(public)} agent applications expose public endpoints",
            "Published agents with public endpoints can be reached from the internet. "
            "For agents handling sensitive data, restrict access via private endpoints "
            "or IP restrictions and apply RBAC-based authentication.",
            "high", "foundry", public,
            {"Description": "Restrict agent application endpoints to private networks.",
             "PortalSteps": ["Go to Azure portal > AI Foundry > Agent Applications",
                             "Select the agent application",
                             "Configure network restrictions or private endpoints",
                             "Ensure RBAC authentication is enforced at the endpoint"]},
        )]
    return []


def _check_agent_app_no_auth(idx: dict) -> list[dict]:
    """Flag agent applications without RBAC or authentication policy."""
    apps = idx.get("foundry-agent-application", [])
    no_auth: list[dict] = []
    for ev in apps:
        data = ev.get("Data", ev.get("data", {}))
        auth_type = str(data.get("AuthenticationType", "")).lower()
        if not auth_type or auth_type in ("none", "anonymous"):
            no_auth.append({
                "Type": "AgentApplication",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ApplicationId", ""),
                "AuthenticationType": data.get("AuthenticationType", "None"),
            })
    if no_auth:
        return [_as_finding(
            "foundry_agent_application", "no_auth_policy",
            f"{len(no_auth)} agent applications lack authentication policies",
            "Agent applications without authentication allow unauthenticated callers. "
            "Configure RBAC-based auth (Azure AI User role) or Bot Service channel auth.",
            "critical", "foundry", no_auth,
            {"Description": "Configure authentication on agent applications.",
             "PortalSteps": ["Go to Azure portal > AI Foundry > Agent Applications",
                             "Select the agent application",
                             "Configure authentication to require Azure AI User RBAC role",
                             "Alternatively, configure Bot Service channel authentication"]},
        )]
    return []


def _check_agent_deployment_unhealthy(idx: dict) -> list[dict]:
    """Flag agent deployments in non-running/unhealthy state."""
    deployments = idx.get("foundry-agent-deployment", [])
    unhealthy: list[dict] = []
    for ev in deployments:
        data = ev.get("Data", ev.get("data", {}))
        state = str(data.get("ProvisioningState", "")).lower()
        if state and state not in ("succeeded", "running"):
            unhealthy.append({
                "Type": "AgentDeployment",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("DeploymentId", ""),
                "ApplicationName": data.get("ApplicationName", ""),
                "ProvisioningState": data.get("ProvisioningState", ""),
            })
    if unhealthy:
        return [_as_finding(
            "foundry_agent_application", "deployment_unhealthy",
            f"{len(unhealthy)} agent deployments are in unhealthy state",
            "Agent deployments not in Succeeded/Running state may indicate failed "
            "provisioning, resource constraints, or configuration issues that affect "
            "agent availability and security posture monitoring.",
            "medium", "foundry", unhealthy,
            {"Description": "Investigate and remediate unhealthy agent deployments.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Go to Agent Applications > Deployments",
                             "Check provisioning state and error details",
                             "Remediate configuration issues and redeploy"]},
        )]
    return []


# ── 9n. MCP Tool Security ───────────────────────────────────────────

def analyze_foundry_mcp_tools(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess MCP (Model Context Protocol) tool connections for security risks."""
    findings: list[dict] = []
    findings.extend(_check_mcp_no_auth(evidence_index))
    findings.extend(_check_mcp_public_endpoint(evidence_index))
    findings.extend(_check_mcp_shared_to_all(evidence_index))
    return findings


def _get_mcp_connections(idx: dict) -> list[dict]:
    """Extract MCP/RemoteTool connections from evidence."""
    connections = idx.get("azure-ai-connection", [])
    mcp_categories = {"mcp", "remotetool", "remote_tool", "mcpserver"}
    return [
        ev for ev in connections
        if str(ev.get("Data", ev.get("data", {})).get("Category", "")).lower().replace(" ", "").replace("-", "") in mcp_categories
    ]


def _check_mcp_no_auth(idx: dict) -> list[dict]:
    """Flag MCP connections without secure authentication."""
    mcp_conns = _get_mcp_connections(idx)
    no_auth: list[dict] = []
    _WEAK_AUTH = {"none", "", "apikey", "pat", "customkeys"}
    for ev in mcp_conns:
        data = ev.get("Data", ev.get("data", {}))
        auth = str(data.get("AuthType", "")).lower()
        if auth in _WEAK_AUTH:
            no_auth.append({
                "Type": "MCPConnection",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ConnectionId", ""),
                "WorkspaceName": data.get("WorkspaceName", ""),
                "AuthType": data.get("AuthType", "None"),
                "Target": data.get("Target", ""),
            })
    if no_auth:
        return [_as_finding(
            "foundry_mcp_tools", "mcp_no_secure_auth",
            f"{len(no_auth)} MCP tool connections lack secure authentication",
            "MCP server connections using API keys or no authentication are vulnerable "
            "to credential theft and replay attacks. Use Entra ID or OAuth passthrough "
            "authentication for MCP tools to benefit from token scoping and rotation.",
            "high", "foundry", no_auth,
            {"Description": "Configure Entra ID authentication on MCP connections.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Go to Connected Resources > Connections",
                             "Edit the MCP server connection",
                             "Change authentication to Entra ID or OAuth passthrough",
                             "Rotate any exposed API keys"]},
        )]
    return []


def _check_mcp_public_endpoint(idx: dict) -> list[dict]:
    """Flag MCP connections targeting public (non-private) endpoints."""
    mcp_conns = _get_mcp_connections(idx)
    public: list[dict] = []
    _PRIVATE_PATTERNS = (".privatelink.", ".internal.", "10.", "172.", "192.168.")
    for ev in mcp_conns:
        data = ev.get("Data", ev.get("data", {}))
        target = str(data.get("Target", "")).lower()
        if target and not any(p in target for p in _PRIVATE_PATTERNS):
            public.append({
                "Type": "MCPConnection",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ConnectionId", ""),
                "WorkspaceName": data.get("WorkspaceName", ""),
                "Target": data.get("Target", ""),
            })
    if public:
        return [_as_finding(
            "foundry_mcp_tools", "mcp_public_endpoint",
            f"{len(public)} MCP tool connections use public endpoints",
            "MCP servers on public endpoints expose agent tool traffic to the internet. "
            "Use private endpoints for MCP servers when handling sensitive data to keep "
            "traffic on the Microsoft backbone network.",
            "medium", "foundry", public,
            {"Description": "Configure private endpoints for MCP tool servers.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Go to Connected Resources > MCP server connections",
                             "Update the target URL to use private endpoint",
                             "Ensure VNet integration allows private connectivity"]},
        )]
    return []


def _check_mcp_shared_to_all(idx: dict) -> list[dict]:
    """Flag MCP connections shared to all users in the workspace."""
    mcp_conns = _get_mcp_connections(idx)
    shared: list[dict] = []
    for ev in mcp_conns:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("IsSharedToAll"):
            shared.append({
                "Type": "MCPConnection",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ConnectionId", ""),
                "WorkspaceName": data.get("WorkspaceName", ""),
            })
    if shared:
        return [_as_finding(
            "foundry_mcp_tools", "mcp_shared_to_all",
            f"{len(shared)} MCP tool connections are shared to all workspace users",
            "MCP connections shared to all users allow any agent in the workspace to "
            "invoke these tools. Restrict MCP connections to specific agents or users "
            "to enforce least-privilege tool access.",
            "medium", "foundry", shared,
            {"Description": "Restrict MCP connection sharing to specific users.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Go to Connected Resources > Connections",
                             "Edit the MCP connection",
                             "Disable 'Shared to all users'",
                             "Configure per-agent or per-user access"]},
        )]
    return []


# ── 9o. Tool Connection Security ─────────────────────────────────────

def analyze_foundry_tool_security(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess tool and agent-to-agent connection security posture."""
    findings: list[dict] = []
    findings.extend(_check_a2a_no_auth(evidence_index))
    findings.extend(_check_non_microsoft_tools(evidence_index))
    findings.extend(_check_tool_connections_credential_based(evidence_index))
    return findings


def _get_a2a_connections(idx: dict) -> list[dict]:
    """Extract Agent-to-Agent connections from evidence."""
    connections = idx.get("azure-ai-connection", [])
    a2a_categories = {"agent", "a2a", "remotea2a", "agenttoagent", "remote_a2a"}
    return [
        ev for ev in connections
        if str(ev.get("Data", ev.get("data", {})).get("Category", "")).lower().replace(" ", "").replace("-", "") in a2a_categories
    ]


def _check_a2a_no_auth(idx: dict) -> list[dict]:
    """Flag Agent-to-Agent connections without identity-based authentication."""
    a2a_conns = _get_a2a_connections(idx)
    no_auth: list[dict] = []
    _IDENTITY_AUTH = {"aad", "managedidentity", "entra", "oauth2", "serviceprincipal"}
    for ev in a2a_conns:
        data = ev.get("Data", ev.get("data", {}))
        auth = str(data.get("AuthType", "")).lower().replace(" ", "").replace("-", "")
        if auth not in _IDENTITY_AUTH:
            no_auth.append({
                "Type": "A2AConnection",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ConnectionId", ""),
                "WorkspaceName": data.get("WorkspaceName", ""),
                "AuthType": data.get("AuthType", "None"),
                "Target": data.get("Target", ""),
            })
    if no_auth:
        return [_as_finding(
            "foundry_tool_security", "a2a_no_identity_auth",
            f"{len(no_auth)} Agent-to-Agent connections lack identity-based authentication",
            "A2A connections should use Entra ID or managed identity authentication "
            "to verify the calling agent's identity. API key or no authentication "
            "allows any caller to invoke the target agent.",
            "high", "foundry", no_auth,
            {"Description": "Configure Entra ID authentication for A2A connections.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Go to Connected Resources > Agent connections",
                             "Edit the A2A connection",
                             "Configure Entra ID authentication with proper audience",
                             "Set the target agent application's resource ID as audience"]},
        )]
    return []


def _check_non_microsoft_tools(idx: dict) -> list[dict]:
    """Flag connections to non-Microsoft external tool services."""
    connections = idx.get("azure-ai-connection", [])
    _TOOL_CATEGORIES = {"mcp", "remotetool", "remote_tool", "mcpserver",
                        "agent", "a2a", "remotea2a", "openapi", "custom"}
    _MICROSOFT_PATTERNS = (".azure.com", ".microsoft.com", ".windows.net",
                           ".azure-api.net", ".cognitiveservices.azure.com",
                           ".openai.azure.com", ".search.windows.net")
    non_ms: list[dict] = []
    for ev in connections:
        data = ev.get("Data", ev.get("data", {}))
        cat = str(data.get("Category", "")).lower().replace(" ", "").replace("-", "")
        if cat not in _TOOL_CATEGORIES:
            continue
        target = str(data.get("Target", "")).lower()
        if target and not any(p in target for p in _MICROSOFT_PATTERNS):
            non_ms.append({
                "Type": "ExternalConnection",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ConnectionId", ""),
                "WorkspaceName": data.get("WorkspaceName", ""),
                "Category": data.get("Category", ""),
                "Target": data.get("Target", ""),
            })
    if non_ms:
        return [_as_finding(
            "foundry_tool_security", "non_microsoft_tool_connection",
            f"{len(non_ms)} tool connections target non-Microsoft external services",
            "Non-Microsoft MCP servers and tool endpoints have no data processing "
            "guarantees under Microsoft's terms. Ensure data governance policies "
            "cover data sent to external tool services and that approval policies "
            "are configured.",
            "medium", "foundry", non_ms,
            {"Description": "Review and govern non-Microsoft tool connections.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Review all external tool/MCP connections",
                             "Verify data governance and privacy agreements",
                             "Configure approval policies for external tools",
                             "Restrict allowed_tools list to minimize data exposure"]},
        )]
    return []


def _check_tool_connections_credential_based(idx: dict) -> list[dict]:
    """Flag tool connections using credential-based (non-MI) authentication."""
    connections = idx.get("azure-ai-connection", [])
    _TOOL_CATEGORIES = {"mcp", "remotetool", "remote_tool", "mcpserver",
                        "azurefunction", "azure_function", "cognitivesearch",
                        "azureaisearch", "openapi", "custom"}
    _CRED_AUTH = {"apikey", "pat", "customkeys", "accountkey", "accesskey"}
    cred_based: list[dict] = []
    for ev in connections:
        data = ev.get("Data", ev.get("data", {}))
        cat = str(data.get("Category", "")).lower().replace(" ", "").replace("-", "")
        if cat not in _TOOL_CATEGORIES:
            continue
        auth = str(data.get("AuthType", "")).lower()
        if auth in _CRED_AUTH:
            cred_based.append({
                "Type": "ToolConnection",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ConnectionId", ""),
                "WorkspaceName": data.get("WorkspaceName", ""),
                "Category": data.get("Category", ""),
                "AuthType": data.get("AuthType", ""),
            })
    if cred_based:
        return [_as_finding(
            "foundry_tool_security", "tool_credential_based_auth",
            f"{len(cred_based)} tool connections use credential-based authentication",
            "Tool connections using API keys or access keys are harder to rotate "
            "and audit. Prefer managed identity or Entra ID authentication for "
            "tool connections to enable automatic credential rotation and RBAC.",
            "medium", "foundry", cred_based,
            {"Description": "Migrate tool connections to identity-based authentication.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Go to Connected Resources > Connections",
                             "Edit each tool connection using API key auth",
                             "Switch to Entra ID or managed identity authentication",
                             "Rotate and revoke old API keys"]},
        )]
    return []


# ── 9p. Guardrails Configuration ─────────────────────────────────────

def analyze_foundry_guardrails(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess agent guardrail configuration and safety interventions."""
    findings: list[dict] = []
    findings.extend(_check_agent_no_custom_guardrail(evidence_index))
    findings.extend(_check_agent_no_content_safety(evidence_index))
    findings.extend(_check_guardrail_default_only(evidence_index))
    return findings


def _check_agent_no_custom_guardrail(idx: dict) -> list[dict]:
    """Flag published agent applications without a custom guardrail assigned."""
    apps = idx.get("foundry-agent-application", [])
    no_guard: list[dict] = []
    for ev in apps:
        data = ev.get("Data", ev.get("data", {}))
        guardrail = str(data.get("GuardrailCollection", "") or "").strip()
        if not guardrail or guardrail.lower() in ("", "none", "default", "microsoft.defaultv2"):
            no_guard.append({
                "Type": "AgentApplication",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ApplicationId", ""),
                "ProjectName": data.get("ProjectName", ""),
                "GuardrailCollection": guardrail or "None",
            })
    if no_guard:
        return [_as_finding(
            "foundry_guardrails", "agent_no_custom_guardrail",
            f"{len(no_guard)} agent applications use default or no custom guardrails",
            "Agent-level guardrails override model guardrails entirely. When agents "
            "have no custom guardrail collection, they rely on the default Microsoft.DefaultV2 "
            "guardrail which may not cover domain-specific risks like PII exposure, "
            "task adherence violations, or tool-call injection.",
            "medium", "foundry", no_guard,
            {"Description": "Assign custom guardrail collections to agent applications.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Open the agent application > Safety & Security tab",
                             "Create a custom guardrail collection with relevant controls",
                             "Enable tool-call and tool-response intervention points",
                             "Assign the collection to the agent"]},
        )]
    return []


def _check_agent_no_content_safety(idx: dict) -> list[dict]:
    """Flag agent applications in projects that have no content safety filters configured."""
    apps = idx.get("foundry-agent-application", [])
    filters = idx.get("azure-openai-content-filter", [])
    if not apps:
        return []
    # Collect accounts that have content filters
    accounts_with_filters = set()
    for f_ev in filters:
        f_data = f_ev.get("Data", f_ev.get("data", {}))
        acct = f_data.get("AccountName", "")
        if acct:
            accounts_with_filters.add(acct.lower())
    no_safety: list[dict] = []
    for ev in apps:
        data = ev.get("Data", ev.get("data", {}))
        acct = str(data.get("AccountName", "")).lower()
        if acct and acct not in accounts_with_filters:
            no_safety.append({
                "Type": "AgentApplication",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ApplicationId", ""),
                "AccountName": data.get("AccountName", ""),
                "ProjectName": data.get("ProjectName", ""),
            })
    if no_safety:
        return [_as_finding(
            "foundry_guardrails", "agent_account_no_content_safety",
            f"{len(no_safety)} agent applications are in accounts with no content safety filters",
            "Agent applications in Foundry accounts that lack content safety filters "
            "have no guardrails against harmful content generation. Configure both "
            "model-level content filters and agent-level guardrails for defense in depth.",
            "high", "foundry", no_safety,
            {"Description": "Configure content safety filters on the Foundry account.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the account",
                             "Go to Content Safety > Filters",
                             "Create content filter policies for model deployments",
                             "Also configure agent-level guardrails for additional protection"]},
        )]
    return []


def _check_guardrail_default_only(idx: dict) -> list[dict]:
    """Flag when all content filters in an account use minimum severity thresholds."""
    filters = idx.get("azure-openai-content-filter", [])
    if not filters:
        return []
    weak_accounts: dict[str, list] = {}
    for ev in filters:
        data = ev.get("Data", ev.get("data", {}))
        # Check if all categories are set to low/allow thresholds
        props = data.get("Properties", data.get("properties", {}))
        if not props:
            continue
        categories = props.get("contentFilters", [])
        all_permissive = True
        for cat in categories:
            sev = str(cat.get("severityThreshold", "")).lower()
            if sev not in ("low", ""):
                all_permissive = False
                break
        if all_permissive and categories:
            acct = data.get("AccountName", "unknown")
            if acct not in weak_accounts:
                weak_accounts[acct] = []
            weak_accounts[acct].append({
                "Type": "ContentFilter",
                "Name": data.get("Name", data.get("FilterName", "Unknown")),
                "AccountName": acct,
            })
    if weak_accounts:
        affected = []
        for acct, items in weak_accounts.items():
            affected.extend(items)
        return [_as_finding(
            "foundry_guardrails", "permissive_content_filters",
            f"{len(affected)} content filters use minimum severity thresholds",
            "Content filters with 'low' severity thresholds allow most harmful content "
            "through. For agents with tool access, use 'medium' or 'high' thresholds "
            "to mitigate prompt injection and content safety risks.",
            "medium", "foundry", affected,
            {"Description": "Increase content filter severity thresholds.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the account",
                             "Go to Content Safety > Filters",
                             "Increase severity thresholds from 'Low' to 'Medium' or 'High'",
                             "Apply to all model deployments used by agents"]},
        )]
    return []


# ── 9q. Hosted Agent Security ────────────────────────────────────────

def analyze_foundry_hosted_agents(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess hosted agent capability hosts for security posture."""
    findings: list[dict] = []
    findings.extend(_check_hosted_no_vnet(evidence_index))
    findings.extend(_check_hosted_no_acr(evidence_index))
    findings.extend(_check_hosted_unhealthy(evidence_index))
    return findings


def _check_hosted_no_vnet(idx: dict) -> list[dict]:
    """Flag hosted agent capability hosts without VNet integration."""
    cap_hosts = idx.get("foundry-capability-host", [])
    no_vnet: list[dict] = []
    for ev in cap_hosts:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasVNetConfig"):
            no_vnet.append({
                "Type": "CapabilityHost",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("CapabilityHostId", ""),
                "AccountName": data.get("AccountName", ""),
            })
    if no_vnet:
        return [_as_finding(
            "foundry_hosted_agents", "hosted_no_vnet",
            f"{len(no_vnet)} hosted agent capability hosts lack VNet integration",
            "Hosted agents without VNet integration have their container traffic "
            "routed over public networks. Configure VNet integration with a delegated "
            "subnet (Microsoft.App/environments) to keep agent execution traffic private.",
            "high", "foundry", no_vnet,
            {"Description": "Configure VNet integration for hosted agent capability hosts.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the account",
                             "Go to Networking > Hosted Agents",
                             "Configure a delegated subnet (Microsoft.App/environments)",
                             "Enable VNet integration for the capability host",
                             "Note: Some features may not support VNet in preview"]},
        )]
    return []


def _check_hosted_no_acr(idx: dict) -> list[dict]:
    """Flag hosted agent capability hosts without a container registry configured."""
    cap_hosts = idx.get("foundry-capability-host", [])
    no_acr: list[dict] = []
    for ev in cap_hosts:
        data = ev.get("Data", ev.get("data", {}))
        acr_id = data.get("ContainerRegistryId", "") or ""
        acr_name = data.get("AcrRegistryName", "") or ""
        if not acr_id and not acr_name:
            no_acr.append({
                "Type": "CapabilityHost",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("CapabilityHostId", ""),
                "AccountName": data.get("AccountName", ""),
            })
    if no_acr:
        return [_as_finding(
            "foundry_hosted_agents", "hosted_no_acr",
            f"{len(no_acr)} hosted agent capability hosts have no container registry configured",
            "Hosted agents require an Azure Container Registry to store and pull "
            "Docker images. Without a configured ACR, the capability host cannot "
            "deploy hosted agent containers securely.",
            "high", "foundry", no_acr,
            {"Description": "Configure Azure Container Registry for capability hosts.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the account",
                             "Go to Hosted Agents > Capability Hosts",
                             "Associate an Azure Container Registry",
                             "Ensure ACR has RBAC (Container Registry Repository Reader)",
                             "Enable private endpoint on ACR for network isolation"]},
        )]
    return []


def _check_hosted_unhealthy(idx: dict) -> list[dict]:
    """Flag hosted agent capability hosts with failed provisioning."""
    cap_hosts = idx.get("foundry-capability-host", [])
    unhealthy: list[dict] = []
    _HEALTHY = {"succeeded", "running", "creating"}
    for ev in cap_hosts:
        data = ev.get("Data", ev.get("data", {}))
        state = str(data.get("ProvisioningState", "")).lower()
        if state and state not in _HEALTHY:
            unhealthy.append({
                "Type": "CapabilityHost",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("CapabilityHostId", ""),
                "AccountName": data.get("AccountName", ""),
                "ProvisioningState": data.get("ProvisioningState", ""),
            })
    if unhealthy:
        return [_as_finding(
            "foundry_hosted_agents", "hosted_unhealthy",
            f"{len(unhealthy)} hosted agent capability hosts are in unhealthy state",
            "Capability hosts with failed provisioning indicate misconfiguration "
            "or resource issues. Investigate and resolve provisioning errors to "
            "ensure hosted agents can be deployed and managed properly.",
            "high", "foundry", unhealthy,
            {"Description": "Investigate and fix unhealthy capability hosts.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the account",
                             "Go to Hosted Agents > Capability Hosts",
                             "Check provisioning state and error details",
                             "Resolve configuration issues (ACR access, VNet, etc.)",
                             "Re-provision the capability host"]},
        )]
    return []


# ── 9r. Agent Data Resources ─────────────────────────────────────────

def analyze_foundry_data_resources(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess data resource connections used by agents (Cosmos DB, AI Search, Storage)."""
    findings: list[dict] = []
    findings.extend(_check_data_connection_no_mi(evidence_index))
    findings.extend(_check_storage_no_encryption(evidence_index))
    findings.extend(_check_data_connection_shared(evidence_index))
    return findings


def _get_data_connections(idx: dict) -> list[dict]:
    """Extract data-resource connections (Cosmos, AI Search, Storage) from evidence."""
    connections = idx.get("azure-ai-connection", [])
    _DATA_CATEGORIES = {
        "cosmosdb", "cosmos", "azurecosmosdb",
        "cognitivesearch", "azureaisearch", "aisearch",
        "azureblobstorage", "azureblob", "blob", "storage", "azurestorage",
        "azuredatalake", "datalake",
    }
    return [
        ev for ev in connections
        if str(ev.get("Data", ev.get("data", {})).get("Category", "")).lower().replace(" ", "").replace("-", "").replace("_", "") in _DATA_CATEGORIES
    ]


def _check_data_connection_no_mi(idx: dict) -> list[dict]:
    """Flag data connections using credential-based auth instead of managed identity."""
    data_conns = _get_data_connections(idx)
    _MI_AUTH = {"managedidentity", "aad", "entra", "identity", "serviceprincipal"}
    no_mi: list[dict] = []
    for ev in data_conns:
        data = ev.get("Data", ev.get("data", {}))
        auth = str(data.get("AuthType", "")).lower().replace(" ", "").replace("-", "")
        if auth not in _MI_AUTH:
            no_mi.append({
                "Type": "DataConnection",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ConnectionId", ""),
                "WorkspaceName": data.get("WorkspaceName", ""),
                "Category": data.get("Category", ""),
                "AuthType": data.get("AuthType", ""),
                "Target": data.get("Target", ""),
            })
    if no_mi:
        return [_as_finding(
            "foundry_data_resources", "data_connection_no_managed_identity",
            f"{len(no_mi)} agent data connections use credential-based authentication",
            "Data resource connections (Cosmos DB, AI Search, Storage) used by agents "
            "should use managed identity authentication. Credential-based access creates "
            "key rotation burden and increases risk of leaked secrets.",
            "high", "foundry", no_mi,
            {"Description": "Switch data connections to managed identity authentication.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Go to Connected Resources > Data connections",
                             "Edit each connection using API keys",
                             "Switch to managed identity authentication",
                             "Ensure the workspace MI has appropriate RBAC on the data resource"]},
        )]
    return []


def _check_storage_no_encryption(idx: dict) -> list[dict]:
    """Flag AI service accounts without customer-managed key encryption."""
    services = idx.get("azure-ai-service", [])
    no_cmk: list[dict] = []
    for ev in services:
        data = ev.get("Data", ev.get("data", {}))
        kind = str(data.get("Kind", "")).lower()
        if kind in ("aiservices", "openai", "azureopenai") and not data.get("HasCMK"):
            no_cmk.append({
                "Type": "AzureAIService",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("AccountId", ""),
                "Kind": data.get("Kind", ""),
            })
    if no_cmk:
        return [_as_finding(
            "foundry_data_resources", "no_customer_managed_key",
            f"{len(no_cmk)} Foundry accounts lack customer-managed key encryption",
            "Agent conversation state, uploaded files, and cached data stored in "
            "Foundry-managed resources are encrypted with Microsoft-managed keys by default. "
            "Configure customer-managed keys (CMK) via Azure Key Vault for data sovereignty "
            "and compliance requirements.",
            "medium", "foundry", no_cmk,
            {"Description": "Enable customer-managed key encryption on Foundry accounts.",
             "PortalSteps": ["Go to Azure portal > AI Services > Select the account",
                             "Go to Encryption > Customer-managed keys",
                             "Select or create a Key Vault with the encryption key",
                             "Assign Key Vault access to the AI service managed identity"]},
        )]
    return []


def _check_data_connection_shared(idx: dict) -> list[dict]:
    """Flag data connections shared to all workspace users."""
    data_conns = _get_data_connections(idx)
    shared: list[dict] = []
    for ev in data_conns:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("IsSharedToAll"):
            shared.append({
                "Type": "DataConnection",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ConnectionId", ""),
                "WorkspaceName": data.get("WorkspaceName", ""),
                "Category": data.get("Category", ""),
            })
    if shared:
        return [_as_finding(
            "foundry_data_resources", "data_connection_shared_to_all",
            f"{len(shared)} agent data connections are shared to all workspace users",
            "Data connections (Cosmos DB, AI Search, Storage) shared to all users "
            "allow any agent or user in the workspace to access the data resource. "
            "Restrict data connections to specific agents for least-privilege data access.",
            "medium", "foundry", shared,
            {"Description": "Restrict data connection sharing to specific users.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Go to Connected Resources > Data connections",
                             "Edit shared connections",
                             "Disable 'Shared to all users'",
                             "Assign per-agent or per-user access to data resources"]},
        )]
    return []


# ── 9s. Agent Observability ──────────────────────────────────────────

def analyze_foundry_observability(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess agent observability coverage: tracing, diagnostics, App Insights."""
    findings: list[dict] = []
    findings.extend(_check_workspace_no_diagnostics(evidence_index))
    findings.extend(_check_project_no_tracing(evidence_index))
    findings.extend(_check_workspace_limited_log_coverage(evidence_index))
    return findings


def _check_workspace_no_diagnostics(idx: dict) -> list[dict]:
    """Flag workspaces with no diagnostic settings configured."""
    ws_diags = idx.get("azure-ai-workspace-diagnostics", [])
    no_diag: list[dict] = []
    for ev in ws_diags:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasDiagnostics"):
            no_diag.append({
                "Type": "AIWorkspace",
                "Name": data.get("WorkspaceName", "Unknown"),
                "ResourceId": data.get("WorkspaceId", ""),
            })
    if no_diag:
        return [_as_finding(
            "foundry_observability", "workspace_no_diagnostics",
            f"{len(no_diag)} AI workspaces have no diagnostic settings",
            "Without diagnostic settings, agent interactions, errors, and tool calls "
            "are not logged. Enable diagnostic settings with Log Analytics for "
            "comprehensive agent activity monitoring and incident response.",
            "high", "foundry", no_diag,
            {"Description": "Enable diagnostic settings on AI workspaces.",
             "PortalSteps": ["Go to Azure portal > AI workspace > Diagnostic settings",
                             "Add diagnostic setting",
                             "Enable all log categories",
                             "Select Log Analytics workspace as destination"]},
        )]
    return []


def _check_project_no_tracing(idx: dict) -> list[dict]:
    """Flag Foundry projects without Application Insights for agent tracing."""
    projects = idx.get("foundry-project", [])
    ws_diags = idx.get("azure-ai-workspace-diagnostics", [])
    if not projects:
        return []
    # Collect workspaces that have App Insights / Log Analytics enabled
    monitored_workspaces = set()
    for ev in ws_diags:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("HasLogAnalytics") or data.get("HasDiagnostics"):
            ws_name = str(data.get("WorkspaceName", "")).lower()
            if ws_name:
                monitored_workspaces.add(ws_name)
    no_trace: list[dict] = []
    for ev in projects:
        data = ev.get("Data", ev.get("data", {}))
        acct = str(data.get("AccountName", "")).lower()
        proj = str(data.get("Name", "")).lower()
        # Check if the parent account or project name matches any monitored workspace
        if acct not in monitored_workspaces and proj not in monitored_workspaces:
            no_trace.append({
                "Type": "FoundryProject",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ProjectId", ""),
                "AccountName": data.get("AccountName", ""),
            })
    if no_trace:
        return [_as_finding(
            "foundry_observability", "project_no_tracing",
            f"{len(no_trace)} Foundry projects lack Application Insights tracing",
            "Foundry agent tracing via Application Insights provides end-to-end "
            "visibility into agent reasoning, tool calls, and guardrail interventions. "
            "Without tracing, debugging agent behavior and detecting anomalies is limited.",
            "medium", "foundry", no_trace,
            {"Description": "Enable Application Insights tracing for Foundry projects.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Go to Tracing > Configure",
                             "Connect Application Insights resource",
                             "Enable OpenTelemetry-based agent tracing",
                             "Verify trace data appears in App Insights"]},
        )]
    return []


def _check_workspace_limited_log_coverage(idx: dict) -> list[dict]:
    """Flag workspaces with diagnostics but incomplete log categories."""
    ws_diags = idx.get("azure-ai-workspace-diagnostics", [])
    limited: list[dict] = []
    _REQUIRED = {"audit", "requestresponse", "allmetrics"}
    for ev in ws_diags:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasDiagnostics"):
            continue
        enabled = set(c.lower() for c in (data.get("EnabledLogs", []) + data.get("EnabledMetrics", [])))
        missing = _REQUIRED - enabled
        if missing:
            limited.append({
                "Type": "AIWorkspace",
                "Name": data.get("WorkspaceName", "Unknown"),
                "ResourceId": data.get("WorkspaceId", ""),
                "EnabledCategories": str(data.get("EnabledLogs", []) + data.get("EnabledMetrics", [])),
                "MissingCategories": str(sorted(missing)),
            })
    if limited:
        return [_as_finding(
            "foundry_observability", "workspace_limited_log_coverage",
            f"{len(limited)} AI workspaces have incomplete diagnostic log coverage",
            "Diagnostic settings exist but not all required log categories are enabled. "
            "Enable Audit, RequestResponse, and AllMetrics for comprehensive "
            "agent activity monitoring.",
            "medium", "foundry", limited,
            {"Description": "Enable all required diagnostic log categories.",
             "PortalSteps": ["Go to Azure portal > AI workspace > Diagnostic settings",
                             "Edit existing diagnostic setting",
                             "Enable missing log categories (Audit, RequestResponse)",
                             "Enable all metric categories",
                             "Save"]},
        )]
    return []


# ── 9t. Agent Lifecycle Governance ───────────────────────────────────

def analyze_foundry_lifecycle(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess agent lifecycle governance: versioning, shadow agents, publishing."""
    findings: list[dict] = []
    findings.extend(_check_projects_no_agents(evidence_index))
    findings.extend(_check_unpublished_agents(evidence_index))
    findings.extend(_check_agent_no_rbac(evidence_index))
    return findings


def _check_projects_no_agents(idx: dict) -> list[dict]:
    """Flag Foundry projects with agent capacity but no published applications."""
    projects = idx.get("foundry-project", [])
    apps = idx.get("foundry-agent-application", [])
    if not projects:
        return []
    # Collect project IDs that have published applications
    published_projects = set()
    for ev in apps:
        data = ev.get("Data", ev.get("data", {}))
        proj_id = str(data.get("ProjectId", "")).lower()
        if proj_id:
            published_projects.add(proj_id)
    no_apps: list[dict] = []
    for ev in projects:
        data = ev.get("Data", ev.get("data", {}))
        proj_id = str(data.get("ProjectId", "")).lower()
        agent_count = data.get("AgentCount", 0) or 0
        # Projects with agents but no published applications indicate shadow/unmanaged agents
        if agent_count > 0 and proj_id not in published_projects:
            no_apps.append({
                "Type": "FoundryProject",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ProjectId", ""),
                "AccountName": data.get("AccountName", ""),
                "AgentCount": agent_count,
            })
    if no_apps:
        return [_as_finding(
            "foundry_lifecycle", "shadow_agents_unpublished",
            f"{len(no_apps)} projects have agents but no published applications (potential shadow agents)",
            "These projects contain active agents that have not been published as "
            "formal Agent Applications. Unpublished agents bypass lifecycle controls, "
            "RBAC scoping, and audit trails. Publish agents to formalize governance "
            "and enable identity-scoped access control.",
            "medium", "foundry", no_apps,
            {"Description": "Review and publish or decommission shadow agents.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Review all agents under the 'Agents' tab",
                             "Publish production-ready agents as Agent Applications",
                             "Decommission or delete unused development agents",
                             "Set up Azure Policy to require agent publishing"]},
        )]
    return []


def _check_unpublished_agents(idx: dict) -> list[dict]:
    """Flag projects with high agent counts relative to published applications."""
    projects = idx.get("foundry-project", [])
    apps = idx.get("foundry-agent-application", [])
    if not projects:
        return []
    # Count published apps per project
    project_app_count: dict[str, int] = {}
    for ev in apps:
        data = ev.get("Data", ev.get("data", {}))
        proj_id = str(data.get("ProjectId", "")).lower()
        if proj_id:
            project_app_count[proj_id] = project_app_count.get(proj_id, 0) + 1
    excess: list[dict] = []
    for ev in projects:
        data = ev.get("Data", ev.get("data", {}))
        proj_id = str(data.get("ProjectId", "")).lower()
        agent_count = data.get("AgentCount", 0) or 0
        published = project_app_count.get(proj_id, 0)
        # If agent count significantly exceeds published count, signal governance gap
        if agent_count > 3 and published > 0 and agent_count > published * 3:
            excess.append({
                "Type": "FoundryProject",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ProjectId", ""),
                "AccountName": data.get("AccountName", ""),
                "AgentCount": agent_count,
                "PublishedApplications": published,
            })
    if excess:
        return [_as_finding(
            "foundry_lifecycle", "excess_unpublished_agents",
            f"{len(excess)} projects have disproportionately more agents than published applications",
            "A large number of unpublished agents relative to published applications "
            "suggests development sprawl or abandoned experiments. Review and clean up "
            "unused agents to reduce attack surface and manage resource costs.",
            "low", "foundry", excess,
            {"Description": "Audit and clean up excess unpublished agents.",
             "PortalSteps": ["Go to Azure AI Foundry portal > Select the project",
                             "Review agent inventory under the 'Agents' tab",
                             "Identify and delete unused or duplicate agents",
                             "Establish naming conventions and cleanup policies"]},
        )]
    return []


def _check_agent_no_rbac(idx: dict) -> list[dict]:
    """Flag published agent applications without explicit RBAC assignments."""
    apps = idx.get("foundry-agent-application", [])
    no_rbac: list[dict] = []
    for ev in apps:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasRBACAssignments"):
            no_rbac.append({
                "Type": "AgentApplication",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ApplicationId", ""),
                "ProjectName": data.get("ProjectName", ""),
                "AccountName": data.get("AccountName", ""),
            })
    if no_rbac:
        return [_as_finding(
            "foundry_lifecycle", "agent_no_rbac",
            f"{len(no_rbac)} published agent applications have no explicit RBAC assignments",
            "Published Agent Applications without RBAC assignments may be accessible "
            "only via inherited permissions, making access control opaque. Assign "
            "explicit Azure AI User role assignments on each Agent Application "
            "resource to enforce least-privilege access.",
            "medium", "foundry", no_rbac,
            {"Description": "Assign explicit RBAC to Agent Application resources.",
             "PortalSteps": ["Go to Azure portal > Agent Application resource",
                             "Go to Access control (IAM) > Add role assignment",
                             "Assign 'Azure AI User' to authorized principals",
                             "Remove broad inherited role assignments if possible"]},
        )]
    return []

