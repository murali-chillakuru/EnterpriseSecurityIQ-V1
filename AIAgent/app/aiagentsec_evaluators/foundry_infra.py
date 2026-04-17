"""Microsoft Foundry infrastructure security evaluators — network, identity, content safety, deployments, governance."""

from __future__ import annotations

from .finding import _as_finding


def analyze_foundry_network(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess network isolation for Azure AI / Foundry services."""
    findings: list[dict] = []
    findings.extend(_check_ai_public_access(evidence_index))
    findings.extend(_check_ai_private_endpoints(evidence_index))
    findings.extend(_check_workspace_isolation(evidence_index))
    return findings


def _check_ai_public_access(idx: dict) -> list[dict]:
    """Flag AI services with public network access enabled."""
    services = idx.get("azure-ai-service", [])
    public: list[dict] = []
    for ev in services:
        data = ev.get("Data", ev.get("data", {}))
        if str(data.get("PublicNetworkAccess", "")).lower() in ("enabled", ""):
            public.append({
                "Type": "AzureAIService",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("AccountId", ""),
                "Kind": data.get("Kind", ""),
                "IsOpenAI": data.get("IsOpenAI", False),
            })
    if public:
        return [_as_finding(
            "foundry_network", "public_access_enabled",
            f"{len(public)} AI service accounts have public network access enabled",
            "AI services with public access can be reached from the internet. "
            "For agents handling sensitive data, network access should be restricted "
            "to private endpoints or specific IP ranges.",
            "high", "foundry", public,
            {"Description": "Disable public network access and use private endpoints.",
             "AzureCLI": "az cognitiveservices account update -n <name> -g <rg> "
                         "--public-network-access Disabled",
             "PowerShell": "Set-AzCognitiveServicesAccount -ResourceGroupName <rg> -Name <name> "
                           "-PublicNetworkAccess Disabled",
             "PortalSteps": ["Go to Azure portal > AI Services > Select the resource", "Go to Networking", "Set 'Public network access' to 'Disabled'", "Configure private endpoint connections", "Save"]},
        )]
    return []


def _check_ai_private_endpoints(idx: dict) -> list[dict]:
    """Flag AI services without private endpoints."""
    services = idx.get("azure-ai-service", [])
    no_pe: list[dict] = []
    for ev in services:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasPrivateEndpoints"):
            no_pe.append({
                "Type": "AzureAIService",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("AccountId", ""),
                "Kind": data.get("Kind", ""),
            })
    if no_pe:
        return [_as_finding(
            "foundry_network", "no_private_endpoints",
            f"{len(no_pe)} AI services lack private endpoint connections",
            "Private endpoints ensure AI service traffic stays on the Microsoft backbone "
            "network, reducing data exfiltration risk for agent interactions.",
            "medium", "foundry", no_pe,
            {"Description": "Configure private endpoints for AI services.",
             "AzureCLI": "az network private-endpoint create --name <pe-name> "
                         "--resource-group <rg> --vnet-name <vnet> --subnet <subnet> "
                         "--private-connection-resource-id <ai-resource-id> "
                         "--group-id account --connection-name <conn-name>",
             "PowerShell": "New-AzPrivateEndpoint -Name <pe-name> -ResourceGroupName <rg> "
                           "-Location <loc> -Subnet (Get-AzVirtualNetwork -Name <vnet> "
                           "-ResourceGroupName <rg>).Subnets[0] "
                           "-PrivateLinkServiceConnection @{Name='conn';PrivateLinkServiceId='<ai-resource-id>';GroupIds=@('account')}",
             "PortalSteps": ["Go to Azure portal > AI Services > Select the resource", "Go to Networking > Private endpoint connections", "Click '+ Private endpoint'", "Select VNet, subnet, and DNS integration", "Complete the wizard and create"]},
        )]
    return []


def _check_workspace_isolation(idx: dict) -> list[dict]:
    """Check AI Foundry workspace network isolation."""
    workspaces = idx.get("azure-ai-workspace", [])
    no_isolation: list[dict] = []
    for ev in workspaces:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasNetworkIsolation"):
            no_isolation.append({
                "Type": "AzureAIWorkspace",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("WorkspaceId", ""),
                "Kind": data.get("Kind", ""),
                "IsolationMode": data.get("IsolationMode", "None"),
            })
    if no_isolation:
        return [_as_finding(
            "foundry_network", "workspace_no_isolation",
            f"{len(no_isolation)} AI Foundry workspaces lack network isolation",
            "AI Foundry workspaces (hubs/projects) should use managed network isolation "
            "to control outbound connectivity and prevent data exfiltration from agents.",
            "medium", "foundry", no_isolation,
            {"Description": "Enable managed network isolation on AI Foundry workspaces.",
             "AzureCLI": "az ml workspace update --name <ws> --resource-group <rg> "
                         "--managed-network allow-internet-outbound",
             "PowerShell": "Update-AzMLWorkspace -Name <ws> -ResourceGroupName <rg> "
                           "-ManagedNetworkIsolationMode AllowInternetOutbound",
             "PortalSteps": ["Go to Azure portal > Microsoft Foundry > Select the workspace", "Go to Settings > Networking", "Enable 'Managed virtual network isolation'", "Choose isolation mode (Allow Internet Outbound or Allow Only Approved Outbound)", "Save"]},
        )]
    return []


# ── 6. Managed Identity ──────────────────────────────────────────────

def analyze_foundry_identity(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess managed identity and key management for AI services."""
    findings: list[dict] = []
    findings.extend(_check_ai_local_auth(evidence_index))
    findings.extend(_check_workspace_managed_identity(evidence_index))
    return findings


def _check_ai_local_auth(idx: dict) -> list[dict]:
    """Flag AI services that have local (key-based) authentication enabled."""
    services = idx.get("azure-ai-service", [])
    key_auth: list[dict] = []
    for ev in services:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("DisableLocalAuth"):
            key_auth.append({
                "Type": "AzureAIService",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("AccountId", ""),
                "Kind": data.get("Kind", ""),
            })
    if key_auth:
        return [_as_finding(
            "foundry_identity", "local_auth_enabled",
            f"{len(key_auth)} AI services have API key authentication enabled",
            "API key authentication is less secure than managed identity. Keys can be "
            "leaked, shared, and don't support fine-grained RBAC or Conditional Access.",
            "high", "foundry", key_auth,
            {"Description": "Disable local authentication and use managed identity.",
             "AzureCLI": "az cognitiveservices account update -n <name> -g <rg> "
                         "--disable-local-auth true",
             "PowerShell": "Set-AzCognitiveServicesAccount -ResourceGroupName <rg> -Name <name> "
                           "-DisableLocalAuth $true",
             "PortalSteps": ["Go to Azure portal > AI Services > Select the resource", "Go to Identity > System assigned", "Set Status to 'On' and Save", "Go to Keys and Endpoint > disable local authentication"]},
        )]
    return []


def _check_workspace_managed_identity(idx: dict) -> list[dict]:
    """Check if AI Foundry workspaces use managed identity."""
    workspaces = idx.get("azure-ai-workspace", [])
    no_mi: list[dict] = []
    for ev in workspaces:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasManagedIdentity"):
            no_mi.append({
                "Type": "AzureAIWorkspace",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("WorkspaceId", ""),
                "IdentityType": data.get("IdentityType", "None"),
            })
    if no_mi:
        return [_as_finding(
            "foundry_identity", "workspace_no_managed_identity",
            f"{len(no_mi)} AI Foundry workspaces lack system-assigned managed identity",
            "Managed identity enables secure, credential-free authentication to Azure "
            "resources used by AI agents (Key Vault, Storage, etc.).",
            "medium", "foundry", no_mi,
            {"Description": "Enable system-assigned managed identity on AI workspaces.",
             "AzureCLI": "az ml workspace update --name <ws> --resource-group <rg> "
                         "--system-datastores-auth-mode identity",
             "PortalSteps": ["Go to Azure portal > Microsoft Foundry > Select the workspace", "Go to Identity > System assigned", "Set Status to 'On'", "Save and grant necessary RBAC roles"]},
        )]
    return []


# ── 7. Content Safety Filters ────────────────────────────────────────

def analyze_foundry_content_safety(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess content safety filter configuration for AI deployments."""
    findings: list[dict] = []
    findings.extend(_check_content_filter_coverage(evidence_index))
    findings.extend(_check_content_filter_strength(evidence_index))
    return findings


def _check_content_filter_coverage(idx: dict) -> list[dict]:
    """Flag OpenAI deployments without content filters."""
    deployments = idx.get("azure-openai-deployment", [])
    filters = idx.get("azure-openai-content-filter", [])
    no_filter: list[dict] = []

    filter_accounts = {
        ev.get("Data", ev.get("data", {})).get("AccountId", "")
        for ev in filters
    }

    for ev in deployments:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasContentFilter"):
            no_filter.append({
                "Type": "OpenAIDeployment",
                "Name": data.get("DeploymentName", "Unknown"),
                "ResourceId": data.get("DeploymentId", ""),
                "AccountName": data.get("AccountName", ""),
                "ModelName": data.get("ModelName", ""),
            })

    if no_filter:
        return [_as_finding(
            "foundry_content_safety", "no_content_filter",
            f"{len(no_filter)} OpenAI deployments lack content safety filters",
            "Content safety filters (Responsible AI policies) are critical to prevent "
            "AI agents from generating harmful, offensive, or sensitive content. "
            "Deployments without filters pose significant content leakage risk.",
            "critical", "foundry", no_filter,
            {"Description": "Apply RAI content filter policies to all OpenAI deployments.",
             "PortalSteps": ["Go to Microsoft Foundry portal > Select the project", "Go to Safety + Security > Content filters", "Create a content filter configuration", "Set all categories (hate, violence, sexual, self-harm) to Block mode", "Apply the filter to target deployments"]},
        )]
    return []


def _check_content_filter_strength(idx: dict) -> list[dict]:
    """Check if content filters have blocking enabled for all categories."""
    filters = idx.get("azure-openai-content-filter", [])
    weak: list[dict] = []
    for ev in filters:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("AllFiltersBlocking") and data.get("TotalFilters", 0) > 0:
            weak.append({
                "Type": "ContentFilter",
                "Name": data.get("PolicyName", "Unknown"),
                "ResourceId": data.get("PolicyId", ""),
                "TotalFilters": data.get("TotalFilters", 0),
                "BlockingFilters": data.get("BlockingFilters", 0),
            })
    if weak:
        return [_as_finding(
            "foundry_content_safety", "weak_content_filters",
            f"{len(weak)} content filter policies have non-blocking categories",
            "Content filters should block harmful content in all categories (hate, violence, "
            "sexual, self-harm). Non-blocking filters only log but don't prevent output.",
            "medium", "foundry", weak,
            {"Description": "Enable blocking mode for all content filter categories.",
             "PortalSteps": ["Go to Microsoft Foundry portal > Select the project", "Go to Safety + Security > Content filters", "Edit the content filter policy", "Set all category severities to 'Block' (not 'Warn' or 'Log')", "Save and reapply to deployments"]},
        )]
    return []


# ── 8. Model Deployment Security ─────────────────────────────────────

def analyze_foundry_deployments(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess model deployment security governance."""
    findings: list[dict] = []
    findings.extend(_check_deployment_governance(evidence_index))
    findings.extend(_check_deployment_deprecated_model(evidence_index))
    findings.extend(_check_deployment_no_rai_policy(evidence_index))
    return findings


def _check_deployment_governance(idx: dict) -> list[dict]:
    """Assess overall deployment governance posture."""
    deployments = idx.get("azure-openai-deployment", [])
    if not deployments:
        return []

    # Check for very high capacity allocations
    high_capacity: list[dict] = []
    for ev in deployments:
        data = ev.get("Data", ev.get("data", {}))
        capacity = data.get("SkuCapacity", 0)
        if isinstance(capacity, (int, float)) and capacity > 100:
            high_capacity.append({
                "Type": "OpenAIDeployment",
                "Name": data.get("DeploymentName", "Unknown"),
                "ResourceId": data.get("DeploymentId", ""),
                "Capacity": capacity,
                "ModelName": data.get("ModelName", ""),
            })

    if high_capacity:
        return [_as_finding(
            "foundry_deployments", "high_capacity_allocation",
            f"{len(high_capacity)} deployments have high capacity (>100 TPM) — review cost governance",
            "High-capacity deployments increase cost and potential attack surface. "
            "Ensure capacity allocations are justified and monitored.",
            "low", "foundry", high_capacity,
            {"Description": "Review deployment capacity allocations. Apply quotas where appropriate.",
             "PortalSteps": ["Go to Azure portal > AI Services > Select the OpenAI resource", "Go to Model deployments > Manage deployments", "Review TPM allocation for each deployment", "Reduce capacity where not needed"]},
            compliance_status="partial",
        )]
    return []


def _check_deployment_deprecated_model(idx: dict) -> list[dict]:
    """Flag deployments using models known to be deprecated or retired."""
    deployments = idx.get("azure-openai-deployment", [])
    _DEPRECATED = {
        "gpt-35-turbo-0301", "gpt-35-turbo-0613", "gpt-4-0314",
        "gpt-4-0613", "gpt-4-32k-0314", "gpt-4-32k-0613",
        "text-davinci-003", "text-davinci-002", "code-davinci-002",
    }
    deprecated: list[dict] = []
    for ev in deployments:
        data = ev.get("Data", ev.get("data", {}))
        model = data.get("ModelName", "")
        version = data.get("ModelVersion", "")
        model_key = f"{model}-{version}" if version else model
        if model_key.lower() in _DEPRECATED or model.lower() in ("text-davinci-003", "text-davinci-002", "code-davinci-002"):
            deprecated.append({
                "Type": "OpenAIDeployment",
                "Name": data.get("DeploymentName", "Unknown"),
                "ResourceId": data.get("DeploymentId", ""),
                "ModelName": model,
                "ModelVersion": version,
            })
    if deprecated:
        return [_as_finding(
            "foundry_deployments", "deployment_deprecated_model",
            f"{len(deprecated)} deployments use deprecated or retired models",
            "Deprecated models may lose support, miss security patches, and lack "
            "newer safety features. Migrate to supported model versions.",
            "high", "foundry", deprecated,
            {"Description": "Migrate deployments to supported model versions.",
             "PortalSteps": ["Go to Microsoft Foundry > Model deployments",
                             "Identify deprecated model deployments",
                             "Create new deployments with supported model versions",
                             "Update applications to use the new deployment endpoints",
                             "Delete deprecated deployments"]},
        )]
    return []


def _check_deployment_no_rai_policy(idx: dict) -> list[dict]:
    """Flag OpenAI deployments with no RAI policy assigned at all."""
    deployments = idx.get("azure-openai-deployment", [])
    no_rai: list[dict] = []
    for ev in deployments:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("RAIPolicy"):
            no_rai.append({
                "Type": "OpenAIDeployment",
                "Name": data.get("DeploymentName", "Unknown"),
                "ResourceId": data.get("DeploymentId", ""),
                "AccountName": data.get("AccountName", ""),
                "ModelName": data.get("ModelName", ""),
            })
    if no_rai:
        return [_as_finding(
            "foundry_deployments", "deployment_no_rai_policy",
            f"{len(no_rai)} OpenAI deployments have no RAI policy assigned",
            "Deployments without a Responsible AI policy lack content filtering, "
            "prompt shield, and jailbreak protection entirely.",
            "high", "foundry", no_rai,
            {"Description": "Assign a RAI content filter policy to all deployments.",
             "PortalSteps": ["Go to Microsoft Foundry > Safety + Security > Content filters",
                             "Create or select a content filter configuration",
                             "Apply the filter to target deployments"]},
        )]
    return []


# ── 9. Workspace Governance ──────────────────────────────────────────

def analyze_foundry_governance(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess AI Foundry workspace governance."""
    findings: list[dict] = []
    findings.extend(_check_hub_project_structure(evidence_index))
    findings.extend(_check_workspace_no_cmk(evidence_index))
    findings.extend(_check_hub_no_project_isolation(evidence_index))
    return findings


def _check_hub_project_structure(idx: dict) -> list[dict]:
    """Check if AI Foundry follows hub/project organizational structure."""
    workspaces = idx.get("azure-ai-workspace", [])
    if not workspaces:
        return []

    hubs = [ev for ev in workspaces if ev.get("Data", ev.get("data", {})).get("IsHub")]
    projects = [ev for ev in workspaces if ev.get("Data", ev.get("data", {})).get("IsProject")]

    if projects and not hubs:
        return [_as_finding(
            "foundry_governance", "no_hub_structure",
            "AI Foundry projects exist without a hub — centralized governance missing",
            "AI Foundry hubs provide centralized management of shared resources, "
            "network configuration, and security policies across projects.",
            "medium", "foundry",
            [{"Type": "GovernanceGap", "Name": "Hub Structure",
              "ResourceId": "foundry-governance", "ProjectCount": len(projects)}],
            {"Description": "Create an AI Foundry hub to centralize governance across projects.",
             "PortalSteps": ["Go to Microsoft Foundry portal", "Click '+ Create' > Hub", "Configure shared resources (Key Vault, Storage, ACR)", "Move existing projects under the hub", "Apply network and identity policies at hub level"]},
        )]
    return []


def _check_workspace_no_cmk(idx: dict) -> list[dict]:
    """Flag workspaces without customer-managed key encryption."""
    workspaces = idx.get("azure-ai-workspace", [])
    no_cmk: list[dict] = []
    for ev in workspaces:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasCMK"):
            no_cmk.append({
                "Type": "AIWorkspace",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("WorkspaceId", ""),
                "Kind": data.get("Kind", ""),
            })
    if no_cmk:
        return [_as_finding(
            "foundry_governance", "workspace_no_cmk",
            f"{len(no_cmk)} AI workspaces lack customer-managed key encryption",
            "Customer-managed keys (CMK) provide additional control over data encryption. "
            "Without CMK, data is encrypted with Microsoft-managed keys only.",
            "medium", "foundry", no_cmk,
            {"Description": "Enable customer-managed key encryption on AI workspaces.",
             "PortalSteps": ["Go to Azure portal > AI Foundry workspace",
                             "Select Encryption > Customer-managed keys",
                             "Configure a Key Vault and key for workspace encryption"]},
        )]
    return []


def _check_hub_no_project_isolation(idx: dict) -> list[dict]:
    """Flag hubs where all projects inherit network config with no isolation."""
    workspaces = idx.get("azure-ai-workspace", [])
    hubs = [ev for ev in workspaces if ev.get("Data", ev.get("data", {})).get("IsHub")]
    projects = [ev for ev in workspaces if ev.get("Data", ev.get("data", {})).get("IsProject")]

    if not hubs or not projects:
        return []

    # Check if any hub has isolation but projects don't
    isolated_hubs = [
        ev for ev in hubs
        if ev.get("Data", ev.get("data", {})).get("HasNetworkIsolation")
    ]
    unisolated_projects = [
        ev for ev in projects
        if not ev.get("Data", ev.get("data", {})).get("HasNetworkIsolation")
    ]

    if isolated_hubs and unisolated_projects:
        affected = [{
            "Type": "AIWorkspace",
            "Name": ev.get("Data", ev.get("data", {})).get("Name", "Unknown"),
            "ResourceId": ev.get("Data", ev.get("data", {})).get("WorkspaceId", ""),
            "Kind": "Project",
        } for ev in unisolated_projects]
        return [_as_finding(
            "foundry_governance", "hub_no_project_isolation",
            f"{len(unisolated_projects)} projects lack network isolation despite hub having it",
            "Projects under a hub should inherit or configure their own network isolation "
            "to prevent data exfiltration from project workspaces.",
            "medium", "foundry", affected,
            {"Description": "Enable network isolation on all projects under isolated hubs.",
             "PortalSteps": ["Go to Microsoft Foundry > Project settings > Networking",
                             "Enable managed network isolation",
                             "Configure outbound rules to match hub policy"]},
        )]
    return []

