"""Microsoft Foundry extended evaluators — compute, datastores, endpoints, registry, connections, serverless, diagnostics."""

from __future__ import annotations

from .finding import _as_finding


def analyze_foundry_compute(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess compute instance security in AI Foundry workspaces."""
    findings: list[dict] = []
    findings.extend(_check_compute_public_ip(evidence_index))
    findings.extend(_check_compute_ssh(evidence_index))
    findings.extend(_check_compute_idle_shutdown(evidence_index))
    findings.extend(_check_compute_no_managed_identity(evidence_index))
    return findings


def _check_compute_public_ip(idx: dict) -> list[dict]:
    """Flag compute instances with public IP enabled."""
    computes = idx.get("azure-ai-compute", [])
    public_ip: list[dict] = []
    for ev in computes:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("HasPublicIP"):
            public_ip.append({
                "Type": "AICompute",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ComputeId", ""),
                "WorkspaceName": data.get("WorkspaceName", ""),
            })
    if public_ip:
        return [_as_finding(
            "foundry_compute", "compute_public_ip",
            f"{len(public_ip)} compute instances have public IP enabled",
            "Compute instances with public IPs are accessible from the internet, "
            "increasing the attack surface for AI workloads.",
            "high", "foundry", public_ip,
            {"Description": "Disable public IP on compute instances and use private connectivity.",
             "AzureCLI": "az ml compute update --name <name> --resource-group <rg> "
                         "--workspace-name <ws> --no-public-ip",
             "PortalSteps": ["Go to Microsoft Foundry > Compute instances",
                             "Select the instance > Edit",
                             "Disable public IP access",
                             "Use VNet or private endpoint for access"]},
        )]
    return []


def _check_compute_ssh(idx: dict) -> list[dict]:
    """Flag compute instances with SSH access enabled."""
    computes = idx.get("azure-ai-compute", [])
    ssh_enabled: list[dict] = []
    for ev in computes:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("SSHEnabled"):
            ssh_enabled.append({
                "Type": "AICompute",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ComputeId", ""),
            })
    if ssh_enabled:
        return [_as_finding(
            "foundry_compute", "compute_ssh_enabled",
            f"{len(ssh_enabled)} compute instances have SSH access enabled",
            "SSH access on compute instances may allow unauthorized interactive "
            "access to training data and model artifacts.",
            "medium", "foundry", ssh_enabled,
            {"Description": "Disable SSH or restrict to bastion hosts.",
             "PortalSteps": ["Go to Microsoft Foundry > Compute instances",
                             "Select the instance > Properties",
                             "Review SSH settings",
                             "Disable or restrict SSH access"]},
        )]
    return []


def _check_compute_idle_shutdown(idx: dict) -> list[dict]:
    """Flag compute instances without idle shutdown schedule."""
    computes = idx.get("azure-ai-compute", [])
    no_shutdown: list[dict] = []
    for ev in computes:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("IdleShutdownEnabled"):
            no_shutdown.append({
                "Type": "AICompute",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ComputeId", ""),
            })
    if no_shutdown:
        return [_as_finding(
            "foundry_compute", "compute_idle_no_shutdown",
            f"{len(no_shutdown)} compute instances lack idle shutdown schedule",
            "Compute instances without idle auto-shutdown may incur unnecessary costs "
            "and remain running with sensitive data in memory.",
            "low", "foundry", no_shutdown,
            {"Description": "Enable idle shutdown on compute instances.",
             "AzureCLI": "az ml compute update --name <name> --resource-group <rg> "
                         "--workspace-name <ws> --idle-time-before-shutdown-minutes 30",
             "PortalSteps": ["Go to Microsoft Foundry > Compute instances",
                             "Select the instance > Schedules",
                             "Enable idle auto-shutdown with appropriate timeout"]},
            compliance_status="partial",
        )]
    return []


def _check_compute_no_managed_identity(idx: dict) -> list[dict]:
    """Flag compute instances without managed identity."""
    computes = idx.get("azure-ai-compute", [])
    no_identity: list[dict] = []
    for ev in computes:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasManagedIdentity"):
            no_identity.append({
                "Type": "AICompute",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ComputeId", ""),
                "WorkspaceName": data.get("WorkspaceName", ""),
            })
    if no_identity:
        return [_as_finding(
            "foundry_compute", "compute_no_managed_identity",
            f"{len(no_identity)} compute instances lack managed identity",
            "Compute instances without managed identity rely on local credentials "
            "or personal tokens, increasing credential leakage risk.",
            "medium", "foundry", no_identity,
            {"Description": "Enable system-assigned managed identity on compute instances.",
             "PortalSteps": ["Go to Microsoft Foundry > Compute instances",
                             "Select the instance > Identity",
                             "Enable System-assigned managed identity",
                             "Assign necessary RBAC roles to the identity"]},
        )]
    return []


# ── 9c. Datastore Security ──────────────────────────────────────────

def analyze_foundry_datastores(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess datastore security in AI Foundry workspaces."""
    findings: list[dict] = []
    findings.extend(_check_datastore_credentials(evidence_index))
    findings.extend(_check_datastore_encryption(evidence_index))
    return findings


def _check_datastore_credentials(idx: dict) -> list[dict]:
    """Flag datastores using stored credentials instead of identity-based access."""
    datastores = idx.get("azure-ai-datastore", [])
    cred_based: list[dict] = []
    for ev in datastores:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("CredentialType") in ("account_key", "sas", "service_principal"):
            cred_based.append({
                "Type": "AIDatastore",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("DatastoreId", ""),
                "CredentialType": data.get("CredentialType", ""),
                "WorkspaceName": data.get("WorkspaceName", ""),
            })
    if cred_based:
        return [_as_finding(
            "foundry_datastores", "datastore_credential_in_config",
            f"{len(cred_based)} datastores use stored credentials instead of identity-based access",
            "Datastores with stored account keys or SAS tokens expose static credentials "
            "that can be extracted and misused. Use managed identity for data access.",
            "high", "foundry", cred_based,
            {"Description": "Switch datastores to identity-based (credential-less) access.",
             "AzureCLI": "az ml datastore update --name <name> --resource-group <rg> "
                         "--workspace-name <ws> --auth-mode identity",
             "PortalSteps": ["Go to Microsoft Foundry > Data > Datastores",
                             "Select the datastore > Edit credentials",
                             "Switch to identity-based authentication",
                             "Ensure workspace managed identity has Storage Blob Data Reader role"]},
        )]
    return []


def _check_datastore_encryption(idx: dict) -> list[dict]:
    """Flag datastores pointing to storage without encryption at rest."""
    datastores = idx.get("azure-ai-datastore", [])
    no_encryption: list[dict] = []
    for ev in datastores:
        data = ev.get("Data", ev.get("data", {}))
        encrypted = data.get("StorageEncrypted")
        # None means unknown (couldn't query), False means confirmed unencrypted
        if encrypted is not True:
            no_encryption.append({
                "Type": "AIDatastore",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("DatastoreId", ""),
                "StorageEncrypted": str(encrypted) if encrypted is not None else "unknown",
            })
    if no_encryption:
        return [_as_finding(
            "foundry_datastores", "datastore_no_encryption",
            f"{len(no_encryption)} datastores reference storage without verified encryption",
            "Storage accounts used by AI datastores should have encryption at rest "
            "to protect training data and model artifacts.",
            "medium", "foundry", no_encryption,
            {"Description": "Ensure backing storage accounts use encryption at rest.",
             "PortalSteps": ["Go to Azure portal > Storage accounts",
                             "Select the storage account > Encryption",
                             "Verify Microsoft-managed or customer-managed keys are active"]},
        )]
    return []


# ── 9d. Endpoint Security ───────────────────────────────────────────

def analyze_foundry_endpoints(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess online/batch endpoint security in AI Foundry."""
    findings: list[dict] = []
    findings.extend(_check_endpoint_public_access(evidence_index))
    findings.extend(_check_endpoint_auth(evidence_index))
    findings.extend(_check_endpoint_key_auth(evidence_index))
    findings.extend(_check_endpoint_no_logging(evidence_index))
    return findings


def _check_endpoint_public_access(idx: dict) -> list[dict]:
    """Flag online endpoints with public access enabled."""
    endpoints = idx.get("azure-ai-endpoint", [])
    public_eps: list[dict] = []
    for ev in endpoints:
        data = ev.get("Data", ev.get("data", {}))
        if str(data.get("PublicNetworkAccess", "")).lower() in ("enabled", ""):
            public_eps.append({
                "Type": "AIEndpoint",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("EndpointId", ""),
                "EndpointType": data.get("EndpointType", ""),
            })
    if public_eps:
        return [_as_finding(
            "foundry_endpoints", "online_endpoint_public",
            f"{len(public_eps)} AI endpoints have public network access enabled",
            "Public AI endpoints expose inference APIs to the internet, enabling "
            "unauthorized model invocation and potential data extraction.",
            "high", "foundry", public_eps,
            {"Description": "Disable public access on AI endpoints.",
             "AzureCLI": "az ml online-endpoint update --name <name> --resource-group <rg> "
                         "--workspace-name <ws> --public-network-access disabled",
             "PortalSteps": ["Go to Microsoft Foundry > Endpoints",
                             "Select the endpoint > Properties",
                             "Disable public network access",
                             "Use private endpoint for invocation"]},
        )]
    return []


def _check_endpoint_auth(idx: dict) -> list[dict]:
    """Flag endpoints with no authentication configured."""
    endpoints = idx.get("azure-ai-endpoint", [])
    no_auth: list[dict] = []
    for ev in endpoints:
        data = ev.get("Data", ev.get("data", {}))
        auth_mode = str(data.get("AuthMode", "")).lower()
        if auth_mode in ("", "none"):
            no_auth.append({
                "Type": "AIEndpoint",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("EndpointId", ""),
            })
    if no_auth:
        return [_as_finding(
            "foundry_endpoints", "endpoint_no_auth",
            f"{len(no_auth)} AI endpoints have no authentication configured",
            "Endpoints without authentication allow anonymous model invocation, "
            "enabling data extraction and abuse.",
            "critical", "foundry", no_auth,
            {"Description": "Enable authentication on all AI endpoints.",
             "AzureCLI": "az ml online-endpoint update --name <name> --resource-group <rg> "
                         "--workspace-name <ws> --auth-mode aad_token",
             "PortalSteps": ["Go to Microsoft Foundry > Endpoints",
                             "Select the endpoint > Properties",
                             "Set authentication mode to AAD Token",
                             "Grant appropriate RBAC roles to consumers"]},
        )]
    return []


def _check_endpoint_key_auth(idx: dict) -> list[dict]:
    """Flag endpoints using key auth instead of AAD token auth."""
    endpoints = idx.get("azure-ai-endpoint", [])
    key_auth: list[dict] = []
    for ev in endpoints:
        data = ev.get("Data", ev.get("data", {}))
        auth_mode = str(data.get("AuthMode", "")).lower()
        if auth_mode == "key":
            key_auth.append({
                "Type": "AIEndpoint",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("EndpointId", ""),
            })
    if key_auth:
        return [_as_finding(
            "foundry_endpoints", "endpoint_key_auth_only",
            f"{len(key_auth)} AI endpoints use key authentication instead of AAD tokens",
            "Key-based authentication lacks identity context, audit trails, and "
            "Conditional Access enforcement. Use AAD token auth for fine-grained access control.",
            "medium", "foundry", key_auth,
            {"Description": "Switch endpoints to AAD token-based authentication.",
             "PortalSteps": ["Go to Microsoft Foundry > Endpoints",
                             "Select the endpoint > Update authentication",
                             "Change from key-based to AAD Token auth",
                             "Update client applications to use managed identity"]},
        )]
    return []


def _check_endpoint_no_logging(idx: dict) -> list[dict]:
    """Flag online endpoints whose workspace lacks diagnostic logging."""
    endpoints = idx.get("azure-ai-endpoint", [])
    diag_records = idx.get("azure-ai-workspace-diagnostics", [])
    if not endpoints:
        return []

    # Build set of workspaces with diagnostics
    ws_with_diag = set()
    for ev in diag_records:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("HasDiagnostics"):
            ws_with_diag.add(data.get("WorkspaceId", ""))

    no_logging: list[dict] = []
    for ev in endpoints:
        data = ev.get("Data", ev.get("data", {}))
        ws_id = data.get("WorkspaceId", "")
        if ws_id and ws_id not in ws_with_diag:
            no_logging.append({
                "Type": "AIEndpoint",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("EndpointId", ""),
                "WorkspaceName": data.get("WorkspaceName", ""),
            })
    if no_logging:
        return [_as_finding(
            "foundry_endpoints", "endpoint_no_logging",
            f"{len(no_logging)} endpoints are in workspaces without diagnostic logging",
            "Endpoints without workspace-level diagnostic settings lack request audit trails, "
            "making it impossible to investigate security incidents.",
            "medium", "foundry", no_logging,
            {"Description": "Enable diagnostic settings on the workspace hosting these endpoints.",
             "PortalSteps": ["Go to Azure portal > AI Foundry workspace",
                             "Select Diagnostic settings > Add diagnostic setting",
                             "Enable all log categories and send to Log Analytics"]},
        )]
    return []


# ── 9e. Registry Security ───────────────────────────────────────────

def analyze_foundry_registry(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess model registry security in AI Foundry."""
    findings: list[dict] = []
    findings.extend(_check_registry_public_access(evidence_index))
    findings.extend(_check_registry_rbac(evidence_index))
    return findings


def _check_registry_public_access(idx: dict) -> list[dict]:
    """Flag model registries with public network access."""
    registries = idx.get("azure-ai-registry", [])
    public_regs: list[dict] = []
    for ev in registries:
        data = ev.get("Data", ev.get("data", {}))
        if str(data.get("PublicNetworkAccess", "")).lower() in ("enabled", ""):
            public_regs.append({
                "Type": "AIRegistry",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("RegistryId", ""),
            })
    if public_regs:
        return [_as_finding(
            "foundry_registry", "registry_public_access",
            f"{len(public_regs)} model registries have public network access",
            "Public model registries allow model download from any network, "
            "risking intellectual property exposure.",
            "medium", "foundry", public_regs,
            {"Description": "Restrict model registry network access.",
             "PortalSteps": ["Go to Microsoft Foundry > Model registry",
                             "Select the registry > Networking",
                             "Disable public network access",
                             "Configure private endpoint connections"]},
        )]
    return []


def _check_registry_rbac(idx: dict) -> list[dict]:
    """Flag registries without explicit RBAC role assignments."""
    registries = idx.get("azure-ai-registry", [])
    no_rbac: list[dict] = []
    for ev in registries:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasRBACAssignments"):
            no_rbac.append({
                "Type": "AIRegistry",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("RegistryId", ""),
            })
    if no_rbac:
        return [_as_finding(
            "foundry_registry", "registry_no_rbac",
            f"{len(no_rbac)} model registries lack explicit RBAC assignments",
            "Registries without explicit RBAC rely on inherited permissions, "
            "which may grant broader access than intended.",
            "medium", "foundry", no_rbac,
            {"Description": "Assign explicit RBAC roles on model registries.",
             "AzureCLI": "az role assignment create --assignee <principal-id> "
                         "--role 'AzureML Registry User' --scope <registry-resource-id>",
             "PortalSteps": ["Go to Azure portal > AI Foundry registry > Access control (IAM)",
                             "Add role assignment",
                             "Assign AzureML Registry User to specific identities"]},
        )]
    return []


# ── 9f. Connection Security ─────────────────────────────────────────

def analyze_foundry_connections(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess workspace connection security in AI Foundry."""
    findings: list[dict] = []
    findings.extend(_check_connection_static_creds(evidence_index))
    findings.extend(_check_connection_shared_all(evidence_index))
    findings.extend(_check_connection_expired(evidence_index))
    findings.extend(_check_connection_no_expiry(evidence_index))
    return findings


def _check_connection_static_creds(idx: dict) -> list[dict]:
    """Flag connections using static credentials instead of managed identity."""
    connections = idx.get("azure-ai-connection", [])
    static: list[dict] = []
    for ev in connections:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("HasCredentials"):
            static.append({
                "Type": "AIConnection",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ConnectionId", ""),
                "WorkspaceName": data.get("WorkspaceName", ""),
                "AuthType": data.get("AuthType", ""),
                "Category": data.get("Category", ""),
            })
    if static:
        return [_as_finding(
            "foundry_connections", "connection_static_credentials",
            f"{len(static)} workspace connections use static credentials",
            "Connections with API keys, PATs, or service principal secrets "
            "store sensitive credentials that can be extracted. Use managed "
            "identity or AAD-based auth for connections where supported.",
            "high", "foundry", static,
            {"Description": "Switch connections to managed identity authentication.",
             "PortalSteps": ["Go to Microsoft Foundry > Management > Connections",
                             "Select the connection > Edit",
                             "Change authentication to Microsoft Entra ID",
                             "Ensure workspace managed identity has required RBAC on target"]},
        )]
    return []


def _check_connection_shared_all(idx: dict) -> list[dict]:
    """Flag connections shared to all workspace users."""
    connections = idx.get("azure-ai-connection", [])
    shared: list[dict] = []
    for ev in connections:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("IsSharedToAll") and data.get("HasCredentials"):
            shared.append({
                "Type": "AIConnection",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ConnectionId", ""),
                "WorkspaceName": data.get("WorkspaceName", ""),
            })
    if shared:
        return [_as_finding(
            "foundry_connections", "connection_shared_to_all",
            f"{len(shared)} credential-based connections are shared to all workspace users",
            "Connections with static credentials shared to all users allow any "
            "workspace member to access secrets. Restrict sharing to specific roles.",
            "high", "foundry", shared,
            {"Description": "Restrict connection sharing to specific users/roles.",
             "PortalSteps": ["Go to Microsoft Foundry > Management > Connections",
                             "Select the connection > Access control",
                             "Disable 'Shared to all users'",
                             "Grant access only to required roles"]},
        )]
    return []


def _check_connection_expired(idx: dict) -> list[dict]:
    """Flag connections with expired or near-expiry credentials."""
    from datetime import datetime, timezone
    connections = idx.get("azure-ai-connection", [])
    expired: list[dict] = []
    for ev in connections:
        data = ev.get("Data", ev.get("data", {}))
        expiry_str = data.get("ExpiryTime", "")
        if not expiry_str:
            continue
        try:
            expiry_dt = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
            if expiry_dt < datetime.now(timezone.utc):
                expired.append({
                    "Type": "AIConnection",
                    "Name": data.get("Name", "Unknown"),
                    "ResourceId": data.get("ConnectionId", ""),
                    "ExpiryTime": expiry_str,
                })
        except (ValueError, TypeError):
            pass
    if expired:
        return [_as_finding(
            "foundry_connections", "connection_expired_credentials",
            f"{len(expired)} workspace connections have expired credentials",
            "Expired connection credentials indicate stale configurations that "
            "may still grant access or may cause service disruptions.",
            "medium", "foundry", expired,
            {"Description": "Rotate or remove expired connection credentials.",
             "PortalSteps": ["Go to Microsoft Foundry > Management > Connections",
                             "Select expired connections > Update credentials",
                             "Remove connections that are no longer needed"]},
        )]
    return []


def _check_connection_no_expiry(idx: dict) -> list[dict]:
    """Flag connections with static credentials that have no expiry date."""
    connections = idx.get("azure-ai-connection", [])
    no_expiry: list[dict] = []
    for ev in connections:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("HasCredentials") and not data.get("ExpiryTime"):
            no_expiry.append({
                "Type": "AIConnection",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("ConnectionId", ""),
                "AuthType": data.get("AuthType", ""),
            })
    if no_expiry:
        return [_as_finding(
            "foundry_connections", "connection_no_expiry",
            f"{len(no_expiry)} connections with static credentials have no expiry date",
            "Connections with static credentials and no expiry are never forced to rotate, "
            "creating a persistent credential that may be compromised without detection.",
            "low", "foundry", no_expiry,
            {"Description": "Set expiry dates on credential-based connections.",
             "PortalSteps": ["Go to Microsoft Foundry > Management > Connections",
                             "Edit each connection with static credentials",
                             "Set an appropriate expiry date to enforce rotation"]},
        )]
    return []


# ── 9g. Serverless Endpoint Security ────────────────────────────────

def analyze_foundry_serverless(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess serverless (MaaS) endpoint security in AI Foundry."""
    findings: list[dict] = []
    findings.extend(_check_serverless_key_auth(evidence_index))
    findings.extend(_check_serverless_content_safety(evidence_index))
    findings.extend(_check_serverless_key_not_rotated(evidence_index))
    return findings


def _check_serverless_key_auth(idx: dict) -> list[dict]:
    """Flag serverless endpoints using key auth instead of AAD."""
    endpoints = idx.get("azure-ai-serverless-endpoint", [])
    key_auth: list[dict] = []
    for ev in endpoints:
        data = ev.get("Data", ev.get("data", {}))
        auth_mode = str(data.get("AuthMode", "")).lower()
        if auth_mode == "key":
            key_auth.append({
                "Type": "ServerlessEndpoint",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("EndpointId", ""),
                "ModelId": data.get("ModelId", ""),
                "WorkspaceName": data.get("WorkspaceName", ""),
            })
    if key_auth:
        return [_as_finding(
            "foundry_serverless", "serverless_key_auth",
            f"{len(key_auth)} serverless endpoints use key authentication",
            "Key-based authentication for serverless model endpoints lacks identity "
            "context, audit trails, and Conditional Access enforcement. "
            "Use AAD token auth for fine-grained access control.",
            "medium", "foundry", key_auth,
            {"Description": "Switch serverless endpoints to AAD token authentication.",
             "PortalSteps": ["Go to Microsoft Foundry > Models + endpoints",
                             "Select the serverless endpoint",
                             "Change authentication from Key to Microsoft Entra ID",
                             "Update client applications to use managed identity"]},
        )]
    return []


def _check_serverless_content_safety(idx: dict) -> list[dict]:
    """Flag serverless endpoints without content safety enabled."""
    endpoints = idx.get("azure-ai-serverless-endpoint", [])
    no_safety: list[dict] = []
    for ev in endpoints:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("ContentSafetyEnabled"):
            no_safety.append({
                "Type": "ServerlessEndpoint",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("EndpointId", ""),
                "ModelId": data.get("ModelId", ""),
                "WorkspaceName": data.get("WorkspaceName", ""),
            })
    if no_safety:
        return [_as_finding(
            "foundry_serverless", "serverless_no_content_safety",
            f"{len(no_safety)} serverless endpoints have content safety disabled",
            "Serverless model endpoints without content safety filters allow "
            "harmful, violent, or hateful content in model inputs and outputs.",
            "high", "foundry", no_safety,
            {"Description": "Enable content safety on serverless endpoints.",
             "PortalSteps": ["Go to Microsoft Foundry > Models + endpoints",
                             "Select the serverless endpoint > Content safety",
                             "Enable content safety filtering",
                             "Configure blocking thresholds for all categories"]},
        )]
    return []


def _check_serverless_key_not_rotated(idx: dict) -> list[dict]:
    """Flag serverless endpoints using key auth (potential non-rotation risk)."""
    endpoints = idx.get("azure-ai-serverless-endpoint", [])
    key_endpoints: list[dict] = []
    for ev in endpoints:
        data = ev.get("Data", ev.get("data", {}))
        auth_mode = str(data.get("AuthMode", "")).lower()
        if auth_mode == "key":
            key_endpoints.append({
                "Type": "ServerlessEndpoint",
                "Name": data.get("Name", "Unknown"),
                "ResourceId": data.get("EndpointId", ""),
                "WorkspaceName": data.get("WorkspaceName", ""),
            })
    if key_endpoints:
        return [_as_finding(
            "foundry_serverless", "serverless_key_not_rotated",
            f"{len(key_endpoints)} serverless endpoints use key auth with no rotation enforcement",
            "Serverless endpoints with key authentication provide no built-in key rotation "
            "mechanism. Keys may remain unchanged indefinitely, increasing compromise risk.",
            "medium", "foundry", key_endpoints,
            {"Description": "Implement key rotation or switch to AAD token auth.",
             "PortalSteps": ["Go to Microsoft Foundry > Models + endpoints",
                             "Select the serverless endpoint > Authentication",
                             "Regenerate API keys periodically or switch to AAD tokens",
                             "Update consuming applications with rotated keys"]},
        )]
    return []


# ── 9h. Workspace Diagnostics ───────────────────────────────────────

def analyze_foundry_ws_diagnostics(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess diagnostic settings for AI Foundry workspaces."""
    findings: list[dict] = []
    findings.extend(_check_ws_no_diagnostics(evidence_index))
    findings.extend(_check_ws_no_log_analytics(evidence_index))
    return findings


def _check_ws_no_diagnostics(idx: dict) -> list[dict]:
    """Flag workspaces with no diagnostic settings configured."""
    diag_records = idx.get("azure-ai-workspace-diagnostics", [])
    no_diag: list[dict] = []
    for ev in diag_records:
        data = ev.get("Data", ev.get("data", {}))
        if not data.get("HasDiagnostics"):
            no_diag.append({
                "Type": "AIWorkspace",
                "Name": data.get("WorkspaceName", "Unknown"),
                "ResourceId": data.get("WorkspaceId", ""),
            })
    if no_diag:
        return [_as_finding(
            "foundry_ws_diagnostics", "ws_no_diagnostic_settings",
            f"{len(no_diag)} AI workspaces have no diagnostic settings",
            "Workspaces without diagnostic settings lack audit logging "
            "for security events, model access, and data operations.",
            "high", "foundry", no_diag,
            {"Description": "Enable diagnostic settings on AI workspaces.",
             "AzureCLI": "az monitor diagnostic-settings create --name ai-diag "
                         "--resource <workspace-resource-id> "
                         "--workspace <log-analytics-workspace-id> "
                         "--logs '[{\"categoryGroup\": \"allLogs\", \"enabled\": true}]' "
                         "--metrics '[{\"category\": \"AllMetrics\", \"enabled\": true}]'",
             "PortalSteps": ["Go to Azure portal > AI Foundry workspace",
                             "Select Diagnostic settings > Add diagnostic setting",
                             "Enable all log categories and metrics",
                             "Send to Log Analytics workspace"]},
        )]
    return []


def _check_ws_no_log_analytics(idx: dict) -> list[dict]:
    """Flag workspaces with diagnostics but no Log Analytics destination."""
    diag_records = idx.get("azure-ai-workspace-diagnostics", [])
    no_la: list[dict] = []
    for ev in diag_records:
        data = ev.get("Data", ev.get("data", {}))
        if data.get("HasDiagnostics") and not data.get("HasLogAnalytics"):
            no_la.append({
                "Type": "AIWorkspace",
                "Name": data.get("WorkspaceName", "Unknown"),
                "ResourceId": data.get("WorkspaceId", ""),
            })
    if no_la:
        return [_as_finding(
            "foundry_ws_diagnostics", "ws_no_log_analytics",
            f"{len(no_la)} AI workspaces send diagnostics but not to Log Analytics",
            "Without Log Analytics, diagnostic data cannot be queried with KQL "
            "for security investigations or integrated with Microsoft Sentinel.",
            "medium", "foundry", no_la,
            {"Description": "Add Log Analytics workspace as diagnostic destination.",
             "PortalSteps": ["Go to Azure portal > AI Foundry workspace",
                             "Select Diagnostic settings",
                             "Edit existing setting > add Log Analytics workspace",
                             "Verify logs appear in the workspace"]},
        )]
    return []

