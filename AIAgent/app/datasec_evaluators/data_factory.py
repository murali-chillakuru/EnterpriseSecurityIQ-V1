"""
Data Security — Data Factory & Synapse Security evaluator.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_data_factory_security(evidence_index: dict[str, list[dict]]) -> list[dict]:
    """Assess Azure Data Factory and Synapse security beyond VNet checks."""
    findings: list[dict] = []
    findings.extend(_check_adf_public_access(evidence_index))
    findings.extend(_check_adf_no_managed_identity(evidence_index))
    findings.extend(_check_adf_no_git(evidence_index))
    findings.extend(_check_synapse_public_access(evidence_index))
    findings.extend(_check_synapse_sql_aad_only(evidence_index))
    return findings


def _check_adf_public_access(idx: dict) -> list[dict]:
    """Flag Data Factory instances with public network access enabled."""
    adfs = idx.get("azure-data-factory", [])
    public: list[dict] = []
    for ev in adfs:
        data = ev.get("Data", ev.get("data", {}))
        props = data.get("properties", data)
        pub = props.get("publicNetworkAccess",
              props.get("PublicNetworkAccess", "")).lower()
        if pub != "disabled":
            public.append({
                "Type": "DataFactory",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if public:
        return [_ds_finding(
            "data_pipeline", "adf_public_access",
            f"{len(public)} Data Factory instances with public network access",
            "Data Factory with public access allows management and data plane "
            "operations from any network, risking pipeline tampering and data exfiltration.",
            "medium", public,
            {"Description": "Disable public network access on Data Factory.",
             "AzureCLI": "az datafactory update -n <name> -g <rg> --public-network-access Disabled"},
        )]
    return []


def _check_adf_no_managed_identity(idx: dict) -> list[dict]:
    """Flag Data Factory instances without managed identity."""
    adfs = idx.get("azure-data-factory", [])
    no_mi: list[dict] = []
    for ev in adfs:
        data = ev.get("Data", ev.get("data", {}))
        identity = data.get("identity", {})
        id_type = ""
        if isinstance(identity, dict):
            id_type = identity.get("type", identity.get("Type", "")).lower()
        has_mi = id_type in ("systemassigned", "userassigned",
                             "systemassigned,userassigned",
                             "systemassigned, userassigned")
        if not has_mi:
            no_mi.append({
                "Type": "DataFactory",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_mi:
        return [_ds_finding(
            "data_pipeline", "adf_no_managed_identity",
            f"{len(no_mi)} Data Factory instances without managed identity",
            "Without managed identity, Data Factory relies on stored credentials "
            "in linked services. Managed identity enables secure, credential-free "
            "authentication to data sources.",
            "medium", no_mi,
            {"Description": "Enable managed identity on Data Factory.",
             "AzureCLI": "az datafactory update -n <name> -g <rg> --identity-type SystemAssigned"},
        )]
    return []


def _check_adf_no_git(idx: dict) -> list[dict]:
    """Flag Data Factory instances without Git integration for pipeline versioning."""
    adfs = idx.get("azure-data-factory", [])
    no_git: list[dict] = []
    for ev in adfs:
        data = ev.get("Data", ev.get("data", {}))
        props = data.get("properties", data)
        repo_config = props.get("repoConfiguration",
                     props.get("RepoConfiguration"))
        if not repo_config:
            no_git.append({
                "Type": "DataFactory",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_git:
        return [_ds_finding(
            "data_pipeline", "adf_no_git_integration",
            f"{len(no_git)} Data Factory instances without Git integration",
            "Without Git integration, pipeline changes are not version-controlled. "
            "There is no audit trail for who changed data flows, and accidental "
            "changes cannot be reverted.",
            "low", no_git,
            {"Description": "Configure Git integration for Data Factory.",
             "PortalSteps": [
                 "Azure Portal > Data Factory > Author & Monitor",
                 "Management Hub > Git configuration > Configure",
                 "Connect to Azure DevOps or GitHub repository",
             ]},
        )]
    return []


def _check_synapse_public_access(idx: dict) -> list[dict]:
    """Flag Synapse workspaces with public network access enabled."""
    workspaces = idx.get("azure-synapse-workspace", [])
    public: list[dict] = []
    for ev in workspaces:
        data = ev.get("Data", ev.get("data", {}))
        props = data.get("properties", data)
        pub = props.get("publicNetworkAccess",
              props.get("PublicNetworkAccess", "")).lower()
        if pub != "disabled":
            public.append({
                "Type": "SynapseWorkspace",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if public:
        return [_ds_finding(
            "data_pipeline", "synapse_public_access",
            f"{len(public)} Synapse workspaces with public network access",
            "Synapse workspaces with public access expose SQL pools, Spark pools, "
            "and data pipelines to the Internet.",
            "medium", public,
            {"Description": "Disable public network access on Synapse workspaces.",
             "PortalSteps": [
                 "Azure Portal > Synapse workspace > Networking",
                 "Set 'Public network access' to Disabled",
             ]},
        )]
    return []


def _check_synapse_sql_aad_only(idx: dict) -> list[dict]:
    """Flag Synapse workspaces not enforcing Azure AD-only authentication."""
    workspaces = idx.get("azure-synapse-workspace", [])
    no_aad: list[dict] = []
    for ev in workspaces:
        data = ev.get("Data", ev.get("data", {}))
        props = data.get("properties", data)
        aad_only = props.get("azureADOnlyAuthentication",
                  props.get("AzureADOnlyAuthentication", False))
        if not aad_only:
            no_aad.append({
                "Type": "SynapseWorkspace",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_aad:
        return [_ds_finding(
            "data_pipeline", "synapse_sql_auth_enabled",
            f"{len(no_aad)} Synapse workspaces allow SQL authentication",
            "SQL authentication uses password-based credentials that can be brute-forced "
            "and lack MFA, conditional access, and identity lifecycle management.",
            "high", no_aad,
            {"Description": "Enforce Azure AD-only authentication on Synapse.",
             "PortalSteps": [
                 "Azure Portal > Synapse workspace > Azure Active Directory",
                 "Enable 'Azure AD-only authentication'",
             ]},
        )]
    return []


# ── Enhanced Event Hub / Service Bus ─────────────────────────────────


def _check_eventhub_local_auth(idx: dict) -> list[dict]:
    """Flag Event Hub namespaces with local/SAS authentication enabled."""
    hubs = idx.get("azure-eventhub-namespace", [])
    local_auth: list[dict] = []
    for ev in hubs:
        data = ev.get("Data", ev.get("data", {}))
        props = data.get("properties", data)
        disable_local = props.get("disableLocalAuth",
                       props.get("DisableLocalAuth", False))
        if not disable_local:
            local_auth.append({
                "Type": "EventHubNamespace",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if local_auth:
        return [_ds_finding(
            "messaging", "eventhub_local_auth",
            f"{len(local_auth)} Event Hub namespaces allow SAS/local authentication",
            "SAS keys are static shared secrets. Disable local auth and use "
            "Azure AD RBAC for fine-grained, auditable access control.",
            "medium", local_auth,
            {"Description": "Disable local auth on Event Hub namespaces.",
             "AzureCLI": "az eventhubs namespace update -n <name> -g <rg> "
                         "--disable-local-auth true"},
        )]
    return []


def _check_servicebus_local_auth(idx: dict) -> list[dict]:
    """Flag Service Bus namespaces with local/SAS authentication enabled."""
    buses = idx.get("azure-servicebus-namespace", [])
    local_auth: list[dict] = []
    for ev in buses:
        data = ev.get("Data", ev.get("data", {}))
        props = data.get("properties", data)
        disable_local = props.get("disableLocalAuth",
                       props.get("DisableLocalAuth", False))
        if not disable_local:
            local_auth.append({
                "Type": "ServiceBusNamespace",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if local_auth:
        return [_ds_finding(
            "messaging", "servicebus_local_auth",
            f"{len(local_auth)} Service Bus namespaces allow SAS/local authentication",
            "SAS keys provide unrestricted access to queues and topics. "
            "Disable local auth and use Azure AD for per-principal access control.",
            "medium", local_auth,
            {"Description": "Disable local auth on Service Bus namespaces.",
             "AzureCLI": "az servicebus namespace update -n <name> -g <rg> "
                         "--disable-local-auth true"},
        )]
    return []


def _check_eventhub_capture_disabled(idx: dict) -> list[dict]:
    """Flag Event Hub namespaces without capture enabled (no audit trail for events)."""
    hubs = idx.get("azure-eventhub-namespace", [])
    no_capture: list[dict] = []
    for ev in hubs:
        data = ev.get("Data", ev.get("data", {}))
        props = data.get("properties", data)
        # Capture is configured per Event Hub, but namespace-level evidence
        # may include a captureEnabled flag from ARM enrichment
        capture = props.get("captureEnabled",
                 props.get("CaptureEnabled", None))
        if capture is False:
            no_capture.append({
                "Type": "EventHubNamespace",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_capture:
        return [_ds_finding(
            "messaging", "eventhub_no_capture",
            f"{len(no_capture)} Event Hub namespaces without event capture",
            "Without capture, events are consumed and discarded. There is no "
            "persistent audit trail for compliance investigations or replay.",
            "low", no_capture,
            {"Description": "Enable Event Hub capture for event archival.",
             "AzureCLI": "az eventhubs eventhub update -g <rg> --namespace-name <ns> "
                         "-n <hub> --enable-capture true --capture-interval 300 "
                         "--storage-account <storage-id> --blob-container <container>"},
        )]
    return []


# ── Enhanced Redis Cache ─────────────────────────────────────────────


def _check_redis_no_patch_schedule(idx: dict) -> list[dict]:
    """Flag Redis caches without a configured patch schedule."""
    caches = idx.get("azure-redis-cache", [])
    no_patch: list[dict] = []
    for ev in caches:
        data = ev.get("Data", ev.get("data", {}))
        props = data.get("properties", data)
        schedule = props.get("patchSchedule",
                  props.get("PatchSchedule",
                  props.get("redisConfiguration", {}).get("patchSchedule")))
        if not schedule:
            no_patch.append({
                "Type": "RedisCache",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_patch:
        return [_ds_finding(
            "redis", "redis_no_patch_schedule",
            f"{len(no_patch)} Redis caches without a configured patch schedule",
            "Without a patch schedule, Redis updates apply at unpredictable times, "
            "potentially causing downtime during business hours. Controlled patching "
            "reduces risk from unpatched vulnerabilities.",
            "low", no_patch,
            {"Description": "Configure a maintenance window for Redis cache patching.",
             "AzureCLI": "az redis patch-schedule create -n <name> -g <rg> "
                         "--schedule-entries '[{dayOfWeek:Sunday,startHourUtc:2}]'"},
        )]
    return []


def _check_redis_public_access(idx: dict) -> list[dict]:
    """Flag Redis caches with public network access enabled."""
    caches = idx.get("azure-redis-cache", [])
    public: list[dict] = []
    for ev in caches:
        data = ev.get("Data", ev.get("data", {}))
        props = data.get("properties", data)
        pub = props.get("publicNetworkAccess",
              props.get("PublicNetworkAccess", "")).lower()
        pe_conns = props.get("privateEndpointConnections", [])
        if pub != "disabled" and not pe_conns:
            public.append({
                "Type": "RedisCache",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if public:
        return [_ds_finding(
            "redis", "redis_public_access",
            f"{len(public)} Redis caches with public network access and no private endpoints",
            "Redis caches storing session data, tokens, and cached PII are accessible "
            "from the public Internet. Use private endpoints for network isolation.",
            "high", public,
            {"Description": "Deploy private endpoints and disable public access for Redis.",
             "AzureCLI": "az redis update -n <name> -g <rg> --set publicNetworkAccess=Disabled"},
        )]
    return []


# ── Enhanced Managed Identity Coverage ───────────────────────────────

