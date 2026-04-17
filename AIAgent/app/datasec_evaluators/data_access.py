"""
Data Security — Data Access Controls evaluator.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS
from app.datasec_evaluators.data_classification_tags import _check_sensitive_data_tags

log = logging.getLogger(__name__)

def analyze_data_access_controls(evidence_index: dict[str, list[dict]]) -> list[dict]:
    findings: list[dict] = []
    findings.extend(_check_sensitive_data_tags(evidence_index))
    findings.extend(_check_broad_data_plane_rbac(evidence_index))
    findings.extend(_check_defender_for_storage(evidence_index))
    findings.extend(_check_defender_for_sql(evidence_index))
    findings.extend(_check_defender_for_keyvault(evidence_index))
    findings.extend(_check_diagnostic_settings(evidence_index))
    findings.extend(_check_owner_contributor_data_services(evidence_index))
    findings.extend(_check_service_principal_keyvault_access(evidence_index))
    findings.extend(_check_managed_identity_adoption(evidence_index))
    return findings


def _check_managed_identity_adoption(idx: dict) -> list[dict]:
    """Flag data services that are not using managed identity for authentication."""
    data_services = (
        idx.get("azure-storage-security", [])
        + idx.get("azure-sql-server", [])
        + idx.get("azure-keyvault", [])
        + idx.get("azure-cosmosdb", [])
    )
    no_mi: list[dict] = []
    for ev in data_services:
        data = ev.get("Data", ev.get("data", {}))
        identity = data.get("identity", data.get("Identity", {}))
        has_mi = False
        if isinstance(identity, dict):
            id_type = identity.get("type", identity.get("Type", "")).lower()
            if id_type and id_type != "none":
                has_mi = True
        if not has_mi:
            no_mi.append({
                "Type": data.get("type", "DataService"),
                "Name": data.get("name", data.get("Name",
                        data.get("StorageAccountName", "Unknown"))),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_mi:
        return [_ds_finding(
            "data_access", "no_managed_identity",
            f"{len(no_mi)} data services without managed identity",
            "Data services without managed identity rely on credentials (keys, passwords, "
            "connection strings) for inter-service authentication. Managed identities "
            "eliminate credential management and enable Entra ID-based access control.",
            "medium", no_mi,
            {"Description": "Enable system-assigned or user-assigned managed identity.",
             "AzureCLI": "az resource update --ids <resource-id> --set identity.type=SystemAssigned"},
        )]
    return []


def _check_broad_data_plane_rbac(idx: dict) -> list[dict]:
    """Flag data-plane roles assigned at subscription scope or above."""
    role_assignments = idx.get("azure-role-assignments", [])
    broad_data_roles = {
        "storage blob data owner", "storage blob data contributor",
        "storage blob data reader",   # reader at sub scope = broad read
        "storage table data contributor", "storage queue data contributor",
        "key vault administrator", "key vault secrets officer",
        "cosmos db account reader role",
        "sql db contributor", "sql server contributor",
    }
    overly_broad: list[dict] = []
    for ev in role_assignments:
        data = ev.get("Data", ev.get("data", {}))
        role_name = data.get("roleDefinitionName", data.get("RoleDefinitionName", "")).lower()
        scope = data.get("scope", data.get("Scope", ""))
        # Subscription-level or management-group-level
        is_sub_scope = scope.count("/") <= 4 and "/providers/" not in scope
        if role_name in broad_data_roles and is_sub_scope:
            overly_broad.append({
                "Type": "RoleAssignment",
                "Name": f"{data.get('principalName', data.get('PrincipalName', 'Unknown'))} → {role_name}",
                "ResourceId": scope,
                "RoleName": role_name,
                "PrincipalType": data.get("principalType", data.get("PrincipalType", "")),
            })
    if overly_broad:
        return [_ds_finding(
            "data_access", "broad_data_plane_rbac",
            f"{len(overly_broad)} overly-broad data-plane RBAC assignments at subscription scope",
            "Data-plane roles (Storage Blob Data Owner/Contributor, Key Vault Admin, etc.) "
            "granted at subscription or management-group level give wide access to all data resources.",
            "high", overly_broad,
            {"Description": "Scope data-plane roles to specific resource groups or resources.",
             "PortalSteps": [
                 "Azure Portal > Subscriptions > IAM > Review data-plane role assignments",
                 "Narrow scope to specific storage accounts, key vaults, or databases",
             ]},
        )]
    return []


def _check_defender_for_storage(idx: dict) -> list[dict]:
    defender = idx.get("azure-defender-plans", [])
    storage_not_enabled = []
    for ev in defender:
        data = ev.get("Data", ev.get("data", {}))
        plan = data.get("name", data.get("Name", "")).lower()
        tier = data.get("pricingTier", data.get("PricingTier", "")).lower()
        sub_id = data.get("subscriptionId", data.get("SubscriptionId", ""))
        if plan == "storageaccounts" and tier == "free":
            storage_not_enabled.append({
                "Type": "DefenderPlan",
                "Name": f"Defender for Storage ({sub_id[:8]}...)",
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if storage_not_enabled:
        return [_ds_finding(
            "data_access", "defender_storage_disabled",
            f"Defender for Storage not enabled on {len(storage_not_enabled)} subscription(s)",
            "Without Defender for Storage, anomalous access patterns and malware uploads go undetected.",
            "medium", storage_not_enabled,
            {"Description": "Enable Microsoft Defender for Storage.",
             "AzureCLI": "az security pricing create -n StorageAccounts --tier Standard"},
        )]
    return []


def _check_defender_for_sql(idx: dict) -> list[dict]:
    defender = idx.get("azure-defender-plans", [])
    sql_not_enabled = []
    for ev in defender:
        data = ev.get("Data", ev.get("data", {}))
        plan = data.get("name", data.get("Name", "")).lower()
        tier = data.get("pricingTier", data.get("PricingTier", "")).lower()
        sub_id = data.get("subscriptionId", data.get("SubscriptionId", ""))
        if plan in ("sqlservers", "sqlservervirtualmachines", "opensourcerelationaldatabases") and tier == "free":
            sql_not_enabled.append({
                "Type": "DefenderPlan",
                "Name": f"Defender for {plan} ({sub_id[:8]}...)",
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if sql_not_enabled:
        return [_ds_finding(
            "data_access", "defender_sql_disabled",
            f"Defender for SQL/DB not enabled on {len(sql_not_enabled)} plan(s)",
            "Without Defender for SQL, SQL injection attempts and brute-force attacks may go undetected.",
            "medium", sql_not_enabled,
            {"Description": "Enable Microsoft Defender for SQL.",
             "AzureCLI": "az security pricing create -n SqlServers --tier Standard"},
        )]
    return []


def _check_defender_for_keyvault(idx: dict) -> list[dict]:
    defender = idx.get("azure-defender-plans", [])
    kv_not_enabled = []
    for ev in defender:
        data = ev.get("Data", ev.get("data", {}))
        plan = data.get("name", data.get("Name", "")).lower()
        tier = data.get("pricingTier", data.get("PricingTier", "")).lower()
        sub_id = data.get("subscriptionId", data.get("SubscriptionId", ""))
        if plan == "keyvaults" and tier == "free":
            kv_not_enabled.append({
                "Type": "DefenderPlan",
                "Name": f"Defender for Key Vault ({sub_id[:8]}...)",
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if kv_not_enabled:
        return [_ds_finding(
            "data_access", "defender_keyvault_disabled",
            f"Defender for Key Vault not enabled on {len(kv_not_enabled)} subscription(s)",
            "Without Defender for Key Vault, unusual secret access patterns are not monitored.",
            "medium", kv_not_enabled,
            {"Description": "Enable Microsoft Defender for Key Vault.",
             "AzureCLI": "az security pricing create -n KeyVaults --tier Standard"},
        )]
    return []


def _check_diagnostic_settings(idx: dict) -> list[dict]:
    """Flag data services that have no diagnostic settings configured."""
    diag = idx.get("azure-diagnostic-settings", [])
    resources_with_diag = {
        ev.get("Data", ev.get("data", {})).get("resourceId", ev.get("ResourceId", "")).lower()
        for ev in diag
    }
    # Check storage, SQL, KV, Cosmos, PG, MySQL
    data_services = (
        idx.get("azure-storage-security", [])
        + idx.get("azure-sql-server", [])
        + idx.get("azure-keyvault", [])
        + idx.get("azure-cosmosdb", [])
        + idx.get("azure-dbforpostgresql", [])
        + idx.get("azure-dbformysql", [])
    )
    no_diag: list[dict] = []
    for ev in data_services:
        rid = ev.get("ResourceId", ev.get("resource_id", "")).lower()
        if rid and rid not in resources_with_diag:
            data = ev.get("Data", ev.get("data", {}))
            no_diag.append({
                "Type": data.get("type", "DataService"),
                "Name": data.get("name", "Unknown"),
                "ResourceId": rid,
            })
    if no_diag:
        return [_ds_finding(
            "data_access", "no_diagnostic_settings",
            f"{len(no_diag)} data services without diagnostic settings",
            "Without diagnostic settings, data-plane access logs are not captured for audit or alerting.",
            "medium", no_diag,
            {"Description": "Enable diagnostic settings to send logs to Log Analytics or Storage.",
             "AzureCLI": "az monitor diagnostic-settings create -n 'data-audit' "
                         "--resource <resource-id> --workspace <log-analytics-id> --logs '[{\"category\":\"audit\",\"enabled\":true}]'"},
        )]
    return []


def _check_owner_contributor_data_services(idx: dict) -> list[dict]:
    """Flag Owner/Contributor role assignments directly on data services."""
    role_assignments = idx.get("azure-role-assignments", [])
    dangerous_roles = {"owner", "contributor"}
    data_rp_prefixes = (
        "/providers/microsoft.storage/",
        "/providers/microsoft.sql/",
        "/providers/microsoft.keyvault/",
        "/providers/microsoft.documentdb/",
        "/providers/microsoft.dbforpostgresql/",
        "/providers/microsoft.dbformysql/",
    )
    flagged: list[dict] = []
    for ev in role_assignments:
        data = ev.get("Data", ev.get("data", {}))
        role_name = data.get("roleDefinitionName", data.get("RoleDefinitionName", "")).lower()
        scope = data.get("scope", data.get("Scope", "")).lower()
        if role_name in dangerous_roles and any(rp in scope for rp in data_rp_prefixes):
            flagged.append({
                "Type": "RoleAssignment",
                "Name": f"{data.get('principalId', 'Unknown')} → {role_name}",
                "ResourceId": scope,
                "RoleName": role_name,
                "PrincipalType": data.get("principalType", ""),
            })
    if flagged:
        return [_ds_finding(
            "data_access", "owner_contributor_on_data_services",
            f"{len(flagged)} Owner/Contributor assignments directly on data services",
            "Owner and Contributor roles on data resources grant full control including "
            "data-plane access, networking changes, and deletion. Use least-privilege "
            "data-plane roles instead (e.g., Storage Blob Data Reader).",
            "high", flagged,
            {"Description": "Replace Owner/Contributor with scoped data-plane roles.",
             "PortalSteps": [
                 "Azure Portal > Resource > IAM > Role assignments",
                 "Remove Owner/Contributor and assign specific data-plane roles",
             ]},
        )]
    return []


def _check_service_principal_keyvault_access(idx: dict) -> list[dict]:
    """Flag service principals with broad Key Vault access roles."""
    role_assignments = idx.get("azure-role-assignments", [])
    kv_broad_roles = {
        "key vault administrator", "key vault secrets officer",
        "key vault crypto officer", "key vault certificates officer",
    }
    flagged: list[dict] = []
    for ev in role_assignments:
        data = ev.get("Data", ev.get("data", {}))
        role_name = data.get("roleDefinitionName", data.get("RoleDefinitionName", "")).lower()
        principal_type = data.get("principalType", data.get("PrincipalType", "")).lower()
        if role_name in kv_broad_roles and principal_type == "serviceprincipal":
            flagged.append({
                "Type": "RoleAssignment",
                "Name": f"SP {data.get('principalId', 'Unknown')[:8]}… → {role_name}",
                "ResourceId": data.get("scope", ""),
                "RoleName": role_name,
            })
    if flagged:
        return [_ds_finding(
            "data_access", "sp_broad_keyvault_access",
            f"{len(flagged)} service principals with broad Key Vault roles",
            "Service principals with Key Vault Administrator or Officer roles can "
            "read/modify all secrets, keys, and certificates. Use narrower roles "
            "(e.g., Key Vault Secrets User) scoped to specific vaults.",
            "medium", flagged,
            {"Description": "Scope SP Key Vault access to least-privilege reader roles.",
             "AzureCLI": "az role assignment create --assignee <sp-id> --role 'Key Vault Secrets User' --scope <vault-id>"},
        )]
    return []


