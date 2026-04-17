"""
Data Security — Cosmos DB Security evaluator.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_cosmosdb_security(evidence_index: dict[str, list[dict]]) -> list[dict]:
    findings: list[dict] = []
    findings.extend(_check_cosmosdb_public_access(evidence_index))
    findings.extend(_check_cosmosdb_ip_firewall(evidence_index))
    findings.extend(_check_cosmosdb_key_auth(evidence_index))
    findings.extend(_check_cosmosdb_backup(evidence_index))
    findings.extend(_check_cosmosdb_cmk(evidence_index))
    findings.extend(_check_cosmosdb_consistency(evidence_index))
    return findings


def _check_cosmosdb_public_access(idx: dict) -> list[dict]:
    cosmos = idx.get("azure-cosmosdb", [])
    public: list[dict] = []
    for ev in cosmos:
        data = ev.get("Data", ev.get("data", {}))
        pna = data.get("publicNetworkAccess", data.get("PublicNetworkAccess", "")).lower()
        if pna in ("enabled", "securedbyperimeter"):
            public.append({
                "Type": "CosmosDBAccount",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if public:
        return [_ds_finding(
            "cosmosdb", "public_network_access",
            f"{len(public)} Cosmos DB accounts with public network access",
            "Cosmos DB accessible from the public internet without network restrictions.",
            "high", public,
            {"Description": "Disable public network access; use private endpoints.",
             "AzureCLI": "az cosmosdb update -n <name> -g <rg> --public-network-access DISABLED"},
        )]
    return []


def _check_cosmosdb_ip_firewall(idx: dict) -> list[dict]:
    cosmos = idx.get("azure-cosmosdb", [])
    no_fw: list[dict] = []
    for ev in cosmos:
        data = ev.get("Data", ev.get("data", {}))
        ip_rules = data.get("ipRules", data.get("IpRules", []))
        vnet_rules = data.get("virtualNetworkRules", data.get("VirtualNetworkRules", []))
        pna = data.get("publicNetworkAccess", data.get("PublicNetworkAccess", "")).lower()
        if pna != "disabled" and not ip_rules and not vnet_rules:
            no_fw.append({
                "Type": "CosmosDBAccount",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_fw:
        return [_ds_finding(
            "cosmosdb", "no_ip_firewall",
            f"{len(no_fw)} Cosmos DB accounts without IP or VNet firewall rules",
            "No IP or virtual-network restrictions — the account is open to all networks.",
            "high", no_fw,
            {"Description": "Add IP rules or virtual-network rules to restrict access.",
             "AzureCLI": "az cosmosdb update -n <name> -g <rg> --ip-range-filter <ip/cidr>"},
        )]
    return []


def _check_cosmosdb_key_auth(idx: dict) -> list[dict]:
    cosmos = idx.get("azure-cosmosdb", [])
    key_auth: list[dict] = []
    for ev in cosmos:
        data = ev.get("Data", ev.get("data", {}))
        disable_key = data.get("disableLocalAuth", data.get("DisableLocalAuth"))
        if disable_key is not True:
            key_auth.append({
                "Type": "CosmosDBAccount",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if key_auth:
        return [_ds_finding(
            "cosmosdb", "key_auth_enabled",
            f"{len(key_auth)} Cosmos DB accounts with key-based auth enabled",
            "Key-based authentication bypasses Entra ID RBAC. Prefer disabling local auth.",
            "medium", key_auth,
            {"Description": "Disable local/key-based auth; use Entra ID (RBAC) only.",
             "AzureCLI": "az cosmosdb update -n <name> -g <rg> --disable-key-based-metadata-write-access true"},
        )]
    return []


def _check_cosmosdb_backup(idx: dict) -> list[dict]:
    cosmos = idx.get("azure-cosmosdb", [])
    periodic_only: list[dict] = []
    for ev in cosmos:
        data = ev.get("Data", ev.get("data", {}))
        bp = data.get("backupPolicy", data.get("BackupPolicy", {}))
        bp_type = ""
        if isinstance(bp, dict):
            bp_type = bp.get("type", bp.get("Type", "")).lower()
        if bp_type == "periodic":
            periodic_only.append({
                "Type": "CosmosDBAccount",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "BackupType": "Periodic",
            })
    if periodic_only:
        return [_ds_finding(
            "cosmosdb", "periodic_backup",
            f"{len(periodic_only)} Cosmos DB accounts using periodic backup (not continuous)",
            "Periodic backup has a limited RPO. Continuous backup enables point-in-time restore.",
            "low", periodic_only,
            {"Description": "Consider upgrading to continuous backup for lower RPO.",
             "AzureCLI": "az cosmosdb update -n <name> -g <rg> --backup-policy-type Continuous"},
        )]
    return []


def _check_cosmosdb_cmk(idx: dict) -> list[dict]:
    """Flag Cosmos DB accounts not using customer-managed keys (CMK)."""
    cosmos = idx.get("azure-cosmosdb", [])
    no_cmk: list[dict] = []
    for ev in cosmos:
        data = ev.get("Data", ev.get("data", {}))
        key_uri = data.get("keyVaultKeyUri", data.get("KeyVaultKeyUri", ""))
        if not key_uri:
            no_cmk.append({
                "Type": "CosmosDBAccount",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_cmk:
        return [_ds_finding(
            "cosmosdb", "no_cmk_encryption",
            f"{len(no_cmk)} Cosmos DB accounts without customer-managed key encryption",
            "Cosmos DB accounts using service-managed keys lack customer control over "
            "key lifecycle and rotation. CMK provides data sovereignty guarantees.",
            "medium", no_cmk,
            {"Description": "Enable Cosmos DB encryption with CMK from Azure Key Vault.",
             "PortalSteps": [
                 "Navigate to Cosmos DB account > Data Encryption",
                 "Select 'Customer-managed key' and specify Key Vault key",
                 "Note: CMK must be configured at account creation for some API types",
             ]},
        )]
    return []


def _check_cosmosdb_consistency(idx: dict) -> list[dict]:
    """Flag Cosmos DB accounts with eventual consistency that hold sensitive data."""
    cosmos = idx.get("azure-cosmosdb", [])
    eventual: list[dict] = []
    for ev in cosmos:
        data = ev.get("Data", ev.get("data", {}))
        consistency = data.get("consistencyPolicy", data.get("ConsistencyPolicy", {}))
        if isinstance(consistency, dict):
            level = consistency.get("defaultConsistencyLevel",
                    consistency.get("DefaultConsistencyLevel", "")).lower()
        else:
            level = str(consistency).lower()
        if level == "eventual":
            eventual.append({
                "Type": "CosmosDBAccount",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "ConsistencyLevel": "Eventual",
            })
    if eventual:
        return [_ds_finding(
            "cosmosdb", "eventual_consistency",
            f"{len(eventual)} Cosmos DB accounts using Eventual consistency",
            "Eventual consistency provides the weakest read guarantees. For applications "
            "handling financial, health, or identity data, consider Session or Strong "
            "consistency to prevent stale reads that could lead to incorrect decisions.",
            "low", eventual,
            {"Description": "Review consistency requirements for sensitive data workloads.",
             "PortalSteps": [
                 "Azure Portal > Cosmos DB account > Default consistency",
                 "Evaluate whether Session or Bounded Staleness is more appropriate",
                 "Note: Changing consistency level affects latency and cost",
             ]},
        )]
    return []


