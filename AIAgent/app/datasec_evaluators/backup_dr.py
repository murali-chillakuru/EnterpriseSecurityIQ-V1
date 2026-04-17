"""
Data Security — Backup & Disaster Recovery evaluator.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_backup_dr(evidence_index: dict[str, list[dict]]) -> list[dict]:
    findings: list[dict] = []
    findings.extend(_check_recovery_vault_redundancy(evidence_index))
    findings.extend(_check_unprotected_vms(evidence_index))
    findings.extend(_check_sql_backup_retention(evidence_index))
    findings.extend(_check_cosmosdb_backup_policy(evidence_index))
    findings.extend(_check_backup_vault_cmk(evidence_index))
    findings.extend(_check_resource_locks(evidence_index))
    return findings


def _check_resource_locks(idx: dict) -> list[dict]:
    """Flag critical data services without resource locks."""
    locks = idx.get("azure-resource-lock", [])
    locked_rids = set()
    for ev in locks:
        data = ev.get("Data", ev.get("data", {}))
        scope = data.get("scope", data.get("Scope",
                ev.get("ResourceId", ev.get("resource_id", "")))).lower()
        if scope:
            locked_rids.add(scope)
    data_services = (
        idx.get("azure-storage-security", [])
        + idx.get("azure-sql-server", [])
        + idx.get("azure-keyvault", [])
        + idx.get("azure-cosmosdb", [])
    )
    unlocked: list[dict] = []
    for ev in data_services:
        rid = ev.get("ResourceId", ev.get("resource_id", "")).lower()
        if rid and rid not in locked_rids:
            # Also check if a parent RG lock covers this resource
            rg_locked = any(rid.startswith(lk) for lk in locked_rids)
            if not rg_locked:
                data = ev.get("Data", ev.get("data", {}))
                unlocked.append({
                    "Type": data.get("type", "DataService"),
                    "Name": data.get("name", data.get("Name",
                            data.get("StorageAccountName", "Unknown"))),
                    "ResourceId": rid,
                })
    if unlocked:
        return [_ds_finding(
            "backup_dr", "no_resource_lock",
            f"{len(unlocked)} critical data services without resource locks",
            "Without CanNotDelete or ReadOnly locks, critical data services can be "
            "accidentally or maliciously deleted. Resource locks provide an additional "
            "layer of protection against data loss.",
            "medium", unlocked,
            {"Description": "Add CanNotDelete locks to critical data services.",
             "AzureCLI": "az lock create --name DoNotDelete --resource <resource-id> "
                         "--lock-type CanNotDelete"},
        )]
    return []


def _check_recovery_vault_redundancy(idx: dict) -> list[dict]:
    """Flag Recovery Services vaults without geo-redundant storage."""
    vaults = idx.get("azure-recovery-vault", [])
    non_geo: list[dict] = []
    for ev in vaults:
        data = ev.get("Data", ev.get("data", {}))
        redundancy = data.get("RedundancySettings", data.get("redundancySettings", {})) or {}
        std_tier = (redundancy.get("standardTierStorageRedundancy", "") or "").lower()
        # Also check cross-region restore
        cross_region = redundancy.get("crossRegionRestore", "Disabled")
        if std_tier and "geo" not in std_tier:
            non_geo.append({
                "Type": "RecoveryServicesVault",
                "Name": data.get("Name", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "StorageRedundancy": std_tier,
                "CrossRegionRestore": cross_region,
            })
    if non_geo:
        return [_ds_finding(
            "backup_dr", "vault_not_geo_redundant",
            f"{len(non_geo)} Recovery Services vaults without geo-redundant storage",
            "Locally redundant vaults risk data loss in a regional disaster. "
            "Geo-redundant storage (GRS) replicates backups to a paired region.",
            "medium", non_geo,
            {"Description": "Change vault storage replication type to Geo-redundant.",
             "PortalSteps": [
                 "Navigate to Recovery Services vault > Properties",
                 "Under Backup Configuration, click Update",
                 "Select 'Geo-redundant' and optionally enable Cross Region Restore",
             ]},
        )]
    return []


def _check_unprotected_vms(idx: dict) -> list[dict]:
    """Flag VMs that have no backup protection (no recovery vault association)."""
    vms = idx.get("azure-compute-instance", [])
    unprotected: list[dict] = []
    for ev in vms:
        data = ev.get("Data", ev.get("data", {}))
        # If ARM enrichment populated BackupProtected flag
        backup = data.get("BackupProtected")
        if backup is False:
            unprotected.append({
                "Type": "VirtualMachine",
                "Name": data.get("Name", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if unprotected:
        return [_ds_finding(
            "backup_dr", "unprotected_vms",
            f"{len(unprotected)} VMs without backup protection",
            "Virtual machines without backup are at risk of permanent data loss "
            "from accidental deletion, ransomware, or infrastructure failures.",
            "high", unprotected,
            {"Description": "Enable Azure Backup for unprotected VMs.",
             "AzureCLI": (
                 "az backup protection enable-for-vm --resource-group <rg> "
                 "--vault-name <vault> --vm <vm-id> --policy-name DefaultPolicy"
             ),
             "PortalSteps": [
                 "Navigate to VM > Backup",
                 "Select or create a Recovery Services vault",
                 "Choose a backup policy and enable backup",
             ]},
        )]
    return []


def _check_sql_backup_retention(idx: dict) -> list[dict]:
    """Flag SQL servers where long-term retention (LTR) may not be configured."""
    sqls = idx.get("azure-sql-server", [])
    no_ltr: list[dict] = []
    for ev in sqls:
        data = ev.get("Data", ev.get("data", {}))
        ltr = data.get("LongTermRetention")
        if ltr is False:
            no_ltr.append({
                "Type": "SQLServer",
                "Name": data.get("Name", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_ltr:
        return [_ds_finding(
            "backup_dr", "sql_no_long_term_retention",
            f"{len(no_ltr)} SQL servers without long-term backup retention",
            "Default SQL backup retention is 7-35 days. Long-term retention (LTR) "
            "policies enable weekly/monthly/yearly backups kept for up to 10 years.",
            "medium", no_ltr,
            {"Description": "Configure long-term retention policies on SQL databases.",
             "AzureCLI": (
                 "az sql db ltr-policy set -g <rg> -s <server> -n <db> "
                 "--weekly-retention P4W --monthly-retention P12M --yearly-retention P5Y"
             )},
        )]
    return []


def _check_cosmosdb_backup_policy(idx: dict) -> list[dict]:
    """Flag Cosmos DB accounts not using continuous backup."""
    cosmos = idx.get("azure-cosmosdb", [])
    periodic: list[dict] = []
    for ev in cosmos:
        data = ev.get("Data", ev.get("data", {}))
        backup_policy = data.get("BackupPolicy", data.get("backupPolicy", {})) or {}
        policy_type = (backup_policy.get("type", "") or "").lower()
        if policy_type and "continuous" not in policy_type:
            periodic.append({
                "Type": "CosmosDB",
                "Name": data.get("Name", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "BackupType": policy_type,
            })
    if periodic:
        return [_ds_finding(
            "backup_dr", "cosmosdb_periodic_backup",
            f"{len(periodic)} Cosmos DB accounts using periodic (non-continuous) backup",
            "Periodic backup has a fixed RPO (hours). Continuous backup provides "
            "point-in-time restore with sub-second RPO for better data protection.",
            "low", periodic,
            {"Description": "Migrate Cosmos DB accounts to continuous backup mode.",
             "AzureCLI": (
                 "az cosmosdb update -n <account> -g <rg> "
                 "--backup-policy-type Continuous --continuous-tier Continuous7Days"
             ),
             "PortalSteps": [
                 "Navigate to Cosmos DB account > Backup & Restore",
                 "Select 'Continuous (7-day or 30-day)' backup mode",
                 "Note: Migration from periodic to continuous is one-way",
             ]},
        )]
    return []


def _check_backup_vault_cmk(idx: dict) -> list[dict]:
    """Flag Recovery Services vaults not using customer-managed key encryption."""
    vaults = idx.get("azure-recovery-vault", [])
    no_cmk: list[dict] = []
    for ev in vaults:
        data = ev.get("Data", ev.get("data", {}))
        enc = data.get("encryption", data.get("Encryption", {})) or {}
        key_source = ""
        if isinstance(enc, dict):
            key_source = enc.get("keyVaultProperties", {}).get("keyUri", "") if enc.get("keyVaultProperties") else ""
            infra_enc = enc.get("infrastructureEncryption", "").lower()
        else:
            infra_enc = ""
        if not key_source:
            no_cmk.append({
                "Type": "RecoveryServicesVault",
                "Name": data.get("Name", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "InfraEncryption": infra_enc or "N/A",
            })
    if no_cmk:
        return [_ds_finding(
            "backup_dr", "vault_no_cmk_encryption",
            f"{len(no_cmk)} Recovery Services vaults without CMK encryption",
            "Recovery vaults use platform-managed keys by default. CMK encryption gives "
            "customer control over backup data encryption keys.",
            "low", no_cmk,
            {"Description": "Enable CMK encryption on Recovery Services vaults.",
             "PortalSteps": [
                 "Navigate to vault > Properties > Encryption Settings",
                 "Select 'Use customer-managed key' and specify Key Vault key",
             ]},
        )]
    return []


