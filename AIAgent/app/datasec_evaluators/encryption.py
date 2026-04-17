"""
Data Security — Encryption Posture evaluator.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.datasec_evaluators.finding import ds_finding as _ds_finding, SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS

log = logging.getLogger(__name__)

def analyze_encryption_posture(evidence_index: dict[str, list[dict]]) -> list[dict]:
    findings: list[dict] = []
    findings.extend(_check_disk_encryption(evidence_index))
    findings.extend(_check_storage_encryption(evidence_index))
    findings.extend(_check_disk_encryption_type(evidence_index))
    findings.extend(_check_encryption_at_host(evidence_index))
    findings.extend(_check_managed_disk_cmk(evidence_index))
    findings.extend(_check_log_analytics_cmk(evidence_index))
    return findings


def _check_log_analytics_cmk(idx: dict) -> list[dict]:
    """Flag Log Analytics workspaces not encrypted with customer-managed keys."""
    workspaces = idx.get("azure-log-analytics", [])
    no_cmk: list[dict] = []
    for ev in workspaces:
        data = ev.get("Data", ev.get("data", {}))
        props = data.get("properties", data)
        cmk_id = props.get("defaultDataCollectionRuleResourceId", "")
        cluster = props.get("clusterResourceId",
                  props.get("ClusterResourceId", ""))
        features = props.get("features", {})
        cmk_enabled = bool(cluster) or (isinstance(features, dict) and
                      features.get("enableDataExport", False))
        # Check dedicated cluster link (CMK requires dedicated cluster)
        if not cluster:
            no_cmk.append({
                "Type": "LogAnalyticsWorkspace",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if no_cmk:
        return [_ds_finding(
            "encryption", "log_analytics_no_cmk",
            f"{len(no_cmk)} Log Analytics workspaces without customer-managed key encryption",
            "Log Analytics workspaces store security logs, audit trails, and potentially "
            "sensitive telemetry. Without CMK, encryption keys are managed by Microsoft. "
            "A dedicated cluster with CMK provides customer-controlled encryption.",
            "low", no_cmk,
            {"Description": "Link workspace to a dedicated cluster with CMK.",
             "AzureCLI": "az monitor log-analytics cluster create -n <cluster> -g <rg> "
                         "--sku-capacity 500 --identity-type SystemAssigned"},
        )]
    return []


def _check_disk_encryption(idx: dict) -> list[dict]:
    vms = idx.get("azure-compute-instance", [])
    unencrypted: list[dict] = []
    for ev in vms:
        data = ev.get("Data", ev.get("data", {}))
        encrypted = data.get("DiskEncryptionEnabled",
                    data.get("disk_encryption_enabled",
                    data.get("OsDiskEncrypted")))
        if encrypted is False:
            unencrypted.append({
                "Type": "VirtualMachine",
                "Name": data.get("Name", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
            })
    if unencrypted:
        return [_ds_finding(
            "encryption", "unencrypted_disks",
            f"{len(unencrypted)} VMs with unencrypted OS disks",
            "Unencrypted VM disks expose data if physical media is accessed.",
            "critical", unencrypted,
            {"Description": "Enable Azure Disk Encryption or encryption-at-host.",
             "AzureCLI": "az vm encryption enable -g <rg> -n <vm> --disk-encryption-keyvault <vault>"},
        )]
    return []


def _check_storage_encryption(idx: dict) -> list[dict]:
    storage = idx.get("azure-storage-security", [])
    no_cmk: list[dict] = []
    for ev in storage:
        data = ev.get("Data", ev.get("data", {}))
        key_source = data.get("KeySource", data.get("key_source", "")).lower()
        if key_source and "keyvault" not in key_source and "microsoft.keyvault" not in key_source:
            no_cmk.append({
                "Type": "StorageAccount",
                "Name": data.get("StorageAccountName", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "KeySource": key_source,
            })
    if no_cmk:
        return [_ds_finding(
            "encryption", "no_cmk",
            f"{len(no_cmk)} storage accounts using Microsoft-managed keys",
            "Customer-managed keys (CMK) provide additional control over encryption.",
            "low", no_cmk,
            {"Description": "Consider migrating to customer-managed keys for sensitive data.",
             "AzureCLI": "az storage account update -n <name> -g <rg> "
                         "--encryption-key-source Microsoft.Keyvault "
                         "--encryption-key-vault <vault-uri> --encryption-key-name <key>"},
        )]
    return []


def _check_disk_encryption_type(idx: dict) -> list[dict]:
    """Flag VMs using only platform-managed keys (PMK) instead of CMK or EncryptionAtHost."""
    vms = idx.get("azure-compute-instance", [])
    pmk_only: list[dict] = []
    for ev in vms:
        data = ev.get("Data", ev.get("data", {}))
        enc_type = data.get("DiskEncryptionType", "")
        encrypted = data.get("DiskEncryptionEnabled",
                    data.get("disk_encryption_enabled", False))
        # Only flag VMs that ARE encrypted but with PMK (weakest option)
        if encrypted and enc_type == "PMK":
            pmk_only.append({
                "Type": "VirtualMachine",
                "Name": data.get("Name", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "EncryptionType": "Platform-Managed Keys",
            })
    if pmk_only:
        return [_ds_finding(
            "encryption", "pmk_only_disk_encryption",
            f"{len(pmk_only)} VMs using only platform-managed key encryption",
            "Platform-managed keys (PMK) provide baseline encryption but do not give "
            "customer control over key lifecycle. Customer-managed keys (CMK) or "
            "encryption-at-host provide stronger data sovereignty guarantees.",
            "low", pmk_only,
            {"Description": "Upgrade to customer-managed keys (CMK) via Disk Encryption Set, "
             "or enable encryption-at-host for confidential computing scenarios.",
             "AzureCLI": (
                 "# Create a disk encryption set with your Key Vault key:\n"
                 "az disk-encryption-set create -n <des-name> -g <rg> -l <location> "
                 "--key-url <key-vault-key-url>\n"
                 "# Update the VM's OS disk to use the DES:\n"
                 "az vm update -n <vm> -g <rg> "
                 "--os-disk-encryption-set <des-id>"
             ),
             "PortalSteps": [
                 "Navigate to VM > Disks > Additional settings",
                 "Under Encryption type, select 'Customer-managed key'",
                 "Choose or create a Disk Encryption Set linked to your Key Vault",
             ]},
        )]
    return []


def _check_encryption_at_host(idx: dict) -> list[dict]:
    """Flag VMs that do not have encryption-at-host enabled (MCSB DP-4)."""
    vms = idx.get("azure-compute-instance", [])
    no_eah: list[dict] = []
    for ev in vms:
        data = ev.get("Data", ev.get("data", {}))
        enc_type = data.get("DiskEncryptionType", "")
        if enc_type and enc_type != "EncryptionAtHost":
            no_eah.append({
                "Type": "VirtualMachine",
                "Name": data.get("Name", data.get("name", "Unknown")),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "CurrentEncryption": enc_type,
            })
    if no_eah:
        return [_ds_finding(
            "encryption", "no_encryption_at_host",
            f"{len(no_eah)} VMs without encryption-at-host",
            "Encryption-at-host ensures temp disks and disk caches are encrypted at rest. "
            "Without it, transient data on the host may be exposed.",
            "low", no_eah,
            {"Description": "Enable encryption-at-host on VMs for full host-level encryption.",
             "AzureCLI": "az vm update -g <rg> -n <vm> --set securityProfile.encryptionAtHost=true"},
        )]
    return []


def _check_managed_disk_cmk(idx: dict) -> list[dict]:
    """Flag managed disks using platform-managed keys instead of CMK."""
    disks = idx.get("azure-managed-disk", [])
    pmk_disks: list[dict] = []
    for ev in disks:
        data = ev.get("Data", ev.get("data", {}))
        enc = data.get("encryption", data.get("Encryption", {})) or {}
        enc_type = enc.get("type", "").lower() if isinstance(enc, dict) else ""
        des_id = enc.get("diskEncryptionSetId", "") if isinstance(enc, dict) else ""
        if not des_id and "customermanaged" not in enc_type:
            pmk_disks.append({
                "Type": "ManagedDisk",
                "Name": data.get("name", "Unknown"),
                "ResourceId": ev.get("ResourceId", ev.get("resource_id", "")),
                "EncryptionType": enc_type or "PlatformManagedKey",
            })
    if pmk_disks:
        return [_ds_finding(
            "encryption", "managed_disk_no_cmk",
            f"{len(pmk_disks)} managed disks using platform-managed keys",
            "Managed disks using platform-managed keys lack customer control over "
            "encryption key lifecycle. Use Disk Encryption Sets with CMK.",
            "low", pmk_disks,
            {"Description": "Create a Disk Encryption Set and attach to managed disks.",
             "AzureCLI": "az disk update -g <rg> -n <disk> --disk-encryption-set <des-id>"},
        )]
    return []


