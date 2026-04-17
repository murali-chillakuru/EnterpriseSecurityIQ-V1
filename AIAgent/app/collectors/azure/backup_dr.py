"""
Azure Backup & Disaster Recovery Collector
Recovery Services vaults, backup items, backup policies, Site Recovery.
"""

from __future__ import annotations
import asyncio
from azure.mgmt.recoveryservices.aio import RecoveryServicesClient
from azure.mgmt.recoveryservicesbackup.aio import RecoveryServicesBackupClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

_CONCURRENCY = asyncio.Semaphore(8)


@register_collector(name="backup_dr", plane="control", source="azure", priority=185)
async def collect_azure_backup_dr(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence: list[dict] = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            # --- Recovery Services Vaults ---
            try:
                rs_client = RecoveryServicesClient(creds.credential, sub_id)
                vaults = await paginate_arm(rs_client.vaults.list_by_subscription_id())

                for v in vaults:
                    rg = (v.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (v.id or "") else ""
                    props = v.properties or type("P", (), {})()
                    identity = v.identity or type("I", (), {"type": None})()
                    enc = getattr(props, "encryption", None)
                    move_details = getattr(props, "move_details", None)

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureBackupDR",
                        evidence_type="azure-recovery-vault",
                        description=f"Recovery vault: {v.name}",
                        data={
                            "VaultId": v.id,
                            "Name": v.name,
                            "Location": v.location,
                            "ResourceGroup": rg,
                            "ProvisioningState": getattr(props, "provisioning_state", ""),
                            "IdentityType": _v(getattr(identity, "type", None)),
                            "EncryptionKeySource": _v(getattr(enc, "key_vault_properties", None)) if enc else "",
                            "InfrastructureEncryption": _v(getattr(enc, "infrastructure_encryption", None)) if enc else "",
                            "PublicNetworkAccess": _v(getattr(props, "public_network_access", None), "Enabled"),
                            "ImmutabilityState": _v(getattr(getattr(props, "security_settings", None), "immutability_settings", None)) if getattr(props, "security_settings", None) else "",
                            "SoftDeleteState": _v(getattr(getattr(props, "security_settings", None), "soft_delete_settings", None)) if getattr(props, "security_settings", None) else "",
                            "CrossRegionRestore": _v(getattr(getattr(props, "redundancy_settings", None), "cross_region_restore", None)) if getattr(props, "redundancy_settings", None) else "",
                            "StandardTierStorageRedundancy": _v(getattr(getattr(props, "redundancy_settings", None), "standard_tier_storage_redundancy", None)) if getattr(props, "redundancy_settings", None) else "",
                            "PrivateEndpointCount": len(getattr(props, "private_endpoint_connections", []) or []),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=v.id or "", resource_type="RecoveryServicesVault",
                    ))

                    # --- Backup Policies per vault ---
                    try:
                        bk_client = RecoveryServicesBackupClient(creds.credential, sub_id)
                        policies = await paginate_arm(
                            bk_client.backup_policies.list(v.name, rg)
                        )
                        for pol in policies:
                            pol_props = pol.properties or type("PP", (), {})()
                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="AzureBackupDR",
                                evidence_type="azure-backup-policy",
                                description=f"Backup policy: {pol.name} in {v.name}",
                                data={
                                    "PolicyId": pol.id,
                                    "Name": pol.name,
                                    "VaultName": v.name,
                                    "BackupManagementType": _v(getattr(pol_props, "backup_management_type", None)),
                                    "ProtectedItemsCount": getattr(pol_props, "protected_items_count", 0),
                                    "ResourceGroup": rg,
                                    "SubscriptionId": sub_id,
                                    "SubscriptionName": sub_name,
                                },
                                resource_id=pol.id or "", resource_type="BackupPolicy",
                            ))
                        await bk_client.close()
                    except Exception as pol_exc:
                        log.debug("  [BackupDR] policies for %s: %s", v.name, pol_exc)

                    # --- Backup Protected Items per vault ---
                    try:
                        bk_client2 = RecoveryServicesBackupClient(creds.credential, sub_id)
                        items = await paginate_arm(
                            bk_client2.backup_protected_items.list(v.name, rg)
                        )
                        for item in items:
                            item_props = item.properties or type("IP", (), {})()
                            evidence.append(make_evidence(
                                source=Source.AZURE, collector="AzureBackupDR",
                                evidence_type="azure-backup-item",
                                description=f"Backup item: {item.name} in {v.name}",
                                data={
                                    "ItemId": item.id,
                                    "Name": item.name,
                                    "VaultName": v.name,
                                    "BackupManagementType": _v(getattr(item_props, "backup_management_type", None)),
                                    "WorkloadType": _v(getattr(item_props, "workload_type", None)),
                                    "ProtectionStatus": getattr(item_props, "protection_status", ""),
                                    "ProtectionState": _v(getattr(item_props, "protection_state", None)),
                                    "LastBackupTime": str(getattr(item_props, "last_backup_time", "")),
                                    "LastBackupStatus": getattr(item_props, "last_backup_status", ""),
                                    "HealthStatus": _v(getattr(item_props, "health_status", None)),
                                    "SourceResourceId": getattr(item_props, "source_resource_id", ""),
                                    "ResourceGroup": rg,
                                    "SubscriptionId": sub_id,
                                    "SubscriptionName": sub_name,
                                },
                                resource_id=item.id or "", resource_type="BackupItem",
                            ))
                        await bk_client2.close()
                    except Exception as item_exc:
                        log.debug("  [BackupDR] items for %s: %s", v.name, item_exc)

                log.info("  [BackupDR] %s: %d recovery vaults", sub_name, len(vaults))
                await rs_client.close()
            except Exception as exc:
                log.warning("  [BackupDR] %s failed: %s", sub_name, exc)

        return evidence

    return (await run_collector("AzureBackupDR", Source.AZURE, _collect)).data
