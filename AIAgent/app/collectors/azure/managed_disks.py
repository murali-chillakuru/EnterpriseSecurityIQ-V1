"""
Azure Managed Disks & Snapshots Collector
Disk encryption, snapshot security, encryption set details.
"""

from __future__ import annotations
import asyncio
from azure.mgmt.compute.aio import ComputeManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

_CONCURRENCY = asyncio.Semaphore(8)


@register_collector(name="managed_disks_snapshots", plane="control", source="azure", priority=170)
async def collect_azure_disks_snapshots(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence: list[dict] = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            try:
                client = ComputeManagementClient(creds.credential, sub_id)

                # --- Managed Disks ---
                disks = await paginate_arm(client.disks.list())
                for d in disks:
                    rg = (d.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (d.id or "") else ""
                    enc = d.encryption or type("E", (), {"type": None, "disk_encryption_set_id": None})()
                    enc_settings = d.encryption_settings_collection

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureManagedDisks",
                        evidence_type="azure-managed-disk",
                        description=f"Managed disk: {d.name}",
                        data={
                            "DiskId": d.id,
                            "Name": d.name,
                            "Location": d.location,
                            "ResourceGroup": rg,
                            "DiskState": _v(d.disk_state),
                            "DiskSizeGB": d.disk_size_gb,
                            "Sku": _v(getattr(d.sku, "name", None)) if d.sku else "",
                            "OsType": _v(d.os_type) if d.os_type else "",
                            "EncryptionType": _v(enc.type) if enc.type else "",
                            "DiskEncryptionSetId": enc.disk_encryption_set_id or "",
                            "EncryptionSettingsEnabled": bool(getattr(enc_settings, "enabled", False)) if enc_settings else False,
                            "NetworkAccessPolicy": _v(getattr(d, "network_access_policy", None)),
                            "PublicNetworkAccess": _v(getattr(d, "public_network_access", None), "Enabled"),
                            "ManagedBy": d.managed_by or "",
                            "CreationSourceResourceId": getattr(getattr(d, "creation_data", None), "source_resource_id", "") or "",
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=d.id or "", resource_type="ManagedDisk",
                    ))
                log.info("  [Disks] %s: %d disks", sub_name, len(disks))

                # --- Snapshots ---
                snapshots = await paginate_arm(client.snapshots.list())
                for s in snapshots:
                    rg = (s.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (s.id or "") else ""
                    enc = s.encryption or type("E", (), {"type": None, "disk_encryption_set_id": None})()

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureManagedDisks",
                        evidence_type="azure-snapshot",
                        description=f"Snapshot: {s.name}",
                        data={
                            "SnapshotId": s.id,
                            "Name": s.name,
                            "Location": s.location,
                            "ResourceGroup": rg,
                            "DiskSizeGB": s.disk_size_gb,
                            "OsType": _v(s.os_type) if s.os_type else "",
                            "EncryptionType": _v(enc.type) if enc.type else "",
                            "DiskEncryptionSetId": enc.disk_encryption_set_id or "",
                            "NetworkAccessPolicy": _v(getattr(s, "network_access_policy", None)),
                            "PublicNetworkAccess": _v(getattr(s, "public_network_access", None), "Enabled"),
                            "Incremental": getattr(s, "incremental", False),
                            "TimeCreated": str(getattr(s, "time_created", "")),
                            "SourceResourceId": getattr(getattr(s, "creation_data", None), "source_resource_id", "") or "",
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=s.id or "", resource_type="Snapshot",
                    ))
                log.info("  [Disks] %s: %d snapshots", sub_name, len(snapshots))

                # --- Disk Encryption Sets ---
                enc_sets = await paginate_arm(client.disk_encryption_sets.list())
                for des in enc_sets:
                    rg = (des.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (des.id or "") else ""
                    identity = des.identity or type("I", (), {"type": None})()
                    kv = getattr(des, "active_key", None)

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureManagedDisks",
                        evidence_type="azure-disk-encryption-set",
                        description=f"Disk encryption set: {des.name}",
                        data={
                            "SetId": des.id,
                            "Name": des.name,
                            "Location": des.location,
                            "ResourceGroup": rg,
                            "EncryptionType": _v(getattr(des, "encryption_type", None)),
                            "IdentityType": _v(getattr(identity, "type", None)),
                            "KeyVaultKeyUrl": getattr(getattr(kv, "key_url", None), "key_url", getattr(kv, "key_url", "")) if kv else "",
                            "RotationToLatestKeyVersionEnabled": getattr(des, "rotation_to_latest_key_version_enabled", False),
                            "AutoKeyRotationError": str(getattr(des, "auto_key_rotation_error", "")) if getattr(des, "auto_key_rotation_error", None) else "",
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=des.id or "", resource_type="DiskEncryptionSet",
                    ))
                log.info("  [Disks] %s: %d encryption sets", sub_name, len(enc_sets))

                await client.close()
            except Exception as exc:
                log.warning("  [Disks] %s failed: %s", sub_name, exc)

        return evidence

    return (await run_collector("AzureManagedDisks", Source.AZURE, _collect)).data
