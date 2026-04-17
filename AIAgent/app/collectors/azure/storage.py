"""
Azure Storage Account Collector
Detailed storage account configuration: encryption, soft delete, lifecycle, network rules.
"""

from __future__ import annotations
from azure.mgmt.storage.aio import StorageManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="storage", plane="control", source="azure", priority=140)
async def collect_azure_storage(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            try:
                client = StorageManagementClient(creds.credential, sub_id)
                accounts = await paginate_arm(client.storage_accounts.list())

                for acct in accounts:
                    props = acct.properties if hasattr(acct, "properties") else acct
                    enc = getattr(props, "encryption", None)
                    net = getattr(props, "network_rule_set", None) or getattr(props, "network_acls", None)
                    blob_props = None
                    try:
                        rg = (acct.id or "").split("/resourceGroups/")[1].split("/")[0] if acct.id else ""
                        if rg:
                            blob_props = await client.blob_services.get_service_properties(rg, acct.name)
                    except Exception:
                        pass

                    soft_delete_blob = False
                    container_soft_delete = False
                    versioning_enabled = False
                    if blob_props:
                        dsr = getattr(blob_props, "delete_retention_policy", None)
                        soft_delete_blob = bool(dsr and getattr(dsr, "enabled", False))
                        csr = getattr(blob_props, "container_delete_retention_policy", None)
                        container_soft_delete = bool(csr and getattr(csr, "enabled", False))
                        versioning_enabled = bool(getattr(blob_props, "is_versioning_enabled", False))

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureStorage",
                        evidence_type="azure-storage-account",
                        description=f"Storage Account: {acct.name}",
                        data={
                            "StorageAccountId": acct.id,
                            "Name": acct.name,
                            "Location": acct.location,
                            "Kind": _v(acct.kind, "StorageV2"),
                            "Sku": acct.sku.name if acct.sku else "Unknown",
                            "AccessTier": _v(getattr(acct, "access_tier", None), ""),
                            "EnableHttpsTrafficOnly": getattr(props, "enable_https_traffic_only", True),
                            "MinimumTlsVersion": _v(getattr(props, "minimum_tls_version", None), "TLS1_0"),
                            "AllowBlobPublicAccess": getattr(props, "allow_blob_public_access", False),
                            "AllowSharedKeyAccess": getattr(props, "allow_shared_key_access", True),
                            "InfrastructureEncryption": bool(enc and getattr(enc, "require_infrastructure_encryption", False)),
                            "EncryptionKeySource": _v(getattr(enc, "key_source", None), "Microsoft.Storage") if enc else "Microsoft.Storage",
                            "NetworkDefaultAction": _v(getattr(net, "default_action", None), "Allow") if net else "Allow",
                            "VirtualNetworkRuleCount": len(getattr(net, "virtual_network_rules", None) or []) if net else 0,
                            "IpRuleCount": len(getattr(net, "ip_rules", None) or []) if net else 0,
                            "PrivateEndpointCount": len(getattr(props, "private_endpoint_connections", None) or []),
                            "BlobSoftDeleteEnabled": soft_delete_blob,
                            "ContainerSoftDeleteEnabled": container_soft_delete,
                            "VersioningEnabled": versioning_enabled,
                            "SupportsHttpsTrafficOnly": getattr(props, "supports_https_traffic_only", True),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=acct.id or "", resource_type="Microsoft.Storage/storageAccounts",
                    ))

                await client.close()
                log.info("  [AzureStorage] %s: %d storage accounts", sub_name, len(accounts))
            except Exception as exc:
                log.warning("  [AzureStorage] %s failed: %s", sub_name, exc)

        return evidence

    result = await run_collector("AzureStorage", Source.AZURE, _collect)
    return result.data
