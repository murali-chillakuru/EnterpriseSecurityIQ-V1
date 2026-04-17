"""
Azure Batch & Container Instances Collector
Batch accounts, pools, Container Instances (ACI) groups.
"""

from __future__ import annotations
import asyncio
from azure.mgmt.batch.aio import BatchManagementClient
from azure.mgmt.containerinstance.aio import ContainerInstanceManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

_CONCURRENCY = asyncio.Semaphore(8)


@register_collector(name="batch_container_instances", plane="control", source="azure", priority=165)
async def collect_azure_batch_aci(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence: list[dict] = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            # --- Batch Accounts ---
            try:
                batch_client = BatchManagementClient(creds.credential, sub_id)
                accounts = await paginate_arm(batch_client.batch_account.list())
                for acct in accounts:
                    rg = (acct.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (acct.id or "") else ""
                    identity = acct.identity or type("I", (), {"type": None})()
                    encryption = getattr(acct, "encryption", None)
                    net_profile = getattr(acct, "network_profile", None)

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureBatchACI",
                        evidence_type="azure-batch-account",
                        description=f"Batch account: {acct.name}",
                        data={
                            "AccountId": acct.id,
                            "Name": acct.name,
                            "Location": acct.location,
                            "ResourceGroup": rg,
                            "ProvisioningState": getattr(acct, "provisioning_state", ""),
                            "PoolAllocationMode": _v(getattr(acct, "pool_allocation_mode", None)),
                            "PublicNetworkAccess": _v(getattr(acct, "public_network_access", None), "Enabled"),
                            "IdentityType": _v(getattr(identity, "type", None)),
                            "EncryptionKeySource": _v(getattr(encryption, "key_source", None)) if encryption else "",
                            "DedicatedCoreQuota": getattr(acct, "dedicated_core_quota", 0),
                            "PoolQuota": getattr(acct, "pool_quota", 0),
                            "ActiveJobAndJobScheduleQuota": getattr(acct, "active_job_and_job_schedule_quota", 0),
                            "AllowedAuthenticationModes": [_v(m) for m in (getattr(acct, "allowed_authentication_modes", []) or [])],
                            "AutoStorageAccountId": getattr(getattr(acct, "auto_storage", None), "storage_account_id", "") if getattr(acct, "auto_storage", None) else "",
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=acct.id or "", resource_type="BatchAccount",
                    ))
                await batch_client.close()
                log.info("  [BatchACI] %s: %d batch accounts", sub_name, len(accounts))
            except Exception as exc:
                log.warning("  [BatchACI] %s batch accounts failed: %s", sub_name, exc)

            # --- Container Instances ---
            try:
                aci_client = ContainerInstanceManagementClient(creds.credential, sub_id)
                groups = await paginate_arm(aci_client.container_groups.list())
                for cg in groups:
                    rg = (cg.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (cg.id or "") else ""
                    identity = cg.identity or type("I", (), {"type": None})()
                    ip_address = cg.ip_address or type("IP", (), {"type": None, "ip": None, "ports": []})()
                    containers = cg.containers or []

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureBatchACI",
                        evidence_type="azure-container-instance",
                        description=f"Container group: {cg.name}",
                        data={
                            "GroupId": cg.id,
                            "Name": cg.name,
                            "Location": cg.location,
                            "ResourceGroup": rg,
                            "OsType": _v(getattr(cg, "os_type", None)),
                            "ProvisioningState": getattr(cg, "provisioning_state", ""),
                            "RestartPolicy": _v(getattr(cg, "restart_policy", None)),
                            "IpAddressType": _v(getattr(ip_address, "type", None)),
                            "IpAddress": getattr(ip_address, "ip", ""),
                            "IdentityType": _v(getattr(identity, "type", None)),
                            "ContainerCount": len(containers),
                            "Sku": _v(getattr(cg, "sku", None)),
                            "SubnetIds": [getattr(s, "id", "") for s in (getattr(cg, "subnet_ids", []) or [])],
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=cg.id or "", resource_type="ContainerGroup",
                    ))
                await aci_client.close()
                log.info("  [BatchACI] %s: %d container groups", sub_name, len(groups))
            except Exception as exc:
                log.warning("  [BatchACI] %s container instances failed: %s", sub_name, exc)

        return evidence

    return (await run_collector("AzureBatchACI", Source.AZURE, _collect)).data
