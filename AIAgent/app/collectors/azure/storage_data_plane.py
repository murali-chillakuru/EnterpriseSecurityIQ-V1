"""
Azure Storage Data-Plane Collector
Per-container public access level, immutability policies, lifecycle management.
"""

from __future__ import annotations
from azure.mgmt.storage.aio import StorageManagementClient
from azure.storage.blob.aio import BlobServiceClient
from azure.identity.aio import DefaultAzureCredential as AsyncDefaultAzureCredential
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="storage_data_plane", plane="data", source="azure", priority=200)
async def collect_azure_storage_data_plane(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            try:
                mgmt = StorageManagementClient(creds.credential, sub_id)
                accounts = await paginate_arm(mgmt.storage_accounts.list())

                for acct in accounts:
                    rg = (acct.id or "").split("/resourceGroups/")[1].split("/")[0] if acct.id else ""
                    if not rg:
                        continue

                    # Check lifecycle management policy
                    lifecycle_rules = 0
                    try:
                        policy = await mgmt.management_policies.get(rg, acct.name, "default")
                        if policy and policy.policy and policy.policy.rules:
                            lifecycle_rules = len(policy.policy.rules)
                    except Exception:
                        pass

                    # Enumerate containers via data-plane
                    account_url = f"https://{acct.name}.blob.core.windows.net"
                    containers_checked = 0
                    public_containers = 0
                    immutable_containers = 0
                    containers_with_legal_hold = 0
                    try:
                        blob_svc = BlobServiceClient(
                            account_url=account_url,
                            credential=creds.credential,
                        )
                        async for container in blob_svc.list_containers(
                            include_metadata=True,
                        ):
                            containers_checked += 1
                            access = container.get("public_access")
                            if access and access.lower() != "none":
                                public_containers += 1
                            if container.get("has_immutability_policy"):
                                immutable_containers += 1
                            if container.get("has_legal_hold"):
                                containers_with_legal_hold += 1
                        await blob_svc.close()
                    except Exception as exc:
                        log.debug("  [StorageDataPlane] %s data-plane: %s", acct.name, exc)

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="StorageDataPlane",
                        evidence_type="azure-storage-container",
                        description=f"Storage containers: {acct.name}",
                        data={
                            "StorageAccountId": acct.id,
                            "StorageAccountName": acct.name,
                            "Location": acct.location,
                            "ContainersChecked": containers_checked,
                            "PublicContainers": public_containers,
                            "ImmutableContainers": immutable_containers,
                            "ContainersWithLegalHold": containers_with_legal_hold,
                            "LifecycleRuleCount": lifecycle_rules,
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=acct.id or "",
                        resource_type="Microsoft.Storage/storageAccounts",
                    ))

                await mgmt.close()
                log.info("  [StorageDataPlane] %s: %d accounts inspected", sub_name, len(accounts))
            except Exception as exc:
                log.warning("  [StorageDataPlane] %s failed: %s", sub_name, exc)

        return evidence

    result = await run_collector("StorageDataPlane", Source.AZURE, _collect)
    return result.data
