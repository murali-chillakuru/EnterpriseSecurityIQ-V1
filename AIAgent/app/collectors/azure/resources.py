"""
Azure Resources Collector
Collects management groups, subscriptions, resource groups, and resources.
"""

from __future__ import annotations
from azure.mgmt.resource.resources.aio import ResourceManagementClient
from azure.mgmt.managementgroups.aio import ManagementGroupsAPI
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


def _rg_from_id(resource_id: str) -> str:
    """Extract the resource group name from an ARM resource ID."""
    if not resource_id:
        return ""
    parts = resource_id.split("/")
    for i, part in enumerate(parts):
        if part.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
    return ""


@register_collector(name="resources", plane="control", source="azure", priority=10)
async def collect_azure_resources(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    """Collect resources across all subscriptions."""

    async def _collect():
        evidence = []

        # Management groups
        try:
            mg_client = ManagementGroupsAPI(credential=creds.credential)
            mgs = []
            async for mg in mg_client.management_groups.list():
                mgs.append({
                    "Id": mg.id,
                    "Name": mg.name,
                    "DisplayName": mg.display_name,
                    "Type": mg.type,
                })
            await mg_client.close()
            for mg in mgs:
                evidence.append(make_evidence(
                    source=Source.AZURE, collector="AzureResources",
                    evidence_type="azure-resource",
                    description=f"Management Group: {mg['DisplayName']}",
                    data={**mg, "ResourceType": "ManagementGroup"},
                    resource_id=mg["Id"], resource_type="ManagementGroup",
                ))
        except Exception as exc:
            log.warning("Management group collection skipped: %s", exc)

        # Per-subscription resources
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]
            try:
                client = ResourceManagementClient(creds.credential, sub_id)

                # Resource groups
                rgs = await paginate_arm(client.resource_groups.list())
                for rg in rgs:
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureResources",
                        evidence_type="azure-resource-group",
                        description=f"Resource Group: {rg.name}",
                        data={
                            "ResourceId": rg.id, "Name": rg.name,
                            "ResourceGroup": rg.name,
                            "Location": rg.location,
                            "Tags": dict(rg.tags) if rg.tags else {},
                            "ResourceType": "ResourceGroup",
                            "SubscriptionId": sub_id, "SubscriptionName": sub_name,
                        },
                        resource_id=rg.id, resource_type="ResourceGroup",
                    ))

                # Resources
                resources = await paginate_arm(client.resources.list())
                for r in resources:
                    tags = dict(r.tags) if r.tags else {}
                    rg_name = _rg_from_id(r.id)
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureResources",
                        evidence_type="azure-resource",
                        description=f"{r.type}: {r.name}",
                        data={
                            "ResourceId": r.id, "Name": r.name,
                            "Type": r.type, "Location": r.location,
                            "ResourceGroup": rg_name,
                            "Tags": tags, "Kind": r.kind or "",
                            "Sku": r.sku.name if r.sku else "",
                            "HasTags": len(tags) > 0,
                            "SubscriptionId": sub_id, "SubscriptionName": sub_name,
                        },
                        resource_id=r.id, resource_type=r.type,
                    ))

                await client.close()
                log.info("  [AzureResources] %s: %d RGs, %d resources",
                         sub_name, len(rgs), len(resources))
            except Exception as exc:
                log.warning("  [AzureResources] %s failed: %s", sub_name, exc)

        return evidence

    return (await run_collector("AzureResources", Source.AZURE, _collect)).data
