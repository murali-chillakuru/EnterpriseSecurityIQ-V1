"""
Azure Diagnostics Collector
Collects diagnostic settings for resources.
"""

from __future__ import annotations
import asyncio
from azure.mgmt.monitor.aio import MonitorManagementClient
from azure.mgmt.resource.resources.aio import ResourceManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

_CONCURRENCY = asyncio.Semaphore(10)

DIAGNOSTIC_RESOURCE_TYPES = [
    # Original 17 types
    "Microsoft.KeyVault/vaults",
    "Microsoft.Network/networkSecurityGroups",
    "Microsoft.Network/applicationGateways",
    "Microsoft.Sql/servers",
    "Microsoft.Storage/storageAccounts",
    "Microsoft.Web/sites",
    "Microsoft.Compute/virtualMachines",
    "Microsoft.ContainerService/managedClusters",
    "Microsoft.Network/azureFirewalls",
    "Microsoft.Network/loadBalancers",
    "Microsoft.Network/publicIPAddresses",
    "Microsoft.Network/virtualNetworkGateways",
    "Microsoft.Cdn/profiles",
    "Microsoft.EventHub/namespaces",
    "Microsoft.ServiceBus/namespaces",
    "Microsoft.Devices/IotHubs",
    "Microsoft.ContainerRegistry/registries",
    # Phase 1 expansion — databases
    "Microsoft.Sql/servers/databases",
    "Microsoft.DBforPostgreSQL/flexibleServers",
    "Microsoft.DBforMySQL/flexibleServers",
    "Microsoft.DocumentDB/databaseAccounts",
    "Microsoft.Cache/redis",
    # Phase 1 expansion — networking
    "Microsoft.Network/frontDoors",
    "Microsoft.Network/trafficManagerProfiles",
    "Microsoft.Network/bastionHosts",
    "Microsoft.Network/expressRouteCircuits",
    "Microsoft.Network/vpnGateways",
    "Microsoft.Network/privateDnsZones",
    # Phase 1 expansion — compute & containers
    "Microsoft.Compute/virtualMachineScaleSets",
    "Microsoft.App/containerApps",
    "Microsoft.ContainerInstance/containerGroups",
    # Phase 1 expansion — integration & messaging
    "Microsoft.ApiManagement/service",
    "Microsoft.Logic/workflows",
    "Microsoft.EventGrid/topics",
    "Microsoft.SignalRService/signalR",
    # Phase 1 expansion — AI & analytics
    "Microsoft.CognitiveServices/accounts",
    "Microsoft.MachineLearningServices/workspaces",
    "Microsoft.DataFactory/factories",
    "Microsoft.Synapse/workspaces",
    # Phase 1 expansion — security & monitoring
    "Microsoft.SecurityInsights/alertRules",
    "Microsoft.OperationalInsights/workspaces",
    "Microsoft.RecoveryServices/vaults",
]


@register_collector(name="diagnostics", plane="control", source="azure", priority=40)
async def collect_azure_diagnostics(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]
            try:
                monitor = MonitorManagementClient(creds.credential, sub_id)
                res_client = ResourceManagementClient(creds.credential, sub_id)
                resources = await paginate_arm(res_client.resources.list())
                target_resources = [
                    r for r in resources if r.type in DIAGNOSTIC_RESOURCE_TYPES
                ]

                async def _check_diag(r):
                    has_diag = False
                    has_la = False
                    has_storage = False
                    has_eventhub = False
                    async with _CONCURRENCY:
                        try:
                            settings = monitor.diagnostic_settings.list(r.id)
                            async for ds in settings:
                                has_diag = True
                                if ds.workspace_id:
                                    has_la = True
                                if ds.storage_account_id:
                                    has_storage = True
                                if ds.event_hub_authorization_rule_id:
                                    has_eventhub = True
                        except Exception:
                            pass
                    return make_evidence(
                        source=Source.AZURE, collector="AzureDiagnostics",
                        evidence_type="azure-diagnostic-setting",
                        description=f"Diagnostics: {r.name}",
                        data={
                            "ResourceId": r.id,
                            "ResourceName": r.name,
                            "ResourceType": r.type,
                            "HasDiagnostics": has_diag,
                            "HasLogAnalytics": has_la,
                            "HasStorageAccount": has_storage,
                            "HasEventHub": has_eventhub,
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=r.id, resource_type=r.type,
                    )

                diag_results = await asyncio.gather(
                    *[_check_diag(r) for r in target_resources],
                    return_exceptions=True,
                )
                for result in diag_results:
                    if not isinstance(result, Exception):
                        evidence.append(result)

                await monitor.close()
                await res_client.close()
                log.info("  [AzureDiagnostics] %s: checked %d resources", sub_name, len(target_resources))
            except Exception as exc:
                log.warning("  [AzureDiagnostics] %s failed: %s", sub_name, exc)
        return evidence

    return (await run_collector("AzureDiagnostics", Source.AZURE, _collect)).data
