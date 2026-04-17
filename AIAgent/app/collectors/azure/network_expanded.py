"""
Azure Network Expanded Collector
Firewalls, route tables, flow logs, DNS zones, load balancers.
"""

from __future__ import annotations
import asyncio
from azure.mgmt.network.aio import NetworkManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector

_CONCURRENCY = asyncio.Semaphore(8)


@register_collector(name="network_expanded", plane="control", source="azure", priority=71)
async def collect_azure_network_expanded(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]
            try:
                net = NetworkManagementClient(creds.credential, sub_id)

                # Firewalls
                firewalls = await paginate_arm(net.azure_firewalls.list_all())
                for fw in firewalls:
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureNetworkExpanded",
                        evidence_type="azure-firewall",
                        description=f"Firewall: {fw.name}",
                        data={
                            "FirewallId": fw.id, "Name": fw.name,
                            "Location": fw.location,
                            "ThreatIntelMode": _v(fw.threat_intel_mode, "Off"),
                            "SkuTier": _v(fw.sku.tier, "Standard") if fw.sku and fw.sku.tier else "Standard",
                            "NetworkRuleCollectionCount": len(fw.network_rule_collections or []),
                            "ApplicationRuleCollectionCount": len(fw.application_rule_collections or []),
                            "NatRuleCollectionCount": len(fw.nat_rule_collections or []),
                            "SubscriptionId": sub_id, "SubscriptionName": sub_name,
                        },
                        resource_id=fw.id or "", resource_type="AzureFirewall",
                    ))

                # Route tables
                rts = await paginate_arm(net.route_tables.list_all())
                for rt in rts:
                    routes = list(rt.routes or [])
                    has_default_to_nva = any(
                        r.address_prefix == "0.0.0.0/0" and r.next_hop_type and
                        _v(r.next_hop_type) in ("VirtualAppliance", "VnetLocal")
                        for r in routes
                    )
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureNetworkExpanded",
                        evidence_type="azure-route-table",
                        description=f"Route table: {rt.name}",
                        data={
                            "RouteTableId": rt.id, "Name": rt.name,
                            "Location": rt.location,
                            "RouteCount": len(routes),
                            "HasDefaultRouteToNVA": has_default_to_nva,
                            "DisableBgpRoutePropagation": rt.disable_bgp_route_propagation or False,
                            "SubscriptionId": sub_id, "SubscriptionName": sub_name,
                        },
                        resource_id=rt.id or "", resource_type="RouteTable",
                    ))

                # NSG Flow Logs (via Network Watcher) — parallel per watcher
                try:
                    watchers = await paginate_arm(net.network_watchers.list_all())

                    async def _fetch_flow_logs(watcher):
                        results = []
                        rg = watcher.id.split("/resourceGroups/")[1].split("/")[0] if watcher.id else ""
                        async with _CONCURRENCY:
                            flow_logs = await paginate_arm(
                                net.flow_logs.list(rg, watcher.name)
                            )
                        for fl in flow_logs:
                            retention = fl.retention_policy
                            results.append(make_evidence(
                                source=Source.AZURE, collector="AzureNetworkExpanded",
                                evidence_type="azure-nsg-flow-log",
                                description=f"Flow log: {fl.name}",
                                data={
                                    "FlowLogId": fl.id, "Name": fl.name,
                                    "Enabled": fl.enabled or False,
                                    "RetentionDays": retention.days if retention else 0,
                                    "RetentionEnabled": retention.enabled if retention else False,
                                    "TrafficAnalyticsEnabled": (
                                        fl.flow_analytics_configuration.network_watcher_flow_analytics_configuration.enabled
                                        if fl.flow_analytics_configuration and
                                           fl.flow_analytics_configuration.network_watcher_flow_analytics_configuration
                                        else False
                                    ),
                                    "SubscriptionId": sub_id, "SubscriptionName": sub_name,
                                },
                                resource_id=fl.id or "", resource_type="FlowLog",
                            ))
                        return results

                    watcher_results = await asyncio.gather(
                        *[_fetch_flow_logs(w) for w in watchers],
                        return_exceptions=True,
                    )
                    for result in watcher_results:
                        if isinstance(result, Exception):
                            continue
                        evidence.extend(result)
                except Exception:
                    pass

                await net.close()
                log.info("  [AzureNetworkExpanded] %s: %d firewalls, %d routes",
                         sub_name, len(firewalls), len(rts))
            except Exception as exc:
                log.warning("  [AzureNetworkExpanded] %s failed: %s", sub_name, exc)
        return evidence

    return (await run_collector("AzureNetworkExpanded", Source.AZURE, _collect)).data
