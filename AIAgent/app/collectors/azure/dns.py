"""
Azure DNS Collector
DNS Zones (public & private), record sets, DNSSEC configuration,
and Traffic Manager profiles.
"""

from __future__ import annotations
from azure.mgmt.dns.aio import DnsManagementClient
from azure.mgmt.privatedns.aio import PrivateDnsManagementClient
from azure.mgmt.trafficmanager.aio import TrafficManagerManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="dns", plane="control", source="azure", priority=140)
async def collect_azure_dns(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence: list[dict] = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]

            # --- Public DNS Zones ---
            try:
                dns_client = DnsManagementClient(creds.credential, sub_id)
                zones = await paginate_arm(dns_client.zones.list())
                for zone in zones:
                    # Count record sets
                    rg = (zone.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (zone.id or "") else ""
                    record_count = 0
                    if rg:
                        try:
                            records = await paginate_arm(dns_client.record_sets.list_by_dns_zone(rg, zone.name))
                            record_count = len(records)
                        except Exception:
                            pass

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureDNS",
                        evidence_type="azure-dns-zone",
                        description=f"DNS Zone: {zone.name}",
                        data={
                            "ZoneId": zone.id,
                            "Name": zone.name,
                            "ZoneType": _v(getattr(zone, "zone_type", None), "Public"),
                            "Location": zone.location or "global",
                            "NumberOfRecordSets": getattr(zone, "number_of_record_sets", record_count),
                            "NameServers": list(getattr(zone, "name_servers", []) or []),
                            "RecordSetCount": record_count,
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=zone.id or "", resource_type="DnsZone",
                    ))
                await dns_client.close()
                log.info("  [AzureDNS] %s: %d public DNS zones", sub_name, len(zones))
            except Exception as exc:
                log.warning("  [AzureDNS] %s Public DNS failed: %s", sub_name, exc)

            # --- Private DNS Zones ---
            try:
                pdns_client = PrivateDnsManagementClient(creds.credential, sub_id)
                private_zones = await paginate_arm(pdns_client.private_zones.list())
                for pz in private_zones:
                    vnet_links_count = 0
                    rg = (pz.id or "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in (pz.id or "") else ""
                    if rg:
                        try:
                            links = await paginate_arm(
                                pdns_client.virtual_network_links.list(rg, pz.name)
                            )
                            vnet_links_count = len(links)
                        except Exception:
                            pass

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureDNS",
                        evidence_type="azure-private-dns-zone",
                        description=f"Private DNS Zone: {pz.name}",
                        data={
                            "ZoneId": pz.id,
                            "Name": pz.name,
                            "Location": pz.location or "global",
                            "NumberOfRecordSets": getattr(pz, "number_of_record_sets", 0),
                            "NumberOfVirtualNetworkLinks": getattr(pz, "number_of_virtual_network_links", vnet_links_count),
                            "VnetLinksCount": vnet_links_count,
                            "MaxNumberOfRecordSets": getattr(pz, "max_number_of_record_sets", 0),
                            "ProvisioningState": _v(getattr(pz, "provisioning_state", None)),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=pz.id or "", resource_type="PrivateDnsZone",
                    ))
                await pdns_client.close()
                log.info("  [AzureDNS] %s: %d private DNS zones", sub_name, len(private_zones))
            except Exception as exc:
                log.warning("  [AzureDNS] %s Private DNS failed: %s", sub_name, exc)

            # --- Traffic Manager Profiles ---
            try:
                tm_client = TrafficManagerManagementClient(creds.credential, sub_id)
                profiles = await paginate_arm(tm_client.profiles.list_by_subscription())
                for profile in profiles:
                    props = profile.properties if hasattr(profile, "properties") else profile
                    endpoints = getattr(props, "endpoints", []) or []
                    dns_config = getattr(props, "dns_config", None)
                    monitor_config = getattr(props, "monitor_config", None)

                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureDNS",
                        evidence_type="azure-traffic-manager",
                        description=f"Traffic Manager: {profile.name}",
                        data={
                            "ProfileId": profile.id,
                            "Name": profile.name,
                            "Location": getattr(profile, "location", "global"),
                            "ProfileStatus": _v(getattr(props, "profile_status", None)),
                            "RoutingMethod": _v(getattr(props, "traffic_routing_method", None)),
                            "DnsRelativeName": getattr(dns_config, "relative_name", "") if dns_config else "",
                            "Ttl": getattr(dns_config, "ttl", 0) if dns_config else 0,
                            "MonitorProtocol": _v(getattr(monitor_config, "protocol", None)) if monitor_config else "",
                            "MonitorPort": getattr(monitor_config, "port", 0) if monitor_config else 0,
                            "MonitorPath": getattr(monitor_config, "path", "") if monitor_config else "",
                            "EndpointCount": len(endpoints),
                            "SubscriptionId": sub_id,
                            "SubscriptionName": sub_name,
                        },
                        resource_id=profile.id or "", resource_type="TrafficManagerProfile",
                    ))
                await tm_client.close()
                log.info("  [AzureDNS] %s: %d traffic manager profiles", sub_name, len(profiles))
            except Exception as exc:
                log.warning("  [AzureDNS] %s Traffic Manager failed: %s", sub_name, exc)

        return evidence

    return (await run_collector("AzureDNS", Source.AZURE, _collect)).data
