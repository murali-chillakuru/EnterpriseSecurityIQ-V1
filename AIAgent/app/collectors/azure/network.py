"""
Azure Network Collector
NSGs, VNets, storage account network settings.
"""

from __future__ import annotations
from azure.mgmt.network.aio import NetworkManagementClient
from azure.mgmt.storage.aio import StorageManagementClient
from app.models import Source
from app.collectors.base import run_collector, paginate_arm, make_evidence, _v
from app.auth import ComplianceCredentials
from app.logger import log
from app.collectors.registry import register_collector


@register_collector(name="network", plane="control", source="azure", priority=70)
async def collect_azure_network(creds: ComplianceCredentials, subscriptions: list[dict]) -> list[dict]:
    async def _collect():
        evidence = []
        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub["display_name"]
            try:
                net_client = NetworkManagementClient(creds.credential, sub_id)

                # NSGs + rules
                nsgs = await paginate_arm(net_client.network_security_groups.list_all())
                for nsg in nsgs:
                    rules = []
                    for rule in (nsg.security_rules or []):
                        rules.append({
                            "Name": rule.name,
                            "Direction": _v(rule.direction),
                            "Access": _v(rule.access),
                            "Priority": rule.priority,
                            "SourceAddressPrefix": rule.source_address_prefix or "",
                            "DestinationPortRange": rule.destination_port_range or "",
                            "Protocol": _v(rule.protocol, "*"),
                        })
                        evidence.append(make_evidence(
                            source=Source.AZURE, collector="AzureNetwork",
                            evidence_type="azure-nsg-rule",
                            description=f"NSG Rule: {nsg.name}/{rule.name}",
                            data={
                                "NsgName": nsg.name,
                                "RuleName": rule.name,
                                "Direction": _v(rule.direction),
                                "Access": _v(rule.access),
                                "Priority": rule.priority,
                                "SourceAddressPrefix": rule.source_address_prefix or "",
                                "SourceAddressPrefixes": list(rule.source_address_prefixes or []),
                                "DestinationPortRange": rule.destination_port_range or "",
                                "DestinationPortRanges": list(rule.destination_port_ranges or []),
                                "Protocol": _v(rule.protocol, "*"),
                                "IsAllowAnyInbound": (
                                    (rule.direction and _v(rule.direction) == "Inbound") and
                                    (rule.access and _v(rule.access) == "Allow") and
                                    (rule.source_address_prefix in ("*", "0.0.0.0/0", "Internet", "Any"))
                                ),
                                "SubscriptionId": sub_id, "SubscriptionName": sub_name,
                            },
                            resource_id=nsg.id or "", resource_type="NSGRule",
                        ))

                # VNets
                vnets = await paginate_arm(net_client.virtual_networks.list_all())
                for vnet in vnets:
                    subnets = []
                    for sn in (vnet.subnets or []):
                        subnets.append({"Name": sn.name, "AddressPrefix": sn.address_prefix})
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureNetwork",
                        evidence_type="azure-virtual-network",
                        description=f"VNet: {vnet.name}",
                        data={
                            "VNetId": vnet.id, "Name": vnet.name,
                            "Location": vnet.location,
                            "AddressSpace": list(vnet.address_space.address_prefixes) if vnet.address_space else [],
                            "SubnetCount": len(vnet.subnets or []),
                            "Subnets": subnets,
                            "DdosProtectionEnabled": (
                                vnet.enable_ddos_protection if vnet.enable_ddos_protection else False
                            ),
                            "SubscriptionId": sub_id, "SubscriptionName": sub_name,
                        },
                        resource_id=vnet.id or "", resource_type="VirtualNetwork",
                    ))

                await net_client.close()

                # Storage security
                storage_client = StorageManagementClient(creds.credential, sub_id)
                accounts = await paginate_arm(storage_client.storage_accounts.list())
                for sa in accounts:
                    evidence.append(make_evidence(
                        source=Source.AZURE, collector="AzureNetwork",
                        evidence_type="azure-storage-security",
                        description=f"Storage: {sa.name}",
                        data={
                            "StorageAccountId": sa.id, "Name": sa.name,
                            "Location": sa.location,
                            "EnableHttpsTrafficOnly": sa.enable_https_traffic_only if sa.enable_https_traffic_only is not None else True,
                            "MinimumTlsVersion": _v(sa.minimum_tls_version, "TLS1_0"),
                            "AllowBlobPublicAccess": sa.allow_blob_public_access if sa.allow_blob_public_access is not None else False,
                            "AllowSharedKeyAccess": sa.allow_shared_key_access if sa.allow_shared_key_access is not None else True,
                            "NetworkDefaultAction": (
                                _v(sa.network_rule_set.default_action, "Allow")
                                if sa.network_rule_set and sa.network_rule_set.default_action else "Allow"
                            ),
                            "SubscriptionId": sub_id, "SubscriptionName": sub_name,
                        },
                        resource_id=sa.id or "", resource_type="StorageAccount",
                    ))
                await storage_client.close()

                log.info("  [AzureNetwork] %s: %d NSGs, %d VNets, %d storage",
                         sub_name, len(nsgs), len(vnets), len(accounts))
            except Exception as exc:
                log.warning("  [AzureNetwork] %s failed: %s", sub_name, exc)
        return evidence

    return (await run_collector("AzureNetwork", Source.AZURE, _collect)).data
